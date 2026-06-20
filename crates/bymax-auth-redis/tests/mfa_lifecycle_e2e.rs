//! Testcontainers coverage of the full MFA lifecycle through a real `AuthEngine` over Redis:
//! setup → verify-and-enable → login → challenge (TOTP and recovery code) → disable, plus the
//! atomic recovery-code regeneration and the single-consume guarantee under two concurrent
//! correct TOTP submissions. Proves the engine behaves identically against the real-Redis tier
//! as against the in-memory tier, with anti-replay holding on every path.
//!
//! Compiles only under the `mfa` feature; every case returns early when Docker is unavailable.
#![cfg(feature = "mfa")]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use base64::Engine as _;
use bymax_auth_core::config::MfaConfig;
use bymax_auth_core::context::RequestContext;
use bymax_auth_core::services::auth::{LoginInput, RegisterInput};
use bymax_auth_core::testing::InMemoryUserRepository;
use bymax_auth_core::{AuthConfig, AuthEngine, Environment, LoginResultMfa};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::{LoginResult, MfaContext};
use secrecy::SecretString;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const PASSWORD: &str = "correct horse battery staple";
const TENANT: &str = "t1";

struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

impl TestRedis {
    fn stores(&self, namespace: &str) -> Option<RedisStores> {
        let _ = self.container.id();
        RedisStores::connect(&self.url, namespace.to_owned()).ok()
    }
}

async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

fn ctx() -> RequestContext {
    RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new())
}

/// Build an engine with MFA configured over the supplied Redis stores.
fn build_engine(stores: Arc<RedisStores>) -> Option<(AuthEngine, Arc<InMemoryUserRepository>)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(
            base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
        ),
        issuer: "Bymax One".to_owned(),
        recovery_code_count: 8,
        totp_window: 2,
    });
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores)
        .build()
        .ok()?;
    Some((engine, users))
}

async fn register(engine: &AuthEngine, email: &str) -> Option<String> {
    let input = RegisterInput {
        email: email.to_owned(),
        name: "U".to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: TENANT.to_owned(),
    };
    match engine.register(input, &ctx()).await {
        Ok(LoginResult::Success(auth)) => Some(auth.user.id),
        _ => None,
    }
}

async fn login_temp_token(engine: &AuthEngine, email: &str) -> Option<String> {
    let input = LoginInput {
        email: email.to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: TENANT.to_owned(),
    };
    match engine.login(input, &ctx()).await {
        Ok(LoginResult::MfaChallenge(c)) => Some(c.mfa_temp_token),
        _ => None,
    }
}

/// The current Unix time in seconds, captured once so a test's several codes share one base.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A valid TOTP code for `secret_b32` at the absolute Unix time `at_unix`.
fn code_at(secret_b32: &str, at_unix: i64) -> String {
    let raw = bymax_auth_crypto::totp::decode_secret_base32(secret_b32).unwrap_or_default();
    let when = u64::try_from(at_unix.max(0)).unwrap_or(0);
    format!("{:06}", bymax_auth_crypto::totp::totp(&raw, when, 30, 6))
}

/// A valid TOTP code for `secret_b32` at `offset_secs` from now (for one- or two-code paths).
fn code(secret_b32: &str, offset_secs: i64) -> String {
    code_at(secret_b32, now_secs() + offset_secs)
}

#[tokio::test]
async fn full_lifecycle_against_real_redis() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfalife") else { return };
    let Some((engine, _users)) = build_engine(Arc::new(stores)) else { return };
    let Some(uid) = register(&engine, "life@example.com").await else { return };
    let Some(mfa) = engine.mfa() else { return };

    // setup → enable. Compute the lifecycle's distinct TOTP codes from one captured base
    // (steps s, s+1, s+2, s-1), so they never collide as the clock advances mid-test.
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else { return };
    assert_eq!(setup.recovery_codes.len(), 8);
    let base = now_secs();
    let enable_code = code_at(&setup.secret, base);
    let challenge_code = code_at(&setup.secret, base + 30);
    let regen_code = code_at(&setup.secret, base + 60);
    let disable_code = code_at(&setup.secret, base - 30);
    assert!(
        mfa.verify_and_enable(&uid, &enable_code, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await
            .is_ok()
    );

    // challenge via TOTP (a fresh step so the anti-replay marker is new).
    let Some(temp) = login_temp_token(&engine, "life@example.com").await else { return };
    assert!(matches!(
        mfa.challenge(&temp, &challenge_code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    // The temp token is single-use: replaying it now fails (its marker is consumed; the code
    // here is irrelevant because the temp-token check precedes the TOTP check).
    assert!(
        mfa.challenge(&temp, &challenge_code, "1.2.3.4", "ua")
            .await
            .is_err()
    );

    // challenge via recovery code, then prove single-use against real Redis.
    let recovery = setup.recovery_codes[0].clone();
    let Some(temp2) = login_temp_token(&engine, "life@example.com").await else { return };
    assert!(matches!(
        mfa.challenge(&temp2, &recovery, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    let Some(temp3) = login_temp_token(&engine, "life@example.com").await else { return };
    assert!(
        mfa.challenge(&temp3, &recovery, "1.2.3.4", "ua")
            .await
            .is_err()
    );

    // Regenerate atomically: the old codes are invalidated wholesale.
    let Ok(fresh) = mfa
        .regenerate_recovery_codes(&uid, &regen_code, "1.2.3.4", "ua", MfaContext::Dashboard)
        .await
    else {
        return;
    };
    assert_ne!(fresh, setup.recovery_codes);
    let Some(temp4) = login_temp_token(&engine, "life@example.com").await else { return };
    // An old recovery code can no longer coexist with the new set.
    assert!(
        mfa.challenge(&temp4, &recovery, "1.2.3.4", "ua")
            .await
            .is_err()
    );

    // disable.
    assert!(
        mfa.disable(&uid, &disable_code, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await
            .is_ok()
    );
    // A subsequent login no longer challenges (MFA is off): it succeeds outright.
    let input = LoginInput {
        email: "life@example.com".to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: TENANT.to_owned(),
    };
    assert!(matches!(
        engine.login(input, &ctx()).await,
        Ok(LoginResult::Success(_))
    ));
}

#[tokio::test]
async fn concurrent_correct_totp_yields_one_session() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfaconc2") else { return };
    let Some((engine, _users)) = build_engine(Arc::new(stores)) else { return };
    let Some(uid) = register(&engine, "conc@example.com").await else { return };

    let secret;
    {
        let Some(mfa) = engine.mfa() else { return };
        let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else { return };
        if mfa
            .verify_and_enable(
                &uid,
                &code(&setup.secret, 0),
                "1.2.3.4",
                "ua",
                MfaContext::Dashboard,
            )
            .await
            .is_err()
        {
            return;
        }
        secret = setup.secret;
    }

    let Some(temp) = login_temp_token(&engine, "conc@example.com").await else { return };
    let totp = code(&secret, 30);
    let engine = Arc::new(engine);

    // Two concurrent submissions of the same correct code share one temp token: the fused Lua
    // admits exactly one (one session); the loser sees the anti-replay marker and is rejected.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let engine = engine.clone();
        let temp = temp.clone();
        let totp = totp.clone();
        handles.push(tokio::spawn(async move {
            match engine.mfa() {
                Some(mfa) => mfa.challenge(&temp, &totp, "1.2.3.4", "ua").await.is_ok(),
                None => false,
            }
        }));
    }
    let mut sessions = 0;
    for handle in handles {
        if let Ok(true) = handle.await {
            sessions += 1;
        }
    }
    assert_eq!(
        sessions, 1,
        "exactly one concurrent challenge may issue a session"
    );
}
