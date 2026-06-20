//! Testcontainers coverage of the platform-administrator identity domain through a real
//! `AuthEngine` over Redis: login → me → refresh → logout → revoke-all, plus the
//! login → MFA-challenge → full-token exchange for an MFA-enabled admin. Proves the
//! `PlatformAuthService` behaves identically against the real-Redis tier as against the
//! in-memory tier, that the platform session keyspaces (`prt:`/`prp:`/`psess:`/`psd:`) are the
//! ones actually written, and that platform tokens carry NO `tenantId`.
//!
//! Compiles only under the `platform` feature; every case returns early when Docker is
//! unavailable, so a no-Docker run still compiles and passes.
#![cfg(feature = "platform")]

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use bymax_auth_core::config::MfaConfig;
use bymax_auth_core::testing::{InMemoryPlatformUserRepository, InMemoryUserRepository};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::{AuthPlatformUser, MfaContext, PlatformLoginResult};
use secrecy::SecretString;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use time::OffsetDateTime;

const PASSWORD: &str = "correct horse battery staple";

/// A running Redis container plus its URL; dropping it stops the container.
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

impl TestRedis {
    fn stores(&self, namespace: &str) -> Option<RedisStores> {
        let _ = self.container.id();
        RedisStores::connect(&self.url, namespace.to_owned()).ok()
    }

    /// Every key currently present (test databases are small and isolated).
    async fn all_keys(&self) -> Vec<String> {
        let Ok(client) = redis::Client::open(self.url.as_str()) else {
            return Vec::new();
        };
        let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
            return Vec::new();
        };
        redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default()
    }
}

/// Start a `redis:8` container, returning `None` when Docker is unavailable so the test skips.
async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

/// A 32-byte AES key, base64-encoded for the MFA config.
fn key_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode([9u8; 32])
}

/// Hash a plaintext with the default (scrypt) hasher, for seeding an admin's stored hash. The
/// crypto crate is pulled with its default `scrypt` hasher, so `PasswordParams::default()`
/// (active = scrypt) is always available here.
fn hash_password(plain: &str) -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    bymax_auth_crypto::password::hash(plain.as_bytes(), &params).unwrap_or_default()
}

/// Build a platform-enabled engine over the supplied Redis stores, returning it plus the
/// in-memory platform repository so the test can seed and inspect admins.
fn build_engine(
    stores: Arc<RedisStores>,
) -> Option<(AuthEngine, Arc<InMemoryPlatformUserRepository>)> {
    // The crypto crate is compiled with its default `scrypt` hasher in this test target, so the
    // engine's default `PasswordAlgorithm::Scrypt` matches the hasher used to seed admin hashes.
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.roles.platform_hierarchy = Some(HashMap::from([
        ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
        ("SUPPORT".to_owned(), Vec::new()),
    ]));
    config.platform.enabled = true;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(key_b64()),
        issuer: "Bymax Platform".to_owned(),
        recovery_code_count: 8,
        totp_window: 2,
    });
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .platform_user_repository(admins.clone())
        .redis_stores(stores)
        .build()
        .ok()?;
    Some((engine, admins))
}

/// Seed an active platform admin (no MFA) and return its id.
fn seed_admin(admins: &InMemoryPlatformUserRepository, id: &str, email: &str) -> String {
    admins.insert(AuthPlatformUser {
        id: id.to_owned(),
        email: email.to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password(PASSWORD),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    id.to_owned()
}

/// The current Unix time in seconds, captured once for stable TOTP code computation.
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

#[tokio::test]
async fn platform_login_me_refresh_logout_and_revoke_all_against_redis() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("auth") else { return };
    let Some((engine, admins)) = build_engine(Arc::new(stores)) else {
        return;
    };
    let id = seed_admin(&admins, "p1", "ops@admin.io");
    let Some(svc) = engine.platform_auth() else { return };

    // Login issues a full platform session written to the PLATFORM keyspace.
    let Ok(PlatformLoginResult::Success(auth)) = svc
        .login("ops@admin.io", PASSWORD, "1.2.3.4", "agent")
        .await
    else {
        return;
    };
    assert_eq!(auth.user.email, "ops@admin.io");

    // The persisted keys are the platform ones (`prt:`/`psess:`/`psd:`), never the dashboard
    // ones (`rt:`/`sess:`/`sd:`), and the namespace prefix applies.
    let keys = redis.all_keys().await;
    assert!(keys.iter().any(|k| k.starts_with("auth:prt:")));
    assert!(keys.iter().any(|k| k.starts_with("auth:psess:")));
    assert!(keys.iter().any(|k| k.starts_with("auth:psd:")));
    assert!(!keys.iter().any(|k| k.starts_with("auth:rt:")));
    assert!(!keys.iter().any(|k| k.starts_with("auth:sess:")));

    // The access token's claims carry a `platform` discriminator and NO tenantId (decoded
    // directly from the JWT payload segment — the public surface proves the wire shape).
    let body = auth.access_token.split('.').nth(1).unwrap_or_default();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .unwrap_or_default();
    let payload = String::from_utf8(decoded).unwrap_or_default();
    assert!(payload.contains("\"type\":\"platform\""));
    assert!(!payload.contains("tenantId"));

    // me returns the admin; refresh rotates to a new pair against the platform keyspace.
    assert!(matches!(svc.me(&id).await, Ok(u) if u.email == "ops@admin.io"));
    let Ok(rotated) = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await else {
        return;
    };
    assert_ne!(rotated.refresh_token, auth.refresh_token);

    // The rotation planted a grace pointer (`prp:`) for the OLD token. Logging out the OLD token
    // must clean BOTH its (already-consumed) primary key AND that grace pointer, so a follow-up
    // grace-window rotation of the old token now fails and no `prp:` key lingers.
    let pre_logout = redis.all_keys().await;
    assert!(pre_logout.iter().any(|k| k.starts_with("auth:prp:")));
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token, &id)
            .await
            .is_ok()
    );
    assert!(matches!(
        svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await,
        Err(bymax_auth_types::AuthError::RefreshTokenInvalid)
    ));
    assert!(
        !redis
            .all_keys()
            .await
            .iter()
            .any(|k| k.starts_with("auth:prp:"))
    );

    // Logout also revokes the live (rotated) session: the rotated refresh token no longer rotates,
    // proving the primary refresh key was cleaned in the platform keyspace.
    assert!(
        svc.logout(&rotated.access_token, &rotated.refresh_token, &id)
            .await
            .is_ok()
    );
    assert!(matches!(
        svc.refresh(&rotated.refresh_token, "1.2.3.4", "agent")
            .await,
        Err(bymax_auth_types::AuthError::RefreshTokenInvalid)
    ));

    // A second login, then revoke-all atomically clears every platform session.
    let Ok(PlatformLoginResult::Success(again)) = svc
        .login("ops@admin.io", PASSWORD, "5.6.7.8", "agent")
        .await
    else {
        return;
    };
    assert!(svc.revoke_all_platform_sessions(&id).await.is_ok());
    assert!(matches!(
        svc.refresh(&again.refresh_token, "5.6.7.8", "agent").await,
        Err(bymax_auth_types::AuthError::RefreshTokenInvalid)
    ));
    // The platform session index for the admin is gone after revoke-all.
    let after = redis.all_keys().await;
    assert!(!after.iter().any(|k| k.starts_with("auth:psess:")));
}

#[tokio::test]
async fn platform_mfa_challenge_exchange_issues_a_full_session_against_redis() {
    let Some(redis) = try_start().await else { return };
    // A distinct namespace isolates this case from the first within one container.
    let Some(stores) = redis.stores("plat") else { return };
    let Some((engine, admins)) = build_engine(Arc::new(stores)) else {
        return;
    };
    let id = seed_admin(&admins, "p-mfa", "mfa-admin.io");
    let Some(mfa) = engine.mfa() else { return };

    // Enable MFA on the platform admin (platform context), then mint a platform temp token and
    // exchange it for a full platform session with a valid TOTP code — the login → challenge →
    // full-token exchange, end to end against Redis.
    let base = now_secs();
    let Ok(setup) = mfa.setup(&id, MfaContext::Platform).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &id,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Platform
        )
        .await
        .is_ok()
    );

    // A login for the now-MFA-enabled admin returns a challenge (not tokens).
    let Some(svc) = engine.platform_auth() else { return };
    let challenge = svc
        .login("mfa-admin.io", PASSWORD, "1.2.3.4", "agent")
        .await;
    let temp = match challenge {
        Ok(PlatformLoginResult::MfaChallenge(c)) => c.mfa_temp_token,
        _ => return,
    };

    // Exchange the temp token for a full session via the MFA challenge flow.
    let exchanged = mfa
        .challenge(&temp, &code_at(&setup.secret, base + 30), "1.2.3.4", "ua")
        .await;
    let result = match exchanged {
        Ok(bymax_auth_core::LoginResultMfa::Platform(result)) => result,
        _ => return,
    };
    assert_eq!(result.user.email, "mfa-admin.io");
    // The issued access token carries `mfaVerified: true` and the platform discriminator, with
    // no tenantId — decoded directly from the JWT payload.
    let body = result.access_token.split('.').nth(1).unwrap_or_default();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .unwrap_or_default();
    let payload = String::from_utf8(decoded).unwrap_or_default();
    assert!(payload.contains("\"type\":\"platform\""));
    assert!(payload.contains("\"mfaVerified\":true"));
    assert!(!payload.contains("tenantId"));
    // The session landed in the platform keyspace under the `plat` namespace.
    let keys = redis.all_keys().await;
    assert!(keys.iter().any(|k| k.starts_with("plat:prt:")));
    assert!(keys.iter().any(|k| k.starts_with("plat:psess:")));
}
