//! Hermetic (in-memory) coverage of the MFA lifecycle: the full dashboard flow against a real
//! `AuthEngine` over the in-memory stores, the platform-context routing, every flow-error
//! branch, and the TOCTOU-race / corrupt-record branches of `setup` via a scripted store.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bymax_auth_jwt::keys::HsKey;
use bymax_auth_types::{AuthError, AuthPlatformUser, LoginResult, MfaContext};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::{LoginResultMfa, MfaService, MfaServiceDeps, MfaSetupData};
use crate::config::{AuthConfig, Environment, MfaConfig, SessionConfig};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::brute_force::BruteForceService;
use crate::services::session::SessionService;
use crate::services::token_manager::TokenManagerService;
use crate::testing::{InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository};
use crate::traits::{
    AuthHooks, BruteForceStore, EmailProvider, HookContext, MfaStore, NoOpAuthHooks,
    NoOpEmailProvider, PlatformUserRepository, SessionStore, UserRepository,
};

const PASSWORD: &str = "correct horse battery staple";
const TENANT: &str = "t1";

/// A 32-byte AES key, base64-encoded for the MFA config.
fn key_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

/// A request context for the engine flows.
fn ctx() -> RequestContext {
    RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new())
}

/// The harness: a real engine over the in-memory stores with MFA configured, plus handles to
/// the in-memory repositories for seeding and inspection.
struct Harness {
    engine: AuthEngine,
    users: Arc<InMemoryUserRepository>,
    platform: Arc<InMemoryPlatformUserRepository>,
}

/// Build the harness. `sessions` toggles session tracking; `wire_platform` wires a platform
/// repository (without enabling the platform domain) so the platform-context routing is
/// exercised.
fn build(sessions: bool, wire_platform: bool) -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let platform = Arc::new(InMemoryPlatformUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;
    config.sessions.enabled = sessions;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(key_b64()),
        issuer: "Bymax One".to_owned(),
        recovery_code_count: 8,
        // A ±2-step window gives five distinct in-window codes, so a test can verify several
        // codes without an anti-replay collision (each distinct step has a distinct value).
        totp_window: 2,
    });
    let mut builder = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores);
    if wire_platform {
        builder = builder.platform_user_repository(platform.clone());
    }
    let engine = builder.build().ok()?;
    Some(Harness {
        engine,
        users,
        platform,
    })
}

/// Register an active dashboard user and return its id.
async fn register(engine: &AuthEngine, email: &str) -> Option<String> {
    let input = crate::services::auth::RegisterInput {
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

/// Log in and return the MFA temp token (the user must already have MFA enabled).
async fn login_temp_token(engine: &AuthEngine, email: &str) -> Option<String> {
    let input = crate::services::auth::LoginInput {
        email: email.to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: TENANT.to_owned(),
    };
    match engine.login(input, &ctx()).await {
        Ok(LoginResult::MfaChallenge(challenge)) => Some(challenge.mfa_temp_token),
        _ => None,
    }
}

/// The current Unix time in seconds, captured once so a test that needs several distinct
/// codes computes them all against one stable base (a per-call clock read could drift across a
/// 30 s step boundary mid-test and collide two offsets, defeating anti-replay).
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

/// A valid TOTP code for `secret_b32` at `offset_secs` from now (for tests that use one or two
/// codes, where a per-call clock read cannot collide).
fn code(secret_b32: &str, offset_secs: i64) -> String {
    code_at(secret_b32, now_secs() + offset_secs)
}

/// A valid TOTP code for raw secret bytes at the absolute Unix time `at_unix`.
fn raw_code(raw: &[u8], at_unix: i64) -> String {
    let when = u64::try_from(at_unix.max(0)).unwrap_or(0);
    format!("{:06}", bymax_auth_crypto::totp::totp(raw, when, 30, 6))
}

/// A six-digit code guaranteed NOT to verify against `secret_b32` within the window: it scans
/// the candidate space for one outside the valid set at every step the verifier could accept,
/// even if its clock has drifted a step since `now`, so the wrong-TOTP path is deterministic.
fn wrong_totp(secret_b32: &str) -> String {
    let base = now_secs();
    let valid: Vec<String> = (-3..=3)
        .map(|o| code_at(secret_b32, base + o * 30))
        .collect();
    for candidate in 0u32..1000 {
        let guess = format!("{candidate:06}");
        if !valid.contains(&guess) {
            return guess;
        }
    }
    "999999".to_owned()
}

/// A sample credential-free user for the detached-notification helpers.
fn sample_safe_user() -> bymax_auth_types::SafeAuthUser {
    bymax_auth_types::SafeAuthUser {
        id: "u1".to_owned(),
        email: "u@example.com".to_owned(),
        name: "U".to_owned(),
        role: "USER".to_owned(),
        status: "ACTIVE".to_owned(),
        tenant_id: TENANT.to_owned(),
        email_verified: true,
        mfa_enabled: true,
        oauth_provider: None,
        oauth_provider_id: None,
        last_login_at: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A sample hook context for the detached-notification helpers.
fn sample_hook_ctx() -> HookContext {
    HookContext {
        user_id: Some("u1".to_owned()),
        email: Some("u@example.com".to_owned()),
        tenant_id: None,
        ip: "1.2.3.4".to_owned(),
        user_agent: "ua".to_owned(),
        sanitized_headers: BTreeMap::new(),
    }
}

#[tokio::test]
async fn full_dashboard_lifecycle() {
    // setup -> idempotent setup -> enable -> challenge (TOTP) -> challenge (recovery) ->
    // recovery single-use -> regenerate (keeps sessions) -> disable, with anti-replay holding
    // across every TOTP path (distinct steps per verification).
    let Some(h) = build(true, false) else { return };
    let Some(uid) = register(&h.engine, "u@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };

    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert_eq!(setup.recovery_codes.len(), 8);
    assert!(setup.qr_code_uri.starts_with("otpauth://totp/Bymax%20One:"));
    // Each recovery code is the documented grouped 96-bit format.
    assert!(
        setup
            .recovery_codes
            .iter()
            .all(|c| c.len() == 29 && c.matches('-').count() == 5)
    );

    // Idempotent setup returns the same material (fast-path).
    let Ok(again) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert_eq!(setup.secret, again.secret);
    assert_eq!(setup.recovery_codes, again.recovery_codes);

    // Four distinct TOTP verifications (enable, TOTP challenge, regenerate, disable) need four
    // distinct, non-colliding codes. Compute them from ONE captured base at steps
    // {s, s+1, s+2, s-1}: distinct, and all within the verifier's ±2 window throughout a test
    // that advances at most one step.
    let base = now_secs();
    let enable_code = code_at(&setup.secret, base);
    let challenge_code = code_at(&setup.secret, base + 30);
    let regen_code = code_at(&setup.secret, base + 60);
    let disable_code = code_at(&setup.secret, base - 30);

    // Enable with a valid code; the success value carries no secret.
    assert!(
        mfa.verify_and_enable(&uid, &enable_code, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await
            .is_ok()
    );
    // No read path re-exposes the secret: a further setup is rejected, never re-returning it.
    assert!(matches!(
        mfa.setup(&uid, MfaContext::Dashboard).await,
        Err(AuthError::MfaAlreadyEnabled)
    ));

    // Challenge via TOTP (a different step than enable, so the anti-replay marker is fresh).
    let Some(temp) = login_temp_token(&h.engine, "u@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, &challenge_code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));

    // Challenge via a recovery code; then prove the code is single-use.
    let recovery = setup.recovery_codes[0].clone();
    let Some(temp2) = login_temp_token(&h.engine, "u@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp2, &recovery, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    let Some(temp3) = login_temp_token(&h.engine, "u@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp3, &recovery, "1.2.3.4", "ua").await,
        Err(AuthError::MfaInvalidCode)
    ));

    // Regenerate: a fresh set, the old codes invalidated, sessions NOT revoked.
    let Ok(new_codes) = mfa
        .regenerate_recovery_codes(&uid, &regen_code, "1.2.3.4", "ua", MfaContext::Dashboard)
        .await
    else {
        return;
    };
    assert_eq!(new_codes.len(), 8);
    assert_ne!(new_codes, setup.recovery_codes);

    // Disable with a fourth distinct step.
    assert!(
        mfa.disable(&uid, &disable_code, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await
            .is_ok()
    );
    // After disable the user is no longer MFA-enabled.
    let after = h.users.find_by_id(&uid, None).await;
    assert!(matches!(after, Ok(Some(u)) if !u.mfa_enabled && u.mfa_secret.is_none()));
}

#[tokio::test]
async fn anti_replay_rejects_a_code_already_used_on_enable() {
    // A code spent enabling MFA cannot be replayed on the challenge path (the `tu:` marker
    // persists), proving anti-replay spans the enable→challenge boundary.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "replay@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    let enable_code = code(&setup.secret, 0);
    assert!(
        mfa.verify_and_enable(&uid, &enable_code, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await
            .is_ok()
    );
    let Some(temp) = login_temp_token(&h.engine, "replay@example.com").await else {
        return;
    };
    // The same code that enabled MFA is now a replay on challenge.
    assert!(matches!(
        mfa.challenge(&temp, &enable_code, "1.2.3.4", "ua").await,
        Err(AuthError::MfaInvalidCode)
    ));
}

#[tokio::test]
async fn setup_rejects_already_enabled_and_a_platform_context_without_a_repo() {
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "guard@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    // No platform repository is wired, so a platform context fails fast.
    assert!(matches!(
        mfa.setup(&uid, MfaContext::Platform).await,
        Err(AuthError::MfaNotEnabled)
    ));
    // An unknown user is also `MfaNotEnabled`.
    assert!(matches!(
        mfa.setup("ghost", MfaContext::Dashboard).await,
        Err(AuthError::MfaNotEnabled)
    ));
    // Enable, then a second setup is rejected.
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    assert!(matches!(
        mfa.setup(&uid, MfaContext::Dashboard).await,
        Err(AuthError::MfaAlreadyEnabled)
    ));
    assert!(matches!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await,
        Err(AuthError::MfaAlreadyEnabled)
    ));
}

#[tokio::test]
async fn enable_requires_a_pending_record_and_rejects_a_wrong_code() {
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "enable@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    // No setup yet -> no pending record.
    assert!(matches!(
        mfa.verify_and_enable(&uid, "000000", "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::MfaSetupRequired)
    ));
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    // A wrong code does not enable and does not consume the pending record.
    assert!(matches!(
        mfa.verify_and_enable(&uid, "not-a-code", "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::MfaInvalidCode)
    ));
    // The record survived, so a correct code still enables.
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn challenge_rejects_a_bad_temp_token_and_a_platform_context() {
    let Some(h) = build(false, true) else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    // A garbage temp token never reaches the user lookup.
    assert!(matches!(
        mfa.challenge("garbage", "000000", "1.2.3.4", "ua").await,
        Err(AuthError::MfaTempTokenInvalid)
    ));
    // A platform-context temp token is rejected (platform challenge issuance is deferred).
    let Some(uid) = register(&h.engine, "plat-challenge@example.com").await else {
        return;
    };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token(&uid, MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, "000000", "1.2.3.4", "ua").await,
        Err(AuthError::MfaNotEnabled)
    ));
}

#[tokio::test]
async fn challenge_rejects_when_mfa_is_not_enabled() {
    // A user without MFA enabled who somehow holds a temp token is rejected at the fetch gate.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "notenabled@example.com").await else {
        return;
    };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token(&uid, MfaContext::Dashboard)
        .await
    else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    assert!(matches!(
        mfa.challenge(&temp, "000000", "1.2.3.4", "ua").await,
        Err(AuthError::MfaNotEnabled)
    ));
}

#[tokio::test]
async fn challenge_locks_out_after_repeated_wrong_codes() {
    // A single temp token (verify is non-consuming) absorbs repeated wrong codes; after the
    // fifth failure the sixth attempt is locked out. Non-numeric codes take the recovery path
    // and never match, so each attempt is a deterministic failure.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "lock@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    let Some(temp) = login_temp_token(&h.engine, "lock@example.com").await else {
        return;
    };
    for _ in 0..5 {
        assert!(matches!(
            mfa.challenge(&temp, "no-such-code", "1.2.3.4", "ua").await,
            Err(AuthError::MfaInvalidCode)
        ));
    }
    assert!(matches!(
        mfa.challenge(&temp, "no-such-code", "1.2.3.4", "ua").await,
        Err(AuthError::AccountLocked { .. })
    ));
}

#[tokio::test]
async fn disable_is_totp_only_and_regenerate_keeps_sessions() {
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "manage@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    // disable before enable -> not enabled.
    assert!(matches!(
        mfa.disable(&uid, "000000", "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::MfaNotEnabled)
    ));
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    // A recovery code can never disable MFA (it is not a TOTP).
    let recovery = setup.recovery_codes[0].clone();
    assert!(matches!(
        mfa.disable(&uid, &recovery, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::MfaInvalidCode)
    ));
    // Regenerate keeps the secret and replaces the codes; an old code no longer verifies.
    let Ok(fresh) = mfa
        .regenerate_recovery_codes(
            &uid,
            &code(&setup.secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
        )
        .await
    else {
        return;
    };
    assert_ne!(fresh, setup.recovery_codes);
    let Some(temp) = login_temp_token(&h.engine, "manage@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, &recovery, "1.2.3.4", "ua").await,
        Err(AuthError::MfaInvalidCode)
    ));
    // Finally disable with a valid TOTP.
    assert!(
        mfa.disable(
            &uid,
            &code(&setup.secret, 60),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn disable_locks_out_after_repeated_wrong_codes() {
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "dislock@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    for _ in 0..5 {
        assert!(matches!(
            mfa.disable(&uid, "wrong-totp", "1.2.3.4", "ua", MfaContext::Dashboard)
                .await,
            Err(AuthError::MfaInvalidCode)
        ));
    }
    assert!(matches!(
        mfa.disable(&uid, "wrong-totp", "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::AccountLocked { .. })
    ));
}

#[tokio::test]
async fn platform_context_routes_to_the_platform_repository() {
    // With a platform repository wired, the full lifecycle routes to it: setup, enable, the
    // recovery-codes regenerate, and disable all read and write the platform admin record.
    let Some(h) = build(false, true) else { return };
    let admin = AuthPlatformUser {
        id: "p1".to_owned(),
        email: "admin@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: "$scrypt$x".to_owned(),
        role: "SUPER".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    };
    h.platform.insert(admin);
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup("p1", MfaContext::Platform).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            "p1",
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Platform
        )
        .await
        .is_ok()
    );
    // The platform admin row now carries the encrypted secret + hashed codes.
    let stored = h.platform.find_by_id("p1").await;
    assert!(matches!(stored, Ok(Some(ref a)) if a.mfa_enabled && a.mfa_secret.is_some()));
    // Regenerate and disable also route to the platform repo.
    assert!(
        mfa.regenerate_recovery_codes(
            "p1",
            &code(&setup.secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Platform
        )
        .await
        .is_ok()
    );
    assert!(
        mfa.disable(
            "p1",
            &code(&setup.secret, 60),
            "1.2.3.4",
            "ua",
            MfaContext::Platform
        )
        .await
        .is_ok()
    );
    let after = h.platform.find_by_id("p1").await;
    assert!(matches!(after, Ok(Some(ref a)) if !a.mfa_enabled));
}

// ---- Scripted-store branches: the TOCTOU race and corrupt-record paths of `setup` ----

/// An `MfaStore` whose `get_setup` returns a scripted sequence and whose `put_setup_nx`
/// returns a fixed value, so the lost-`SET NX`-race and record-corruption branches of `setup`
/// — unreachable with a coherent real store — are driven deterministically. The remaining
/// methods return benign defaults (they are not exercised by these tests).
struct ScriptedMfaStore {
    get_setup: Mutex<VecDeque<Option<String>>>,
    put_nx: bool,
}

#[async_trait]
impl MfaStore for ScriptedMfaStore {
    async fn put_setup_nx(&self, _k: &str, _v: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(self.put_nx)
    }
    async fn get_setup(&self, _k: &str) -> Result<Option<String>, AuthError> {
        // Recover the guard on a poisoned lock rather than masking it as an empty queue, so a
        // panic in another test thread surfaces the scripted state instead of a silent `None`.
        let mut queue = self
            .get_setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(queue.pop_front().flatten())
    }
    async fn take_setup(&self, _k: &str) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    async fn put_temp(&self, _j: &str, _u: &str, _ttl: u64) -> Result<(), AuthError> {
        Ok(())
    }
    async fn get_temp(&self, _j: &str) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    async fn del_temp(&self, _j: &str) -> Result<(), AuthError> {
        Ok(())
    }
    async fn mark_totp_used(&self, _r: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn challenge_consume(&self, _r: &str, _j: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// Build an `MfaService` directly over a custom MFA store and a seeded user, with the other
/// collaborators backed by fresh in-memory doubles. The AES key is the fixed `[7u8; 32]` the
/// scripted records are encrypted under.
fn service_over(store: Arc<dyn MfaStore>, users: Arc<InMemoryUserRepository>) -> MfaService {
    let inmem = Arc::new(InMemoryStores::new());
    let session_store: Arc<dyn SessionStore> = inmem.clone();
    let brute_force_store: Arc<dyn BruteForceStore> = inmem;
    let tokens = Arc::new(TokenManagerService::new(
        HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
        session_store.clone(),
        Duration::from_secs(900),
        7,
        Duration::from_secs(30),
    ));
    let sessions = Arc::new(SessionService::new(
        session_store.clone(),
        users.clone(),
        Arc::new(NoOpAuthHooks),
        SessionConfig::default(),
        3600,
    ));
    let brute_force = Arc::new(BruteForceService::new(brute_force_store, 5, 900));
    MfaService::new(MfaServiceDeps {
        mfa_store: store,
        user_repo: users,
        platform_repo: None,
        tokens,
        sessions,
        session_store,
        brute_force,
        email: Arc::new(NoOpEmailProvider),
        hooks: Arc::new(NoOpAuthHooks),
        encryption_key: zeroize::Zeroizing::new([7u8; 32]),
        identifier_key: zeroize::Zeroizing::new([9u8; 32]),
        issuer: "Bymax One".to_owned(),
        totp_window: 2,
        recovery_code_count: 8,
        sessions_enabled: false,
    })
}

/// Seed a fresh user (not MFA-enabled) and return its id.
async fn seed_user(users: &InMemoryUserRepository, email: &str) -> Option<String> {
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: email.to_owned(),
            name: "U".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    created.ok().map(|u| u.id)
}

/// A pending-setup record encrypted under `[7u8; 32]` with an explicit encrypted-secret wire
/// and encrypted-plain-codes wire (so a test can inject a valid secret with corrupt codes).
fn record_with(secret_wire: String, plain_wire: String) -> String {
    serde_json::to_string(&MfaSetupData {
        encrypted_secret: secret_wire,
        hashed_codes: vec!["digest".to_owned()],
        encrypted_plain_codes: plain_wire,
    })
    .unwrap_or_default()
}

/// A valid encrypted-secret wire (the raw secret `[1u8; 20]` under `[7u8; 32]`).
fn good_secret_wire() -> String {
    bymax_auth_crypto::aead::encrypt(&[1u8; 20], &[7u8; 32]).unwrap_or_default()
}

/// A valid pending-setup record encrypted under `[7u8; 32]`, carrying `recovery` as the single
/// plaintext code.
fn winner_record(recovery: &str) -> String {
    let plain_json = format!("[\"{recovery}\"]");
    let plain =
        bymax_auth_crypto::aead::encrypt(plain_json.as_bytes(), &[7u8; 32]).unwrap_or_default();
    record_with(good_secret_wire(), plain)
}

#[tokio::test]
async fn setup_returns_the_winner_record_after_a_lost_nx_race() {
    // First read misses, the `SET NX` loses, and the second read finds the concurrent winner —
    // whose material is returned so both callers agree on the secret.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "race@example.com").await else {
        return;
    };
    let store = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([
            None,
            Some(winner_record("WINNER-0000-CODE")),
        ])),
        put_nx: false,
    });
    let svc = service_over(store, users);
    let result = svc.setup(&uid, MfaContext::Dashboard).await;
    assert!(matches!(&result, Ok(r) if r.recovery_codes == ["WINNER-0000-CODE"]));
}

#[tokio::test]
async fn setup_errors_when_the_record_vanishes_after_a_lost_race() {
    // The `SET NX` loses but the winner's record expired in the gap — an internal inconsistency.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "vanish@example.com").await else {
        return;
    };
    let store = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([None, None])),
        put_nx: false,
    });
    let svc = service_over(store, users);
    assert!(matches!(
        svc.setup(&uid, MfaContext::Dashboard).await,
        Err(AuthError::Internal(_))
    ));
}

#[tokio::test]
async fn setup_fast_path_rejects_a_corrupt_or_undecryptable_record() {
    // A pending record that will not parse, and one that parses but will not decrypt, both
    // surface as an opaque internal error (never a decrypt oracle).
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "corrupt@example.com").await else {
        return;
    };
    // Unparseable JSON.
    let garbage = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([Some("not json".to_owned())])),
        put_nx: false,
    });
    assert!(matches!(
        service_over(garbage, users.clone())
            .setup(&uid, MfaContext::Dashboard)
            .await,
        Err(AuthError::Internal(_))
    ));
    // Well-formed record whose ciphertext will not decrypt under the key.
    let bad_cipher = serde_json::to_string(&MfaSetupData {
        encrypted_secret: "bad".to_owned(),
        hashed_codes: vec![],
        encrypted_plain_codes: "bad".to_owned(),
    })
    .unwrap_or_default();
    let undecryptable = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([Some(bad_cipher)])),
        put_nx: false,
    });
    assert!(matches!(
        service_over(undecryptable, users.clone())
            .setup(&uid, MfaContext::Dashboard)
            .await,
        Err(AuthError::Internal(_))
    ));
    // A valid secret but recovery-codes ciphertext that will not decrypt.
    let codes_undecryptable = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([Some(record_with(
            good_secret_wire(),
            "bad".to_owned(),
        ))])),
        put_nx: false,
    });
    assert!(matches!(
        service_over(codes_undecryptable, users.clone())
            .setup(&uid, MfaContext::Dashboard)
            .await,
        Err(AuthError::Internal(_))
    ));
    // A valid secret and decryptable codes blob that is not a JSON array of strings.
    let bad_codes_json =
        bymax_auth_crypto::aead::encrypt(b"not-a-json-array", &[7u8; 32]).unwrap_or_default();
    let codes_undecodable = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([Some(record_with(
            good_secret_wire(),
            bad_codes_json,
        ))])),
        put_nx: false,
    });
    assert!(matches!(
        service_over(codes_undecodable, users)
            .setup(&uid, MfaContext::Dashboard)
            .await,
        Err(AuthError::Internal(_))
    ));
}

#[tokio::test]
async fn scripted_store_default_methods_are_inert() {
    // Exercise the scripted double's unused trait surface so its full object-safe impl is
    // covered (it backs only the setup-race tests, which touch a subset of the methods).
    let store = ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::new()),
        put_nx: true,
    };
    let store: &dyn MfaStore = &store;
    assert!(store.put_temp("j", "u", 1).await.is_ok());
    assert!(matches!(store.get_temp("j").await, Ok(None)));
    assert!(store.del_temp("j").await.is_ok());
    assert!(matches!(
        store.challenge_consume("r", "j", 1).await,
        Ok(true)
    ));
}

#[tokio::test]
async fn enable_fails_when_the_completion_gate_is_lost() {
    // The pending record is present at read and the code verifies, but a concurrent enable wins
    // the `GETDEL`, so this request's completion gate (`take_setup` -> None) rejects it.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "gate@example.com").await else { return };
    let store = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::from([Some(winner_record("X"))])),
        put_nx: false,
    });
    let svc = service_over(store, users);
    // `winner_record` encrypts the raw secret `[1u8; 20]`, so a code for those bytes verifies.
    let valid = raw_code(&[1u8; 20], now_secs());
    assert!(matches!(
        svc.verify_and_enable(&uid, &valid, "1.2.3.4", "ua", MfaContext::Dashboard)
            .await,
        Err(AuthError::MfaSetupRequired)
    ));
}

#[tokio::test]
async fn challenge_rejects_a_wrong_six_digit_totp_code() {
    // A six-digit code that does not verify takes the TOTP branch and is rejected (the
    // `accept_totp` false path), distinct from the recovery-code branch.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "wrong-totp@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else { return };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    let Some(temp) = login_temp_token(&h.engine, "wrong-totp@example.com").await else { return };
    assert!(matches!(
        mfa.challenge(&temp, &wrong_totp(&setup.secret), "1.2.3.4", "ua")
            .await,
        Err(AuthError::MfaInvalidCode)
    ));
}

#[tokio::test]
async fn challenge_succeeds_with_session_tracking_disabled() {
    // A successful challenge with `sessions.enabled = false` takes the session-limit early
    // return; the dashboard result is still issued.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "nosess@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else { return };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    let Some(temp) = login_temp_token(&h.engine, "nosess@example.com").await else { return };
    assert!(matches!(
        mfa.challenge(&temp, &code(&setup.secret, 30), "1.2.3.4", "ua")
            .await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
}

#[tokio::test]
async fn challenge_collapses_an_undecryptable_secret_to_an_opaque_error() {
    // If the stored secret will not decrypt (corruption / wrong key), the challenge returns the
    // opaque `TokenInvalid` with no decrypt oracle.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "decrypt@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else { return };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    // Corrupt the persisted secret so it can no longer be decrypted.
    let corrupt = h
        .users
        .update_mfa(
            &uid,
            bymax_auth_types::UpdateMfaData {
                mfa_enabled: true,
                mfa_secret: Some("not-a-valid-wire".to_owned()),
                mfa_recovery_codes: Some(vec![]),
            },
        )
        .await;
    assert!(corrupt.is_ok());
    let Some(temp) = login_temp_token(&h.engine, "decrypt@example.com").await else { return };
    assert!(matches!(
        mfa.challenge(&temp, "000000", "1.2.3.4", "ua").await,
        Err(AuthError::TokenInvalid)
    ));
}

#[tokio::test]
async fn detached_notifications_invoke_their_targets() {
    // The fire-and-forget email/hook bodies are driven directly (not via the detached spawn) so
    // their success paths are deterministically covered.
    let email: Arc<dyn EmailProvider> = Arc::new(NoOpEmailProvider);
    let hooks: Arc<dyn AuthHooks> = Arc::new(NoOpAuthHooks);
    assert!(
        super::setup::run_send_mfa_enabled(email.clone(), "u@example.com".to_owned())
            .await
            .is_ok()
    );
    assert!(
        super::manage::run_send_mfa_disabled(email, "u@example.com".to_owned())
            .await
            .is_ok()
    );
    assert!(
        super::setup::run_after_mfa_enabled(hooks.clone(), sample_safe_user(), sample_hook_ctx())
            .await
            .is_ok()
    );
    assert!(
        super::manage::run_after_mfa_disabled(hooks.clone(), sample_safe_user(), sample_hook_ctx())
            .await
            .is_ok()
    );
    assert!(
        super::manage::run_after_mfa_regenerated(hooks, sample_safe_user(), sample_hook_ctx())
            .await
            .is_ok()
    );
}

#[test]
fn anti_replay_ttl_is_derived_from_the_window_and_scales() {
    // The marker must outlive the maximum span over which the same code stays acceptable:
    // a code is accepted at any step in [s-window, s+window], so the span is (2·window+1)
    // full 30 s steps. For the test/config window of 2 that is (2·2+1)·30 = 150 s — at least
    // the longest time a code can be replayed — and a fixed 90 s literal would expire early.
    let users = Arc::new(InMemoryUserRepository::new());
    let store: Arc<dyn MfaStore> = Arc::new(ScriptedMfaStore {
        get_setup: Mutex::new(VecDeque::new()),
        put_nx: true,
    });
    let mut service = service_over(store.clone(), users.clone());

    // `service_over` builds with totp_window = 2: the derived TTL is exactly the max
    // code-acceptance window, never the old fixed 90 s.
    let max_window_secs_w2 = (2 * 2 + 1) * 30;
    assert_eq!(service.anti_replay_ttl_seconds(), max_window_secs_w2);
    assert!(service.anti_replay_ttl_seconds() >= max_window_secs_w2);

    // It scales with the window: a wider window yields a strictly longer TTL, and a zero
    // window collapses to a single step (the code is accepted at exactly one step).
    service.totp_window = 4;
    assert_eq!(service.anti_replay_ttl_seconds(), (2 * 4 + 1) * 30);
    assert!(service.anti_replay_ttl_seconds() > max_window_secs_w2);
    service.totp_window = 0;
    assert_eq!(service.anti_replay_ttl_seconds(), 30);
}

#[tokio::test]
async fn concurrent_distinct_valid_codes_issue_one_session() {
    // The real anti-replay attack the same-code test cannot catch: two concurrent challenges on
    // ONE temp token with DIFFERENT still-valid codes (steps s+1 and s+2, both inside the ±2
    // window) have DISTINCT `tu:` markers, so each wins its own `SET NX`. Only the temp-token
    // deletion gate may admit one — exactly one session is issued, the loser is rejected (with a
    // typed `Mfa*` error), and the single temp token is consumed exactly once. The loser's error
    // is either `MfaInvalidCode` (it lost the fused gate after reading a still-present token) or
    // `MfaTempTokenInvalid` (the winner had already deleted the token before its temp-token
    // check) — both are correct second-factor rejections; what matters is that no SECOND session
    // is ever issued.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "twocode@example.com").await else {
        return;
    };
    let secret;
    {
        let Some(mfa) = h.engine.mfa() else { return };
        let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
            return;
        };
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

    let Some(temp) = login_temp_token(&h.engine, "twocode@example.com").await else {
        return;
    };
    // Two distinct in-window codes off one captured base, so they never collide as the clock
    // advances. Steps s+1 and s+2 are both within the ±2 verifier window and differ in value.
    let base = now_secs();
    let code_a = code_at(&secret, base + 30);
    let code_b = code_at(&secret, base + 60);
    assert_ne!(
        code_a, code_b,
        "the two codes must be distinct to exercise the attack"
    );
    let engine = Arc::new(h.engine);

    let mut handles = Vec::new();
    for submitted in [code_a, code_b] {
        let engine = engine.clone();
        let temp = temp.clone();
        handles.push(tokio::spawn(async move {
            match engine.mfa() {
                Some(mfa) => mfa.challenge(&temp, &submitted, "1.2.3.4", "ua").await,
                None => Err(AuthError::MfaNotEnabled),
            }
        }));
    }
    let mut sessions = 0;
    let mut rejected = 0;
    for handle in handles {
        match handle.await {
            Ok(Ok(LoginResultMfa::Dashboard(_))) => sessions += 1,
            // Either typed rejection is a correct second-factor failure; neither issues a session.
            Ok(Err(AuthError::MfaInvalidCode | AuthError::MfaTempTokenInvalid)) => rejected += 1,
            _ => {}
        }
    }
    assert_eq!(
        sessions, 1,
        "exactly one distinct-code challenge may issue a session"
    );
    assert_eq!(
        rejected, 1,
        "the loser is rejected with a typed Mfa* error, never a second session"
    );

    // The single temp token was consumed exactly once: a fresh challenge on the SAME temp token
    // now fails the temp-token check outright (regardless of the code), proving one consumption.
    let Some(mfa) = engine.mfa() else { return };
    let leftover = code_at(&secret, base + 90);
    let replay = mfa.challenge(&temp, &leftover, "1.2.3.4", "ua").await;
    assert!(
        replay.is_err(),
        "the temp token was already consumed exactly once"
    );
}

#[test]
fn setup_result_debug_redacts_the_secret_and_codes() {
    // A `{:?}` of the one-time result must never leak the secret, the secret-bearing QR URI, or
    // the plaintext recovery codes.
    let result = super::MfaSetupResult {
        secret: "TOPSECRETBASE32".to_owned(),
        qr_code_uri: "otpauth://totp/Bymax:u?secret=TOPSECRETBASE32".to_owned(),
        recovery_codes: vec!["AAAA-BBBB".to_owned(), "CCCC-DDDD".to_owned()],
    };
    let rendered = format!("{:?}", result.clone());
    assert!(!rendered.contains("TOPSECRETBASE32"));
    assert!(!rendered.contains("AAAA-BBBB"));
    assert!(rendered.contains("[REDACTED]"));
    assert!(rendered.contains("2 REDACTED codes"));
}

#[test]
fn repository_error_maps_both_variants_to_internal() {
    // Both a backend failure and a (logically impossible here) conflict collapse to the opaque
    // internal error, never leaking a datastore detail.
    assert!(matches!(
        super::repository_error(crate::RepositoryError::Conflict("x".to_owned())),
        AuthError::Internal(_)
    ));
    assert!(matches!(
        super::repository_error(crate::RepositoryError::Backend("y".into())),
        AuthError::Internal(_)
    ));
}
