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
    build_with(sessions, wire_platform, None, None)
}

/// The same harness, with an optional email provider and hooks so the fire-and-forget
/// notifications the MFA flows emit can be observed.
fn build_with(
    sessions: bool,
    wire_platform: bool,
    email: Option<Arc<dyn EmailProvider>>,
    hooks: Option<Arc<dyn AuthHooks>>,
) -> Option<Harness> {
    build_full(sessions, wire_platform, email, hooks, Vec::new())
}

/// The same harness with a retired MFA encryption key configured, so a secret written under
/// that key still opens through the engine's own flows.
fn build_rotating(retired_b64: String) -> Option<Harness> {
    build_full(
        true,
        false,
        None,
        None,
        vec![SecretString::from(retired_b64)],
    )
}

/// The harness builder every variant above delegates to.
fn build_full(
    sessions: bool,
    wire_platform: bool,
    email: Option<Arc<dyn EmailProvider>>,
    hooks: Option<Arc<dyn AuthHooks>>,
    previous_encryption_keys: Vec<SecretString>,
) -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let platform = Arc::new(InMemoryPlatformUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;
    config.sessions.enabled = sessions;
    config.mfa = Some(MfaConfig {
        previous_encryption_keys,
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
    if let Some(email) = email {
        builder = builder.email_provider(email);
    }
    if let Some(hooks) = hooks {
        builder = builder.hooks(hooks);
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
    // This harness has session tracking on, and the session the challenge issued has to be
    // registered under the user — otherwise it is invisible to the session list, to the cap,
    // and to "sign out everywhere". The returned tokens look identical either way.
    let listed = h.engine.list_user_sessions(&uid, None).await;
    assert!(
        matches!(&listed, Ok(list) if !list.is_empty()),
        "the challenge's session must be registered: {listed:?}"
    );

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

/// An email + hook spy recording the security alerts the MFA management flows emit.
#[derive(Default)]
struct AlertSpy {
    alerts: Mutex<Vec<String>>,
}

impl AlertSpy {
    fn push(&self, alert: String) {
        if let Ok(mut alerts) = self.alerts.lock() {
            alerts.push(alert);
        }
    }

    fn seen(&self) -> Vec<String> {
        self.alerts.lock().map(|a| a.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl EmailProvider for AlertSpy {
    async fn send_password_reset_token(
        &self,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_password_reset_otp(
        &self,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_enabled(
        &self,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        self.push(format!("mail:enabled:{email}"));
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        self.push(format!("mail:disabled:{email}"));
        Ok(())
    }
    async fn send_new_session_alert(
        &self,
        _email: &str,
        _session: &crate::traits::SessionInfo,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_invitation(
        &self,
        _email: &str,
        _invite: &crate::traits::InviteData,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
}

#[async_trait]
impl AuthHooks for AlertSpy {
    async fn on_new_session(
        &self,
        user: &bymax_auth_types::SafeAuthUser,
        _session: &crate::traits::SessionInfo,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        self.push(format!("hook:new_session:{}", user.id));
        Ok(())
    }
    async fn after_mfa_enabled(
        &self,
        user: &bymax_auth_types::SafeAuthUser,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        self.push(format!("hook:enabled:{}", user.id));
        Ok(())
    }
    async fn after_mfa_disabled(
        &self,
        user: &bymax_auth_types::SafeAuthUser,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        self.push(format!("hook:disabled:{}", user.id));
        Ok(())
    }
    async fn after_mfa_recovery_codes_regenerated(
        &self,
        user: &bymax_auth_types::SafeAuthUser,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        self.push(format!("hook:regenerated:{}", user.id));
        Ok(())
    }
}

#[tokio::test]
async fn every_mfa_state_change_alerts_the_account_owner() {
    // Enabling, regenerating and disabling a second factor are all account-security changes,
    // and each one's mail and hook are the owner's only warning — turning MFA off is exactly
    // what an attacker holding the password does. Every notification is fire-and-forget, so
    // each call returns the same `Ok(())` whether it fired or not.
    let spy = Arc::new(AlertSpy::default());
    let email: Arc<dyn EmailProvider> = spy.clone();
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    let Some(h) = build_with(false, false, Some(email), Some(hooks)) else {
        return;
    };
    let Some(uid) = register(&h.engine, "alert@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    // Regenerating the recovery codes invalidates the old set, which is equally worth
    // telling the owner about: it is how an attacker locks the real owner out of their own
    // fallback.
    assert!(
        mfa.regenerate_recovery_codes(
            &uid,
            &code_at(&setup.secret, base + 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    assert!(
        mfa.disable(
            &uid,
            &code_at(&setup.secret, base + 60),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    // Long enough for the detached notifications to have run.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = spy.seen();
    // Enabling is an account-security change too: a second factor appearing on an account
    // is the owner's cue that either they did it or someone else did.
    assert!(
        seen.contains(&"mail:enabled:alert@example.com".to_owned()),
        "no enabled mail: {seen:?}"
    );
    assert!(
        seen.contains(&format!("hook:enabled:{uid}")),
        "no enabled hook: {seen:?}"
    );
    assert!(
        seen.contains(&"mail:disabled:alert@example.com".to_owned()),
        "no disabled mail: {seen:?}"
    );
    assert!(
        seen.contains(&format!("hook:disabled:{uid}")),
        "no disabled hook: {seen:?}"
    );
    assert!(
        seen.contains(&format!("hook:regenerated:{uid}")),
        "no regenerated hook: {seen:?}"
    );
}

#[tokio::test]
async fn a_challenge_registers_its_session_with_the_session_service() {
    // The challenge issues a session like a login does, and with tracking on it must go
    // through the session service — that is what enforces the per-user cap and fires the
    // new-session notification. The tokens it returns look identical either way, so the
    // hook is the observation point.
    let spy = Arc::new(AlertSpy::default());
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    let Some(h) = build_with(true, false, None, Some(hooks)) else {
        return;
    };
    let Some(uid) = register(&h.engine, "tracked@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    let Some(temp) = login_temp_token(&h.engine, "tracked@example.com").await else {
        return;
    };
    // Counted, not merely present: the registration at the top of this test already issued a
    // session and fired this hook once, so an assertion on presence alone would hold with the
    // challenge's own registration removed entirely.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let event = format!("hook:new_session:{uid}");
    let before = spy.seen().iter().filter(|e| **e == event).count();
    assert!(matches!(
        mfa.challenge(&temp, &code_at(&setup.secret, base + 30), "1.2.3.4", "ua")
            .await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    // The notification is fire-and-forget.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = spy.seen().iter().filter(|e| **e == event).count();
    assert_eq!(
        after,
        before + 1,
        "the challenge's session never reached the session service"
    );
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
async fn challenge_rejects_an_account_blocked_after_the_temp_token_was_issued() {
    // The temp token outlives the login-time status gate by its whole TTL, so an account
    // suspended inside that window must not be able to clear the second factor and walk away
    // with a full session — revoking access cannot depend on how far through the login the
    // holder had already got. The account here is not even MFA-enrolled, so getting the
    // status error rather than MfaNotEnabled also pins that the gate runs first, before the
    // MFA checks and before any key derivation.
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "blocked-mid-challenge@example.com").await else {
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
    assert!(h.users.update_status(&uid, "SUSPENDED").await.is_ok());

    let Some(mfa) = h.engine.mfa() else { return };
    assert!(matches!(
        mfa.challenge(&temp, "000000", "1.2.3.4", "ua").await,
        Err(AuthError::AccountSuspended)
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

    // The counter is per user. A shared one would let anybody lock any account out of MFA by
    // failing their own challenge five times — a denial of service with no credential needed.
    let Some(other) = register(&h.engine, "other@example.com").await else {
        return;
    };
    let Ok(other_setup) = mfa.setup(&other, MfaContext::Dashboard).await else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &other,
            &code_at(&other_setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    let Some(other_temp) = login_temp_token(&h.engine, "other@example.com").await else {
        return;
    };
    assert!(
        mfa.challenge(
            &other_temp,
            &code_at(&other_setup.secret, base + 30),
            "1.2.3.4",
            "ua"
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn two_users_setting_up_never_share_a_pending_record() {
    // The pending-setup slot is keyed per user. On one shared key the second caller loses the
    // SET NX race and is handed the *winner's* record — enrolling their authenticator against
    // someone else's account, and learning that account's TOTP secret and recovery codes.
    let Some(h) = build(false, false) else { return };
    let Some(first) = register(&h.engine, "first@example.com").await else {
        return;
    };
    let Some(second) = register(&h.engine, "second@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };

    let Ok(a) = mfa.setup(&first, MfaContext::Dashboard).await else {
        return;
    };
    let Ok(b) = mfa.setup(&second, MfaContext::Dashboard).await else {
        return;
    };
    assert_ne!(a.secret, b.secret);
    assert_ne!(a.recovery_codes, b.recovery_codes);

    // And each enables against their own secret, which a shared slot could not satisfy.
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &first,
            &code_at(&a.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    assert!(
        mfa.verify_and_enable(
            &second,
            &code_at(&b.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
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

    // The management counter is per user, and separate from the challenge one. A shared
    // counter would let any account freeze every other account's MFA management by failing
    // its own disable five times.
    let Some(other) = register(&h.engine, "dislock2@example.com").await else {
        return;
    };
    let Ok(other_setup) = mfa.setup(&other, MfaContext::Dashboard).await else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &other,
            &code_at(&other_setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    assert!(
        mfa.disable(
            &other,
            &code_at(&other_setup.secret, base + 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
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

#[cfg(feature = "platform")]
#[tokio::test]
async fn platform_challenge_exchanges_a_temp_token_for_a_full_platform_session() {
    // The login → MFA-challenge → full-token exchange for an MFA-enabled platform admin: enable
    // MFA on the admin (platform context), mint a PLATFORM temp token, then run the challenge
    // with a valid TOTP code and assert a full PLATFORM session is issued (mfa_verified, no
    // tenant). A recovery code then completes a second challenge and is spent single-use.
    let Some(h) = build(false, true) else { return };
    let admin = AuthPlatformUser {
        id: "p1".to_owned(),
        email: "admin@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: "$scrypt$x".to_owned(),
        role: "SUPER_ADMIN".to_owned(),
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

    // Enable MFA on the platform admin so a challenge has a secret to verify against.
    let base = now_secs();
    let Ok(setup) = mfa.setup("p1", MfaContext::Platform).await else {
        return;
    };
    let enable_code = code_at(&setup.secret, base);
    assert!(
        mfa.verify_and_enable("p1", &enable_code, "1.2.3.4", "ua", MfaContext::Platform)
            .await
            .is_ok()
    );

    // Mint a PLATFORM temp token (what the platform login plants for an MFA-enabled admin) and
    // exchange it for a full session with a fresh TOTP code from a later step (distinct from the
    // enable code so the anti-replay marker does not reject it).
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p1", MfaContext::Platform)
        .await
    else {
        return;
    };
    let challenge_code = code_at(&setup.secret, base + 30);
    let exchanged = mfa.challenge(&temp, &challenge_code, "1.2.3.4", "ua").await;
    assert!(matches!(&exchanged, Ok(LoginResultMfa::Platform(_))));
    let Ok(LoginResultMfa::Platform(result)) = exchanged else {
        return;
    };
    assert_eq!(result.admin.email, "admin@example.com");
    // The issued access token verifies as a PLATFORM token carrying mfa_verified, and the
    // serialized claims carry no tenantId.
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&result.access_token)
        .await;
    assert!(matches!(&claims, Ok(c) if c.mfa_verified && c.role == "SUPER_ADMIN"));
    let body = result.access_token.split('.').nth(1).unwrap_or_default();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .unwrap_or_default();
    assert!(
        !String::from_utf8(decoded)
            .unwrap_or_default()
            .contains("tenantId")
    );

    // A recovery code completes a SECOND challenge (fresh temp token) and is then spent: a
    // replay of the same recovery code fails.
    let recovery = setup.recovery_codes[0].clone();
    let Ok(temp2) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p1", MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp2, &recovery, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
    let Ok(temp3) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p1", MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp3, &recovery, "1.2.3.4", "ua").await,
        Err(AuthError::MfaInvalidCode)
    ));
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn platform_challenge_rejects_a_wrong_code_and_keeps_the_temp_token_alive() {
    // A wrong TOTP code on a platform challenge is the retryable MfaInvalidCode (the temp token
    // stays alive within its TTL); a correct code on the retry then succeeds.
    let Some(h) = build(false, true) else { return };
    h.platform.insert(AuthPlatformUser {
        id: "p2".to_owned(),
        email: "retry@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: "$scrypt$x".to_owned(),
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
    let Some(mfa) = h.engine.mfa() else { return };
    let base = now_secs();
    let Ok(setup) = mfa.setup("p2", MfaContext::Platform).await else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            "p2",
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Platform
        )
        .await
        .is_ok()
    );
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p2", MfaContext::Platform)
        .await
    else {
        return;
    };
    // A wrong code is rejected but leaves the temp token alive.
    assert!(matches!(
        mfa.challenge(&temp, &wrong_totp(&setup.secret), "1.2.3.4", "ua")
            .await,
        Err(AuthError::MfaInvalidCode)
    ));
    // The same temp token then succeeds with a valid code from a later step.
    let good = code_at(&setup.secret, base + 60);
    assert!(matches!(
        mfa.challenge(&temp, &good, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn platform_challenge_rejects_an_admin_without_enabled_mfa_or_a_secret() {
    // A platform temp token minted for an admin that is NOT MFA-enabled (or has no secret) is
    // rejected as MfaNotEnabled — the challenge never issues a session for an account that has
    // not configured the second factor.
    let Some(h) = build(false, true) else { return };
    h.platform.insert(AuthPlatformUser {
        id: "p-no".to_owned(),
        email: "noenroll@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: "$scrypt$x".to_owned(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        // MFA not enabled and no secret stored.
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-no", MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, "123456", "1.2.3.4", "ua").await,
        Err(AuthError::MfaNotEnabled)
    ));
    // A missing admin entirely is also MfaNotEnabled.
    let Ok(ghost_temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("ghost", MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&ghost_temp, "123456", "1.2.3.4", "ua").await,
        Err(AuthError::MfaNotEnabled)
    ));
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn platform_challenge_with_an_undecryptable_secret_is_an_opaque_failure() {
    // An admin marked MFA-enabled but whose stored secret will not decrypt (corrupt/foreign
    // ciphertext) yields the opaque TokenInvalid — no decrypt oracle leaks the failure mode.
    let Some(h) = build(false, true) else { return };
    h.platform.insert(AuthPlatformUser {
        id: "p-corrupt".to_owned(),
        email: "corrupt@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: "$scrypt$x".to_owned(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: true,
        // A non-decryptable wire string (not produced by this engine's AES key).
        mfa_secret: Some("not-a-valid-aes-wire-string".to_owned()),
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-corrupt", MfaContext::Platform)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, "123456", "1.2.3.4", "ua").await,
        Err(AuthError::TokenInvalid)
    ));
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
fn service_with_previous_keys(
    store: Arc<dyn MfaStore>,
    users: Arc<InMemoryUserRepository>,
    previous_identifier_keys: Vec<zeroize::Zeroizing<[u8; 64]>>,
) -> MfaService {
    let mut deps = service_deps(store, users);
    deps.previous_identifier_keys = previous_identifier_keys;
    MfaService::new(deps)
}

fn service_deps(store: Arc<dyn MfaStore>, users: Arc<InMemoryUserRepository>) -> MfaServiceDeps {
    let inmem = Arc::new(InMemoryStores::new());
    let session_store: Arc<dyn SessionStore> = inmem.clone();
    let brute_force_store: Arc<dyn BruteForceStore> = inmem;
    let tokens = Arc::new(TokenManagerService::new(
        HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
        Vec::new(),
        session_store.clone(),
        Duration::from_secs(900),
        7,
        Duration::from_secs(30),
        0,
    ));
    let sessions = Arc::new(SessionService::new(
        session_store.clone(),
        users.clone(),
        Arc::new(NoOpAuthHooks),
        SessionConfig::default(),
        3600,
    ));
    let brute_force = Arc::new(BruteForceService::new(brute_force_store, 5, 900));
    MfaServiceDeps {
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
        previous_encryption_keys: Vec::new(),
        identifier_key: zeroize::Zeroizing::new([9u8; 64]),
        previous_identifier_keys: Vec::new(),
        issuer: "Bymax One".to_owned(),
        totp_window: 2,
        recovery_code_count: 8,
        sessions_enabled: false,
        blocked_statuses: vec!["BANNED".to_owned(), "SUSPENDED".to_owned()],
    }
}

fn service_over(store: Arc<dyn MfaStore>, users: Arc<InMemoryUserRepository>) -> MfaService {
    MfaService::new(service_deps(store, users))
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
    // The at-rest form is the encrypted Base32 TEXT, not the raw bytes — the same shape
    // nest-auth writes, so the two backends can read one another's `mfaSecret`.
    let base32 = bymax_auth_crypto::totp::encode_secret_base32(&[1u8; 20]);
    bymax_auth_crypto::aead::encrypt(base32.as_bytes(), &[7u8; 32]).unwrap_or_default()
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

/// Read `credentialFormats.{key}` from the shared cross-implementation wire contract.
///
/// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth. This section
/// is the shape of the credentials themselves, so a drift here is not a parse error on the other
/// side — it is a session that cannot continue, or a TOTP code that never verifies.
fn contract_credential_formats() -> serde_json::Map<String, serde_json::Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    let section = root
        .get("credentialFormats")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    assert!(
        !section.is_empty(),
        "the wire contract declared no `credentialFormats` — it did not load"
    );
    section
}

fn credential_format(key: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    let value = root
        .get("credentialFormats")
        .and_then(|c| c.get(key))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(
        !value.is_empty(),
        "the wire contract declared no `credentialFormats.{key}` — it did not load"
    );
    value
}

#[test]
fn the_refresh_token_matches_the_shared_credential_format() {
    // 64 lowercase hex characters, from 32 CSPRNG bytes. The contract is asserted against a
    // token this library actually mints, not against the constant that produces it: a shape
    // read back through its own generator would round-trip any change to either.
    let declared = credential_format("refreshToken");
    assert!(declared.contains("64 lowercase hex"));
    assert!(declared.contains("32 CSPRNG bytes"));

    for _ in 0..32 {
        let token = bymax_auth_jwt::RawRefreshToken::generate();
        let raw = token.expose_secret();
        assert_eq!(raw.len(), 64, "refresh token is not 64 characters: {raw}");
        assert!(
            raw.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "refresh token is not lowercase hex: {raw}"
        );
    }

    // No legacy shape is declared, and none is accepted: the libraries are new, so a parsing
    // allowance for a corpus that does not exist is a widened input for nothing.
    assert!(
        contract_credential_formats()
            .get("refreshTokenLegacy")
            .is_none()
    );
}

#[tokio::test]
async fn the_stored_totp_secret_and_recovery_digests_match_the_shared_credential_format() {
    // The at-rest TOTP secret is AES-GCM over the BASE32 **text**, not over the raw bytes.
    // Decrypting one form as the other hands the wrong key to HMAC-SHA-1 and every code the
    // user's authenticator produces is rejected — which is exactly the regression a merge
    // introduced here once, by calling the raw-bytes decrypt on a base32-text record.
    let declared = credential_format("totpSecretAtRest");
    assert!(declared.contains("aes-256-gcm"));
    assert!(declared.contains("BASE32"));

    let users = Arc::new(InMemoryUserRepository::new());
    let service = service_over(Arc::new(InMemoryStores::new()), users);
    let (raw_secret, plain_codes, data) = service
        .generate_setup_material()
        .unwrap_or_else(|_| unreachable!("setup material generation cannot fail"));

    // Decrypting the stored form yields the Base32 TEXT, and decoding that text yields the very
    // bytes the HMAC uses as its key.
    let decrypted = service
        .decrypt(&data.encrypted_secret)
        .unwrap_or_else(|| unreachable!("the record was just encrypted under this key"));
    let text = String::from_utf8(decrypted).unwrap_or_default();
    assert!(
        text.chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
        "the stored secret is not Base32 text: {text}"
    );
    assert_eq!(
        service.decrypt_secret(&data.encrypted_secret).as_deref(),
        Some(raw_secret.as_slice()),
        "the at-rest form does not decode back to the HMAC key"
    );

    // Recovery codes are stored as a hex HMAC-SHA-256 under the derived identifier key — 64
    // lowercase hex characters, and never the code itself.
    let declared = credential_format("recoveryCodeDigest");
    assert!(declared.contains("hex hmac-sha256"));
    for (digest, code) in data.hashed_codes.iter().zip(plain_codes.iter()) {
        assert_eq!(digest.len(), 64, "recovery digest is not 64 hex characters");
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "recovery digest is not lowercase hex: {digest}"
        );
        assert_ne!(digest, code, "the recovery code was stored in the clear");
    }

    assert!(
        contract_credential_formats()
            .get("recoveryCodeDigestLegacy")
            .is_none()
    );
    assert!(
        !data
            .hashed_codes
            .iter()
            .any(|digest| digest.starts_with("scrypt:")),
        "a recovery digest was written as a KDF hash instead of a keyed MAC"
    );
}

#[tokio::test]
async fn a_recovery_code_digested_under_a_retired_key_still_verifies() {
    // The digest is keyed by an HMAC derived from the signing secret, so a rotation without the
    // retired key silently invalidates every code a user printed and filed — and they find out
    // at the moment they most need it, locked out of an account they cannot reach another way.
    let users = Arc::new(InMemoryUserRepository::new());
    let retired = zeroize::Zeroizing::new([3u8; 64]);

    // A digest written under the retired key: nothing in the stored set matches the current one.
    let plain = "ABCD-EF12-3456";
    let stale_digest = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        retired.as_ref(),
        plain.as_bytes(),
    ));

    // Without the retired key listed, the code does not verify…
    let strict = service_over(Arc::new(InMemoryStores::new()), users.clone());
    assert!(
        super::verify_recovery_code(
            std::slice::from_ref(&stale_digest),
            &strict.recovery_code_candidates(plain)
        )
        .is_none()
    );

    // …and with it, it does — at index 0, so the right code is the one consumed.
    let rotating =
        service_with_previous_keys(Arc::new(InMemoryStores::new()), users, vec![retired]);
    assert_eq!(
        super::verify_recovery_code(
            &["a".repeat(64), stale_digest],
            &rotating.recovery_code_candidates(plain)
        ),
        Some(1)
    );
}

#[tokio::test]
async fn a_secret_stored_under_a_retired_key_still_opens_and_is_rewritten() {
    // The ciphertext records no key identifier, so without the retired key a change of
    // `mfa.encryption_key` makes every stored secret undecryptable — every enrolled user's
    // authenticator stops matching at once, with no way back.
    let users = Arc::new(InMemoryUserRepository::new());
    let retired = zeroize::Zeroizing::new([3u8; 32]);

    // A service that encrypts under the RETIRED key, to produce the stored form.
    let mut old_deps = service_deps(Arc::new(InMemoryStores::new()), users.clone());
    old_deps.encryption_key = retired.clone();
    let old_service = MfaService::new(old_deps);
    let (raw_secret, _codes, data) = old_service
        .generate_setup_material()
        .unwrap_or_else(|_| unreachable!("setup material generation cannot fail"));

    // The current service cannot open it…
    let strict = service_over(Arc::new(InMemoryStores::new()), users.clone());
    assert!(strict.decrypt_secret(&data.encrypted_secret).is_none());

    // …and with the retired key listed it opens, and is reported as needing a rewrite.
    let mut deps = service_deps(Arc::new(InMemoryStores::new()), users.clone());
    deps.previous_encryption_keys = vec![retired];
    let rotating = MfaService::new(deps);
    let opened = rotating.decrypt_secret_with_rotation(&data.encrypted_secret);
    assert!(matches!(opened, Some((ref secret, true)) if *secret == raw_secret));

    // A record under a key nobody holds is still refused: the retired list widens what opens,
    // it does not make decryption lenient. Without this the loop's exhausted path is untested
    // and a rotation could silently accept a tampered record.
    let mut third_deps = service_deps(Arc::new(InMemoryStores::new()), users);
    third_deps.encryption_key = zeroize::Zeroizing::new([9u8; 32]);
    let stranger = MfaService::new(third_deps);
    let Ok((_, _, foreign)) = stranger.generate_setup_material() else {
        return;
    };
    assert!(
        rotating
            .decrypt_secret_with_rotation(&foreign.encrypted_secret)
            .is_none()
    );

    // The rewrite produces a record the CURRENT key opens, carrying the same secret.
    let rewritten = rotating
        .reencrypt_secret(&raw_secret)
        .unwrap_or_else(|_| unreachable!("re-encryption cannot fail for a 20-byte secret"));
    assert!(matches!(
        rotating.decrypt_secret_with_rotation(&rewritten),
        Some((ref secret, false)) if *secret == raw_secret
    ));
    assert!(strict.decrypt_secret(&rewritten).is_some());
}

#[tokio::test]
async fn a_totp_challenge_rewrites_a_secret_stored_under_a_retired_key() {
    // The rewrite has to happen on the TOTP path too, which persists nothing on its own —
    // otherwise the rotation never drains for a user who only ever uses their authenticator,
    // and the retired key has to stay configured forever: a key that still opens every secret.
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let Some(h) = build_rotating(retired_b64) else {
        return;
    };
    let Some(uid) = register(&h.engine, "rot@example.com").await else {
        return;
    };

    // Enrol out of band, with the secret encrypted under the RETIRED key — the state a
    // deployment is in the moment it rotates `mfa.encryption_key`.
    let mut old_deps = service_deps(Arc::new(InMemoryStores::new()), h.users.clone());
    old_deps.encryption_key = zeroize::Zeroizing::new(retired_bytes);
    let old_service = MfaService::new(old_deps);
    let Ok((raw_secret, _codes, data)) = old_service.generate_setup_material() else {
        return;
    };
    let stored_under_retired = data.encrypted_secret.clone();
    assert!(
        h.users
            .update_mfa(
                &uid,
                bymax_auth_types::UpdateMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some(stored_under_retired.clone()),
                    mfa_recovery_codes: Some(data.hashed_codes),
                },
            )
            .await
            .is_ok()
    );

    // A plain TOTP challenge succeeds — the retired key opened the secret.
    let Some(mfa) = h.engine.mfa() else { return };
    let Some(temp) = login_temp_token(&h.engine, "rot@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, &raw_code(&raw_secret, now_secs()), "1.2.3.4", "ua")
            .await,
        Ok(LoginResultMfa::Dashboard(_))
    ));

    // …and it was rewritten in place: the stored record changed, and a service holding ONLY
    // the current key now opens it. Without the rewrite the retired key could never be dropped.
    let Ok(Some(after)) = h.users.find_by_id(&uid, None).await else {
        return;
    };
    let rewritten = after.mfa_secret.unwrap_or_default();
    assert_ne!(rewritten, stored_under_retired);
    let strict = service_over(Arc::new(InMemoryStores::new()), h.users.clone());
    assert_eq!(
        strict.decrypt_secret(&rewritten).as_deref(),
        Some(raw_secret.as_slice())
    );
}

#[tokio::test]
async fn an_mfa_state_change_kills_the_outstanding_access_tokens() {
    // Enabling a second factor advances the token epoch: every access token issued before
    // that moment is stamped `mfa_enabled: false`, and the MFA gate refuses only
    // `mfa_enabled && !mfa_verified` — so without the bump a stolen access token keeps
    // clearing every MFA-gated route for its remaining lifetime, at the exact moment the
    // user enabled MFA because they suspected that theft. Disable applies the same rule in
    // the other direction: an auth-state change revokes everything issued under the
    // previous state, exactly as the password-reset flow does.
    let Some(h) = build(true, false) else { return };
    let input = crate::services::auth::RegisterInput {
        email: "epoch@example.com".to_owned(),
        name: "U".to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: TENANT.to_owned(),
    };
    let registered = h.engine.register(input, &ctx()).await;
    let Ok(LoginResult::Success(auth)) = registered else {
        return;
    };
    let uid = auth.user.id.clone();
    let pre_enable_token = auth.access_token.clone();
    assert!(
        h.engine
            .tokens()
            .verify_access(&pre_enable_token)
            .await
            .is_ok()
    );

    // Enable MFA. Distinct TOTP steps per verification, as in the lifecycle test.
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa.setup(&uid, MfaContext::Dashboard).await else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );

    // The pre-enable token is dead the moment the state changed — not fifteen minutes later.
    assert!(
        h.engine
            .tokens()
            .verify_access(&pre_enable_token)
            .await
            .is_err()
    );

    // A fresh login through the challenge mints a token stamped with the NEW epoch…
    let Some(temp) = login_temp_token(&h.engine, "epoch@example.com").await else {
        return;
    };
    let challenged = mfa
        .challenge(&temp, &code_at(&setup.secret, base + 30), "1.2.3.4", "ua")
        .await;
    let Ok(LoginResultMfa::Dashboard(post_enable)) = challenged else {
        return;
    };
    assert!(
        h.engine
            .tokens()
            .verify_access(&post_enable.access_token)
            .await
            .is_ok()
    );

    // …and disabling bumps again, so that token dies with the state that minted it.
    assert!(
        mfa.disable(
            &uid,
            &code_at(&setup.secret, base + 60),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard
        )
        .await
        .is_ok()
    );
    assert!(
        h.engine
            .tokens()
            .verify_access(&post_enable.access_token)
            .await
            .is_err()
    );
}
