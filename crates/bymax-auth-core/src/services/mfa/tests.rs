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

/// A real scrypt hash of [`PASSWORD`], for platform admins seeded straight into the
/// repository. `AuthPlatformUser::password_hash` is a plain `String`, so every admin has one
/// and enrolment's re-authentication always applies on that plane — a placeholder like
/// `"$scrypt$x"` makes `setup` refuse, and a test that swallows the refusal with `else
/// { return }` then passes while exercising nothing.
fn admin_password_hash() -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    bymax_auth_crypto::password::hash(PASSWORD.as_bytes(), &params).unwrap_or_default()
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
    /// The same stores the engine holds, so a test can arm the transition-lock window.
    stores: Arc<InMemoryStores>,
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
        .redis_stores(stores.clone());
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
        stores,
    })
}

/// Register an active dashboard user and return its id.
async fn register(engine: &AuthEngine, email: &str) -> Option<String> {
    let input = crate::services::auth::RegisterInput {
        email: email.to_owned(),
        name: "U".to_owned(),
        password: PASSWORD.to_owned(),
        tenant_id: Some(TENANT.to_owned()),
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
        tenant_id: Some(TENANT.to_owned()),
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

    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
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
    let Ok(again) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
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
        mfa.verify_and_enable(
            &uid,
            &enable_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
        .await
        .is_ok()
    );
    // No read path re-exposes the secret: a further setup is rejected, never re-returning it.
    assert!(matches!(
        mfa.setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
            .await,
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
        .regenerate_recovery_codes(
            &uid,
            &regen_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
    else {
        return;
    };
    assert_eq!(new_codes.len(), 8);
    assert_ne!(new_codes, setup.recovery_codes);

    // Disable with a fourth distinct step.
    assert!(
        mfa.disable(
            &uid,
            &disable_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
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
    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _new_email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }

    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        self.push(format!("mail:enabled:{email}"));
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        self.push(format!("mail:disabled:{email}"));
        Ok(())
    }
    async fn send_new_session_alert(
        &self,
        _tenant_id: &str,
        _email: &str,
        _session: &crate::traits::SessionInfo,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_invitation(
        &self,
        _tenant_id: &str,
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let enable_code = code(&setup.secret, 0);
    assert!(
        mfa.verify_and_enable(
            &uid,
            &enable_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
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
        mfa.setup(&uid, MfaContext::Platform, None, Some(PASSWORD))
            .await,
        Err(AuthError::MfaNotEnabled)
    ));
    // An unknown user is also `MfaNotEnabled`.
    assert!(matches!(
        mfa.setup("ghost", MfaContext::Dashboard, Some("t1"), None)
            .await,
        Err(AuthError::MfaNotEnabled)
    ));
    // Enable, then a second setup is rejected.
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
        .is_ok()
    );
    assert!(matches!(
        mfa.setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
            .await,
        Err(AuthError::MfaAlreadyEnabled)
    ));
    assert!(matches!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
        mfa.verify_and_enable(
            &uid,
            "000000",
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
        .await,
        Err(AuthError::MfaSetupRequired)
    ));
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    // A wrong code does not enable and does not consume the pending record.
    assert!(matches!(
        mfa.verify_and_enable(
            &uid,
            "not-a-code",
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
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
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(other_setup) = mfa
        .setup(&other, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &other,
            &code_at(&other_setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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

    let Ok(a) = mfa
        .setup(&first, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let Ok(b) = mfa
        .setup(&second, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
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
            MfaContext::Dashboard,
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
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
        mfa.disable(
            &uid,
            "000000",
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
        .await,
        Err(AuthError::MfaNotEnabled)
    ));
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
        .is_ok()
    );
    // A recovery code can never disable MFA (it is not a TOTP).
    let recovery = setup.recovery_codes[0].clone();
    assert!(matches!(
        mfa.disable(
            &uid,
            &recovery,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
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
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
        .is_ok()
    );
    for _ in 0..5 {
        assert!(matches!(
            mfa.disable(
                &uid,
                "wrong-totp",
                "1.2.3.4",
                "ua",
                MfaContext::Dashboard,
                Some("t1")
            )
            .await,
            Err(AuthError::MfaInvalidCode)
        ));
    }
    assert!(matches!(
        mfa.disable(
            &uid,
            "wrong-totp",
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
        .await,
        Err(AuthError::AccountLocked { .. })
    ));

    // The management counter is per user, and separate from the challenge one. A shared
    // counter would let any account freeze every other account's MFA management by failing
    // its own disable five times.
    let Some(other) = register(&h.engine, "dislock2@example.com").await else {
        return;
    };
    let Ok(other_setup) = mfa
        .setup(&other, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &other,
            &code_at(&other_setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
        .is_ok()
    );
}

/// The platform plane's recovery splice abandons for the same reason the dashboard's does —
/// and it is the plane where a resurrected factor is worth more, since the account it guards
/// is an operator console.
#[tokio::test]
async fn the_platform_recovery_splice_abandons_when_mfa_vanished_under_the_lock() {
    let Some(h) = build(false, true) else { return };
    let admin = AuthPlatformUser {
        id: "p-abandon".to_owned(),
        email: "abandon@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
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
    let Ok(setup) = mfa
        .setup("p-abandon", MfaContext::Platform, None, Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            "p-abandon",
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await
        .is_ok()
    );
    let Some(recovery) = setup.recovery_codes.first().cloned() else {
        return;
    };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-abandon", MfaContext::Platform)
        .await
    else {
        return;
    };

    // The `disable` completes in the window the splice's own lock opens.
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    h.platform.report_mfa_gone_when(gone.clone());
    h.stores.raise_on_next_mfa_lock(gone);

    let _ = mfa.challenge(&temp, &recovery, "1.2.3.4", "ua").await;

    let after = h.platform.find_by_id("p-abandon").await;
    assert!(
        matches!(&after, Ok(Some(a)) if !a.mfa_enabled),
        "the abandoned platform splice must not have written: {after:?}"
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
        password_hash: admin_password_hash(),
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
    let Ok(setup) = mfa
        .setup("p1", MfaContext::Platform, None, Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            "p1",
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
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
            MfaContext::Platform,
            None,
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
            MfaContext::Platform,
            None,
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
        password_hash: admin_password_hash(),
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
    let Ok(setup) = mfa
        .setup("p1", MfaContext::Platform, None, Some(PASSWORD))
        .await
    else {
        return;
    };
    let enable_code = code_at(&setup.secret, base);
    assert!(
        mfa.verify_and_enable(
            "p1",
            &enable_code,
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            Some("t1")
        )
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
        password_hash: admin_password_hash(),
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
    let Ok(setup) = mfa
        .setup("p2", MfaContext::Platform, None, Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            "p2",
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
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
        password_hash: admin_password_hash(),
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
        password_hash: admin_password_hash(),
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
#[tokio::test]
async fn a_transition_is_refused_while_another_one_holds_the_lock() {
    // Every MFA transition rewrites one repository record carrying `mfa_enabled`, the encrypted
    // secret and the recovery-code digests TOGETHER, and `update_mfa` replaces all three
    // wholesale — the repository is the consumer's and offers no compare-and-set. Interleaved,
    // two transitions silently undo each other: a challenge that read the codes before a
    // `regenerate` and splices after it restores the whole replaced set, and one that splices
    // after `disable` completes puts `mfa_enabled` back with the pre-disable secret. Refusing
    // the second caller is how the engine serializes them, and the refusal is retryable.
    let users = Arc::new(InMemoryUserRepository::new());
    let releases = Arc::new(Mutex::new(0usize));
    let store = Arc::new(ContendedLockMfaStore {
        inner: Arc::new(InMemoryStores::new()),
        releases: releases.clone(),
    });
    let mfa = service_over(store, users.clone());
    let Some(uid) = seed_user(&users, "locked@example.com").await else {
        return;
    };
    // Enrolment on a passwordless account takes a recent authentication, so this test has to
    // arrange one — without it `setup` refuses and the case below silently becomes a no-op.
    plant_recent_auth(&mfa, &uid).await;

    // `setup` writes only the pending record, so it does not contend; `verify_and_enable` is
    // the first call that rewrites the account, and it is the one refused.
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let code = code_at(&setup.secret, now_secs());
    let refused = mfa
        .verify_and_enable(
            &uid,
            &code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(
        matches!(refused, Err(AuthError::MfaStateConflict)),
        "a contended transition must be refused, got {refused:?}"
    );

    // The account is untouched — the refusal happens before any write.
    let after = users.find_by_id(&uid, None).await;
    assert!(
        matches!(&after, Ok(Some(u)) if !u.mfa_enabled),
        "a refused transition must not have written: {after:?}"
    );

    // And the lock this caller never took is not released either: releasing a lock somebody
    // else holds would hand them a partner mid-transition.
    assert_eq!(
        releases.lock().map(|c| *c).unwrap_or(usize::MAX),
        0,
        "a caller that did not take the lock must not release it"
    );
}

/// The lock is released by a compare-and-delete against the token the acquiring call wrote, so
/// a release carrying anybody else's token must leave it standing.
///
/// This is what a fixed lock value cost. The TTL is ten seconds and a transition calls into the
/// consumer's repository twice, so a run that overruns has already lost its lock: releasing
/// unconditionally would remove whichever transition holds it now, and a third caller would
/// enter beside the second — the serialization broken precisely under the load that makes
/// concurrent transitions likely. The in-memory store implements the same rule as the
/// `release_lock` Lua, and a double that ignored the token could never fail this way.
#[tokio::test]
async fn a_lock_is_released_only_by_the_call_that_took_it() {
    let store = InMemoryStores::new();

    assert!(
        matches!(
            store.acquire_mfa_lock("acct", "token-a", 10).await,
            Ok(true)
        ),
        "the first caller must take the lock"
    );
    assert!(
        matches!(
            store.acquire_mfa_lock("acct", "token-b", 10).await,
            Ok(false)
        ),
        "a held lock must refuse a second caller"
    );

    // The successor's release names its own token, which is not the one held.
    assert!(store.release_mfa_lock("acct", "token-b").await.is_ok());
    assert!(
        matches!(
            store.acquire_mfa_lock("acct", "token-c", 10).await,
            Ok(false)
        ),
        "a release carrying a foreign token must leave the lock standing"
    );

    // The holder's own release does remove it.
    assert!(store.release_mfa_lock("acct", "token-a").await.is_ok());
    assert!(
        matches!(
            store.acquire_mfa_lock("acct", "token-d", 10).await,
            Ok(true)
        ),
        "the holder's own release must free the lock"
    );
}

/// The service must release with the token it acquired with, and that token must be a per-call
/// nonce — the store's compare-and-delete is only worth anything if the two agree and no two
/// callers can present the same value.
#[tokio::test]
async fn the_transition_releases_with_the_token_it_acquired_with() {
    let users = Arc::new(InMemoryUserRepository::new());
    let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let store = Arc::new(RecordingLockMfaStore {
        inner: Arc::new(InMemoryStores::new()),
        seen: seen.clone(),
    });
    let mfa = service_over(store, users.clone());
    let Some(uid) = seed_user(&users, "nonce@example.com").await else {
        return;
    };
    // Enrolment on a passwordless account takes a recent authentication, so this test has to
    // arrange one — without it `setup` refuses and the case below silently becomes a no-op.
    plant_recent_auth(&mfa, &uid).await;
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let code = code_at(&setup.secret, now_secs());
    let enabled = mfa
        .verify_and_enable(
            &uid,
            &code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(
        enabled.is_ok(),
        "the transition should succeed: {enabled:?}"
    );

    let Ok(calls) = seen.lock() else {
        return;
    };
    let acquired = calls.iter().find(|(kind, _)| kind == "acquire");
    let released = calls.iter().find(|(kind, _)| kind == "release");
    assert!(
        acquired.is_some() && released.is_some(),
        "the transition must both acquire and release the lock: {calls:?}"
    );
    let (Some((_, acquired_token)), Some((_, released_token))) = (acquired, released) else {
        return;
    };
    assert_eq!(
        acquired_token, released_token,
        "the release must name the token the acquire wrote"
    );
    // 16 CSPRNG bytes, hex-encoded. A fixed value would make every caller's token identical,
    // which is exactly the state the compare-and-delete cannot detect.
    assert_eq!(
        acquired_token.len(),
        32,
        "the lock token must be a 128-bit hex nonce, got {acquired_token:?}"
    );
    assert!(
        acquired_token.chars().all(|c| c.is_ascii_hexdigit()),
        "the lock token must be hex, got {acquired_token:?}"
    );
}

/// The recovery-code splice abandons when the account lost MFA under the lock.
///
/// A challenge that read the code list before a `disable` completed, and splices after it,
/// would write `mfa_enabled: true` back with the pre-disable secret — putting the account under
/// a factor the user removed and may no longer hold. The code still counts as spent (its claim
/// already stands), so nothing is written and the challenge fails; what must not happen is the
/// resurrection.
#[tokio::test]
async fn the_recovery_splice_abandons_when_mfa_vanished_under_the_lock() {
    let Some(h) = build_with(true, false, None, None) else {
        return;
    };
    let Some(uid) = register(&h.engine, "splice-abandon@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let base = now_secs();
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let enabled = mfa
        .verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(enabled.is_ok(), "enrolment should succeed: {enabled:?}");
    let Some(recovery) = setup.recovery_codes.first().cloned() else {
        return;
    };

    let Some(temp) = login_temp_token(&h.engine, "splice-abandon@example.com").await else {
        return;
    };

    // The `disable` lands exactly in the window: the flag is raised by the transition lock,
    // so the challenge's own read of the account happened before it and the splice's re-read
    // inside the lock happens after.
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    h.users.report_mfa_gone_when(gone.clone());
    h.stores.raise_on_next_mfa_lock(gone);

    // The challenge itself may still answer: the code was genuinely presented and its claim
    // stands, so it is spent either way. What must not happen is the WRITE — the resurrection
    // of a factor the user removed, with the secret they removed it to be rid of.
    let _ = mfa.challenge(&temp, &recovery, "1.2.3.4", "ua").await;

    // The account is left as the `disable` left it — not re-enabled by the loser.
    let after = h.users.find_by_id(&uid, None).await;
    assert!(
        matches!(&after, Ok(Some(u)) if !u.mfa_enabled),
        "the abandoned splice must not have written: {after:?}"
    );
}

/// A `disable` that completes between a transition's first read and its re-read inside the
/// lock must not be undone by that transition.
///
/// This is the interleaving `transition_mfa_record` exists for, and it is the one an in-memory
/// store cannot produce on its own: the two reads sit either side of `acquire_mfa_lock`, so a
/// store that turns MFA off *while granting the lock* lands exactly in the window. Every
/// mutation then sees `mfa_enabled: false` on the record it was handed and abandons — which is
/// what keeps a challenge or a regenerate from writing `mfa_enabled: true` back with the
/// pre-disable secret, putting the account under a factor the user removed.
#[tokio::test]
async fn a_transition_abandons_when_mfa_is_disabled_under_the_lock() {
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "vanishes@example.com").await else {
        return;
    };
    let store = Arc::new(DisableOnLockMfaStore {
        inner: Arc::new(InMemoryStores::new()),
        user_id: uid.clone(),
        users: users.clone(),
        armed: Mutex::new(false),
    });
    let mfa = service_over(store.clone(), users.clone());
    // Enrolment on a passwordless account takes a recent authentication, so this test has to
    // arrange one — without it `setup` refuses and everything below silently becomes a no-op.
    plant_recent_auth(&mfa, &uid).await;

    // Enrol first: the account really does have MFA when the caller starts.
    let base = now_secs();
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await
    else {
        return;
    };
    let enable_code = code_at(&setup.secret, base);
    let regen_code = code_at(&setup.secret, base + 60);
    let enabled = mfa
        .verify_and_enable(
            &uid,
            &enable_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(enabled.is_ok(), "enrolment should succeed: {enabled:?}");

    // From here on, the store disables MFA as it hands over the lock — so the re-read inside
    // the lock reports it off and the mutation abandons rather than writing the codes back.
    if let Ok(mut armed) = store.armed.lock() {
        *armed = true;
    }
    let regenerated = mfa
        .regenerate_recovery_codes(
            &uid,
            &regen_code,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(
        matches!(regenerated, Err(AuthError::MfaNotEnabled)),
        "an abandoned transition must report the factor gone, got {regenerated:?}"
    );

    // And the account is left as the `disable` left it — not re-enabled by the loser.
    let after = users.find_by_id(&uid, None).await;
    assert!(
        matches!(&after, Ok(Some(u)) if !u.mfa_enabled),
        "the abandoned transition must not have written: {after:?}"
    );
}

/// An MFA store that delegates everything to a real in-memory one, but turns the account's MFA
/// off at the moment it grants the transition lock — placing a completed `disable` in the one
/// window `transition_mfa_record` re-reads across.
struct DisableOnLockMfaStore {
    inner: Arc<InMemoryStores>,
    user_id: String,
    users: Arc<InMemoryUserRepository>,
    /// Off until the enrolment has completed — otherwise the store would undo the very
    /// transition that turns MFA on, and the test would never reach the state it is about.
    armed: Mutex<bool>,
}

#[async_trait]
impl MfaStore for DisableOnLockMfaStore {
    async fn acquire_mfa_lock(&self, id: &str, token: &str, ttl: u64) -> Result<bool, AuthError> {
        let granted = self.inner.acquire_mfa_lock(id, token, ttl).await?;
        let armed = self.armed.lock().map(|a| *a).unwrap_or(false);
        if granted && armed {
            // The `disable` that completed while this caller was in flight.
            let _ = self
                .users
                .update_mfa(
                    &self.user_id,
                    bymax_auth_types::UpdateMfaData {
                        mfa_enabled: false,
                        mfa_secret: None,
                        mfa_recovery_codes: None,
                    },
                )
                .await;
        }
        Ok(granted)
    }
    async fn release_mfa_lock(&self, id: &str, token: &str) -> Result<(), AuthError> {
        self.inner.release_mfa_lock(id, token).await
    }
    async fn claim_recovery_code(&self, id: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.claim_recovery_code(id, ttl).await
    }
    async fn put_setup_nx(&self, k: &str, v: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.put_setup_nx(k, v, ttl).await
    }
    async fn get_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_setup(k).await
    }
    async fn take_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.take_setup(k).await
    }
    async fn put_temp(&self, j: &str, u: &str, ttl: u64) -> Result<(), AuthError> {
        self.inner.put_temp(j, u, ttl).await
    }
    async fn get_temp(&self, j: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_temp(j).await
    }
    async fn del_temp(&self, j: &str) -> Result<bool, AuthError> {
        self.inner.del_temp(j).await
    }
    async fn mark_totp_used(&self, r: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.mark_totp_used(r, ttl).await
    }
    async fn challenge_consume(&self, r: &str, j: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.challenge_consume(r, j, ttl).await
    }
}

/// An MFA store that delegates everything to a real in-memory one, recording the lock token
/// each transition presents so the acquire and the release can be compared.
struct RecordingLockMfaStore {
    inner: Arc<InMemoryStores>,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

#[async_trait]
impl MfaStore for RecordingLockMfaStore {
    async fn acquire_mfa_lock(&self, id: &str, token: &str, ttl: u64) -> Result<bool, AuthError> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(("acquire".to_owned(), token.to_owned()));
        }
        self.inner.acquire_mfa_lock(id, token, ttl).await
    }
    async fn release_mfa_lock(&self, id: &str, token: &str) -> Result<(), AuthError> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(("release".to_owned(), token.to_owned()));
        }
        self.inner.release_mfa_lock(id, token).await
    }
    async fn claim_recovery_code(&self, id: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.claim_recovery_code(id, ttl).await
    }
    async fn put_setup_nx(&self, k: &str, v: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.put_setup_nx(k, v, ttl).await
    }
    async fn get_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_setup(k).await
    }
    async fn take_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.take_setup(k).await
    }
    async fn put_temp(&self, j: &str, u: &str, ttl: u64) -> Result<(), AuthError> {
        self.inner.put_temp(j, u, ttl).await
    }
    async fn get_temp(&self, j: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_temp(j).await
    }
    async fn del_temp(&self, j: &str) -> Result<bool, AuthError> {
        self.inner.del_temp(j).await
    }
    async fn mark_totp_used(&self, r: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.mark_totp_used(r, ttl).await
    }
    async fn challenge_consume(&self, r: &str, j: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.challenge_consume(r, j, ttl).await
    }
}

/// An MFA store that delegates everything to a real in-memory one **except** the transition
/// lock, which is always already held and whose releases are counted.
///
/// A held lock is another interleaving the in-memory store cannot produce on its own: it would
/// need two challenges genuinely in flight at once. Forcing it is what exercises the refusal,
/// and counting the releases is what proves a failed transition does not strand the account
/// for the lock's whole TTL.
struct ContendedLockMfaStore {
    inner: Arc<InMemoryStores>,
    releases: Arc<Mutex<usize>>,
}

#[async_trait]
impl MfaStore for ContendedLockMfaStore {
    async fn acquire_mfa_lock(
        &self,
        _id: &str,
        _token: &str,
        _ttl: u64,
    ) -> Result<bool, AuthError> {
        // Someone else holds it.
        Ok(false)
    }
    async fn release_mfa_lock(&self, _id: &str, _token: &str) -> Result<(), AuthError> {
        if let Ok(mut count) = self.releases.lock() {
            *count += 1;
        }
        Ok(())
    }
    async fn claim_recovery_code(&self, id: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.claim_recovery_code(id, ttl).await
    }
    async fn put_setup_nx(&self, k: &str, v: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.put_setup_nx(k, v, ttl).await
    }
    async fn get_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_setup(k).await
    }
    async fn take_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.take_setup(k).await
    }
    async fn put_temp(&self, j: &str, u: &str, ttl: u64) -> Result<(), AuthError> {
        self.inner.put_temp(j, u, ttl).await
    }
    async fn get_temp(&self, j: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_temp(j).await
    }
    async fn del_temp(&self, j: &str) -> Result<bool, AuthError> {
        self.inner.del_temp(j).await
    }
    async fn mark_totp_used(&self, r: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.mark_totp_used(r, ttl).await
    }
    async fn challenge_consume(&self, r: &str, j: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.challenge_consume(r, j, ttl).await
    }
}

/// An MFA store that delegates everything to a real in-memory one **except** `del_temp`,
/// which always reports that someone else won the consume.
///
/// This is the interleaving the in-memory repository cannot produce on its own: its
/// recovery-code splice serialises two concurrent challenges, so the loser fails on the code
/// rather than on the token. Forcing the lost consume is what exercises the gate that keeps a
/// single recovery code and a single temp token from minting two sessions.
struct LosingConsumeMfaStore {
    inner: Arc<InMemoryStores>,
}

#[async_trait]
impl MfaStore for LosingConsumeMfaStore {
    async fn claim_recovery_code(&self, id: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.claim_recovery_code(id, ttl).await
    }
    async fn acquire_mfa_lock(&self, id: &str, token: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.acquire_mfa_lock(id, token, ttl).await
    }
    async fn release_mfa_lock(&self, id: &str, token: &str) -> Result<(), AuthError> {
        self.inner.release_mfa_lock(id, token).await
    }
    async fn put_setup_nx(&self, k: &str, v: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.put_setup_nx(k, v, ttl).await
    }
    async fn get_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_setup(k).await
    }
    async fn take_setup(&self, k: &str) -> Result<Option<String>, AuthError> {
        self.inner.take_setup(k).await
    }
    async fn put_temp(&self, j: &str, u: &str, ttl: u64) -> Result<(), AuthError> {
        self.inner.put_temp(j, u, ttl).await
    }
    async fn get_temp(&self, j: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_temp(j).await
    }
    async fn del_temp(&self, _j: &str) -> Result<bool, AuthError> {
        Ok(false)
    }
    async fn mark_totp_used(&self, r: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.mark_totp_used(r, ttl).await
    }
    async fn challenge_consume(&self, r: &str, j: &str, ttl: u64) -> Result<bool, AuthError> {
        self.inner.challenge_consume(r, j, ttl).await
    }
}

struct ScriptedMfaStore {
    get_setup: Mutex<VecDeque<Option<String>>>,
    put_nx: bool,
    /// What `del_temp` reports. `false` stands in for losing the consume to a concurrent
    /// challenge — the interleaving the in-memory repository cannot produce, because its
    /// recovery-code splice serialises the two callers.
    del_temp_wins: bool,
}

#[async_trait]
impl MfaStore for ScriptedMfaStore {
    async fn claim_recovery_code(&self, _id: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn acquire_mfa_lock(
        &self,
        _id: &str,
        _token: &str,
        _ttl: u64,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn release_mfa_lock(&self, _id: &str, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }
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
    async fn del_temp(&self, _j: &str) -> Result<bool, AuthError> {
        Ok(self.del_temp_wins)
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
    // Enrolment re-authenticates against the account password, so the service needs a real
    // hasher. The scrypt cost is the configured default — these tests hash at most once.
    let passwords = Arc::new(
        crate::services::password::PasswordService::new(
            &crate::config::PasswordConfig::default(),
            Arc::new(crate::traits::AllowAllBreachChecker),
        )
        .unwrap_or_else(|_| unreachable!("the default password config always builds")),
    );
    MfaServiceDeps {
        mfa_store: store,
        passwords,
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

/// Plant the recent-authentication marker for a dashboard account, as a real sign-in would.
///
/// `seed_user` creates accounts with no local password, so enrolment now takes the temporal
/// proof rather than the password one. Tests that are about the setup RECORD, not about the
/// gate, arrange the proof here and stay focused on what they came to assert. The key must be
/// derived exactly as the service derives it — `hmac_sha256("{plane}:{userId}")` under the same
/// identifier key the fixture wires — which is also a small conformance check: a change to
/// either side breaks these tests rather than silently splitting the keyspace.
async fn plant_recent_auth(service: &MfaService, user_id: &str) {
    let hash = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        format!("dashboard:{user_id}").as_bytes(),
    ));
    let _ = service.session_store.mark_recent_auth(&hash, 300).await;
}

/// Seed a fresh user (not MFA-enabled) and return its id.
async fn seed_user(users: &InMemoryUserRepository, email: &str) -> Option<String> {
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: email.to_owned(),
            name: "U".to_owned(),
            // No local password: these MFA tests are about MFA mechanics, and enrolment's
            // password re-auth is a no-op for an OAuth-provisioned account. The re-auth itself
            // has dedicated tests that seed a real hash.
            password_hash: None,
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
        del_temp_wins: true,
    });
    let svc = service_over(store, users);
    plant_recent_auth(&svc, &uid).await;
    let result = svc
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await;
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
        del_temp_wins: true,
    });
    let svc = service_over(store, users);
    plant_recent_auth(&svc, &uid).await;
    assert!(matches!(
        svc.setup(&uid, MfaContext::Dashboard, Some("t1"), None)
            .await,
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
        del_temp_wins: true,
    });
    let garbage_svc = service_over(garbage, users.clone());
    plant_recent_auth(&garbage_svc, &uid).await;
    assert!(matches!(
        garbage_svc
            .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
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
        del_temp_wins: true,
    });
    let undecryptable_svc = service_over(undecryptable, users.clone());
    plant_recent_auth(&undecryptable_svc, &uid).await;
    assert!(matches!(
        undecryptable_svc
            .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
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
        del_temp_wins: true,
    });
    let codes_undecryptable_svc = service_over(codes_undecryptable, users.clone());
    plant_recent_auth(&codes_undecryptable_svc, &uid).await;
    assert!(matches!(
        codes_undecryptable_svc
            .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
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
        del_temp_wins: true,
    });
    let codes_undecodable_svc = service_over(codes_undecodable, users);
    plant_recent_auth(&codes_undecodable_svc, &uid).await;
    assert!(matches!(
        codes_undecodable_svc
            .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
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
        del_temp_wins: true,
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
        del_temp_wins: true,
    });
    let svc = service_over(store, users);
    // `winner_record` encrypts the raw secret `[1u8; 20]`, so a code for those bytes verifies.
    let valid = raw_code(&[1u8; 20], now_secs());
    assert!(matches!(
        svc.verify_and_enable(
            &uid,
            &valid,
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1")
        )
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
        super::setup::run_send_mfa_enabled(
            email.clone(),
            "t1".to_owned(),
            "u@example.com".to_owned()
        )
        .await
        .is_ok()
    );
    assert!(
        super::manage::run_send_mfa_disabled(email, "t1".to_owned(), "u@example.com".to_owned())
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
        del_temp_wins: true,
    });
    let mut service = service_over(store.clone(), users.clone());

    // `service_over` builds with totp_window = 2: the derived TTL is exactly the max
    // code-acceptance window, never the old fixed 90 s.
    let max_window_secs_w2 = (2 * 2 + 1) * 30;
    assert_eq!(service.anti_replay_ttl_seconds(), max_window_secs_w2);
    assert!(service.anti_replay_ttl_seconds() >= max_window_secs_w2);

    // It scales with the window, and a zero window collapses to a single step (the code is
    // accepted at exactly one step).
    service.totp_window = 1;
    assert_eq!(service.anti_replay_ttl_seconds(), 3 * 30);
    assert!(service.anti_replay_ttl_seconds() < max_window_secs_w2);
    service.totp_window = 0;
    assert_eq!(service.anti_replay_ttl_seconds(), 30);

    // A window past the verifier's clamp sizes the marker to the window ACTUALLY in force,
    // not the configured one. `verify` clamps to MAX_VERIFY_WINDOW so an oversized value
    // cannot become a CPU-amplification vector; deriving the TTL from the unclamped value
    // would leave the marker's lifetime and the acceptance span disagreeing. Startup
    // validation refuses anything above the clamp, so this only bites a caller reaching the
    // service directly.
    service.totp_window = 40;
    assert_eq!(service.anti_replay_ttl_seconds(), max_window_secs_w2);
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
        let Ok(setup) = mfa
            .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
            .await
        else {
            return;
        };
        if mfa
            .verify_and_enable(
                &uid,
                &code(&setup.secret, 0),
                "1.2.3.4",
                "ua",
                MfaContext::Dashboard,
                Some("t1"),
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

/// The retired-key rewrite abandons for the same reason the splice does.
///
/// A TOTP challenge persists nothing on its own, so the rewrite is its own write — and it
/// carries `mfa_enabled: true` and the secret. Landing it after a completed `disable` would
/// re-enrol the account under the very secret the user removed, from a path whose whole purpose
/// is bookkeeping.
#[tokio::test]
async fn the_retired_key_rewrite_abandons_when_mfa_vanished_under_the_lock() {
    let retired_bytes = [4u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let Some(h) = build_rotating(retired_b64) else {
        return;
    };
    let Some(uid) = register(&h.engine, "rot-abandon@example.com").await else {
        return;
    };

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

    let Some(mfa) = h.engine.mfa() else { return };
    let Some(temp) = login_temp_token(&h.engine, "rot-abandon@example.com").await else {
        return;
    };

    // The `disable` completes in the window the rewrite's own lock opens.
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    h.users.report_mfa_gone_when(gone.clone());
    h.stores.raise_on_next_mfa_lock(gone);

    let _ = mfa
        .challenge(&temp, &raw_code(&raw_secret, now_secs()), "1.2.3.4", "ua")
        .await;

    // The rewrite did not put the removed factor back.
    let after = h.users.find_by_id(&uid, None).await;
    assert!(
        matches!(&after, Ok(Some(u)) if !u.mfa_enabled),
        "the abandoned rewrite must not have re-enrolled the account: {after:?}"
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
        tenant_id: Some(TENANT.to_owned()),
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
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let base = now_secs();
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code_at(&setup.secret, base),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
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
            MfaContext::Dashboard,
            Some("t1"),
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

#[tokio::test]
async fn a_recovery_challenge_that_loses_the_temp_token_consume_issues_no_session() {
    // The gate that keeps ONE recovery code and ONE temp token from minting TWO sessions. The
    // recovery path has no `tu:` marker to fuse against (unlike TOTP), so it consumes the temp
    // token standalone — and when that consume reported nothing, both concurrent challenges
    // "succeeded". The losing store forces the interleaving directly: the in-memory repository
    // serialises the recovery-code splice, so a spawned race resolves on the code instead and
    // would pass with or without this gate.
    let users = Arc::new(InMemoryUserRepository::new());
    let inner = Arc::new(InMemoryStores::new());
    let losing: Arc<dyn MfaStore> = Arc::new(LosingConsumeMfaStore {
        inner: inner.clone(),
    });

    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "lose@example.com".to_owned(),
            name: "L".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { return };

    // Enrol with a known recovery code, digested exactly as the service digests one.
    let mut deps = service_deps(losing.clone(), users.clone());
    // The token manager needs MFA support over the SAME losing store, so the temp token it
    // issues is readable and its consume is the one that loses.
    deps.tokens = Arc::new(
        TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            inner.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        )
        .with_mfa_support(crate::services::token_manager::MfaTokenSupport::new(
            losing.clone(),
        )),
    );
    let service = MfaService::new(deps);

    let plain = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF";
    let digest = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        plain.as_bytes(),
    ));
    let material = service.generate_setup_material();
    let Ok((_, _, data)) = material else { return };
    assert!(
        users
            .update_mfa(
                &user.id,
                bymax_auth_types::UpdateMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some(data.encrypted_secret),
                    mfa_recovery_codes: Some(vec![digest]),
                },
            )
            .await
            .is_ok()
    );

    let issued = service
        .tokens
        .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)
        .await;
    let Ok(temp) = issued else { return };

    // The code is valid and the token is present — only the consume loses. No session.
    let outcome = service.challenge(&temp, plain, "1.2.3.4", "ua").await;
    assert!(
        matches!(outcome, Err(AuthError::MfaTempTokenInvalid)),
        "a lost consume must issue no session, got {outcome:?}"
    );
}

#[tokio::test]
async fn one_recovery_code_cannot_be_spent_twice_even_with_two_temp_tokens() {
    // Splicing a code out of the stored set is a read-modify-write against the CONSUMER's
    // repository: two challenges landing together both read the array containing the code, both
    // match it, and both write. The temp-token consume does not cover this — that gate is per
    // token, and two logins hold two tokens. One code, two sessions, which is the one property
    // a recovery code has. The claim in the store the engine owns is what closes it.
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "twice@example.com".to_owned(),
            name: "T".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { return };

    // The token manager needs MFA support over the SAME store, or the temp tokens it issues
    // are not store-backed and no challenge can consume one.
    let mfa_store: Arc<dyn MfaStore> = stores.clone();
    let mut deps = service_deps(mfa_store.clone(), users.clone());
    deps.tokens = Arc::new(
        TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            stores.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        )
        .with_mfa_support(crate::services::token_manager::MfaTokenSupport::new(
            mfa_store,
        )),
    );
    let service = MfaService::new(deps);
    let plain = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF";
    let digest = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        plain.as_bytes(),
    ));
    let material = service.generate_setup_material();
    let Ok((_, _, data)) = material else { return };
    // The SAME digest stored twice, so the second challenge would still find a match after the
    // first spliced one out — the shape a stale read produces, without needing real
    // concurrency to reproduce it.
    assert!(
        users
            .update_mfa(
                &user.id,
                bymax_auth_types::UpdateMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some(data.encrypted_secret),
                    mfa_recovery_codes: Some(vec![digest.clone(), digest]),
                },
            )
            .await
            .is_ok()
    );

    // Two temp tokens: two independent logins, so the per-token consume gate does not apply.
    let Ok(first_token) = service
        .tokens
        .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)
        .await
    else {
        return;
    };
    let Ok(second_token) = service
        .tokens
        .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)
        .await
    else {
        return;
    };

    let first = service
        .challenge(&first_token, plain, "1.2.3.4", "ua")
        .await;
    assert!(first.is_ok(), "the first use must succeed: {first:?}");

    let second = service
        .challenge(&second_token, plain, "1.2.3.4", "ua")
        .await;
    // The code is spent. It reads as an invalid code, which is what it now is.
    assert!(
        matches!(second, Err(AuthError::MfaInvalidCode)),
        "a spent recovery code must not mint a second session, got {second:?}"
    );
}

#[test]
fn every_mfa_key_is_namespaced_by_identity_plane() {
    // The two planes draw their ids from DIFFERENT consumer repositories, which may hand out
    // the same string — sequential integers make it certain. Keyed on the id alone, a dashboard
    // user and a platform admin sharing an id shared: the pending-enrolment record (so whoever
    // called `verify_and_enable` second adopted the FIRST party's secret and recovery digests),
    // the TOTP anti-replay marker, and both brute-force counters (so either could exhaust the
    // other's lockout budget, or clear it).
    //
    // Everything else about the two planes is already separate — Redis prefixes, claim types,
    // session indexes. This was the one place the isolation leaked.
    let users = Arc::new(InMemoryUserRepository::new());
    let service = service_over(Arc::new(InMemoryStores::new()), users);
    let id = "1";

    assert_ne!(
        service.setup_key(MfaContext::Dashboard, id),
        service.setup_key(MfaContext::Platform, id),
        "a shared pending-enrolment record lets one plane adopt the other's secret"
    );
    assert_ne!(
        service.replay_id(MfaContext::Dashboard, id, "123456"),
        service.replay_id(MfaContext::Platform, id, "123456"),
        "a shared anti-replay marker lets one plane burn the other's code"
    );
    assert_ne!(
        service.challenge_bf_id(MfaContext::Dashboard, id),
        service.challenge_bf_id(MfaContext::Platform, id),
        "a shared challenge counter lets one plane lock the other out"
    );
    assert_ne!(
        service.disable_bf_id(MfaContext::Dashboard, id),
        service.disable_bf_id(MfaContext::Platform, id),
        "a shared disable counter lets one plane lock the other out"
    );

    // The `challenge:` / `disable:` split still holds WITHIN a plane — the pre-auth counter an
    // attacker can drive must not be able to exhaust the authenticated user's management
    // budget.
    assert_ne!(
        service.challenge_bf_id(MfaContext::Dashboard, id),
        service.disable_bf_id(MfaContext::Dashboard, id)
    );

    // And the plane component is the wire name, so nest-auth derives the same key.
    assert_eq!(MfaContext::Dashboard.as_str(), "dashboard");
    assert_eq!(MfaContext::Platform.as_str(), "platform");
}

#[tokio::test]
async fn enrolment_re_authenticates_against_the_account_password() {
    // Enabling MFA changes how the account authenticates, and an access token alone is not
    // proof of who is asking: a token lifted by XSS or from a shared machine could otherwise
    // enrol an authenticator the attacker holds — and the enable then revokes every session
    // and bumps the epoch, locking the real owner out of an account they still know the
    // password to, with the recovery codes displayed only to the attacker. ASVS requires
    // re-authentication before an authentication factor changes; `disable` already demanded a
    // TOTP code, and this closes the other half.
    let users = Arc::new(InMemoryUserRepository::new());
    let password = "correct horse battery staple";
    let params = bymax_auth_crypto::password::PasswordParams::default();
    let Ok(hash) = bymax_auth_crypto::password::hash(password.as_bytes(), &params) else {
        return;
    };

    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "reauth@example.com".to_owned(),
            name: "R".to_owned(),
            password_hash: Some(hash),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { return };
    let service = service_over(Arc::new(InMemoryStores::new()), users);

    // No password, and the wrong password, are both refused — with the same error a failed
    // login returns, so an attacker holding a stolen token learns nothing new.
    for attempt in [None, Some("wrong")] {
        let refused = service
            .setup(&user.id, MfaContext::Dashboard, Some("t1"), attempt)
            .await;
        assert!(
            matches!(refused, Err(AuthError::InvalidCredentials)),
            "enrolment must refuse {attempt:?}, got {refused:?}"
        );
    }

    // The correct password enrols.
    let allowed = service
        .setup(&user.id, MfaContext::Dashboard, Some("t1"), Some(password))
        .await;
    assert!(
        allowed.is_ok(),
        "the right password must enrol, got {allowed:?}"
    );
}

#[tokio::test]
async fn enrolment_on_a_passwordless_account_takes_a_recent_authentication_instead() {
    // An account provisioned purely through OAuth has no local password to re-prove — its
    // credential belongs to the provider, which this engine cannot verify inline. Refusing
    // outright would make MFA unreachable for those users, so the proof is TEMPORAL: the caller
    // must have completed a real authentication within the last few minutes.
    //
    // The arm used to return `Ok(())` unconditionally, and it was the single worst thing in the
    // library. An access token lifted by XSS or from a shared machine was enough to enrol a
    // factor the ATTACKER holds; the enable then invalidates every session and bumps the epoch,
    // so the owner — who still signs in with the provider perfectly well — is stopped at a
    // challenge they cannot pass, with the recovery codes having been shown once, to the
    // attacker. And there was no way back: `disable` and `regenerate_recovery_codes` both demand
    // a live TOTP code, and the reset flow refuses an account with no password. A
    // fifteen-minute token theft became permanent, unrecoverable loss of the account.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "oauthonly@example.com").await else {
        return;
    };
    let service = service_over(Arc::new(InMemoryStores::new()), users);

    // No marker: the caller holds a token but has not proved it authenticated recently.
    let refused = service
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::ReauthenticationRequired)),
        "a stolen token alone must not enrol a factor, got {refused:?}"
    );

    // …and after a real sign-in, the same call proceeds — the gate is a delay, not a wall.
    plant_recent_auth(&service, &uid).await;
    let enrolled = service
        .setup(&uid, MfaContext::Dashboard, Some("t1"), None)
        .await;
    assert!(
        enrolled.is_ok(),
        "a recently authenticated OAuth account must still be able to enrol, got {enrolled:?}"
    );
}

#[tokio::test]
async fn the_recent_auth_marker_is_derived_per_plane() {
    // A dashboard user and a platform admin can carry the same id from different consumer
    // repositories, so the plane is part of the marker's PREIMAGE. Without it one plane's
    // authentication would satisfy the other's freshness check — the same collision the `lf:`
    // lockout identifier was fixed for.
    //
    // Asserted on the derivation rather than through `setup`, because the passwordless branch
    // is dashboard-only in practice: `AuthPlatformUser::password_hash` is non-optional, so a
    // platform admin always has a credential to re-prove and never reaches the marker.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "twoplanes@example.com").await else {
        return;
    };
    let service = service_over(Arc::new(InMemoryStores::new()), users);

    // Plant only the DASHBOARD marker, exactly as `issue_tokens` derives it.
    plant_recent_auth(&service, &uid).await;

    let platform_marker = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        format!("platform:{uid}").as_bytes(),
    ));
    assert!(
        !service
            .session_store
            .has_recent_auth(&platform_marker)
            .await
            .unwrap_or(true),
        "a dashboard authentication must not answer for the platform plane"
    );
}

#[tokio::test]
async fn a_rotation_cannot_refresh_the_recent_authentication_proof() {
    // THE property the marker rests on. A refresh proves possession of a token, not of a
    // credential — so if rotating re-planted the mark, an attacker holding a stolen session
    // could keep it fresh indefinitely and the gate above would gate nothing at all.
    let users = Arc::new(InMemoryUserRepository::new());
    let Some(uid) = seed_user(&users, "rotate@example.com").await else {
        return;
    };
    let service = service_over(Arc::new(InMemoryStores::new()), users);

    plant_recent_auth(&service, &uid).await;
    let hash = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        format!("dashboard:{uid}").as_bytes(),
    ));

    // The marker is READ, never consumed: two security changes after one sign-in both proceed.
    for _ in 0..2 {
        assert!(
            service
                .session_store
                .has_recent_auth(&hash)
                .await
                .unwrap_or(false),
            "reading the proof must not spend it"
        );
    }
}

#[tokio::test]
async fn a_platform_recovery_challenge_that_loses_the_consume_issues_no_session() {
    // The platform twin of the dashboard gate. Both planes run the recovery path with a
    // standalone temp-token consume — no `tu:` marker to fuse against — so both need the
    // deletion to WIN before a session is issued. The dashboard one was gated first and this
    // one was missed, which is exactly the shape a per-plane copy of a rule tends to take.
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let inner = Arc::new(InMemoryStores::new());
    let losing: Arc<dyn MfaStore> = Arc::new(LosingConsumeMfaStore {
        inner: inner.clone(),
    });

    let plain = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF";
    let digest = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        plain.as_bytes(),
    ));

    let mut deps = service_deps(losing.clone(), users);
    deps.platform_repo = Some(admins.clone());
    deps.tokens = Arc::new(
        TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            inner.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        )
        .with_mfa_support(crate::services::token_manager::MfaTokenSupport::new(
            losing.clone(),
        )),
    );
    let service = MfaService::new(deps);

    let material = service.generate_setup_material();
    let Ok((_, _, data)) = material else { return };
    admins.insert(AuthPlatformUser {
        id: "plose".to_owned(),
        email: "plose@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: true,
        mfa_secret: Some(data.encrypted_secret),
        mfa_recovery_codes: Some(vec![digest]),
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });

    let issued = service
        .tokens
        .issue_mfa_temp_token("plose", MfaContext::Platform)
        .await;
    let Ok(temp) = issued else { return };

    let outcome = service.challenge(&temp, plain, "1.2.3.4", "ua").await;
    assert!(
        matches!(outcome, Err(AuthError::MfaTempTokenInvalid)),
        "a lost consume must issue no platform session, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_platform_recovery_code_is_claimed_before_it_is_accepted() {
    // The platform twin of the double-spend gate. Splicing a code out is a read-modify-write
    // against the consumer's platform repository, so two challenges landing together both read
    // the array containing it, both match, and both write — and the per-token consume does not
    // cover it, because two logins hold two tokens. This is the plane where a spent code buys
    // the most.
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let mfa_store: Arc<dyn MfaStore> = stores.clone();

    let plain = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF";
    let digest = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        &[9u8; 64],
        plain.as_bytes(),
    ));

    let mut deps = service_deps(mfa_store.clone(), users);
    deps.platform_repo = Some(admins.clone());
    deps.tokens = Arc::new(
        TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            stores.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        )
        .with_mfa_support(crate::services::token_manager::MfaTokenSupport::new(
            mfa_store,
        )),
    );
    let service = MfaService::new(deps);

    let material = service.generate_setup_material();
    let Ok((_, _, data)) = material else { return };
    // The same digest twice, so the second challenge still finds a match after the first
    // spliced one out — the shape a stale read produces, without needing real concurrency.
    admins.insert(AuthPlatformUser {
        id: "ptwice".to_owned(),
        email: "ptwice@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: true,
        mfa_secret: Some(data.encrypted_secret),
        mfa_recovery_codes: Some(vec![digest.clone(), digest]),
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });

    let Ok(first_token) = service
        .tokens
        .issue_mfa_temp_token("ptwice", MfaContext::Platform)
        .await
    else {
        return;
    };
    let first = service
        .challenge(&first_token, plain, "1.2.3.4", "ua")
        .await;
    assert!(first.is_ok(), "the first use must succeed: {first:?}");

    let Ok(second_token) = service
        .tokens
        .issue_mfa_temp_token("ptwice", MfaContext::Platform)
        .await
    else {
        return;
    };
    let second = service
        .challenge(&second_token, plain, "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(second, Err(AuthError::MfaInvalidCode)),
        "a spent platform recovery code must not mint a second session, got {second:?}"
    );
}

#[tokio::test]
async fn reset_mfa_removes_the_factor_without_a_code_and_tells_the_owner() {
    // Scenario: a user who has lost both the authenticator and the recovery codes. Expected: the
    // support desk can clear the factor with no code at all, and the owner is told. Why: every
    // self-service exit needs the factor itself, so without this path that user is locked out
    // permanently by the control meant to protect them (ASVS v5 §6.1.1).
    //
    // The notification is not decoration. An administrative reset the account holder cannot see
    // is an account-takeover path — an attacker who reaches the support desk removes the second
    // factor and nothing reaches the owner. Asserting the mail and the hook is asserting that
    // the event is detectable.
    let spy = Arc::new(AlertSpy::default());
    let email: Arc<dyn EmailProvider> = spy.clone();
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    let Some(h) = build_with(false, false, Some(email), Some(hooks)) else {
        return;
    };
    let Some(uid) = register(&h.engine, "reset@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    assert!(
        mfa.verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await
        .is_ok()
    );

    assert!(
        mfa.reset_mfa(&uid, MfaContext::Dashboard, Some("t1"))
            .await
            .is_ok()
    );

    // The factor is actually gone, not merely reported gone: `disable` answers "not enabled",
    // which it can only do by reading the record back.
    assert!(matches!(
        mfa.disable(
            &uid,
            &code(&setup.secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await,
        Err(AuthError::MfaNotEnabled)
    ));

    // Long enough for the detached notifications to have run.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = spy.seen();
    assert!(
        seen.contains(&"mail:disabled:reset@example.com".to_owned()),
        "the owner was not told: {seen:?}"
    );
    assert!(
        seen.contains(&format!("hook:disabled:{uid}")),
        "no hook for host-side alerting: {seen:?}"
    );
}

#[tokio::test]
async fn reset_mfa_is_idempotent_and_refuses_an_unknown_subject() {
    // Idempotent: a support desk retrying a job already done is not told it failed — the same
    // promise `unlock_account` makes. And an id that resolves to nobody is refused rather than
    // answering `Ok`, so a typo at the desk cannot read as "reset done".
    let Some(h) = build(false, false) else { return };
    let Some(uid) = register(&h.engine, "noreset@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };

    // No second factor was ever enrolled.
    assert!(
        mfa.reset_mfa(&uid, MfaContext::Dashboard, Some("t1"))
            .await
            .is_ok()
    );
    // And again, for the retry.
    assert!(
        mfa.reset_mfa(&uid, MfaContext::Dashboard, Some("t1"))
            .await
            .is_ok()
    );

    assert!(matches!(
        mfa.reset_mfa("nobody-at-all", MfaContext::Dashboard, Some("t1"))
            .await,
        Err(AuthError::MfaNotEnabled)
    ));
}

#[test]
fn an_mfa_notice_is_attributed_to_the_account_tenant_or_the_platform_plane() {
    // The email port takes a tenant so a multi-tenant channel can attribute and route the
    // message. A dashboard user has one; a platform admin is cross-tenant and has none, and the
    // reserved `platform` name is what keeps the admin plane from being silently attributed to
    // whatever tenant happens to sort first — or to an empty string the channel cannot route.
    // `dashboard_user` is `None` exactly on the platform plane, which is what makes it the
    // discriminator rather than a second field that could disagree with it.
    let dashboard = super::MfaUserView {
        email: "u@example.com".to_owned(),
        mfa_enabled: true,
        mfa_secret: None,
        mfa_recovery_codes: None,
        dashboard_user: Some(sample_safe_user()),
        password_hash: None,
    };
    assert_eq!(dashboard.email_tenant(), TENANT);

    let platform = super::MfaUserView {
        dashboard_user: None,
        ..dashboard
    };
    assert_eq!(
        platform.email_tenant(),
        crate::traits::PLATFORM_EMAIL_TENANT
    );
}
