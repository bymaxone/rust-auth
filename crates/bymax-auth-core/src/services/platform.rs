//! The platform-administrator identity domain (§7.9): a distinct authentication surface for
//! operators, isolated from the tenant/dashboard domain. It mints platform JWTs that carry
//! **no `tenantId`**, persists sessions in the dedicated `psess:`/`prt:`/`psd:`/`prp:`
//! keyspaces (via [`SessionKind::Platform`]), and authorizes against an isolated platform role
//! hierarchy.
//!
//! # Security posture
//!
//! - **Anti-enumeration parity with dashboard login.** An unknown admin pays the same KDF cost
//!   (the sentinel verify) and the same timing floor as a wrong password, so neither the status,
//!   the body, nor the latency distinguishes a missing admin from a bad credential. Every login
//!   failure is the generic [`AuthError::InvalidCredentials`].
//! - **No PII in store keys.** The brute-force identifier is `hmac_sha256("platform:{email}")`
//!   (hex) under the engine's derived key — the `platform:` namespace keeps it disjoint from the
//!   dashboard `{tenant}:{email}` identifiers, so a platform and a dashboard account sharing an
//!   email never share a lockout counter.
//! - **No tenant / verification / OAuth surface.** Platform admins are provisioned directly:
//!   there is no email-verification gate and no OAuth path here, by construction.
//! - **MFA via [`MfaContext::Platform`].** An MFA-enabled admin gets a challenge whose temp
//!   token carries the `context: platform` discriminant, so the challenge flow routes
//!   persistence and issuance through the platform user store (the arm completed alongside this
//!   domain).

use std::time::Instant;

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{
    AuthError, AuthPlatformUser, MfaChallengeResult, MfaContext, PlatformLoginResult,
    SafeAuthPlatformUser,
};

use crate::services::auth::{normalize_anti_enum, spawn_guarded};
use crate::services::brute_force::BruteForceService;
use crate::services::password::PasswordService;
use crate::services::token_manager::TokenManagerService;
use crate::services::{is_refresh_token_shape, now_unix, to_hex};
use crate::traits::{AuthHooks, HookContext, PlatformUserRepository, SessionKind, SessionStore};

use std::sync::Arc;

/// The platform-admin authentication service. Constructed by the engine builder only when
/// `config.platform.enabled` (which itself requires `roles.platform_hierarchy` and a
/// [`PlatformUserRepository`]); the collaborators it shares with the engine are held as `Arc`
/// handles.
pub struct PlatformAuthService {
    repo: Arc<dyn PlatformUserRepository>,
    tokens: Arc<TokenManagerService>,
    session_store: Arc<dyn SessionStore>,
    passwords: Arc<PasswordService>,
    brute_force: Arc<BruteForceService>,
    hooks: Arc<dyn AuthHooks>,
    /// The engine's derived identifier-hashing key, copied into a zeroizing buffer; it keys the
    /// `platform:{email}` brute-force identifier so no raw email reaches a store key.
    identifier_key: zeroize::Zeroizing<[u8; 32]>,
    /// Whether this build wires the MFA challenge surface; when `false`, an MFA-enabled admin
    /// cannot complete a login (fail-closed) because there is no challenge flow to route to.
    mfa_enabled_for_build: bool,
    /// Statuses that block a platform login (the engine's `blocked_statuses`, applied to admins
    /// exactly as to dashboard users).
    blocked_statuses: Vec<String>,
}

/// The collaborators a [`PlatformAuthService`] is assembled from. Grouped into a struct so the
/// constructor takes a single value rather than a long positional argument list.
pub(crate) struct PlatformAuthDeps {
    pub(crate) repo: Arc<dyn PlatformUserRepository>,
    pub(crate) tokens: Arc<TokenManagerService>,
    pub(crate) session_store: Arc<dyn SessionStore>,
    pub(crate) passwords: Arc<PasswordService>,
    pub(crate) brute_force: Arc<BruteForceService>,
    pub(crate) hooks: Arc<dyn AuthHooks>,
    pub(crate) identifier_key: zeroize::Zeroizing<[u8; 32]>,
    pub(crate) mfa_enabled_for_build: bool,
    pub(crate) blocked_statuses: Vec<String>,
}

impl PlatformAuthService {
    /// Assemble the service from its resolved collaborators.
    pub(crate) fn new(deps: PlatformAuthDeps) -> Self {
        Self {
            repo: deps.repo,
            tokens: deps.tokens,
            session_store: deps.session_store,
            passwords: deps.passwords,
            brute_force: deps.brute_force,
            hooks: deps.hooks,
            identifier_key: deps.identifier_key,
            mfa_enabled_for_build: deps.mfa_enabled_for_build,
            blocked_statuses: deps.blocked_statuses,
        }
    }

    /// Authenticate a platform admin by email + password, returning either a full platform
    /// session or an MFA challenge. Uniform-timing, generic-error anti-enumeration holds: an
    /// unknown admin and a wrong password are indistinguishable in status, body, and latency.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AccountLocked`] when the brute-force window is tripped,
    /// [`AuthError::InvalidCredentials`] for an unknown admin or wrong password (uniform), a
    /// status [`AuthError`] for a blocked account, or an internal/store [`AuthError`]. An
    /// MFA-enabled admin in a build without the MFA surface fails closed as
    /// [`AuthError::InvalidCredentials`] (no challenge can be issued).
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<PlatformLoginResult, AuthError> {
        let identifier = self.brute_force_identifier(email);

        // Brute-force gate first, so an already-locked account never increments again.
        self.assert_not_locked(&identifier).await?;

        // The timing floor starts here so the unknown-admin and wrong-password paths are
        // indistinguishable in elapsed time, not just in status/body.
        let started = Instant::now();
        let admin = self
            .repo
            .find_by_email(email)
            .await
            .map_err(repository_error)?;

        // Unknown admin: run the sentinel verify so the KDF cost is paid either way, then record
        // the failure and return generically (no "account exists" oracle).
        let Some(admin) = admin else {
            self.passwords.verify_sentinel(password).await?;
            return self.record_failure_and_reject(&identifier, started).await;
        };

        // Status gate runs before the KDF so a blocked account never consumes hashing CPU. The
        // platform domain has NO email-verification gate (admins are provisioned directly) and
        // NO OAuth path — both are absent by construction.
        self.assert_not_blocked(&admin.status)?;

        let outcome = self
            .passwords
            .verify(password, &admin.password_hash)
            .await?;
        if !outcome.matched {
            return self.record_failure_and_reject(&identifier, started).await;
        }

        // Password proven: clear the failure counter.
        self.brute_force.reset(&identifier).await?;

        // Transparent rehash-on-verify, fire-and-forget, never blocking login.
        if self.passwords.rehash_on_verify() && outcome.needs_rehash {
            spawn_guarded(run_rehash_platform_password(
                self.passwords.clone(),
                self.repo.clone(),
                password.to_owned(),
                admin.id.clone(),
            ));
        }

        // MFA branch: return a challenge instead of tokens. The temp token carries the
        // `context: platform` discriminant so the challenge flow routes through the platform
        // user store. A build without the MFA surface cannot complete the challenge, so an
        // MFA-enabled admin fails closed rather than being handed a session that skips the
        // second factor.
        if admin.mfa_enabled {
            if !self.mfa_enabled_for_build {
                return Err(AuthError::InvalidCredentials);
            }
            let mfa_temp_token = self
                .tokens
                .issue_mfa_temp_token(&admin.id, MfaContext::Platform)
                .await?;
            return Ok(PlatformLoginResult::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                mfa_temp_token,
            }));
        }

        self.issue_login(admin, ip, user_agent).await
    }

    /// Return the credential-free admin for the authenticated subject.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenInvalid`] when the subject no longer exists, or a store
    /// [`AuthError`] on a repository failure.
    pub async fn me(&self, admin_id: &str) -> Result<SafeAuthPlatformUser, AuthError> {
        match self
            .repo
            .find_by_id(admin_id)
            .await
            .map_err(repository_error)?
        {
            Some(admin) => Ok(SafeAuthPlatformUser::from(admin)),
            None => Err(AuthError::TokenInvalid),
        }
    }

    /// Rotate the presented platform refresh token, returning a fresh token pair (atomic
    /// rotation with a grace window), over the platform keyspace.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RefreshTokenInvalid`] when the token is neither live nor inside the
    /// grace window, or a store/signing [`AuthError`].
    pub async fn refresh(
        &self,
        old_refresh: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<bymax_auth_types::RotatedTokens, AuthError> {
        self.tokens
            .reissue_platform_tokens(old_refresh, ip, user_agent)
            .await
    }

    /// Revoke the current platform session: blacklist the access token's `jti` for its
    /// remaining lifetime — only when the token actually verifies as a platform token — and
    /// delete BOTH the primary refresh session and any rotation grace pointer for it. Idempotent
    /// and best-effort: a logout is never blocked by a store failure.
    ///
    /// # Errors
    ///
    /// The `Result` is reserved for forward compatibility and currently always returns `Ok`.
    pub async fn logout(
        &self,
        access_token: &str,
        raw_refresh: &str,
        admin_id: &str,
    ) -> Result<(), AuthError> {
        // Blacklist only a token that actually verifies as a PLATFORM token: a forged/expired
        // token needs no revocation, and a dashboard token can never verify here (the platform
        // discriminator rejects it), so a dashboard `jti` can never pollute the platform-session
        // logout path. Best-effort — a store failure must not block the logout.
        if let Ok(claims) = self.tokens.verify_platform_access(access_token).await {
            let ttl = u64::try_from(claims.exp.saturating_sub(now_unix())).unwrap_or(0);
            let _ = self.tokens.revoke_access(&claims.jti, ttl).await;
        }

        // Clean BOTH the primary and the grace refresh keys for the presented token, against the
        // PLATFORM keyspace. The ownership-checked revoke deletes the primary `prt:`/`psd:` keys
        // and the `psess:` membership in one atomic step; the grace-pointer delete then removes
        // any `prp:` recovery pointer keyed by this same hash — so a token logged out within its
        // grace window cannot still rotate into a fresh session. Both are best-effort: a store
        // failure (or a `SessionNotFound` for an already-rotated token) must never block logout.
        // A malformed/oversized token is skipped before hashing — it owns no session anyway.
        if is_refresh_token_shape(raw_refresh) {
            let session_hash = RawRefreshToken::from_raw(raw_refresh.to_owned()).redis_hash();
            let _ = self
                .session_store
                .revoke_session(SessionKind::Platform, admin_id, &session_hash)
                .await;
            let _ = self
                .session_store
                .delete_grace_pointer(SessionKind::Platform, &session_hash)
                .await;
        }

        let hook_ctx = identity_only_context(admin_id);
        spawn_guarded(run_after_logout(
            self.hooks.clone(),
            admin_id.to_owned(),
            hook_ctx,
        ));
        Ok(())
    }

    /// Atomically invalidate EVERY platform session for the admin (the "log out everywhere"
    /// action), clearing the `psess:` set and every member's `prt:`/`psd:` keys in one
    /// transaction over the platform keyspace.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] on an infrastructure failure.
    pub async fn revoke_all_platform_sessions(&self, admin_id: &str) -> Result<(), AuthError> {
        self.session_store
            .revoke_all(SessionKind::Platform, admin_id)
            .await
    }

    /// The hashed brute-force identifier for a platform login: `hmac_sha256("platform:{email}")`
    /// (hex) under the engine's derived key. The `platform:` namespace keeps it disjoint from the
    /// dashboard `{tenant}:{email}` identifiers and carries no PII into a store key.
    fn brute_force_identifier(&self, email: &str) -> String {
        to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            self.identifier_key.as_ref(),
            format!("platform:{email}").as_bytes(),
        ))
    }

    /// Issue a full platform session for the verified admin and fire the fire-and-forget
    /// last-login stamp. No tenant scope and no dashboard-typed `after_login` hook are involved —
    /// the platform identity surface manages its sessions and notifications separately.
    async fn issue_login(
        &self,
        admin: AuthPlatformUser,
        ip: &str,
        user_agent: &str,
    ) -> Result<PlatformLoginResult, AuthError> {
        let admin_id = admin.id.clone();
        let safe = SafeAuthPlatformUser::from(admin);
        let result = self
            .tokens
            .issue_platform_tokens(&safe, ip, user_agent, false)
            .await?;
        spawn_guarded(run_update_platform_last_login(self.repo.clone(), admin_id));
        Ok(PlatformLoginResult::Success(Box::new(result)))
    }

    /// Reject a credential attempt: record the failure and normalize the elapsed time to the
    /// anti-enumeration floor before returning the generic [`AuthError::InvalidCredentials`], so
    /// the unknown-admin and wrong-password paths are indistinguishable.
    async fn record_failure_and_reject<T>(
        &self,
        identifier: &str,
        started: Instant,
    ) -> Result<T, AuthError> {
        self.brute_force.record_failure(identifier).await?;
        normalize_anti_enum(started).await;
        Err(AuthError::InvalidCredentials)
    }

    /// Reject the login when the identifier is already locked out, surfacing the retry hint.
    async fn assert_not_locked(&self, identifier: &str) -> Result<(), AuthError> {
        if self.brute_force.is_locked(identifier).await? {
            let retry = self.brute_force.remaining_lockout_secs(identifier).await?;
            return Err(AuthError::AccountLocked {
                retry_after_seconds: Some(retry),
            });
        }
        Ok(())
    }

    /// Map a platform admin's `status` (case-insensitive) against `blocked_statuses`, returning
    /// the status-specific 403 when blocked and `Ok(())` otherwise. The mapping mirrors the
    /// dashboard status gate.
    fn assert_not_blocked(&self, status: &str) -> Result<(), AuthError> {
        if !self
            .blocked_statuses
            .iter()
            .any(|s| s.eq_ignore_ascii_case(status))
        {
            return Ok(());
        }
        Err(match status.to_ascii_lowercase().as_str() {
            "banned" => AuthError::AccountBanned,
            "inactive" => AuthError::AccountInactive,
            "suspended" => AuthError::AccountSuspended,
            "pending" | "pending_approval" => AuthError::PendingApproval,
            _ => AuthError::AccountInactive,
        })
    }
}

/// Map a repository failure to the opaque internal error (the concrete cause is carried for
/// logging, never serialized).
fn repository_error(error: crate::RepositoryError) -> AuthError {
    match error {
        crate::RepositoryError::Backend(source) => AuthError::Internal(source),
        crate::RepositoryError::Conflict(_) => {
            crate::services::internal_error("platform repository conflict")
        }
    }
}

/// Build a [`HookContext`] from only the admin id known to a flow that has no originating
/// request context (logout). The transport fields are empty and the platform domain carries no
/// tenant, so `tenant_id` is `None`.
fn identity_only_context(admin_id: &str) -> HookContext {
    HookContext {
        user_id: Some(admin_id.to_owned()),
        email: None,
        tenant_id: None,
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: std::collections::BTreeMap::new(),
    }
}

/// Stamp the admin's last successful login (fire-and-forget).
async fn run_update_platform_last_login(
    repo: Arc<dyn PlatformUserRepository>,
    admin_id: String,
) -> Result<(), crate::RepositoryError> {
    repo.update_last_login(&admin_id).await
}

/// Re-hash the just-proven plaintext with the current scheme and persist the upgrade — the
/// transparent rehash-on-verify path for a platform admin (fire-and-forget).
async fn run_rehash_platform_password(
    passwords: Arc<PasswordService>,
    repo: Arc<dyn PlatformUserRepository>,
    password: String,
    admin_id: String,
) -> Result<(), AuthError> {
    let new_hash = passwords.hash(&password).await?;
    repo.update_password(&admin_id, &new_hash)
        .await
        .map_err(repository_error)
}

/// Invoke the `after_logout` notification hook for a platform admin. The hook is domain-neutral
/// (it takes only the subject id), so it is shared with the dashboard logout.
async fn run_after_logout(
    hooks: Arc<dyn AuthHooks>,
    admin_id: String,
    ctx: HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks.after_logout(&admin_id, &ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Environment};
    use crate::context::RequestContext;
    use crate::engine::AuthEngine;
    use crate::testing::{InMemoryPlatformUserRepository, InMemoryStores};
    use bymax_auth_types::{
        AuthPlatformUser, LoginResult, PlatformLoginResult, UpdatePlatformMfaData,
    };
    use secrecy::SecretString;
    use std::collections::HashMap;
    use std::time::Duration;
    use time::OffsetDateTime;

    /// A config that enables the platform domain with a disjoint platform hierarchy, MFA wired,
    /// and a known JWT secret, valid under either hasher matrix.
    fn platform_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        #[cfg(not(feature = "scrypt"))]
        {
            cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
        }
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
        cfg.roles.platform_hierarchy = Some(HashMap::from([
            ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
            ("SUPPORT".to_owned(), Vec::new()),
        ]));
        cfg.platform.enabled = true;
        cfg.blocked_statuses = vec![
            "BANNED".to_owned(),
            "INACTIVE".to_owned(),
            "SUSPENDED".to_owned(),
            "PENDING_APPROVAL".to_owned(),
        ];
        // Wire MFA so the platform login can issue a real challenge for an MFA-enabled admin.
        // The encryption key is a 32-byte base64 value; the issuer is required and non-empty.
        {
            use base64::Engine as _;
            cfg.mfa = Some(crate::config::MfaConfig {
                encryption_key: SecretString::from(
                    base64::engine::general_purpose::STANDARD.encode([5u8; 32]),
                ),
                issuer: "Bymax Platform".to_owned(),
                recovery_code_count: 8,
                totp_window: 1,
            });
        }
        cfg
    }

    /// An engine plus the concrete platform repository behind it, so a test can both drive the
    /// platform flows and seed/inspect the backing admins.
    struct PlatformHarness {
        engine: AuthEngine,
        admins: Arc<InMemoryPlatformUserRepository>,
    }

    /// Build a platform harness from `cfg`. Returns `None` if assembly somehow fails, so callers
    /// stay panic-free with `let-else`.
    fn harness(cfg: AuthConfig) -> Option<PlatformHarness> {
        let admins = Arc::new(InMemoryPlatformUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let engine = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
            .platform_user_repository(admins.clone())
            .redis_stores(stores)
            .build()
            .ok()?;
        Some(PlatformHarness { engine, admins })
    }

    /// Hash a plaintext password with the compiled hasher, for seeding an admin's stored hash.
    fn hash_password(plain: &str) -> String {
        #[cfg(not(feature = "scrypt"))]
        let params = bymax_auth_crypto::password::PasswordParams {
            active: bymax_auth_crypto::password::PasswordAlgorithm::Argon2id,
            ..bymax_auth_crypto::password::PasswordParams::default()
        };
        #[cfg(feature = "scrypt")]
        let params = bymax_auth_crypto::password::PasswordParams::default();
        bymax_auth_crypto::password::hash(plain.as_bytes(), &params).unwrap_or_default()
    }

    /// Seed a platform admin (active, no MFA) and return its id.
    fn seed_admin(admins: &InMemoryPlatformUserRepository, email: &str, password: &str) -> String {
        let id = format!("admin-{email}");
        admins.insert(AuthPlatformUser {
            id: id.clone(),
            email: email.to_owned(),
            name: "Admin".to_owned(),
            password_hash: hash_password(password),
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
        id
    }

    #[test]
    fn engine_exposes_no_platform_service_when_the_domain_is_disabled() {
        // With `platform.enabled = false` the engine constructs no platform service, even though
        // the feature is compiled in.
        let mut cfg = platform_config();
        cfg.platform.enabled = false;
        cfg.roles.platform_hierarchy = None;
        let admins = Arc::new(InMemoryPlatformUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let built = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
            .platform_user_repository(admins)
            .redis_stores(stores)
            .build();
        assert!(matches!(&built, Ok(engine) if engine.platform_auth().is_none()));
    }

    #[tokio::test]
    async fn login_issues_a_platform_session_with_no_tenant() {
        // A correct password for an active admin returns a full platform session; me/refresh
        // then work against the platform keyspace.
        let Some(h) = harness(platform_config()) else { return };
        let _ = seed_admin(&h.admins, "ok@admin.io", "s3cret-pass");
        let Some(svc) = h.engine.platform_auth() else { return };
        let result = svc
            .login("ok@admin.io", "s3cret-pass", "1.2.3.4", "agent")
            .await;
        assert!(matches!(&result, Ok(PlatformLoginResult::Success(_))));
        let Ok(PlatformLoginResult::Success(auth)) = result else { return };
        assert_eq!(auth.user.email, "ok@admin.io");
        assert!(!auth.access_token.is_empty());

        // The platform access token verifies as a platform token and carries no tenant.
        let claims = h
            .engine
            .tokens()
            .verify_platform_access(&auth.access_token)
            .await;
        assert!(matches!(&claims, Ok(c) if c.role == "SUPER_ADMIN"));

        // me returns the admin; refresh rotates to a new pair.
        let me = svc.me(&format!("admin-{}", "ok@admin.io")).await;
        assert!(matches!(me, Ok(u) if u.email == "ok@admin.io"));
        let rotated = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
        assert!(matches!(&rotated, Ok(r) if r.refresh_token != auth.refresh_token));
    }

    #[tokio::test]
    async fn unknown_admin_and_wrong_password_are_indistinguishable() {
        // Both failure paths return InvalidCredentials and both honor the timing floor, so
        // neither status/body nor latency leaks whether the admin exists.
        let Some(h) = harness(platform_config()) else { return };
        let _ = seed_admin(&h.admins, "real@admin.io", "right-pass");
        let Some(svc) = h.engine.platform_auth() else { return };

        let unknown_started = Instant::now();
        let unknown = svc.login("ghost@admin.io", "any", "1.2.3.4", "agent").await;
        let unknown_elapsed = unknown_started.elapsed();

        let wrong_started = Instant::now();
        let wrong = svc
            .login("real@admin.io", "wrong-pass", "1.2.3.4", "agent")
            .await;
        let wrong_elapsed = wrong_started.elapsed();

        assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
        assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
        assert!(unknown_elapsed >= Duration::from_millis(300));
        assert!(wrong_elapsed >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn lockout_triggers_after_max_attempts() {
        // The default cap is five failures; the sixth attempt is AccountLocked with a retry
        // hint, before any credential check — keyed by the platform brute-force identifier.
        let Some(h) = harness(platform_config()) else { return };
        let _ = seed_admin(&h.admins, "lock@admin.io", "right");
        let Some(svc) = h.engine.platform_auth() else { return };
        for _ in 0..5 {
            let attempt = svc
                .login("lock@admin.io", "wrong", "1.2.3.4", "agent")
                .await;
            assert!(matches!(attempt, Err(AuthError::InvalidCredentials)));
        }
        let locked = svc
            .login("lock@admin.io", "right", "1.2.3.4", "agent")
            .await;
        assert!(matches!(
            locked,
            Err(AuthError::AccountLocked {
                retry_after_seconds: Some(_)
            })
        ));
    }

    #[tokio::test]
    async fn each_blocked_status_maps_to_its_specific_error() {
        // The status gate runs before the KDF and maps every blocked status to its 403.
        let Some(h) = harness(platform_config()) else { return };
        for (email, status) in [
            ("banned@admin.io", "BANNED"),
            ("inactive@admin.io", "INACTIVE"),
            ("suspended@admin.io", "SUSPENDED"),
        ] {
            let id = format!("admin-{email}");
            h.admins.insert(AuthPlatformUser {
                id,
                email: email.to_owned(),
                name: "Admin".to_owned(),
                password_hash: hash_password("pw"),
                role: "SUPER_ADMIN".to_owned(),
                status: status.to_owned(),
                mfa_enabled: false,
                mfa_secret: None,
                mfa_recovery_codes: None,
                platform_id: None,
                last_login_at: None,
                updated_at: OffsetDateTime::UNIX_EPOCH,
                created_at: OffsetDateTime::UNIX_EPOCH,
            });
        }
        let Some(svc) = h.engine.platform_auth() else { return };
        assert!(matches!(
            svc.login("banned@admin.io", "pw", "1.2.3.4", "a").await,
            Err(AuthError::AccountBanned)
        ));
        assert!(matches!(
            svc.login("inactive@admin.io", "pw", "1.2.3.4", "a").await,
            Err(AuthError::AccountInactive)
        ));
        assert!(matches!(
            svc.login("suspended@admin.io", "pw", "1.2.3.4", "a").await,
            Err(AuthError::AccountSuspended)
        ));
        // The pending alias and an unknown blocked status both map through the gate helper.
        assert!(matches!(
            svc.assert_not_blocked("PENDING_APPROVAL"),
            Err(AuthError::PendingApproval)
        ));
        assert!(matches!(svc.assert_not_blocked("ACTIVE"), Ok(())));
    }

    #[tokio::test]
    async fn pending_and_unknown_blocked_statuses_map_through_the_gate() {
        // The lowercase "pending" alias maps to PendingApproval, and a blocked status with no
        // specific arm falls back to AccountInactive.
        let mut cfg = platform_config();
        cfg.blocked_statuses = vec!["pending".to_owned(), "FROZEN".to_owned()];
        let Some(h) = harness(cfg) else { return };
        let Some(svc) = h.engine.platform_auth() else { return };
        assert!(matches!(
            svc.assert_not_blocked("pending"),
            Err(AuthError::PendingApproval)
        ));
        assert!(matches!(
            svc.assert_not_blocked("FROZEN"),
            Err(AuthError::AccountInactive)
        ));
    }

    #[tokio::test]
    async fn me_returns_token_invalid_for_an_unknown_admin() {
        // `me` projects the stored admin; an unknown subject is TokenInvalid.
        let Some(h) = harness(platform_config()) else { return };
        let Some(svc) = h.engine.platform_auth() else { return };
        assert!(matches!(
            svc.me("missing").await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[tokio::test]
    async fn logout_blacklists_the_jti_and_revokes_the_session() {
        // After logout the platform access jti is blacklisted (verify rejects it) and the
        // refresh session is gone, so the refresh token no longer rotates.
        let Some(h) = harness(platform_config()) else { return };
        let id = seed_admin(&h.admins, "out@admin.io", "pw");
        let Some(svc) = h.engine.platform_auth() else { return };
        let logged = svc.login("out@admin.io", "pw", "1.2.3.4", "agent").await;
        let Ok(PlatformLoginResult::Success(auth)) = logged else { return };
        assert!(
            svc.logout(&auth.access_token, &auth.refresh_token, &id)
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine
                .tokens()
                .verify_platform_access(&auth.access_token)
                .await,
            Err(AuthError::TokenRevoked)
        ));
        assert!(matches!(
            svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        // Logout tolerates a non-shaped refresh token, a garbage access token, and an unknown
        // admin, still succeeding.
        assert!(
            svc.logout("not-a-jwt", "unknown-refresh", "nobody")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn logout_cleans_the_grace_pointer_and_reuse_of_the_old_token_revokes_the_family() {
        // Login, then refresh (which plants a grace pointer for the OLD token). Logging out the
        // OLD token cleans BOTH its primary key (already consumed by the rotation) AND its grace
        // pointer, so a follow-up rotation of the old token can no longer recover through the
        // grace window. The consumed-family marker outlives the grace pointer, so that follow-up
        // is now caught as a REUSE of a consumed token — the signature of a stolen token — and
        // revokes the whole family, taking the live rotated token down with it.
        let Some(h) = harness(platform_config()) else { return };
        let id = seed_admin(&h.admins, "grace@admin.io", "pw");
        let Some(svc) = h.engine.platform_auth() else { return };
        let logged = svc.login("grace@admin.io", "pw", "1.2.3.4", "agent").await;
        let Ok(PlatformLoginResult::Success(auth)) = logged else { return };
        // Rotate: the old refresh token is consumed and a grace pointer is planted for it.
        let rotation = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
        let Ok(rotated) = rotation else { return };
        // Logging out the OLD token cleans its grace pointer.
        assert!(
            svc.logout(&auth.access_token, &auth.refresh_token, &id)
                .await
                .is_ok()
        );
        // Replaying the OLD token can no longer recover through the (now-cleaned) grace window; it
        // is rejected as a reuse of a consumed token, which revokes the family.
        assert!(matches!(
            svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        // The reuse revoked the whole lineage, so even the freshly rotated (previously live)
        // token no longer rotates — a stolen token can never keep a parallel chain alive.
        assert!(matches!(
            svc.refresh(&rotated.refresh_token, "1.2.3.4", "agent")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn revoke_all_invalidates_every_platform_session() {
        // Two logins for the same admin, then revoke-all leaves neither refresh token usable.
        let Some(h) = harness(platform_config()) else { return };
        let id = seed_admin(&h.admins, "all@admin.io", "pw");
        let Some(svc) = h.engine.platform_auth() else { return };
        let first_login = svc.login("all@admin.io", "pw", "1.2.3.4", "agent").await;
        let Ok(PlatformLoginResult::Success(first)) = first_login else { return };
        let second_login = svc.login("all@admin.io", "pw", "5.6.7.8", "agent").await;
        let Ok(PlatformLoginResult::Success(second)) = second_login else { return };
        assert!(svc.revoke_all_platform_sessions(&id).await.is_ok());
        assert!(matches!(
            svc.refresh(&first.refresh_token, "1.2.3.4", "agent").await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        assert!(matches!(
            svc.refresh(&second.refresh_token, "5.6.7.8", "agent").await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn mfa_enabled_admin_gets_a_platform_challenge() {
        // A correct password for an MFA-enabled admin returns the challenge, not tokens.
        let Some(h) = harness(platform_config()) else { return };
        let id = seed_admin(&h.admins, "mfa@admin.io", "pw");
        let _ = h
            .admins
            .update_mfa(
                &id,
                UpdatePlatformMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some("enc".to_owned()),
                    mfa_recovery_codes: None,
                },
            )
            .await;
        let Some(svc) = h.engine.platform_auth() else { return };
        let result = svc.login("mfa@admin.io", "pw", "1.2.3.4", "agent").await;
        assert!(matches!(
            result,
            Ok(PlatformLoginResult::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn no_dashboard_path_is_reachable_for_a_platform_admin() {
        // A platform admin is not a dashboard user: the dashboard login cannot find them (they
        // live in a separate repository), so the dashboard surface is unreachable for them.
        let Some(h) = harness(platform_config()) else { return };
        let _ = seed_admin(&h.admins, "iso@admin.io", "pw");
        let dashboard = h
            .engine
            .login(
                crate::services::auth::LoginInput {
                    email: "iso@admin.io".to_owned(),
                    password: "pw".to_owned(),
                    tenant_id: "t1".to_owned(),
                },
                &RequestContext::new("1.2.3.4", "agent", std::collections::BTreeMap::new()),
            )
            .await;
        // The dashboard repository has no such user, so login is a generic credential failure —
        // never a success that would cross the domain boundary.
        assert!(matches!(dashboard, Err(AuthError::InvalidCredentials)));
        // And the dashboard login never returns a platform result type, by construction.
        assert!(!matches!(dashboard, Ok(LoginResult::Success(_))));
    }

    #[tokio::test]
    async fn mfa_enabled_admin_fails_closed_without_the_mfa_surface() {
        // A platform domain enabled WITHOUT MFA config has no challenge surface, so an
        // MFA-enabled admin cannot complete a login: it fails closed as InvalidCredentials
        // rather than being handed a session that skips the second factor.
        let mut cfg = platform_config();
        cfg.mfa = None; // no MFA surface in this build
        let Some(h) = harness(cfg) else { return };
        let id = seed_admin(&h.admins, "nomfa@admin.io", "pw");
        let _ = h
            .admins
            .update_mfa(
                &id,
                UpdatePlatformMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some("enc".to_owned()),
                    mfa_recovery_codes: None,
                },
            )
            .await;
        let Some(svc) = h.engine.platform_auth() else { return };
        let result = svc.login("nomfa@admin.io", "pw", "1.2.3.4", "agent").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[test]
    fn repository_error_maps_backend_and_conflict_to_internal() {
        // A backend failure and a (contract-impossible) conflict both collapse to the opaque
        // internal error, so a platform repository failure never surfaces its concrete cause.
        assert!(matches!(
            repository_error(crate::RepositoryError::Backend("db down".into())),
            AuthError::Internal(_)
        ));
        assert!(matches!(
            repository_error(crate::RepositoryError::Conflict("dup".to_owned())),
            AuthError::Internal(_)
        ));
    }

    #[tokio::test]
    async fn rehash_on_verify_upgrades_a_weaker_admin_hash() {
        // A hash stored under weaker scrypt params is upgraded on a successful login; the
        // detached task replaces the stored hash with a stronger one.
        #[cfg(feature = "scrypt")]
        {
            let Some(h) = harness(platform_config()) else { return };
            let weak_params = bymax_auth_crypto::password::PasswordParams {
                active: bymax_auth_crypto::password::PasswordAlgorithm::Scrypt,
                scrypt: bymax_auth_crypto::password::ScryptParams {
                    cost_factor: 1 << 14,
                    block_size: 8,
                    parallelization: 1,
                },
                #[cfg(feature = "argon2")]
                argon2: bymax_auth_crypto::password::Argon2Params::default(),
            };
            let weak_hash =
                bymax_auth_crypto::password::hash(b"pw", &weak_params).unwrap_or_default();
            let id = "admin-weak@admin.io".to_owned();
            h.admins.insert(AuthPlatformUser {
                id: id.clone(),
                email: "weak@admin.io".to_owned(),
                name: "Admin".to_owned(),
                password_hash: weak_hash.clone(),
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
            let Some(svc) = h.engine.platform_auth() else { return };
            let result = svc.login("weak@admin.io", "pw", "1.2.3.4", "agent").await;
            assert!(matches!(result, Ok(PlatformLoginResult::Success(_))));
            tokio::time::sleep(Duration::from_millis(500)).await;
            let stored = h.admins.find_by_id(&id).await;
            let Ok(Some(stored)) = stored else { return };
            assert_ne!(stored.password_hash, weak_hash);
        }
    }
}
