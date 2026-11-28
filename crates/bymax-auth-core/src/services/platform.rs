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
    RotatedTokens, SafeAuthPlatformUser,
};

use crate::normalize::normalize_email;
use crate::services::auth::{normalize_anti_enum, spawn_guarded};
use crate::services::brute_force::BruteForceService;
use crate::services::logout_pending::{
    marker_ttl_secs, remember_failed_attempt, resolve_owner, settle_completed,
};
use crate::services::password::PasswordService;
use crate::services::session_access::end_logout_access;
use crate::services::token_manager::TokenManagerService;
use crate::services::{is_refresh_token_shape, note_logout_failure, now_unix, to_hex};
use crate::traits::{
    AuthHooks, HookContext, HookPlane, LogoutOwner, PlatformUserRepository, SessionKind,
    SessionStore,
};

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
    identifier_key: zeroize::Zeroizing<[u8; 64]>,
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
    pub(crate) identifier_key: zeroize::Zeroizing<[u8; 64]>,
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
        // Canonicalize before the lockout identifier and the repository lookup are derived, so
        // rotating the casing cannot mint a fresh failure budget for the same administrator.
        let email = normalize_email(email);
        let email = email.as_str();
        let identifier = self.brute_force_identifier(email);

        // Brute-force gate first, so an already-locked account never increments again.
        if let Err(error) = self.assert_not_locked(&identifier).await {
            tracing::warn!(
                event = "RUST_AUTH_PLATFORM_LOGIN_ACCOUNT_LOCKED",
                "platform login: account locked"
            );
            return Err(error);
        }

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

        // The password is proved FIRST. The status gate below used to run ahead of the KDF to
        // spare hashing an account that could never sign in — but it answered with the
        // administrator's own status, well inside the anti-enumeration floor every other
        // refusal pays, and without touching the failure counter. That enumerated operator
        // accounts and read their moderation state on the highest-privilege plane in the
        // system. The hashing it saved is bounded by the per-IP limiter; the disclosure was
        // bounded by nothing.
        let outcome = self
            .passwords
            .verify(password, &admin.password_hash)
            .await?;
        if !outcome.matched {
            return self.record_failure_and_reject(&identifier, started).await;
        }

        // Only now is the account's state described. The platform domain has NO
        // email-verification gate (admins are provisioned directly) and NO OAuth path — both
        // are absent by construction.
        self.assert_not_blocked(&admin.status)?;

        // Password proven: clear the failure counter.
        self.brute_force.reset(&identifier).await?;

        // Transparent rehash-on-verify, fire-and-forget, never blocking login.
        if upgrades_hash(self.passwords.rehash_on_verify(), outcome.needs_rehash) {
            spawn_guarded(run_rehash_platform_password(
                self.passwords.clone(),
                self.repo.clone(),
                password.to_owned(),
                admin.id.clone(),
                admin.password_hash.clone(),
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
                // Platform admins are cross-tenant and carry no tenant; `None` here is the
                // asserted absence the verifier requires, not a missing value.
                .issue_mfa_temp_token(&admin.id, MfaContext::Platform, None)
                .await?;
            tracing::info!(
                event = "RUST_AUTH_PLATFORM_LOGIN_MFA_CHALLENGE_ISSUED",
                "platform login: MFA challenge issued"
            );
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
        let rotated = self
            .tokens
            .reissue_platform_tokens(old_refresh, ip, user_agent)
            .await?;

        // Re-read the administrator and re-apply the status gate — the backstop the dashboard
        // plane has carried since ASVS v5 §7.4.2 was applied to it, and which this plane went
        // without. Rotation works entirely from the stored `prt:` record, so nothing else on
        // this path ever looks at the account again: a SUSPENDED or BANNED operator kept
        // renewing access every fifteen minutes for the refresh token's whole lifetime, on the
        // highest-privilege identity in the system, and the kill switch was advisory exactly
        // where it mattered most.
        // The session entry is not read: a family can hold a second session, and the entry of an
        // ended one would refuse this token after rotation had already spent the presented one.
        let claims = self
            .tokens
            .verify_issued_platform_access(&rotated.access_token)
            .await?;
        let admin = self
            .repo
            .find_by_id(&claims.sub)
            .await
            .map_err(repository_error)?;
        let Some(admin) = admin else {
            // The account was deleted while the session outlived it. Clear what is left rather
            // than leaving the freshly rotated records to be rotated again.
            self.revoke_all_platform_sessions(&claims.sub).await?;
            return Err(AuthError::RefreshTokenInvalid);
        };

        if let Err(error) = self.assert_not_blocked(&admin.status) {
            // Compensated, not merely refused: the rotation above already minted a live pair,
            // and leaving it would hand back exactly the access this gate exists to end.
            self.revoke_all_platform_sessions(&admin.id).await?;
            return Err(error);
        }

        // Re-stamp the access token from the administrator just re-read — the same fix the
        // dashboard plane carries, on the plane where the authority is worth more. Rotation
        // builds its claims from the `prt:` record written at login, so a demotion from
        // `super_admin` to `support` had no effect on a live console session: it kept minting
        // tokens with the old role for the refresh token's whole lifetime, and every role check
        // reads that claim. `mfa_enabled` is re-stamped for the same reason as on the dashboard
        // plane — it gates whether a second factor is demanded at all.
        //
        // The account was already read a few lines above for the status gate; the authority was
        // sitting there, unused. Only re-signed when a claim actually differs.
        if claims.role == admin.role && claims.mfa_enabled == admin.mfa_enabled {
            return Ok(rotated);
        }
        Ok(RotatedTokens {
            access_token: self
                .tokens
                .reissue_platform_access_with_authority(&claims, &admin.role, admin.mfa_enabled)
                .await?,
            refresh_token: rotated.refresh_token,
        })
    }

    /// Revoke the current platform session: blacklist the access token's `jti` for its
    /// remaining lifetime — only when the token actually verifies as a platform token — and
    /// delete BOTH the primary refresh session and any rotation grace pointer for it. The
    /// session's access tokens are ended with it.
    ///
    /// # Errors
    ///
    /// Attempts every revocation write whatever an earlier one did, then answers the first
    /// failure as [`AuthError::Internal`]: a success is answered only when the access token, the
    /// refresh session and the grace pointer are all gone. A session already rotated or evicted
    /// is not a failure, so a retry finishes whatever the first attempt left.
    pub async fn logout(&self, access_token: &str, raw_refresh: &str) -> Result<String, AuthError> {
        // The stored session names its owner. Presenting the refresh token proves possession;
        // the record proves whose it is. The admin id used to come from the route's
        // `PlatformUser` extractor — which is why the route refused an EXPIRED access token,
        // so an operator who stepped away for longer than the access lifetime could not sign
        // out at all and the refresh session of the highest-privilege identity in the system
        // stayed live on a console they believed they had left.
        let session_hash = is_refresh_token_shape(raw_refresh)
            .then(|| RawRefreshToken::from_raw(raw_refresh.to_owned()).redis_hash());
        let live = self.logout_live_owner(session_hash.as_deref()).await?;
        let store = self.session_store.as_ref();
        let hash = session_hash.as_deref();
        let resolved = resolve_owner(store, SessionKind::Platform, hash, live).await?;
        let admin_id = resolved.owner.as_ref().map_or("", |o| o.user_id.as_str());
        let mut failure = None;

        self.blacklist_logout_access_token(access_token, &mut failure)
            .await;
        if is_refresh_token_shape(raw_refresh) {
            self.revoke_logout_session(raw_refresh, admin_id, &mut failure)
                .await;
        }
        self.end_logout_session_access(resolved.owner.as_ref(), &mut failure)
            .await;
        if let Some(error) = failure {
            let ttl = marker_ttl_secs(self.tokens.access_ttl());
            remember_failed_attempt(store, SessionKind::Platform, hash, &resolved, ttl).await;
            return Err(error);
        }
        // No owner means no live session matched and no failed attempt left a marker: already
        // signed out, or expired. There is no identity to hand the hook, and logout stays a
        // success either way: it is idempotent, and answering an error would tell a caller
        // whether a token was live.
        let ttl = marker_ttl_secs(self.tokens.access_ttl());
        let announce = settle_completed(store, SessionKind::Platform, hash, &resolved, ttl).await?;
        if let (true, Some(owner)) = (announce, &resolved.owner) {
            let hook_ctx = identity_only_context(&owner.user_id);
            spawn_guarded(run_after_platform_logout(
                self.hooks.clone(),
                owner.user_id.clone(),
                hook_ctx,
            ));
        }
        Ok(admin_id.to_owned())
    }

    /// Write the platform session entry for the family `owner` names, so every access token of
    /// the session being signed out is refused.
    async fn end_logout_session_access(
        &self,
        owner: Option<&LogoutOwner>,
        failure: &mut Option<AuthError>,
    ) {
        let ttl = self.tokens.access_ttl();
        let store = self.session_store.as_ref();
        let ended = end_logout_access(store, SessionKind::Platform, owner, ttl).await;
        note_logout_failure(failure, "logout: session access revocation failed", ended);
    }

    /// The admin the live platform refresh session names, or `None` when the session is gone.
    ///
    /// A lookup that fails ends the logout before any write: the owner is unknown, so the
    /// writes that follow could not be aimed.
    async fn logout_live_owner(
        &self,
        session_hash: Option<&str>,
    ) -> Result<Option<LogoutOwner>, AuthError> {
        let Some(hash) = session_hash else {
            return Ok(None);
        };
        let found = self
            .session_store
            .find_session(SessionKind::Platform, hash)
            .await
            .map_err(|error| {
                tracing::warn!(
                    event = "RUST_AUTH_PLATFORM_LOGOUT_SESSION_LOOKUP_FAILED",
                    "logout: session lookup failed"
                );
                crate::services::answer_store_failure(error, "a logout could not read its session")
            })?;
        Ok(found.map(|record| LogoutOwner {
            user_id: record.user_id,
            tenant_id: None,
            family_id: crate::services::session_id(&record.family_id).map(str::to_owned),
        }))
    }

    /// Blacklist the access token's `jti` for its remaining lifetime, only when it verifies as a
    /// PLATFORM token: a forged token needs no revocation, and a dashboard token can never verify
    /// here (the platform discriminator rejects it), so a dashboard `jti` can never pollute the
    /// platform-session logout path. Expiry is waived and the signature is not, since the `jti`
    /// decides which token gets blacklisted.
    async fn blacklist_logout_access_token(
        &self,
        access_token: &str,
        failure: &mut Option<AuthError>,
    ) {
        if let Ok(claims) = self
            .tokens
            .verify_platform_access_ignoring_expiry(access_token)
        {
            let ttl = u64::try_from(claims.exp.saturating_sub(now_unix())).unwrap_or(0);
            let revoked = self.tokens.revoke_access(&claims.jti, ttl).await;
            note_logout_failure(failure, "logout: access token revocation failed", revoked);
        }
    }

    /// Delete BOTH the primary and the grace refresh keys for the presented token, against the
    /// PLATFORM keyspace. The ownership-checked revoke deletes the primary `prt:`/`psd:` keys and
    /// the `psess:` membership in one atomic step; the grace-pointer delete then removes any
    /// `prp:` recovery pointer keyed by this same hash, so a token logged out within its grace
    /// window cannot still rotate into a fresh session. Both are attempted whatever the other
    /// did; `SessionNotFound` (already rotated or evicted) is not recorded.
    async fn revoke_logout_session(
        &self,
        raw_refresh: &str,
        admin_id: &str,
        failure: &mut Option<AuthError>,
    ) {
        let session_hash = RawRefreshToken::from_raw(raw_refresh.to_owned()).redis_hash();
        let revoked = self
            .session_store
            .revoke_session(
                SessionKind::Platform,
                &self.session_subject(admin_id),
                &session_hash,
            )
            .await;
        let revoked = match revoked {
            Err(AuthError::SessionNotFound) => Ok(()),
            other => other,
        };
        note_logout_failure(failure, "logout: session cleanup failed", revoked);
        let grace = self
            .session_store
            .delete_grace_pointer(SessionKind::Platform, &session_hash)
            .await;
        note_logout_failure(failure, "logout: grace pointer cleanup failed", grace);
    }

    /// Atomically invalidate EVERY platform session for the admin (the "log out everywhere"
    /// action), clearing the `psess:` set and every member's `prt:`/`psd:` keys in one
    /// transaction over the platform keyspace — then advance the admin's token epoch, so
    /// outstanding platform **access** tokens die with the refresh sessions rather than
    /// working on to expiry. Bumped after the sweep so a failed sweep leaves the operation
    /// visibly incomplete instead of reading as done while the sessions live on. The
    /// dashboard revoke-all bumps its plane's epoch the same way.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] on an infrastructure failure.
    pub async fn revoke_all_platform_sessions(&self, admin_id: &str) -> Result<(), AuthError> {
        let subject = self.session_subject(admin_id);
        self.session_store
            .revoke_all(SessionKind::Platform, &subject)
            .await?;
        self.session_store
            .bump_epoch(SessionKind::Platform, &subject)
            .await?;
        Ok(())
    }

    /// The platform session subject for one admin: `hmac_sha256(identifier_key,
    /// "platform:{adminId}")` in lower-case hex — the suffix of `psess:` and `pep:`.
    ///
    /// No tenant segment, because a platform admin has none. The relocation off the bare id
    /// still matters on this plane, and matters most here: `pep:` is what makes a revoked
    /// administrator's outstanding access tokens stop verifying, and an epoch written under one
    /// key while the verifier reads another is a revocation that silently does nothing.
    fn session_subject(&self, admin_id: &str) -> String {
        crate::services::session_subject_hash(
            &self.identifier_key,
            SessionKind::Platform,
            None,
            admin_id,
        )
    }

    /// The hashed brute-force identifier for a platform login: `hmac_sha256("platform:{email}")`
    /// (hex) under the engine's derived key. The `platform:` namespace keeps it disjoint from the
    /// dashboard `dashboard:{tenant}:{email}` identifier and carries no PII into a store key.
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
        tracing::info!(
            event = "RUST_AUTH_PLATFORM_LOGIN_SUCCEEDED",
            "platform login: success"
        );
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
        tracing::warn!(
            event = "RUST_AUTH_PLATFORM_LOGIN_INVALID_CREDENTIALS",
            "platform login: invalid credentials"
        );
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
    /// the status-specific 403 when blocked and `Ok(())` otherwise. Delegates to the shared gate
    /// so the platform plane can never drift from the dashboard one.
    fn assert_not_blocked(&self, status: &str) -> Result<(), AuthError> {
        crate::status_gate::assert_not_blocked(status, &self.blocked_statuses)
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
        plane: HookPlane::Platform,
        user_id: Some(admin_id.to_owned()),
        email: None,
        tenant_id: None,
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: std::collections::BTreeMap::new(),
    }
}

/// Stamp the admin's last successful login (fire-and-forget).
pub(crate) async fn run_update_platform_last_login(
    repo: Arc<dyn PlatformUserRepository>,
    admin_id: String,
) -> Result<(), crate::RepositoryError> {
    repo.update_last_login(&admin_id).await
}

/// Whether a successful login schedules the hash upgrade: the toggle is on AND the stored hash is
/// stale. Either alone leaves a current hash untouched, so a rehash is never a write on every login
/// and the toggle always disables it.
const fn upgrades_hash(rehash_on_verify: bool, needs_rehash: bool) -> bool {
    rehash_on_verify && needs_rehash
}

/// Re-hash the just-proven plaintext with the current scheme and persist the upgrade — the
/// transparent rehash-on-verify path for a platform admin (fire-and-forget).
///
/// `verified_hash` gates the write for the same reason it does on the dashboard plane: the task
/// carries the plaintext and lands after a slow derivation, so an unconditional write can
/// re-install a credential the admin has since replaced — most likely replaced BECAUSE it was
/// compromised, by the very login that scheduled this. See `detached::run_rehash_password`.
async fn run_rehash_platform_password(
    passwords: Arc<PasswordService>,
    repo: Arc<dyn PlatformUserRepository>,
    password: String,
    admin_id: String,
    verified_hash: String,
) -> Result<(), AuthError> {
    let new_hash = passwords.hash(&password).await?;
    let current = repo.find_by_id(&admin_id).await.map_err(repository_error)?;
    if current.map(|admin| admin.password_hash) != Some(verified_hash) {
        return Ok(());
    }
    repo.update_password(&admin_id, &new_hash)
        .await
        .map_err(repository_error)
}

/// Invoke the `after_platform_logout` notification hook. It is not `after_logout`, which a
/// consumer wrote for dashboard users and may answer with a tenant lookup an administrator
/// cannot satisfy.
async fn run_after_platform_logout(
    hooks: Arc<dyn AuthHooks>,
    admin_id: String,
    ctx: HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks.after_platform_logout(&admin_id, &ctx).await
}

#[cfg(test)]
mod tests;
