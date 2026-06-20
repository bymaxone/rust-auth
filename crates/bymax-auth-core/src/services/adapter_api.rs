//! The thin public engine surface an HTTP adapter (`bymax-auth-axum`) calls to source and
//! verify credentials, run authorization checks, and mint/redeem WebSocket upgrade tickets.
//!
//! Every method here is a one-line delegation to an existing internal service — the adapter
//! owns no auth logic, so these exist purely to expose the already-implemented checks
//! (HS256-pinned token verification, the role hierarchy, the status gate, the single-use WS
//! ticket) across the crate boundary without leaking the `pub(crate)` collaborators.

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, DashboardClaims, DashboardType};
#[cfg(feature = "mfa")]
use bymax_auth_types::{AuthResult, MfaContext};
#[cfg(feature = "platform")]
use bymax_auth_types::{
    PlatformAuthResult, PlatformClaims, PlatformLoginResult, RotatedTokens, SafeAuthPlatformUser,
};

use crate::engine::AuthEngine;
use crate::services::auth::map_repository_error;
#[cfg(feature = "mfa")]
use crate::services::mfa::{LoginResultMfa, MfaSetupResult};
use crate::services::session::SessionInfo;
use crate::services::{is_refresh_token_shape, new_uuid_v4, now_unix};
use crate::traits::WsTicketSnapshot;

/// The lifetime, in seconds, of a single-use WebSocket upgrade ticket (§7.3.6). Short enough
/// that a leaked upgrade URL exposes at most a seconds-long, already-consumable handshake.
pub const WS_TICKET_TTL_SECONDS: u64 = 30;

impl AuthEngine {
    /// Verify a **dashboard** access JWT for the HTTP boundary: HS256-pinned signature, the
    /// `type == "dashboard"` assertion (enforced structurally by the single-variant
    /// discriminator), temporal validity, and the `rv:{jti}` revocation check. Returns the
    /// verified [`DashboardClaims`].
    ///
    /// # Errors
    ///
    /// Returns the internal-only [`AuthError::TokenExpired`]/[`AuthError::TokenRevoked`] or
    /// the public [`AuthError::TokenInvalid`]; the adapter collapses all of them to
    /// `token_invalid` at the boundary so no expired-vs-revoked-vs-garbage oracle leaks.
    pub async fn verify_access_token(&self, token: &str) -> Result<DashboardClaims, AuthError> {
        self.tokens().verify_access(token).await
    }

    /// Verify a **platform** access JWT for the HTTP boundary: HS256-pinned signature, the
    /// `type == "platform"` assertion (a dashboard token fails to deserialize here),
    /// temporal validity, and the `rv:{jti}` revocation check.
    ///
    /// # Errors
    ///
    /// As [`AuthEngine::verify_access_token`], but a dashboard token presented here yields
    /// [`AuthError::TokenInvalid`]; the adapter maps that to `PlatformAuthRequired`.
    #[cfg(feature = "platform")]
    pub async fn verify_platform_token(&self, token: &str) -> Result<PlatformClaims, AuthError> {
        self.tokens().verify_platform_access(token).await
    }

    /// Whether a held dashboard role satisfies a required dashboard role under the configured
    /// hierarchy (a role satisfies itself or any role it transitively includes). Consults the
    /// dashboard hierarchy only, never the platform one.
    #[must_use]
    pub fn role_satisfies(&self, held_role: &str, required_role: &str) -> bool {
        self.config()
            .dashboard_role_satisfies(held_role, required_role)
    }

    /// Whether a held platform role satisfies a required platform role under the platform
    /// hierarchy. Returns `false` when no platform hierarchy is configured.
    #[cfg(feature = "platform")]
    #[must_use]
    pub fn platform_role_satisfies(&self, held_role: &str, required_role: &str) -> bool {
        self.config()
            .platform_role_satisfies(held_role, required_role)
    }

    /// The no-PII hashed identifier for a `(tenant_id, email)` pair — the same value that keys
    /// the brute-force counter and OTP records. Exposed so an integration test can locate the
    /// engine-generated OTP record by its key; it reveals no secret (the output is a one-way
    /// keyed HMAC of the low-entropy email).
    #[doc(hidden)]
    #[must_use]
    pub fn hashed_identifier_for(&self, tenant_id: &str, email: &str) -> String {
        self.hashed_identifier(tenant_id, email)
    }

    /// Assert the dashboard user identified by `sub` is not in a blocked status, fetching the
    /// current status from the user store and applying the same status gate the login path
    /// uses (`banned → AccountBanned`, etc.). A subject that no longer exists is treated as an
    /// invalid token (no enumeration oracle).
    ///
    /// # Errors
    ///
    /// Returns the status-specific [`AuthError`] (`AccountBanned`/`AccountInactive`/
    /// `AccountSuspended`/`PendingApproval`) for a blocked account, [`AuthError::TokenInvalid`]
    /// for an unknown subject, or a store [`AuthError`] on a repository failure.
    pub async fn assert_user_active(&self, sub: &str) -> Result<(), AuthError> {
        let user = self
            .user_repository()
            .find_by_id(sub, None)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::TokenInvalid)?;
        self.assert_user_not_blocked(&user.status)
    }

    /// List the caller's active sessions for the HTTP `GET /auth/sessions` route. The current
    /// session is flagged when the request carries the matching raw refresh token (cookie or
    /// body), whose hash is derived here; an absent/ malformed token simply leaves every
    /// session `is_current = false`.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] on an infrastructure failure.
    pub async fn list_user_sessions(
        &self,
        user_id: &str,
        raw_refresh: Option<&str>,
    ) -> Result<Vec<SessionInfo>, AuthError> {
        let current_hash = current_session_hash(raw_refresh);
        self.sessions()
            .list_sessions(user_id, current_hash.as_deref())
            .await
    }

    /// Revoke one of the caller's sessions by its full hash (`DELETE /auth/sessions/{id}`),
    /// ownership-checked. A malformed or unowned hash is [`AuthError::SessionNotFound`]
    /// (anti-IDOR; callers cannot distinguish a bad format from an absent session).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::SessionNotFound`] for a malformed/unowned hash, or a store
    /// [`AuthError`].
    pub async fn revoke_user_session(
        &self,
        user_id: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.sessions().revoke_session(user_id, session_hash).await
    }

    /// Revoke every session for the caller except the current one (`DELETE /auth/sessions/all`).
    /// The current session is identified by the request's raw refresh token; when none is
    /// present the caller's session cannot be excluded, so this is a no-op rather than wiping
    /// the live session out from under the request.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] on an infrastructure failure.
    pub async fn revoke_other_user_sessions(
        &self,
        user_id: &str,
        raw_refresh: Option<&str>,
    ) -> Result<(), AuthError> {
        match current_session_hash(raw_refresh) {
            Some(current) => {
                self.sessions()
                    .revoke_all_except_current(user_id, &current)
                    .await
            }
            // No identifiable current session: do not revoke the live request's own session.
            None => Ok(()),
        }
    }

    /// Mint a single-use WebSocket upgrade ticket (§7.3.6) from an already-verified dashboard
    /// session snapshot: the store generates an opaque CSPRNG ticket, persists the snapshot
    /// under `wst:{sha256(ticket)}` with a ~30 s TTL, and returns the raw ticket. The access
    /// token is never echoed into the ticket — only the verified identity snapshot is stored.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] when no WS-ticket store is wired, or a store
    /// [`AuthError`] on a persistence failure.
    pub async fn issue_ws_ticket(&self, claims: &DashboardClaims) -> Result<String, AuthError> {
        let store = self
            .ws_ticket_store()
            .ok_or_else(|| crate::services::internal_error("ws-ticket store not configured"))?;
        let snapshot = WsTicketSnapshot {
            sub: claims.sub.clone(),
            tenant_id: Some(claims.tenant_id.clone()),
            role: claims.role.clone(),
            status: claims.status.clone(),
            mfa_enabled: claims.mfa_enabled,
            mfa_verified: claims.mfa_verified,
        };
        store.mint(&snapshot, WS_TICKET_TTL_SECONDS).await
    }

    /// Redeem a single-use WebSocket upgrade ticket (§7.3.6): the store atomically `GETDEL`s
    /// `wst:{sha256(ticket)}`, so the first redemption wins and a captured URL cannot be
    /// replayed. On a hit the stored snapshot is reconstructed into [`DashboardClaims`] (an
    /// authorization snapshot for the socket's lifetime — never re-signed, no REST access).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] when no WS-ticket store is wired, [`AuthError::TokenInvalid`]
    /// for a missing/expired/already-redeemed ticket, or a store [`AuthError`].
    pub async fn redeem_ws_ticket(&self, ticket: &str) -> Result<DashboardClaims, AuthError> {
        let store = self
            .ws_ticket_store()
            .ok_or_else(|| crate::services::internal_error("ws-ticket store not configured"))?;
        let snapshot = store.redeem(ticket).await?.ok_or(AuthError::TokenInvalid)?;
        let now = now_unix();
        Ok(DashboardClaims {
            sub: snapshot.sub,
            jti: new_uuid_v4(),
            tenant_id: snapshot.tenant_id.unwrap_or_default(),
            role: snapshot.role,
            token_type: DashboardType::Dashboard,
            status: snapshot.status,
            mfa_enabled: snapshot.mfa_enabled,
            mfa_verified: snapshot.mfa_verified,
            iat: now,
            exp: now.saturating_add(i64::try_from(WS_TICKET_TTL_SECONDS).unwrap_or(i64::MAX)),
        })
    }

    // ---- MFA adapter surface (mfa feature) --------------------------------------------

    /// Begin MFA enrolment for a dashboard/platform user (`POST /auth/mfa/setup`). Returns
    /// [`AuthError::MfaNotEnabled`] when MFA is not configured for the deployment.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured, [`AuthError::MfaAlreadyEnabled`]
    /// when already enrolled, or a store/crypto [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn mfa_setup(
        &self,
        user_id: &str,
        ctx: MfaContext,
    ) -> Result<MfaSetupResult, AuthError> {
        self.mfa()
            .ok_or(AuthError::MfaNotEnabled)?
            .setup(user_id, ctx)
            .await
    }

    /// Confirm and enable MFA (`POST /auth/mfa/verify-enable`).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured, [`AuthError::MfaInvalidCode`]
    /// on a wrong code, or a store/crypto [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn mfa_verify_enable(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
    ) -> Result<(), AuthError> {
        self.mfa()
            .ok_or(AuthError::MfaNotEnabled)?
            .verify_and_enable(user_id, code, ip, user_agent, ctx)
            .await
    }

    /// Run the public MFA challenge (`POST /auth/mfa/challenge`), returning the dashboard or
    /// platform session per the temp token's context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured, [`AuthError::MfaTempTokenInvalid`]
    /// for a bad temp token, [`AuthError::MfaInvalidCode`] on a wrong code, or a store [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn mfa_challenge(
        &self,
        mfa_temp_token: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<LoginResultMfa, AuthError> {
        self.mfa()
            .ok_or(AuthError::MfaNotEnabled)?
            .challenge(mfa_temp_token, code, ip, user_agent)
            .await
    }

    /// Run the **platform** MFA challenge (`POST /auth/platform/mfa/challenge`): the temp
    /// token's `context: platform` discriminant routes it through the platform store. A
    /// dashboard-context result here is a mismatch surfaced as
    /// [`AuthError::MfaTempTokenInvalid`], so the adapter handler never sees the wrong arm.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured,
    /// [`AuthError::MfaTempTokenInvalid`] for a bad temp token or a dashboard-context result,
    /// [`AuthError::MfaInvalidCode`] on a wrong code, or a store [`AuthError`].
    #[cfg(all(feature = "mfa", feature = "platform"))]
    pub async fn platform_mfa_challenge(
        &self,
        mfa_temp_token: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<PlatformAuthResult, AuthError> {
        let result = self
            .mfa_challenge(mfa_temp_token, code, ip, user_agent)
            .await?;
        Self::mfa_result_platform(result).ok_or(AuthError::MfaTempTokenInvalid)
    }

    /// Run the **dashboard** MFA challenge (`POST /auth/mfa/challenge`): a platform-context
    /// result is a mismatch surfaced as [`AuthError::MfaTempTokenInvalid`], so the adapter
    /// handler never sees the wrong arm.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured,
    /// [`AuthError::MfaTempTokenInvalid`] for a bad temp token or a platform-context result,
    /// [`AuthError::MfaInvalidCode`] on a wrong code, or a store [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn dashboard_mfa_challenge(
        &self,
        mfa_temp_token: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<AuthResult, AuthError> {
        let result = self
            .mfa_challenge(mfa_temp_token, code, ip, user_agent)
            .await?;
        Self::mfa_result_dashboard(result).ok_or(AuthError::MfaTempTokenInvalid)
    }

    /// Disable MFA (`POST /auth/mfa/disable`), TOTP-gated.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured, [`AuthError::MfaInvalidCode`]
    /// on a wrong code, or a store [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn mfa_disable(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
    ) -> Result<(), AuthError> {
        self.mfa()
            .ok_or(AuthError::MfaNotEnabled)?
            .disable(user_id, code, ip, user_agent, ctx)
            .await
    }

    /// Regenerate the recovery-code set (`POST /auth/mfa/recovery-codes`), TOTP-gated.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] when MFA is not configured, [`AuthError::MfaInvalidCode`]
    /// on a wrong code, or a store [`AuthError`].
    #[cfg(feature = "mfa")]
    pub async fn mfa_regenerate_recovery_codes(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
    ) -> Result<Vec<String>, AuthError> {
        self.mfa()
            .ok_or(AuthError::MfaNotEnabled)?
            .regenerate_recovery_codes(user_id, code, ip, user_agent, ctx)
            .await
    }

    // ---- Platform adapter surface (platform feature) ----------------------------------

    /// Platform-admin login (`POST /auth/platform/login`).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PlatformAuthRequired`] when the platform domain is not enabled,
    /// [`AuthError::InvalidCredentials`] on a credential failure, or a store [`AuthError`].
    #[cfg(feature = "platform")]
    pub async fn platform_login(
        &self,
        email: &str,
        password: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<PlatformLoginResult, AuthError> {
        self.platform_auth()
            .ok_or(AuthError::PlatformAuthRequired)?
            .login(email, password, ip, user_agent)
            .await
    }

    /// The current platform admin (`GET /auth/platform/me`).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PlatformAuthRequired`] when the platform domain is not enabled,
    /// [`AuthError::TokenInvalid`] for an unknown subject, or a store [`AuthError`].
    #[cfg(feature = "platform")]
    pub async fn platform_me(&self, admin_id: &str) -> Result<SafeAuthPlatformUser, AuthError> {
        self.platform_auth()
            .ok_or(AuthError::PlatformAuthRequired)?
            .me(admin_id)
            .await
    }

    /// Rotate the platform token pair (`POST /auth/platform/refresh`).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PlatformAuthRequired`] when the platform domain is not enabled,
    /// [`AuthError::RefreshTokenInvalid`] for a stale token, or a store/signing [`AuthError`].
    #[cfg(feature = "platform")]
    pub async fn platform_refresh(
        &self,
        old_refresh: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<RotatedTokens, AuthError> {
        self.platform_auth()
            .ok_or(AuthError::PlatformAuthRequired)?
            .refresh(old_refresh, ip, user_agent)
            .await
    }

    /// Revoke the current platform session (`POST /auth/platform/logout`). Best-effort.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PlatformAuthRequired`] when the platform domain is not enabled.
    #[cfg(feature = "platform")]
    pub async fn platform_logout(
        &self,
        access_token: &str,
        raw_refresh: &str,
        admin_id: &str,
    ) -> Result<(), AuthError> {
        self.platform_auth()
            .ok_or(AuthError::PlatformAuthRequired)?
            .logout(access_token, raw_refresh, admin_id)
            .await
    }

    /// Revoke every platform session for the admin (`DELETE /auth/platform/sessions`).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PlatformAuthRequired`] when the platform domain is not enabled, or
    /// a store [`AuthError`].
    #[cfg(feature = "platform")]
    pub async fn platform_revoke_all(&self, admin_id: &str) -> Result<(), AuthError> {
        self.platform_auth()
            .ok_or(AuthError::PlatformAuthRequired)?
            .revoke_all_platform_sessions(admin_id)
            .await
    }
}

/// Helper used by the adapter to discriminate an MFA challenge result into the dashboard /
/// platform arms without naming the `pub(crate)` types. Kept here so the adapter never matches
/// the engine's internal enum directly.
#[cfg(feature = "mfa")]
impl AuthEngine {
    /// Extract a dashboard [`AuthResult`] from an MFA challenge outcome, or `None` for a
    /// platform outcome (a context mismatch the adapter renders as an invalid temp token).
    #[must_use]
    pub fn mfa_result_dashboard(result: LoginResultMfa) -> Option<AuthResult> {
        match result {
            LoginResultMfa::Dashboard(auth) => Some(auth),
            #[cfg(feature = "platform")]
            LoginResultMfa::Platform(_) => None,
        }
    }

    /// Extract a platform [`PlatformAuthResult`] from an MFA challenge outcome, or `None` for a
    /// dashboard outcome.
    #[cfg(feature = "platform")]
    #[must_use]
    pub fn mfa_result_platform(result: LoginResultMfa) -> Option<PlatformAuthResult> {
        match result {
            LoginResultMfa::Platform(auth) => Some(auth),
            LoginResultMfa::Dashboard(_) => None,
        }
    }
}

/// Derive the current session hash from a presented raw refresh token, when it is present
/// and has the expected shape. Returns `None` for an absent or malformed token, so the
/// session surfaces degrade safely (no `is_current` flag, no current-exclusion on revoke-all)
/// rather than acting on a bogus hash.
fn current_session_hash(raw_refresh: Option<&str>) -> Option<String> {
    let raw = raw_refresh?;
    if !is_refresh_token_shape(raw) {
        return None;
    }
    Some(RawRefreshToken::from_raw(raw.to_owned()).redis_hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{base_config, harness};

    /// `current_session_hash` returns `None` for an absent/malformed token and a 64-hex hash
    /// for a well-shaped one.
    #[test]
    fn current_session_hash_only_accepts_a_well_shaped_token() {
        assert!(current_session_hash(None).is_none());
        assert!(current_session_hash(Some("not-64-hex")).is_none());
        let shaped = "a".repeat(64);
        assert!(current_session_hash(Some(&shaped)).is_some());
    }

    /// The synchronous authorization helpers delegate to the configured hierarchies and the
    /// keyed-HMAC identifier: a role satisfies itself, an unknown required role is not
    /// satisfied, and the hashed identifier is a stable, non-PII 64-hex digest.
    #[tokio::test]
    async fn authorization_helpers_delegate_to_the_configured_engine() {
        let Some(h) = harness(base_config(), None) else { return };
        assert!(h.engine.role_satisfies("USER", "USER"));
        assert!(!h.engine.role_satisfies("USER", "ADMIN"));
        #[cfg(feature = "platform")]
        {
            // No platform hierarchy is configured in the base fixture, so nothing is satisfied.
            assert!(!h.engine.platform_role_satisfies("SUPER_ADMIN", "SUPPORT"));
        }
        let digest = h.engine.hashed_identifier_for("t1", "a@e.com");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!digest.contains("a@e.com"));
    }

    /// The verify/status/session delegation surface, driven end-to-end against a freshly
    /// registered account: the issued access token verifies, the active account passes the
    /// status gate, the session lists with the current one flagged via the refresh token, the
    /// non-current sessions are wiped on the real current hash, and a malformed session hash
    /// revokes as not-found (anti-IDOR).
    #[tokio::test]
    async fn verify_status_and_session_delegations_run_against_a_real_session() {
        use crate::context::RequestContext;
        use crate::services::auth::RegisterInput;
        use bymax_auth_types::LoginResult;

        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let ctx = RequestContext::new(
            "203.0.113.4",
            "agent/1.0",
            std::collections::BTreeMap::new(),
        );
        let result = h
            .engine
            .register(
                RegisterInput {
                    email: "adapter@e.com".to_owned(),
                    name: "Adapter".to_owned(),
                    password: "correct horse battery staple".to_owned(),
                    tenant_id: "t1".to_owned(),
                },
                &ctx,
            )
            .await;
        assert!(matches!(&result, Ok(LoginResult::Success(_))));
        let Ok(LoginResult::Success(auth)) = result else { return };
        let sub = auth.user.id.clone();

        // The freshly issued access token verifies to the same subject.
        let verified = h.engine.verify_access_token(&auth.access_token).await;
        assert!(matches!(verified, Ok(claims) if claims.sub == sub));

        // An active account passes the status gate; a garbage token fails verification.
        assert!(h.engine.assert_user_active(&sub).await.is_ok());
        assert!(matches!(
            h.engine.verify_access_token("not-a-jwt").await,
            Err(AuthError::TokenInvalid)
        ));

        // The session lists, with the current session flagged via the presented refresh token.
        let sessions = h
            .engine
            .list_user_sessions(&sub, Some(&auth.refresh_token))
            .await;
        assert!(matches!(&sessions, Ok(list) if list.iter().any(|s| s.is_current)));

        // Revoking all-but-current with the real refresh token takes the current-hash branch.
        assert!(
            h.engine
                .revoke_other_user_sessions(&sub, Some(&auth.refresh_token))
                .await
                .is_ok()
        );

        // A malformed/unowned session hash revokes as not-found (no IDOR oracle).
        assert!(matches!(
            h.engine.revoke_user_session(&sub, "not-a-hash").await,
            Err(AuthError::SessionNotFound)
        ));
    }

    /// `revoke_other_user_sessions` with no identifiable current session (absent/malformed
    /// refresh token) is a no-op `Ok(())` — it never wipes the live request's own session.
    #[tokio::test]
    async fn revoke_other_user_sessions_without_a_current_hash_is_a_noop() {
        let Some(h) = harness(base_config(), None) else { return };
        assert!(h.engine.revoke_other_user_sessions("u", None).await.is_ok());
        assert!(
            h.engine
                .revoke_other_user_sessions("u", Some("not-shaped"))
                .await
                .is_ok()
        );
    }

    /// A sample set of dashboard claims for the ticket surfaces.
    fn sample_claims() -> DashboardClaims {
        DashboardClaims {
            sub: "u".to_owned(),
            jti: new_uuid_v4(),
            tenant_id: "t1".to_owned(),
            role: "USER".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: now_unix(),
            exp: now_unix(),
        }
    }

    /// With a WS-ticket store wired, `issue_ws_ticket` mints an opaque ticket and
    /// `redeem_ws_ticket` reconstructs the same identity snapshot once; a second redemption of
    /// the consumed ticket, and a bogus ticket, both refuse with `token_invalid`.
    #[tokio::test]
    async fn ws_ticket_mints_and_redeems_once_then_refuses_replay() {
        let Some(h) = harness(base_config(), None) else { return };
        assert!(h.engine.ws_ticket_store().is_some());
        let claims = sample_claims();

        let minted = h.engine.issue_ws_ticket(&claims).await;
        assert!(minted.is_ok());
        let Ok(ticket) = minted else { return };

        let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
        assert!(matches!(redeemed, Ok(c) if c.sub == "u" && c.role == "USER"));

        // The single-use ticket is consumed: a replay and a never-minted ticket both refuse.
        assert!(matches!(
            h.engine.redeem_ws_ticket(&ticket).await,
            Err(AuthError::TokenInvalid)
        ));
        assert!(matches!(
            h.engine.redeem_ws_ticket("never-minted").await,
            Err(AuthError::TokenInvalid)
        ));
    }

    /// A WS-ticket store whose backend always fails, to exercise the store-error propagation
    /// arms of `issue_ws_ticket` (after the store is present) and `redeem_ws_ticket` (distinct
    /// from the `Ok(None)` not-found arm).
    struct FailingTicketStore;

    #[async_trait::async_trait]
    impl crate::traits::WsTicketStore for FailingTicketStore {
        async fn mint(
            &self,
            _snapshot: &WsTicketSnapshot,
            _ttl_secs: u64,
        ) -> Result<String, AuthError> {
            Err(crate::services::internal_error(
                "ws-ticket backend unavailable",
            ))
        }
        async fn redeem(&self, _ticket: &str) -> Result<Option<WsTicketSnapshot>, AuthError> {
            Err(crate::services::internal_error(
                "ws-ticket backend unavailable",
            ))
        }
    }

    /// Both ticket surfaces propagate a backend failure from a present store as-is — the
    /// store-error arms, separate from the not-found (`Ok(None)`) and absent-store arms.
    #[tokio::test]
    async fn ws_ticket_surfaces_propagate_a_store_backend_failure() {
        use crate::config::Environment;
        use crate::testing::{InMemoryStores, InMemoryUserRepository};
        use std::sync::Arc;

        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let built = AuthEngine::builder()
            .config(base_config())
            .environment(Environment::Test)
            .user_repository(users)
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores)
            .ws_ticket_store(Arc::new(FailingTicketStore))
            .build();
        assert!(built.is_ok());
        let Ok(engine) = built else { return };
        assert!(matches!(
            engine.issue_ws_ticket(&sample_claims()).await,
            Err(AuthError::Internal(_))
        ));
        assert!(matches!(
            engine.redeem_ws_ticket("any-ticket").await,
            Err(AuthError::Internal(_))
        ));
    }

    /// With no WS-ticket store wired (the store is optional on the builder), both ticket
    /// surfaces collapse to the internal error — the otherwise-unreachable store-absent arm,
    /// since a router that mounts the WS endpoints is always assembled with the store.
    #[tokio::test]
    async fn ws_ticket_surfaces_report_internal_when_no_store_is_wired() {
        use crate::config::Environment;
        use crate::testing::{InMemoryStores, InMemoryUserRepository};
        use std::sync::Arc;

        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        // Wire only the three required store seams; deliberately omit `ws_ticket_store` so the
        // engine assembles without one and the adapter ticket methods hit the absent arm.
        let built = AuthEngine::builder()
            .config(base_config())
            .environment(Environment::Test)
            .user_repository(users)
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores)
            .build();
        assert!(built.is_ok());
        let Ok(engine) = built else { return };
        assert!(engine.ws_ticket_store().is_none());

        let claims = sample_claims();
        assert!(matches!(
            engine.issue_ws_ticket(&claims).await,
            Err(AuthError::Internal(_))
        ));
        assert!(matches!(
            engine.redeem_ws_ticket("any-ticket").await,
            Err(AuthError::Internal(_))
        ));
    }

    /// With MFA not configured, the MFA adapter methods all return `MfaNotEnabled` — the
    /// otherwise-unreachable service-absent arm (the router never mounts the MFA group without
    /// MFA config, so this is the only path that exercises it).
    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn mfa_methods_report_not_enabled_when_mfa_is_absent() {
        use bymax_auth_types::MfaContext;
        let Some(h) = harness(base_config(), None) else { return };
        assert!(matches!(
            h.engine.mfa_setup("u", MfaContext::Dashboard).await,
            Err(AuthError::MfaNotEnabled)
        ));
        assert!(matches!(
            h.engine
                .mfa_verify_enable("u", "000000", "ip", "ua", MfaContext::Dashboard)
                .await,
            Err(AuthError::MfaNotEnabled)
        ));
        assert!(matches!(
            h.engine.mfa_challenge("t", "000000", "ip", "ua").await,
            Err(AuthError::MfaNotEnabled)
        ));
        assert!(matches!(
            h.engine
                .mfa_disable("u", "000000", "ip", "ua", MfaContext::Dashboard)
                .await,
            Err(AuthError::MfaNotEnabled)
        ));
        assert!(matches!(
            h.engine
                .mfa_regenerate_recovery_codes("u", "000000", "ip", "ua", MfaContext::Dashboard)
                .await,
            Err(AuthError::MfaNotEnabled)
        ));
    }

    /// With the platform domain not enabled, the platform adapter methods return
    /// `PlatformAuthRequired` — the otherwise-unreachable service-absent arm.
    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn platform_methods_report_auth_required_when_platform_is_absent() {
        let Some(h) = harness(base_config(), None) else { return };
        assert!(matches!(
            h.engine.platform_login("a@e.com", "pw", "ip", "ua").await,
            Err(AuthError::PlatformAuthRequired)
        ));
        assert!(matches!(
            h.engine.platform_me("a").await,
            Err(AuthError::PlatformAuthRequired)
        ));
        assert!(matches!(
            h.engine.platform_refresh("r", "ip", "ua").await,
            Err(AuthError::PlatformAuthRequired)
        ));
        assert!(matches!(
            h.engine.platform_logout("t", "r", "a").await,
            Err(AuthError::PlatformAuthRequired)
        ));
        assert!(matches!(
            h.engine.platform_revoke_all("a").await,
            Err(AuthError::PlatformAuthRequired)
        ));
    }

    /// The MFA-result discriminators return the matching arm and `None` on the cross-context
    /// mismatch (a platform result asked for as dashboard, and vice versa).
    #[cfg(all(feature = "mfa", feature = "platform"))]
    #[test]
    fn mfa_result_discriminators_split_by_context() {
        use crate::services::mfa::LoginResultMfa;
        use bymax_auth_types::{
            AuthPlatformUser, AuthResult, AuthUser, PlatformAuthResult, SafeAuthPlatformUser,
            SafeAuthUser,
        };
        use time::OffsetDateTime;

        fn safe_user() -> SafeAuthUser {
            SafeAuthUser::from(AuthUser {
                id: "u".to_owned(),
                email: "u@e.com".to_owned(),
                name: "U".to_owned(),
                password_hash: None,
                role: "USER".to_owned(),
                status: "ACTIVE".to_owned(),
                tenant_id: "t1".to_owned(),
                email_verified: true,
                mfa_enabled: false,
                mfa_secret: None,
                mfa_recovery_codes: None,
                oauth_provider: None,
                oauth_provider_id: None,
                last_login_at: None,
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
        }
        fn safe_admin() -> SafeAuthPlatformUser {
            SafeAuthPlatformUser::from(AuthPlatformUser {
                id: "a".to_owned(),
                email: "a@e.com".to_owned(),
                name: "A".to_owned(),
                password_hash: "ph".to_owned(),
                role: "SUPER_ADMIN".to_owned(),
                status: "ACTIVE".to_owned(),
                mfa_enabled: false,
                mfa_secret: None,
                mfa_recovery_codes: None,
                platform_id: None,
                last_login_at: None,
                updated_at: OffsetDateTime::UNIX_EPOCH,
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
        }
        fn auth() -> AuthResult {
            AuthResult {
                user: safe_user(),
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
            }
        }
        fn platform() -> PlatformAuthResult {
            PlatformAuthResult {
                user: safe_admin(),
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
            }
        }

        assert!(AuthEngine::mfa_result_dashboard(LoginResultMfa::Dashboard(auth())).is_some());
        // Asking for the dashboard arm on a platform result yields `None` (mismatch).
        assert!(AuthEngine::mfa_result_dashboard(LoginResultMfa::Platform(platform())).is_none());
        assert!(AuthEngine::mfa_result_platform(LoginResultMfa::Platform(platform())).is_some());
        assert!(AuthEngine::mfa_result_platform(LoginResultMfa::Dashboard(auth())).is_none());
    }
}
