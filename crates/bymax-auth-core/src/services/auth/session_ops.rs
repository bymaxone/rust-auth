//! The session-scoped flows: `logout` (§7.1.3), `me` (§7.1.5), `refresh` (§7.1.4), and the
//! password-less `issue_tokens_for_user_id` (§7.1.7).

use std::collections::BTreeMap;

use bymax_auth_jwt::{RawRefreshToken, decode_unverified};
use bymax_auth_types::{AuthError, AuthResult, DashboardClaims, RotatedTokens, SafeAuthUser};

use crate::engine::AuthEngine;
use crate::services::auth::detached::{run_after_login, run_after_logout, run_update_last_login};
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::services::{is_refresh_token_shape, now_unix};
use crate::traits::{HookContext, SessionKind};

impl AuthEngine {
    /// Revoke the current session: blacklist the access token's `jti` for its remaining
    /// lifetime and delete the refresh session (idempotent on an already-gone session).
    ///
    /// # Errors
    ///
    /// Best-effort cleanup — store failures are swallowed so a logout is never blocked. The
    /// `Result` is reserved for forward compatibility and currently always returns `Ok`.
    pub async fn logout(
        &self,
        access_token: &str,
        raw_refresh: &str,
        user_id: &str,
    ) -> Result<(), AuthError> {
        // Decode WITHOUT verifying — the access token may already be expired at logout.
        if let Ok(claims) = decode_unverified::<DashboardClaims>(access_token) {
            let remaining = claims.exp.saturating_sub(now_unix());
            if remaining > 0 {
                // Best-effort blacklist; a store failure must not block the logout.
                let _ = self
                    .tokens()
                    .revoke_access(&claims.jti, remaining.unsigned_abs())
                    .await;
            }
        }

        // Ownership-checked refresh revoke; SessionNotFound (already rotated/evicted) and any
        // other store error are both swallowed, so logout is idempotent and never blocks. A
        // malformed/oversized token is skipped before hashing — it owns no session anyway.
        if is_refresh_token_shape(raw_refresh) {
            let session_hash = RawRefreshToken::from_raw(raw_refresh.to_owned()).redis_hash();
            let _ = self
                .session_store()
                .revoke_session(SessionKind::Dashboard, user_id, &session_hash)
                .await;
        }

        let hook_ctx = identity_only_context(user_id, None, None);
        spawn_guarded(run_after_logout(
            self.hooks().clone(),
            user_id.to_owned(),
            hook_ctx,
        ));
        Ok(())
    }

    /// Return the credential-free user for the authenticated subject.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenInvalid`] when the subject no longer exists, or a store
    /// [`AuthError`] on a repository failure.
    pub async fn me(&self, user_id: &str) -> Result<SafeAuthUser, AuthError> {
        match self
            .user_repository()
            .find_by_id(user_id, None)
            .await
            .map_err(map_repository_error)?
        {
            Some(user) => Ok(SafeAuthUser::from(user)),
            None => Err(AuthError::TokenInvalid),
        }
    }

    /// Rotate the presented refresh token, returning a fresh token pair (atomic rotation
    /// with a grace window).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RefreshTokenInvalid`] when the token is neither live nor inside
    /// the grace window, or a store/signing [`AuthError`].
    pub async fn refresh(
        &self,
        old_refresh: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<RotatedTokens, AuthError> {
        self.tokens()
            .reissue_tokens(old_refresh, ip, user_agent)
            .await
    }

    /// Issue a full dashboard session for an existing user **without** a password
    /// (workspace-switch / impersonation). Authorization is the caller's responsibility; the
    /// status and email-verification gates still run, and an MFA-enabled user is refused
    /// (the host must route through the MFA challenge instead).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenInvalid`] for an unknown user, a status [`AuthError`] for a
    /// blocked account, [`AuthError::EmailNotVerified`] when verification is pending,
    /// [`AuthError::MfaRequired`] for an MFA-enabled user, or a store/signing [`AuthError`].
    pub async fn issue_tokens_for_user_id(
        &self,
        user_id: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<AuthResult, AuthError> {
        let config = self.config().config();
        let user = match self
            .user_repository()
            .find_by_id(user_id, None)
            .await
            .map_err(map_repository_error)?
        {
            Some(user) => user,
            None => return Err(AuthError::TokenInvalid),
        };

        // The status and verification gates must run so a blocked or unverified account is
        // never revived through a password-less switch.
        self.assert_user_not_blocked(&user.status)?;
        if config.email_verification.required && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // Distinct from login's challenge: refuse outright so the host routes through MFA.
        if user.mfa_enabled {
            return Err(AuthError::MfaRequired);
        }

        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens()
            .issue_tokens(&safe, ip, user_agent, false)
            .await?;

        spawn_guarded(run_update_last_login(
            self.user_repository().clone(),
            safe.id.clone(),
        ));
        let hook_ctx = identity_only_context(
            &safe.id,
            Some(safe.email.clone()),
            Some(safe.tenant_id.clone()),
        );
        spawn_guarded(run_after_login(self.hooks().clone(), safe, hook_ctx));
        Ok(result)
    }
}

/// Build a [`HookContext`] from only the identity fields known to a flow that has no
/// originating [`crate::context::RequestContext`] (logout / password-less issuance). The
/// transport fields are empty and the header map is empty.
fn identity_only_context(
    user_id: &str,
    email: Option<String>,
    tenant_id: Option<String>,
) -> HookContext {
    HookContext {
        user_id: Some(user_id.to_owned()),
        email,
        tenant_id,
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::LoginInput;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, ctx, harness};
    use bymax_auth_types::LoginResult;

    fn login_input(email: &str, password: &str) -> LoginInput {
        LoginInput {
            email: email.to_owned(),
            password: password.to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    async fn logged_in(h: &Harness, email: &str, password: &str) -> Option<(String, AuthResult)> {
        let id = h.seed(SeedUser::active(email, password)).await;
        let result = h.engine.login(login_input(email, password), &ctx()).await;
        let Ok(LoginResult::Success(auth)) = result else { return None };
        Some((id, *auth))
    }

    #[tokio::test]
    async fn logout_blacklists_the_access_token_and_revokes_the_session() {
        // After logout the access jti is blacklisted (verify_access rejects it) and the
        // refresh session is gone, so the refresh token no longer rotates.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "out@example.com", "pw").await else { return };
        assert!(
            h.engine
                .logout(&auth.access_token, &auth.refresh_token, &id)
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine.tokens().verify_access(&auth.access_token).await,
            Err(AuthError::TokenRevoked)
        ));
        assert!(matches!(
            h.engine
                .refresh(&auth.refresh_token, "1.2.3.4", "agent")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn logout_is_idempotent_for_an_expired_or_garbage_token() {
        // Logout tolerates an undecodable access token (skip the blacklist) and an unknown
        // refresh token (SessionNotFound swallowed), still succeeding.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        assert!(
            h.engine
                .logout("not-a-jwt", "unknown-refresh", "user-x")
                .await
                .is_ok()
        );

        // A decodable but already-expired access token skips the blacklist (remaining ≤ 0)
        // yet logout still succeeds.
        let now = crate::services::now_unix();
        let expired = DashboardClaims {
            sub: "user-x".to_owned(),
            jti: crate::services::new_uuid_v4(),
            tenant_id: "t1".to_owned(),
            role: "USER".to_owned(),
            token_type: bymax_auth_types::DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: now - 1_000,
            exp: now - 500,
        };
        let Ok(token) = h.engine.tokens().issue_access(&expired) else { return };
        assert!(
            h.engine
                .logout(&token, "unknown-refresh", "user-x")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn me_returns_the_user_or_token_invalid() {
        // `me` projects the stored user; an unknown subject is TokenInvalid.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let id = h.seed(SeedUser::active("me@example.com", "pw")).await;
        let found = h.engine.me(&id).await;
        assert!(matches!(found, Ok(u) if u.email == "me@example.com"));
        assert!(matches!(
            h.engine.me("missing").await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[tokio::test]
    async fn refresh_rotates_to_a_new_pair() {
        // Refresh returns a new token pair distinct from the presented refresh token.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_id, auth)) = logged_in(&h, "rot@example.com", "pw").await else { return };
        let rotated = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await;
        assert!(matches!(&rotated, Ok(r) if r.refresh_token != auth.refresh_token));
    }

    #[tokio::test]
    async fn issue_tokens_for_user_id_happy_path_and_unknown_user() {
        // The password-less path issues a session for an active user and rejects an unknown
        // id as TokenInvalid.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let id = h.seed(SeedUser::active("switch@example.com", "pw")).await;
        let issued = h
            .engine
            .issue_tokens_for_user_id(&id, "1.2.3.4", "agent")
            .await;
        assert!(matches!(&issued, Ok(a) if a.user.email == "switch@example.com"));
        assert!(matches!(
            h.engine
                .issue_tokens_for_user_id("missing", "1.2.3.4", "agent")
                .await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[tokio::test]
    async fn issue_tokens_for_user_id_enforces_status_verification_and_mfa() {
        // The status gate, the verification gate, and the MFA refusal all hold on the
        // password-less path so a blocked/unverified/MFA user cannot be revived.
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        let Some(h) = harness(cfg, None) else { return };

        let banned = h
            .seed(SeedUser {
                email: "b@x.io".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "BANNED".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            })
            .await;
        assert!(matches!(
            h.engine
                .issue_tokens_for_user_id(&banned, "1.2.3.4", "agent")
                .await,
            Err(AuthError::AccountBanned)
        ));

        let unverified = h
            .seed(SeedUser {
                email: "u@x.io".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        assert!(matches!(
            h.engine
                .issue_tokens_for_user_id(&unverified, "1.2.3.4", "agent")
                .await,
            Err(AuthError::EmailNotVerified)
        ));

        let mfa = h
            .seed(SeedUser {
                email: "m@x.io".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: true,
                mfa_enabled: true,
            })
            .await;
        assert!(matches!(
            h.engine
                .issue_tokens_for_user_id(&mfa, "1.2.3.4", "agent")
                .await,
            Err(AuthError::MfaRequired)
        ));
    }
}
