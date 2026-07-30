//! The session-scoped flows: `logout` (§7.1.3), `me` (§7.1.5), `refresh` (§7.1.4), and the
//! password-less `issue_tokens_for_user_id` (§7.1.7).

use std::collections::BTreeMap;

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, AuthResult, RotatedTokens, SafeAuthUser};

use crate::context::to_safe_user;
use crate::engine::AuthEngine;
use crate::services::auth::detached::{run_after_login, run_after_logout, run_update_last_login};
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::services::{is_refresh_token_shape, now_unix};
use crate::traits::{HookContext, SessionKind};

/// What a **dashboard** refresh returns: the rotated tokens plus the account behind them.
///
/// Rotation itself works entirely from the store record, so the repository read this carries is
/// what lets the status and email-verification gates apply on refresh at all. Without them a
/// suspended account renews its access token for the refresh token's whole lifetime — the login
/// door a ban closes is one a signed-in user never needs to open again (ASVS v5 §7.4.2) — and
/// an address that was never proven holds a session indefinitely. The user is returned rather
/// than discarded so the adapter does not verify the token and read the repository a second
/// time to build the response body. `nest-auth` returns the same shape.
pub struct RefreshedSession {
    /// The freshly minted access + refresh pair.
    pub tokens: RotatedTokens,
    /// The account behind the rotated session, re-read and re-checked during the rotation.
    pub user: SafeAuthUser,
}

impl AuthEngine {
    /// Revoke the current session: blacklist the access token's `jti` for its remaining
    /// lifetime — only when the token's signature verifies — and delete the refresh session
    /// (idempotent on an already-gone session).
    ///
    /// The caller is **not** required to hold a live access token. The common case is a user
    /// returning after their access token expired and signing out: refusing that leaves the
    /// refresh session — the long-lived credential logout exists to kill — alive for its whole
    /// lifetime, on a device the user just told the system to sign out. The refresh token is
    /// what authorizes this operation, and the session's owner is read from the stored record
    /// rather than taken from the caller, so an absent or forged access token cannot aim the
    /// revocation at somebody else's session.
    ///
    /// Expiry is waived when verifying the access token, but the signature is not: the `jti`
    /// decides which token gets blacklisted, so an unverified one would let a caller revoke a
    /// token they do not own by naming its id.
    ///
    /// # Errors
    ///
    /// Best-effort cleanup — store failures are swallowed so a logout is never blocked. The
    /// `Result` is reserved for forward compatibility and currently always returns `Ok`.
    pub async fn logout(&self, access_token: &str, raw_refresh: &str) -> Result<(), AuthError> {
        // The stored session names its owner. Presenting the refresh token proves possession;
        // the record proves whose it is. An access token's claims cannot serve that purpose
        // when the token is allowed to be absent.
        let session_hash = is_refresh_token_shape(raw_refresh)
            .then(|| RawRefreshToken::from_raw(raw_refresh.to_owned()).redis_hash());
        let user_id = match &session_hash {
            Some(hash) => self
                .session_store()
                .find_session(SessionKind::Dashboard, hash)
                .await
                .ok()
                .flatten()
                .map(|record| record.user_id)
                .unwrap_or_default(),
            None => String::new(),
        };
        let user_id = user_id.as_str();

        if let Ok(claims) = self.tokens().verify_access_ignoring_expiry(access_token) {
            // Blacklist for the token's residual lifetime only. `try_from` clamps to `0` if
            // the token lapsed in the window between `verify_access` and this clock read, so a
            // stale token can never be handed a positive (extended) TTL. Best-effort — a store
            // failure (including a store that rejects a zero TTL for an already-expiring token)
            // must not block the logout.
            let ttl = u64::try_from(claims.exp.saturating_sub(now_unix())).unwrap_or(0);
            let _ = self.tokens().revoke_access(&claims.jti, ttl).await;
        }

        // Clean BOTH the primary and grace refresh keys for the presented token. The
        // ownership-checked revoke deletes the primary `rt:`/`sd:` keys and the `sess:`
        // membership; the grace-pointer delete then removes any `rp:` recovery pointer for this
        // hash, so a token logged out inside its grace window cannot still rotate into a fresh
        // session. Both are best-effort: `SessionNotFound` (already rotated/evicted) and any
        // other store error are swallowed, so logout is idempotent and never blocks. A
        // malformed/oversized token is skipped before hashing — it owns no session anyway.
        if let Some(session_hash) = &session_hash {
            if let Err(error) = self
                .session_store()
                .revoke_session(SessionKind::Dashboard, user_id, session_hash)
                .await
            {
                // Swallowed by design, but not silently: an operator seeing repeated cleanup
                // failures is looking at sessions that outlive the logout that asked for them.
                // `SessionNotFound` is the expected outcome for a session already rotated or
                // evicted, so it is not worth an operator's attention — the same distinction
                // nest-auth draws before logging.
                if !matches!(error, AuthError::SessionNotFound) {
                    tracing::warn!(%error, "logout: session cleanup failed");
                }
            }
            if let Err(error) = self
                .session_store()
                .delete_grace_pointer(SessionKind::Dashboard, session_hash)
                .await
            {
                tracing::warn!(%error, "logout: grace pointer cleanup failed");
            }
        }

        tracing::info!(%user_id, "logout: session closed");
        // The hook names the user who was signed out, so it only fires when the session told
        // us who that was. A logout for an already-gone session has nobody to name.
        if !user_id.is_empty() {
            let hook_ctx = identity_only_context(user_id, None, None);
            spawn_guarded(run_after_logout(
                self.hooks().clone(),
                user_id.to_owned(),
                hook_ctx,
            ));
        }
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
    ) -> Result<RefreshedSession, AuthError> {
        let rotated = self
            .tokens()
            .reissue_tokens(old_refresh, ip, user_agent)
            .await?;

        // The owner: read from the token we just minted, which is the only place it is
        // available on both the live and the grace path. The adapter verified this same token
        // to build its response body, so the work is moved rather than added.
        let claims = self.tokens().verify_access(&rotated.access_token).await?;
        let user_id = claims.sub;

        // Re-read the account and re-apply the two gates `login` applies. Rotation works
        // entirely from the store record, so nothing else on this path ever looks at the user
        // again — and rotation is the door a signed-in caller actually uses. Without this, two
        // things hold in the default configuration: a banned account renews its access token
        // for the refresh token's whole lifetime, because the ban closes only the login door
        // (ASVS v5 §7.4.2 requires disabling an account to terminate its sessions); and an
        // address that was never verified holds a session indefinitely, because `register`
        // issues one deliberately and only `login` ever checked.
        //
        // The check runs AFTER rotation because that is the only point where the owner is known
        // on both the live and the grace path. The compensation is deliberately total: every
        // session the account holds is revoked, including the one just minted, and the epoch
        // bump kills the access token issued a moment ago.
        let user = match self
            .user_repository()
            .find_by_id(&user_id, None)
            .await
            .map_err(map_repository_error)?
        {
            Some(user) => user,
            None => {
                // The account is gone and the session record outlived it. End it rather than
                // hand back a token for a user nobody can look up.
                self.revoke_all_sessions(&user_id).await?;
                return Err(AuthError::TokenInvalid);
            }
        };
        if let Err(error) = self.assert_user_not_blocked(&user.status) {
            self.revoke_all_sessions(&user_id).await?;
            return Err(error);
        }
        // Refused, but NOT compensated. An unproven address is an unfinished onboarding, not a
        // denied account: the refusal alone bounds the window to one access-token lifetime,
        // which is exactly what the specification promises. Revoking everything here would
        // also kill the token the consumer is using to render its "check your inbox" screen,
        // breaking the flow that issued it.
        if self.config().config().email_verification.required && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        Ok(RefreshedSession {
            tokens: rotated,
            user: to_safe_user(&user),
        })
    }

    /// End every dashboard session for one account, and kill the access tokens already issued.
    ///
    /// The dashboard twin of [`AuthEngine::platform_revoke_all`]. It exists because a
    /// library cannot see the moment a host suspends, bans, or deletes an account — the user
    /// record is the host's — and until the host says so, that account's live sessions keep
    /// working. ASVS v5 §7.4.2 requires that moment to terminate them, so the host needs a
    /// supported way to say it; `revoke_all_except_current` cannot serve, because it wants the
    /// hash of a session to keep and an administrator banning somebody else has none.
    ///
    /// The epoch is bumped after the sweep, not before: a failure in the sweep then leaves the
    /// operation visibly incomplete rather than reading as done while the sessions live on.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] when the sweep or the epoch bump fails.
    pub async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        self.session_store()
            .revoke_all(SessionKind::Dashboard, user_id)
            .await?;
        self.session_store()
            .bump_epoch(SessionKind::Dashboard, user_id)
            .await?;
        Ok(())
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

        let hook_ctx = identity_only_context(
            &safe.id,
            Some(safe.email.clone()),
            Some(safe.tenant_id.clone()),
        );
        // Enforce the concurrent-session cap (and fire the new-session hook) for the
        // password-less session; a no-op when session tracking is disabled.
        self.enforce_sessions_after_issue(&result, ip, user_agent, &hook_ctx)
            .await?;

        spawn_guarded(run_update_last_login(
            self.user_repository().clone(),
            safe.id.clone(),
        ));
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
    use crate::traits::{SessionRecord, SessionStore as _, UserRepository as _};
    use bymax_auth_types::{DashboardClaims, LoginResult};
    use time::OffsetDateTime;

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
    async fn refresh_refuses_and_revokes_everything_for_an_account_blocked_after_login() {
        // A ban has to end an existing session, not merely refuse the next login — a door a
        // signed-in user never needs to open again. Rotation works entirely from the store
        // record, so without a re-read a suspended account renews its access token for the
        // refresh token's whole lifetime (ASVS v5 §7.4.2).
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "banned@e.com", "pw123456").await else { return };

        // The operator bans the account through their own admin surface.
        assert!(h.users.update_status(&id, "BANNED").await.is_ok());

        let refused = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await;
        assert!(matches!(refused, Err(AuthError::AccountBanned)));

        // Total compensation: the session just minted goes with every other one the account
        // holds, so a second attempt has nothing left to rotate.
        let again = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await;
        assert!(
            matches!(again, Err(AuthError::RefreshTokenInvalid)),
            "unexpected ok"
        );
    }

    #[tokio::test]
    async fn refresh_refuses_when_the_account_no_longer_exists() {
        // The session record outlived the account. Hand back nothing, and clear the orphan
        // rather than leaving it to be rotated again.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "gone@e.com", "walnut42x").await else { return };

        h.users.remove(&id);

        let refused = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await;
        assert!(matches!(refused, Err(AuthError::TokenInvalid)));
    }

    #[tokio::test]
    async fn refresh_refuses_an_unverified_address_without_revoking_the_session() {
        // `register` issues a full session deliberately — a consumer needs one to render the
        // "check your inbox" screen — and the specification bounds that window at one
        // access-token lifetime. Rotation is what un-bounded it: the gate lived only on
        // `login`, a door the caller never has to open again once register handed them a
        // refresh token. The refusal alone restores the bound; revoking everything would also
        // kill the token rendering that very screen, so this path is refused, not compensated.
        //
        // The session is seeded straight into the store because every issuance path applies
        // the very gate under test — going through one would prove only that the gate it
        // already had works.
        let Some(h) = harness(base_config(), None) else { return };
        let id = h
            .seed(SeedUser {
                email: "unverified@e.com".to_owned(),
                password: "glidingwalnut42".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        let raw = RawRefreshToken::generate();
        let record = SessionRecord {
            user_id: id,
            tenant_id: Some("t1".to_owned()),
            role: "USER".to_owned(),
            device: "Chrome".to_owned(),
            ip: "1.2.3.4".to_owned(),
            created_at: OffsetDateTime::now_utc(),
            mfa_enabled: false,
            family_id: "fam-unverified".to_owned(),
            family_created_at: Some(OffsetDateTime::now_utc()),
        };
        let seeded = h
            .stores
            .create_session(SessionKind::Dashboard, &raw.redis_hash(), &record, 3600)
            .await;
        assert!(seeded.is_ok());

        let refused = h
            .engine
            .refresh(raw.expose_secret(), "1.2.3.4", "agent")
            .await;
        assert!(matches!(refused, Err(AuthError::EmailNotVerified)));

        // NOT compensated: the account still holds its sessions, so the token that rendered
        // the "check your inbox" screen keeps working for its remaining lifetime.
        assert!(
            h.stores
                .find_session(SessionKind::Dashboard, &raw.redis_hash())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn logout_blacklists_the_access_token_and_revokes_the_session() {
        // After logout the access jti is blacklisted (verify_access rejects it) and the
        // refresh session is gone, so the refresh token no longer rotates.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_id, auth)) = logged_in(&h, "out@example.com", "pw").await else { return };
        assert!(
            h.engine
                .logout(&auth.access_token, &auth.refresh_token)
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
    async fn logout_revokes_the_session_without_a_live_access_token() {
        // The common case: the user comes back after their access token expired and signs
        // out. The route used to sit behind the `AuthUser` extractor, so that request answered
        // 401 and the engine never ran — the refresh session, the long-lived credential logout
        // exists to kill, stayed valid for its full lifetime on a device the user had just
        // told the system to sign out.
        //
        // Driven with NO access token at all, which is the strongest form of the case: the
        // owner has to come from the stored session, because there are no claims to read.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_, auth)) = logged_in(&h, "exp@example.com", "pw").await else { return };

        assert!(h.engine.logout("", &auth.refresh_token).await.is_ok());

        // The session is gone: the refresh token no longer rotates.
        assert!(matches!(
            h.engine
                .refresh(&auth.refresh_token, "1.2.3.4", "agent")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn logout_takes_the_owner_from_the_stored_session() {
        // A refresh token that matches no live session names nobody, so there is nothing to
        // revoke and nothing to attribute — and the call still succeeds, because logout is
        // idempotent and must never tell a caller whether a session existed.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let unknown = "0".repeat(64);
        assert!(h.engine.logout("", &unknown).await.is_ok());
    }

    #[tokio::test]
    async fn logout_skips_blacklist_for_an_unverified_token_but_revokes_the_session() {
        // A forged/garbage access token never verifies, so logout skips the blacklist
        // (the live access token is left untouched) yet still revokes the refresh session.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_id, auth)) = logged_in(&h, "skip@example.com", "pw").await else { return };
        assert!(
            h.engine
                .logout("not-a-jwt", &auth.refresh_token)
                .await
                .is_ok()
        );
        // The blacklist was skipped: the genuine access token still verifies.
        assert!(
            h.engine
                .tokens()
                .verify_access(&auth.access_token)
                .await
                .is_ok()
        );
        // The refresh session was revoked all the same.
        assert!(matches!(
            h.engine
                .refresh(&auth.refresh_token, "1.2.3.4", "agent")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));

        // Logout also tolerates a non-shaped refresh token (skipped before hashing) and an
        // unknown user, still succeeding.
        assert!(
            h.engine
                .logout("not-a-jwt", "unknown-refresh")
                .await
                .is_ok()
        );

        // An already-expired access token fails verification, so the blacklist is skipped
        // and logout still succeeds.
        let now = crate::services::now_unix();
        let expired = DashboardClaims {
            iss: None,
            aud: None,
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
            epoch: 0,
        };
        let Ok(token) = h.engine.tokens().issue_access(&expired) else { return };
        assert!(h.engine.logout(&token, "unknown-refresh").await.is_ok());
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
        assert!(matches!(&rotated, Ok(r) if r.tokens.refresh_token != auth.refresh_token));
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

    #[tokio::test]
    async fn logout_survives_a_store_that_refuses_both_cleanups() {
        // A backend outage during logout must not fail the logout: the access token is already
        // blacklisted, and the caller has no way to retry the parts that failed. What it must
        // not do is pass silently — an operator with a store that keeps refusing is looking at
        // refresh sessions and grace pointers outliving the logouts that asked for them, and the
        // response says nothing. Both cleanups are armed to fail, so both report.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_id, auth)) = logged_in(&h, "down@x.io", "pw").await else { return };

        h.stores.fail_next_cleanup_writes(2);
        let (events, capture) = crate::log_capture::capture_events();
        assert!(
            h.engine
                .logout(&auth.access_token, &auth.refresh_token)
                .await
                .is_ok()
        );
        drop(capture);

        // Both refusals are reported. The warning is the whole body of its branch — the logout
        // returns `Ok` either way and the session survives either way — so the log is the only
        // place the condition guarding it is observable at all.
        assert!(events.contains_at(tracing::Level::WARN, "logout: session cleanup failed"));
        assert!(events.contains_at(tracing::Level::WARN, "logout: grace pointer cleanup failed"));

        // The failures were consumed by the two cleanup calls, and the session survives them —
        // which is what makes the swallowed error worth reporting rather than ignoring.
        let store: &dyn crate::traits::SessionStore = h.stores.as_ref();
        assert!(matches!(
            store
                .find_session(
                    crate::traits::SessionKind::Dashboard,
                    &RawRefreshToken::from_raw(auth.refresh_token.clone()).redis_hash(),
                )
                .await,
            Ok(Some(_))
        ));
    }

    #[tokio::test]
    async fn logout_stays_quiet_when_the_session_was_already_gone() {
        // `SessionNotFound` is the ordinary outcome for a session already rotated or evicted, so
        // it takes the swallow path WITHOUT the warning an outage gets. Logging it would drown
        // the real signal in noise on every double logout.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((_id, auth)) = logged_in(&h, "twice@x.io", "pw").await else { return };
        assert!(
            h.engine
                .logout(&auth.access_token, &auth.refresh_token)
                .await
                .is_ok()
        );

        // The second logout finds the session already gone. That is `SessionNotFound`, the
        // ordinary outcome of a double logout or a session rotated away — and it must NOT be
        // reported, or the one line that means "sessions are outliving their logouts" drowns in
        // one line per ordinary race. Inverting the guard is invisible to every other assertion:
        // the call still returns `Ok` and the store is still empty.
        let (events, capture) = crate::log_capture::capture_events();
        assert!(
            h.engine
                .logout(&auth.access_token, &auth.refresh_token)
                .await
                .is_ok()
        );
        drop(capture);
        assert!(!events.contains("logout: session cleanup failed"));
        // …while the logout itself is still recorded, so "quiet" means quiet about the failure,
        // not quiet altogether.
        assert!(events.contains_at(tracing::Level::INFO, "logout: session closed"));
    }
}
