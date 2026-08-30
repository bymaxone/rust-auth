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
        // The record, not just its `user_id`: the session index this logout has to prune is
        // keyed by the TENANT-SCOPED subject, and the record is the only thing on this path
        // that carries the tenant — the access token is allowed to be absent.
        let owner = match &session_hash {
            Some(hash) => self
                .session_store()
                .find_session(SessionKind::Dashboard, hash)
                .await
                .ok()
                .flatten(),
            None => None,
        };
        let user_id = owner.as_ref().map_or("", |record| record.user_id.as_str());

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
            let subject = self.session_subject(
                SessionKind::Dashboard,
                owner
                    .as_ref()
                    .and_then(|record| record.tenant_id.as_deref()),
                user_id,
            );
            if let Err(error) = self
                .session_store()
                .revoke_session(SessionKind::Dashboard, &subject, session_hash)
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
        let user_id = claims.sub.clone();

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
                // hand back a token for a user nobody can look up. The tenant comes from the
                // token just minted, which is the only place it is available on this path.
                self.revoke_all_sessions(&claims.tenant_id, &user_id)
                    .await?;
                return Err(AuthError::TokenInvalid);
            }
        };
        if let Err(error) = self.assert_user_not_blocked(&user.status) {
            self.revoke_all_sessions(&user.tenant_id, &user_id).await?;
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

        // Re-stamp the access token from the account just re-read.
        //
        // Rotation builds its claims from the session record written at LOGIN, and that record
        // carries the role and tenant the account had then, inherited unchanged through every
        // later rotation. So demoting an ADMIN to MEMBER, or moving a user between tenants,
        // had no effect on a live session: it kept minting tokens carrying the old authority
        // for the refresh token's whole lifetime, and every role check in the system reads
        // that claim. The gates above already re-read the account — the current authority was
        // sitting right there, unused.
        //
        // The comparison covers every claim the token carries authority in, not just the two
        // that motivated the original fix. Naming a subset is what left `mfa_enabled` stale:
        // `MfaSatisfied` decides on `mfa_enabled && !mfa_verified`, so a session created while
        // the account had no second factor kept minting `mfa_enabled: false` tokens for the
        // refresh token's whole lifetime and every MFA-gated route waved it through —
        // reachable whenever the host enables MFA through its own admin surface rather than
        // this library's, since only `verify_and_enable` revokes the sessions and bumps.
        //
        // `status` is deliberately NOT compared: `rotated_claims` stamps it empty by
        // construction, because the session record carries no live status, so comparing it
        // would differ on every refresh and prove nothing. It is re-validated per request
        // against the repository/status cache instead.
        //
        // Re-signed only when a claim actually differs, so ordinary rotation costs nothing
        // extra.
        // A TENANT change is not an authority re-stamp; it orphans the session.
        //
        // The refresh session is indexed under the subject of the tenant it was created in, and
        // rotation carries that tenant forward from the stored record. So once the account moves,
        // every management API — which is called with the account's CURRENT tenant — addresses a
        // different index and cannot see this session. `revoke_all_sessions(new_tenant, user_id)`
        // then succeeds, bumps the new tenant's epoch, and leaves the refresh credential alive
        // under the old one, still able to rotate and still receiving the old, unbumped epoch.
        // No revocation in either tenant reaches it.
        //
        // Re-stamping the claims would paper over that: the token would name the new tenant while
        // the credential behind it stayed unreachable. So the session ends instead. The account
        // signs in again and gets a session indexed where its tenant now is. A tenant move is an
        // administrative event, and ending the sessions established under the previous tenancy is
        // the coherent outcome — the same reasoning `revoke_all_sessions` already applies to a
        // status change.
        if claims.tenant_id != user.tenant_id {
            tracing::warn!(
                user_id = %user_id,
                "refresh: the account changed tenant — ending the sessions held under the previous one"
            );
            // Under the OLD tenant, which is the index this session actually lives in. The new
            // tenant's index does not contain it and sweeping that one would revoke nothing.
            self.revoke_all_sessions(&claims.tenant_id, &user_id)
                .await?;
            return Err(AuthError::TokenInvalid);
        }

        let rotated = if claims.role == user.role && claims.mfa_enabled == user.mfa_enabled {
            rotated
        } else {
            RotatedTokens {
                access_token: self
                    .tokens()
                    .reissue_access_with_authority(
                        &claims,
                        &user.role,
                        &user.tenant_id,
                        user.mfa_enabled,
                    )
                    .await?,
                refresh_token: rotated.refresh_token,
            }
        };

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
    pub async fn revoke_all_sessions(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), AuthError> {
        let subject = self.session_subject(SessionKind::Dashboard, Some(tenant_id), user_id);
        self.session_store()
            .revoke_all(SessionKind::Dashboard, &subject)
            .await?;
        self.session_store()
            .bump_epoch(SessionKind::Dashboard, &subject)
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
            .issue_tokens(
                &safe,
                ip,
                user_agent,
                false,
                // No credential was verified: this is the password-less workspace-switch /
                // impersonation door, and the authority is the CALLER's. Planting the
                // recent-authentication marker here would let an impersonation session enrol a
                // second factor on an account with no local password, which has no other proof.
                crate::services::token_manager::CredentialProof::Unproven,
            )
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
            tenant_id: Some("t1".to_owned()),
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

    /// Rotate `refresh` and hand back the new pair, or `None` when the harness could not.
    ///
    /// A helper rather than an inline `let-else`: the multi-line form leaves its `return` on a
    /// line of its own, which no run ever reaches, and llvm-cov counts it. Short enough here
    /// that `else { return }` stays on one line, which is the idiom the rest of the file uses.
    async fn rotate(h: &Harness, refresh: &str) -> Option<RefreshedSession> {
        h.engine.refresh(refresh, "1.2.3.4", "agent").await.ok()
    }

    /// The claims inside an access token, or `None` when it does not verify.
    async fn claims_of(h: &Harness, access: &str) -> Option<DashboardClaims> {
        h.engine.verify_access_token(access).await.ok()
    }

    #[tokio::test]
    async fn a_demoted_user_stops_carrying_the_old_role_on_the_very_next_rotation() {
        // Rotation used to build its claims from the session record written at login, so the
        // role travelled unchanged for the refresh token's whole lifetime. Demoting an ADMIN
        // therefore did nothing to a live session, and every role check reads that claim.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "demoted@e.com", "pw123456").await else { return };
        assert!(h.users.set_authority(&id, Some("ADMIN"), None));

        // One rotation to put ADMIN into the session's own lineage, then the demotion.
        let Some(promoted) = rotate(&h, &auth.refresh_token).await else { return };
        let access = promoted.tokens.access_token.clone();
        let Some(before) = claims_of(&h, &access).await else { return };
        assert_eq!(before.role, "ADMIN");

        assert!(h.users.set_authority(&id, Some("MEMBER"), None));
        let Some(rotated) = rotate(&h, &promoted.tokens.refresh_token).await else { return };
        let Some(after) = claims_of(&h, &rotated.tokens.access_token).await else { return };
        assert_eq!(after.role, "MEMBER");
    }

    #[tokio::test]
    async fn moving_a_user_between_tenants_ends_the_sessions_held_under_the_old_one() {
        // A tenant move does NOT re-stamp the claims and carry on. It ends the session.
        //
        // The refresh session is indexed under the subject of the tenant it was created in, and
        // rotation carries that tenant forward from the stored record — so once the account
        // moves, every management API, called with the account's CURRENT tenant, addresses a
        // different index and cannot see it. `revoke_all_sessions(new_tenant, user_id)` would
        // then succeed, bump the new tenant's epoch, and leave the refresh credential alive
        // under the old one, still rotating and still receiving the old, unbumped epoch. No
        // revocation in either tenant would reach it.
        //
        // This test asserted the opposite until the keyspace moved onto the tenant-scoped
        // subject — that the rotation lands the new tenant in the claims. That behaviour was
        // only safe while the index was keyed on the bare id, where a move orphaned nothing.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "moved@e.com", "pw123456").await else { return };
        assert!(h.users.set_authority(&id, None, Some("tenant-b")));

        let refused = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await
            .err();
        assert!(
            matches!(refused, Some(AuthError::TokenInvalid)),
            "a refresh across a tenant move must not continue the session: {refused:?}"
        );

        // …and the credential is spent, not merely refused: presenting it again cannot revive
        // the session the move orphaned.
        let again = h
            .engine
            .refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await
            .err();
        assert!(
            matches!(
                again,
                Some(AuthError::TokenInvalid | AuthError::RefreshTokenInvalid)
            ),
            "the orphaned refresh token survived the revocation: {again:?}"
        );
    }

    #[tokio::test]
    async fn enabling_mfa_outside_this_library_lands_on_the_very_next_rotation() {
        // The same freeze as the two above, on the claim that gates a security control rather
        // than an authorization one. `MfaSatisfied` refuses a token only when
        // `mfa_enabled && !mfa_verified`, so a session created while the account had no second
        // factor kept minting `mfa_enabled: false` for the refresh token's whole lifetime and
        // cleared every MFA-gated route without a challenge.
        //
        // `verify_and_enable` revokes the sessions and bumps the epoch, which hides this — but
        // it is not the only way an account gains MFA. The repository is the host's, and a host
        // that flips the flag through its own admin surface leaves every existing session
        // permanently exempt with no reconciliation path. That is what this closes.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let signed_in = logged_in(&h, "mfa-out-of-band@e.com", "pw123456").await;
        let Some((id, auth)) = signed_in else { return };

        // The session was minted before MFA existed on the account.
        let Some(before) = rotate(&h, &auth.refresh_token).await else { return };
        let Some(exempt) = claims_of(&h, &before.tokens.access_token).await else { return };
        assert!(!exempt.mfa_enabled, "fixture should start without MFA");

        // The host enables MFA directly on its own record, never touching this library.
        assert!(
            h.users
                .update_mfa(
                    &id,
                    None,
                    bymax_auth_types::UpdateMfaData {
                        mfa_enabled: true,
                        mfa_secret: Some("encrypted-secret".to_owned()),
                        mfa_recovery_codes: None,
                    },
                )
                .await
                .is_ok()
        );

        let Some(rotated) = rotate(&h, &before.tokens.refresh_token).await else { return };
        let Some(after) = claims_of(&h, &rotated.tokens.access_token).await else { return };
        assert!(
            after.mfa_enabled,
            "the rotated token still claims the account has no second factor"
        );
    }

    #[tokio::test]
    async fn an_unchanged_authority_leaves_the_rotated_token_exactly_as_rotation_built_it() {
        // The re-stamp is conditional on purpose: the ordinary rotation — every rotation, for
        // every user who was not moved — must not pay for a second signature.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, None) else { return };
        let Some((id, auth)) = logged_in(&h, "steady@e.com", "pw123456").await else { return };

        let Some(rotated) = rotate(&h, &auth.refresh_token).await else { return };
        let Some(claims) = claims_of(&h, &rotated.tokens.access_token).await else { return };
        let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { return };
        assert_eq!(claims.role, user.role);
        assert_eq!(claims.tenant_id, user.tenant_id);
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
            .create_session(
                SessionKind::Dashboard,
                &h.engine.session_subject(
                    SessionKind::Dashboard,
                    record.tenant_id.as_deref(),
                    &record.user_id,
                ),
                &raw.redis_hash(),
                &record,
                3600,
            )
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
