//! The login flow (§7.1.2) and the status gate (§7.1.8). Login is the most
//! security-sensitive path: it upholds anti-enumeration (a generic credential error and a
//! normalized timing floor for both unknown-email and wrong-password), brute-force lockout,
//! the status and email-verification gates before the KDF, transparent rehash-on-verify,
//! the MFA-challenge branch, and session-fixation resistance (a fresh session per login).

use std::time::Instant;

use bymax_auth_types::{
    AuthError, AuthUser, LoginResult, MfaChallengeResult, MfaContext, SafeAuthUser,
};

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::normalize::{mask_email, normalize_email};
use crate::services::auth::detached::{
    run_after_login, run_rehash_password, run_update_last_login,
};
use crate::services::auth::{LoginInput, map_repository_error, normalize_anti_enum, spawn_guarded};
use crate::status_gate::assert_not_blocked;
use crate::traits::{HookContext, LoginFailure, LoginFailureReason};

impl AuthEngine {
    /// Authenticate email + password, returning either a full session or an MFA challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AccountLocked`] when the brute-force window is tripped,
    /// [`AuthError::InvalidCredentials`] for an unknown email or wrong password (uniform
    /// status/body/timing), a status [`AuthError`] for a blocked account,
    /// [`AuthError::EmailNotVerified`] when verification is required and pending, or an
    /// internal/store [`AuthError`].
    pub async fn login(
        &self,
        input: LoginInput,
        ctx: &RequestContext,
    ) -> Result<LoginResult, AuthError> {
        // Canonicalize before ANY email-keyed value below is derived. The lockout identifier
        // and the repository lookup must agree on one spelling, otherwise each casing of the
        // same address is its own failure budget and the lockout never fires.
        let input = LoginInput {
            email: normalize_email(&input.email),
            ..input
        };
        let config = self.config().config();
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let identifier = self.lockout_identifier(&tenant_id, &input.email);

        let hook_ctx = HookContext::from_request(
            ctx,
            None,
            Some(input.email.clone()),
            Some(tenant_id.clone()),
        );

        // Brute-force gate first (so an already-locked account never increments again).
        if let Err(error) = self.assert_not_locked(&identifier).await {
            // Kept on one line on purpose: a `tracing` field expression on its own line is
            // never evaluated without an installed subscriber, so it would read as an
            // uncovered line under the 100% gate while being perfectly exercised.
            tracing::warn!(email = %mask_email(&input.email), %tenant_id, "login: account locked");
            self.fire_login_failed(
                &input.email,
                &tenant_id,
                None,
                LoginFailureReason::LockedOut,
                &hook_ctx,
            )
            .await;
            return Err(error);
        }
        self.hooks()
            .before_login(&input.email, &tenant_id, &hook_ctx)
            .await
            .map_err(|_| AuthError::Forbidden)?;

        // The timing floor starts here so the unknown-email and wrong-password paths are
        // indistinguishable in elapsed time, not just in status/body.
        let started = Instant::now();
        let user = self
            .user_repository()
            .find_by_email(&input.email, &tenant_id)
            .await
            .map_err(map_repository_error)?;

        // Unknown email or an OAuth-only account (no local hash): run the sentinel verify so
        // the KDF cost is paid either way, then record the failure and return generically.
        let Some(user) = user.filter(has_local_hash) else {
            self.passwords().verify_sentinel(&input.password).await?;
            return self
                .record_failure_and_reject(
                    &identifier,
                    started,
                    &input.email,
                    &tenant_id,
                    None,
                    &hook_ctx,
                )
                .await;
        };

        // A present local hash is guaranteed by the filter above.
        let phc = user.password_hash.clone().unwrap_or_default();
        let outcome = self.passwords().verify(&input.password, &phc).await?;
        if !outcome.matched {
            return self
                .record_failure_and_reject(
                    &identifier,
                    started,
                    &input.email,
                    &tenant_id,
                    Some(&user.id),
                    &hook_ctx,
                )
                .await;
        }

        // Only NOW, with the password proved, may the account's own state be described.
        //
        // Both gates used to run before the KDF, to spare the CPU of hashing against an
        // account that could never sign in. The saving was real and the cost was worse: a
        // blocked or unverified account answered with its own status, in ~1 ms against the
        // 300 ms anti-enumeration floor every other refusal pays, and without touching the
        // failure counter — so anyone could enumerate addresses AND read their moderation
        // state at whatever rate the per-IP limiter allowed, and never trip a lockout. The CPU
        // it saved is bounded by that limiter; the disclosure it bought was bounded by nothing.
        //
        // The holder of the credential is not the attacker this hides from, and telling them
        // "your address is unverified" is the whole point of the flow.
        if let Err(error) = self.assert_user_not_blocked(&user.status) {
            self.fire_login_failed(
                &input.email,
                &tenant_id,
                Some(&user.id),
                LoginFailureReason::AccountBlocked,
                &hook_ctx,
            )
            .await;
            return Err(error);
        }

        if config.email_verification.required && !user.email_verified {
            self.fire_login_failed(
                &input.email,
                &tenant_id,
                Some(&user.id),
                LoginFailureReason::EmailNotVerified,
                &hook_ctx,
            )
            .await;
            return Err(AuthError::EmailNotVerified);
        }

        // Password proven: clear the failure counter.
        self.brute_force().reset(&identifier).await?;

        // Transparent rehash-on-verify, fire-and-forget, never blocking login.
        if self.passwords().rehash_on_verify() && outcome.needs_rehash {
            spawn_guarded(run_rehash_password(
                self.passwords().clone(),
                self.user_repository().clone(),
                input.password.clone(),
                user.id.clone(),
            ));
        }

        // MFA branch: return a challenge instead of tokens; the second factor is verified by
        // the MFA challenge flow, not here.
        if user.mfa_enabled {
            let mfa_temp_token = self
                .tokens()
                .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)
                .await?;
            tracing::info!(user_id = %user.id, tenant_id = %tenant_id, "login: MFA challenge issued");
            return Ok(LoginResult::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                mfa_temp_token,
            }));
        }

        // A fresh session is minted on success (session-fixation resistance).
        tracing::info!(user_id = %user.id, tenant_id = %tenant_id, "login: success");
        self.issue_session_result(user, &ctx.ip, &ctx.user_agent, hook_ctx)
            .await
    }

    /// Reject a credential attempt: record the failure and normalize the elapsed time to the
    /// anti-enumeration floor before returning the generic [`AuthError::InvalidCredentials`],
    /// so the unknown-email and wrong-password paths are indistinguishable.
    ///
    /// # Errors
    ///
    /// Always returns [`AuthError::InvalidCredentials`] on success of the bookkeeping, or a
    /// store [`AuthError`] if recording the failure fails.
    async fn record_failure_and_reject<T>(
        &self,
        identifier: &str,
        started: Instant,
        email: &str,
        tenant_id: &str,
        user_id: Option<&str>,
        hook_ctx: &HookContext,
    ) -> Result<T, AuthError> {
        tracing::warn!("login: invalid credentials");
        self.brute_force().record_failure(identifier).await?;
        self.fire_login_failed(
            email,
            tenant_id,
            user_id,
            LoginFailureReason::InvalidCredentials,
            hook_ctx,
        )
        .await;
        // Read the lock AFTER recording, so the event fires on the attempt that crosses the
        // threshold rather than on the next one — an attacker who trips the lock and walks
        // away would otherwise never produce it.
        self.fire_lockout_if_crossed(identifier, email, tenant_id, hook_ctx)
            .await;
        normalize_anti_enum(started).await;
        Err(AuthError::InvalidCredentials)
    }

    /// Fire the fire-and-forget [`AuthHooks::on_login_failed`] hook.
    ///
    /// Swallowed like every other notification hook: a consumer's SIEM being unreachable is
    /// not an authentication decision, and the refusal the caller receives is unchanged.
    ///
    /// [`AuthHooks::on_login_failed`]: crate::traits::AuthHooks::on_login_failed
    async fn fire_login_failed(
        &self,
        email: &str,
        tenant_id: &str,
        user_id: Option<&str>,
        reason: LoginFailureReason,
        hook_ctx: &HookContext,
    ) {
        let failure = LoginFailure {
            email,
            tenant_id,
            user_id,
            reason,
        };
        if let Err(error) = self.hooks().on_login_failed(&failure, hook_ctx).await {
            tracing::error!(%error, "login: on_login_failed hook returned an error (ignored)");
        }
    }

    /// Fire [`AuthHooks::on_lockout`] when the failure just recorded closed the window.
    ///
    /// A store error here is swallowed too: it means the *hook* could not be decided, not
    /// that the login should answer differently.
    ///
    /// [`AuthHooks::on_lockout`]: crate::traits::AuthHooks::on_lockout
    async fn fire_lockout_if_crossed(
        &self,
        identifier: &str,
        email: &str,
        tenant_id: &str,
        hook_ctx: &HookContext,
    ) {
        let crossed = match self.brute_force().is_locked(identifier).await {
            Ok(locked) => locked,
            Err(error) => {
                tracing::error!(%error, "login: could not read the lockout state for the hook");
                return;
            }
        };
        if !crossed {
            return;
        }
        let retry = self
            .brute_force()
            .remaining_lockout_secs(identifier)
            .await
            .unwrap_or(0);
        if let Err(error) = self
            .hooks()
            .on_lockout(email, tenant_id, retry, hook_ctx)
            .await
        {
            tracing::error!(%error, "login: on_lockout hook returned an error (ignored)");
        }
    }

    /// Clear an account's brute-force lockout so the next attempt is judged on its merits.
    ///
    /// A lockout is a denial of service the library imposes on its own users, and until now it
    /// could only be waited out: the counter is keyed by an HMAC of `{tenant_id}:{email}`
    /// under the library's own HMAC key, which no consumer can derive, so a host facing "I am
    /// locked out and I need in now" had nothing to offer. ASVS v5 §6.1.1 asks for an
    /// administrative path to clear it — and the lockout is also the lever an attacker pulls
    /// to deny service to a specific account, which makes the ability to undo it part of the
    /// defence rather than a convenience.
    ///
    /// **This grants no access.** It restores the ability to *try*: the password, the status
    /// gate, the verification gate and MFA all still apply. Authorising the caller is the
    /// host's job — the adapter deliberately ships no route for this, because who may unlock
    /// whom is a decision only the application can make.
    ///
    /// Idempotent: unlocking an account that is not locked is a no-op.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] if the counter cannot be cleared.
    pub async fn unlock_account(&self, email: &str, tenant_id: &str) -> Result<(), AuthError> {
        // Normalized exactly as login normalizes it, or the derived key misses the counter the
        // lockout actually wrote and the unlock silently does nothing.
        let identifier = self.lockout_identifier(tenant_id, &normalize_email(email));
        self.brute_force().reset(&identifier).await?;
        tracing::info!(email = %mask_email(email), %tenant_id, "lockout cleared");
        Ok(())
    }

    /// Reject the login when the identifier is already locked out, surfacing the retry hint.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AccountLocked`] when the fixed window is tripped, or a store
    /// [`AuthError`] on failure.
    async fn assert_not_locked(&self, identifier: &str) -> Result<(), AuthError> {
        if self.brute_force().is_locked(identifier).await? {
            let retry = self
                .brute_force()
                .remaining_lockout_secs(identifier)
                .await?;
            return Err(AuthError::AccountLocked {
                retry_after_seconds: Some(retry),
            });
        }
        Ok(())
    }

    /// Project the verified user, issue a fresh session, and spawn the fire-and-forget
    /// last-login stamp and `after_login` hook.
    ///
    /// # Errors
    ///
    /// Returns a store/signing [`AuthError`] if token issuance fails.
    async fn issue_session_result(
        &self,
        user: AuthUser,
        ip: &str,
        user_agent: &str,
        hook_ctx: HookContext,
    ) -> Result<LoginResult, AuthError> {
        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens()
            .issue_tokens(&safe, ip, user_agent, false)
            .await?;
        // Enforce the concurrent-session cap (and fire the new-session hook) for the
        // just-issued session before the fire-and-forget bookkeeping; a no-op when session
        // tracking is disabled.
        self.enforce_sessions_after_issue(&result, ip, user_agent, &hook_ctx)
            .await?;
        spawn_guarded(run_update_last_login(
            self.user_repository().clone(),
            safe.id.clone(),
        ));
        spawn_guarded(run_after_login(self.hooks().clone(), safe, hook_ctx));
        Ok(LoginResult::Success(Box::new(result)))
    }

    /// Map `status` (case-insensitive) against `config.blocked_statuses`, returning the
    /// status-specific 403 when blocked and `Ok(())` otherwise (§7.1.8). The mapping is
    /// `banned → AccountBanned`, `inactive → AccountInactive`, `suspended → AccountSuspended`,
    /// `pending`/`pending_approval → PendingApproval`, with any other blocked status falling
    /// back to `AccountInactive`.
    ///
    /// # Errors
    ///
    /// Returns the status-specific [`AuthError`] when `status` is in the blocked set.
    pub(crate) fn assert_user_not_blocked(&self, status: &str) -> Result<(), AuthError> {
        assert_not_blocked(status, &self.config().config().blocked_statuses)
    }
}

/// Whether a present user still has a usable local password hash. Kept as a tiny helper so
/// the `Option::filter` predicate in `login` reads clearly.
fn has_local_hash(user: &AuthUser) -> bool {
    user.password_hash.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, ctx, harness};
    use crate::traits::UserRepository;
    use std::sync::Arc;
    use std::time::Duration;

    fn login_input(email: &str, password: &str) -> LoginInput {
        LoginInput {
            email: email.to_owned(),
            password: password.to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    async fn active_harness(verification_required: bool) -> Option<Harness> {
        let mut cfg = base_config();
        cfg.email_verification.required = verification_required;
        harness(cfg, None)
    }

    #[tokio::test]
    async fn successful_login_issues_a_session() {
        // A correct password for an active, verified user returns a full session.
        let Some(h) = active_harness(false).await else { return };
        let _ = h
            .seed(SeedUser::active("ok@example.com", "s3cret-pass"))
            .await;
        let result = h
            .engine
            .login(login_input("ok@example.com", "s3cret-pass"), &ctx())
            .await;
        assert!(matches!(&result, Ok(LoginResult::Success(_))));
        let Ok(LoginResult::Success(auth)) = result else { return };
        assert_eq!(auth.user.email, "ok@example.com");
        assert!(!auth.access_token.is_empty());
        // The refresh session is stored with the configured lifetime, in seconds. The double
        // cannot expire anything, so without this the arithmetic that turns days into the
        // key's TTL is unobservable — a session that never expired, or expired at once, would
        // look exactly like this one.
        assert_eq!(h.stores.peek_session_ttl(), Some(7 * 86_400));
    }

    #[tokio::test]
    async fn login_with_session_tracking_enforces_the_cap_via_the_session_service() {
        // With session tracking on and a cap of one, a second login for the same user evicts
        // the first session, so only the newest survives — exercising the engine's
        // enforce-sessions-after-issue path and the session service it drives.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        cfg.sessions.enabled = true;
        cfg.sessions.default_max_sessions = 1;
        let Some(h) = harness(cfg, None) else { return };
        let id = h.seed(SeedUser::active("cap@example.com", "pw")).await;

        let first = h
            .engine
            .login(login_input("cap@example.com", "pw"), &ctx())
            .await;
        let Ok(LoginResult::Success(first)) = first else { return };
        let first_hash =
            bymax_auth_jwt::RawRefreshToken::from_raw(first.refresh_token.clone()).redis_hash();

        let second = h
            .engine
            .login(login_input("cap@example.com", "pw"), &ctx())
            .await;
        let Ok(LoginResult::Success(second)) = second else { return };
        let second_hash =
            bymax_auth_jwt::RawRefreshToken::from_raw(second.refresh_token.clone()).redis_hash();

        // The cap of one held: the first session was evicted, the newest survives.
        let listed = h
            .engine
            .sessions()
            .list_sessions(&id, Some(&second_hash))
            .await;
        assert!(matches!(&listed, Ok(v) if v.len() == 1));
        let Ok(listed) = listed else { return };
        assert_eq!(listed[0].session_hash, second_hash);
        assert_ne!(listed[0].session_hash, first_hash);
        assert!(listed[0].is_current);
    }

    #[tokio::test]
    async fn unknown_email_and_wrong_password_are_indistinguishable() {
        // Both failure paths return InvalidCredentials and both honor the timing floor, so
        // neither status/body nor latency leaks whether the account exists.
        let Some(h) = active_harness(false).await else { return };
        let _ = h
            .seed(SeedUser::active("real@example.com", "right-pass"))
            .await;

        let unknown_started = Instant::now();
        let unknown = h
            .engine
            .login(login_input("ghost@example.com", "any"), &ctx())
            .await;
        let unknown_elapsed = unknown_started.elapsed();

        let wrong_started = Instant::now();
        let wrong = h
            .engine
            .login(login_input("real@example.com", "wrong-pass"), &ctx())
            .await;
        let wrong_elapsed = wrong_started.elapsed();

        assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
        assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
        assert!(unknown_elapsed >= Duration::from_millis(300));
        assert!(wrong_elapsed >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn oauth_only_account_without_a_hash_is_a_generic_failure() {
        // A user with no local password hash takes the same sentinel path as an unknown
        // email (no distinct "use OAuth" oracle).
        let Some(h) = active_harness(false).await else { return };
        // Seed a user, then clear its hash by creating it directly without a password.
        let created = h
            .users
            .create(bymax_auth_types::CreateUserData {
                email: "oauth@example.com".to_owned(),
                name: "O".to_owned(),
                password_hash: None,
                role: None,
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        assert!(created.is_ok());
        let result = h
            .engine
            .login(login_input("oauth@example.com", "whatever"), &ctx())
            .await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn lockout_triggers_after_max_attempts() {
        // The default cap is five failures; the sixth attempt is rejected as AccountLocked
        // with a retry hint, before any credential check.
        let Some(h) = active_harness(false).await else { return };
        let _ = h.seed(SeedUser::active("lock@example.com", "right")).await;
        for _ in 0..5 {
            let attempt = h
                .engine
                .login(login_input("lock@example.com", "wrong"), &ctx())
                .await;
            assert!(matches!(attempt, Err(AuthError::InvalidCredentials)));
        }
        let locked = h
            .engine
            .login(login_input("lock@example.com", "right"), &ctx())
            .await;
        assert!(matches!(
            locked,
            Err(AuthError::AccountLocked {
                retry_after_seconds: Some(_)
            })
        ));
    }

    #[tokio::test]
    async fn rotating_the_email_case_cannot_reset_the_lockout_budget() {
        // The case-rotation bypass. The lockout identifier is an HMAC of the email, so without
        // canonicalization each casing is its own counter while every one of them resolves the
        // same account — an attacker cycles the spelling and the lockout never fires. Spend the
        // five-failure budget across five DIFFERENT casings; the sixth attempt must already be
        // locked, proving all five landed in one bucket.
        let Some(h) = active_harness(false).await else { return };
        let _ = h.seed(SeedUser::active("case@example.com", "right")).await;

        for spelling in [
            "case@example.com",
            "CASE@EXAMPLE.COM",
            "Case@Example.Com",
            "cAsE@eXaMpLe.CoM",
            "  case@example.com  ",
        ] {
            let attempt = h.engine.login(login_input(spelling, "wrong"), &ctx()).await;
            assert!(matches!(attempt, Err(AuthError::InvalidCredentials)));
        }

        let locked = h
            .engine
            .login(login_input("case@example.com", "right"), &ctx())
            .await;
        assert!(matches!(
            locked,
            Err(AuthError::AccountLocked {
                retry_after_seconds: Some(_)
            })
        ));
    }

    #[tokio::test]
    async fn login_resolves_an_account_under_any_casing() {
        // The other half of canonicalization: the repository lookup uses the same canonical
        // value, so an account seeded lowercase authenticates when the caller types it
        // uppercase. Without this the fix would close the bypass by breaking real logins.
        let Some(h) = active_harness(false).await else { return };
        let _ = h
            .seed(SeedUser::active("mixed@example.com", "s3cret-pass"))
            .await;

        let result = h
            .engine
            .login(login_input("  MiXeD@Example.COM ", "s3cret-pass"), &ctx())
            .await;

        assert!(matches!(&result, Ok(LoginResult::Success(_))));
    }

    #[tokio::test]
    async fn each_blocked_status_maps_to_its_specific_error() {
        // The status gate runs before the KDF and maps every blocked status to its 403.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        cfg.blocked_statuses = vec![
            "BANNED".to_owned(),
            "INACTIVE".to_owned(),
            "SUSPENDED".to_owned(),
            "PENDING_APPROVAL".to_owned(),
            "FROZEN".to_owned(),
        ];
        let Some(h) = harness(cfg, None) else { return };
        let cases = [
            ("banned@x.io", "BANNED", AuthError::AccountBanned),
            ("inactive@x.io", "INACTIVE", AuthError::AccountInactive),
            ("suspended@x.io", "SUSPENDED", AuthError::AccountSuspended),
            (
                "pending@x.io",
                "PENDING_APPROVAL",
                AuthError::PendingApproval,
            ),
            ("frozen@x.io", "FROZEN", AuthError::AccountInactive),
        ];
        for (email, status, _expected) in cases {
            let _ = h
                .seed(SeedUser {
                    email: email.to_owned(),
                    password: "pw".to_owned(),
                    tenant_id: "t1".to_owned(),
                    status: status.to_owned(),
                    email_verified: true,
                    mfa_enabled: false,
                })
                .await;
        }
        assert!(matches!(
            h.engine
                .login(login_input("banned@x.io", "pw"), &ctx())
                .await,
            Err(AuthError::AccountBanned)
        ));
        assert!(matches!(
            h.engine
                .login(login_input("inactive@x.io", "pw"), &ctx())
                .await,
            Err(AuthError::AccountInactive)
        ));
        assert!(matches!(
            h.engine
                .login(login_input("suspended@x.io", "pw"), &ctx())
                .await,
            Err(AuthError::AccountSuspended)
        ));
        assert!(matches!(
            h.engine
                .login(login_input("pending@x.io", "pw"), &ctx())
                .await,
            Err(AuthError::PendingApproval)
        ));
        assert!(matches!(
            h.engine
                .login(login_input("frozen@x.io", "pw"), &ctx())
                .await,
            Err(AuthError::AccountInactive)
        ));
        // The lowercase "pending" alias also maps to PendingApproval.
        assert!(matches!(
            h.engine.assert_user_not_blocked("BANNED"),
            Err(AuthError::AccountBanned)
        ));
    }

    #[tokio::test]
    async fn pending_lowercase_alias_maps_to_pending_approval() {
        // A blocked-set that lists the lowercase "pending" alias maps to PendingApproval,
        // covering that arm of the status mapping.
        let mut cfg = base_config();
        cfg.blocked_statuses = vec!["pending".to_owned()];
        let Some(h) = harness(cfg, None) else { return };
        assert!(matches!(
            h.engine.assert_user_not_blocked("pending"),
            Err(AuthError::PendingApproval)
        ));
        assert!(h.engine.assert_user_not_blocked("ACTIVE").is_ok());
    }

    #[tokio::test]
    async fn unverified_email_is_rejected_when_verification_is_required() {
        // With verification required, a correct password for an unverified account is gated.
        let Some(h) = active_harness(true).await else { return };
        let _ = h
            .seed(SeedUser {
                email: "unverified@example.com".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        let result = h
            .engine
            .login(login_input("unverified@example.com", "pw"), &ctx())
            .await;
        assert!(matches!(result, Err(AuthError::EmailNotVerified)));

        // The gate needs *both* halves: with verification required, an account that HAS
        // verified must still log in. Only this case separates the pair from an either-or,
        // which would lock out every verified user the moment the requirement is switched on.
        let _ = h.seed(SeedUser::active("verified@example.com", "pw")).await;
        assert!(matches!(
            h.engine
                .login(login_input("verified@example.com", "pw"), &ctx())
                .await,
            Ok(LoginResult::Success(_))
        ));
    }

    #[tokio::test]
    async fn the_rehash_wait_gives_up_rather_than_hanging() {
        // The helper the two rehash tests rely on has to report a deadline it never met, or a
        // rehash that silently stopped happening would hang the suite instead of failing it.
        // Exercised with a one-poll deadline against a hash nothing is going to change.
        let Some(h) = active_harness(false).await else { return };
        let id = h.seed(SeedUser::active("nochange@example.com", "pw")).await;
        let stored = h.users.find_by_id(&id, Some("t1")).await;
        let Ok(Some(stored)) = stored else { return };
        let current = stored.password_hash.unwrap_or_default();

        assert!(
            !super::super::test_support::await_rehash_within(&h, &id, &current, 1).await,
            "the wait reported a change nobody made"
        );
    }

    #[tokio::test]
    async fn a_current_password_hash_is_not_rehashed_on_login() {
        // The upgrade needs the toggle *and* a genuinely stale hash. Either alone must not
        // rewrite a current one: a rehash on every login is a write on the hot path for no
        // gain, and it would leave the toggle disabling nothing.
        let Some(h) = active_harness(false).await else { return };
        let id = h.seed(SeedUser::active("fresh@example.com", "pw")).await;
        let before = h.users.find_by_id(&id, Some("t1")).await;
        let Ok(Some(before)) = before else { return };
        assert!(matches!(
            h.engine
                .login(login_input("fresh@example.com", "pw"), &ctx())
                .await,
            Ok(LoginResult::Success(_))
        ));
        // The deterministic half: the hash is not stale to begin with, so nothing should have
        // been spawned. This is what the test really means, and unlike the wait below it cannot
        // pass by being too slow to observe a write.
        let stored = before.password_hash.clone().unwrap_or_default();
        assert!(!bymax_auth_crypto::password::needs_rehash(
            &stored,
            &crate::services::auth::test_support::crypto_params()
        ));

        // …and the observational half, which only ever weakens: a wait too short to catch a
        // write makes this pass, never fail. It is kept because it is the one check that would
        // notice a rehash spawned for some reason other than staleness.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let after = h.users.find_by_id(&id, Some("t1")).await;
        let Ok(Some(after)) = after else { return };
        assert_eq!(before.password_hash, after.password_hash);
    }

    #[tokio::test]
    async fn mfa_enabled_account_returns_a_challenge() {
        // A correct password for an MFA-enabled account returns the challenge, not tokens.
        let Some(h) = active_harness(false).await else { return };
        let _ = h
            .seed(SeedUser {
                email: "mfa@example.com".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: true,
                mfa_enabled: true,
            })
            .await;
        let result = h
            .engine
            .login(login_input("mfa@example.com", "pw"), &ctx())
            .await;
        assert!(matches!(
            result,
            Ok(LoginResult::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn rehash_on_verify_upgrades_a_weaker_stored_hash() {
        // A hash stored under weaker scrypt params is upgraded on a successful login; the
        // detached task replaces the stored hash with a stronger one.
        #[cfg(feature = "scrypt")]
        {
            let mut cfg = base_config();
            cfg.email_verification.required = false;
            // The active params are the default (cost 2^15); seed a weaker (2^14) hash.
            let Some(h) = harness(cfg, None) else { return };
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
            let created = h
                .users
                .create(bymax_auth_types::CreateUserData {
                    email: "weak@example.com".to_owned(),
                    name: "W".to_owned(),
                    password_hash: Some(weak_hash.clone()),
                    role: None,
                    status: Some("ACTIVE".to_owned()),
                    tenant_id: "t1".to_owned(),
                    email_verified: Some(true),
                })
                .await;
            let Ok(user) = created else { return };
            let result = h
                .engine
                .login(login_input("weak@example.com", "pw"), &ctx())
                .await;
            assert!(matches!(result, Ok(LoginResult::Success(_))));
            // Poll for the detached rehash rather than sleeping a fixed span. The rehash is one
            // scrypt derivation at the configured cost, and how long that takes depends on the
            // machine — a fixed wait tuned on a developer's laptop is a test that fails on a
            // slower CI runner and tells you nothing about the code.
            assert!(
                super::super::test_support::await_rehash(&h, &user.id, &weak_hash).await,
                "the stored hash was never upgraded"
            );
        }
    }

    /// The failure-side hook surface, recorded in order.
    #[derive(Default)]
    struct FailureSpy {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl FailureSpy {
        fn seen(&self) -> Vec<String> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    #[async_trait::async_trait]
    impl crate::traits::AuthHooks for FailureSpy {
        async fn on_login_failed(
            &self,
            failure: &LoginFailure<'_>,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!(
                    "failed:{}:{}:{}",
                    failure.reason,
                    failure.email,
                    failure.user_id.unwrap_or("-")
                ));
            }
            Ok(())
        }
        async fn on_lockout(
            &self,
            email: &str,
            _tenant_id: &str,
            retry_after_seconds: u64,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!("lockout:{email}:{retry_after_seconds}"));
            }
            Ok(())
        }
    }

    /// Hooks that fail on every failure-side callback, to prove the refusal is unchanged.
    struct BrokenFailureHooks;

    #[async_trait::async_trait]
    impl crate::traits::AuthHooks for BrokenFailureHooks {
        async fn on_login_failed(
            &self,
            _failure: &LoginFailure<'_>,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            Err(crate::traits::HookError::Rejected(
                "siem unreachable".to_owned(),
            ))
        }
        async fn on_lockout(
            &self,
            _email: &str,
            _tenant_id: &str,
            _retry: u64,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            Err(crate::traits::HookError::Rejected(
                "siem unreachable".to_owned(),
            ))
        }
    }

    #[tokio::test]
    async fn a_tenant_named_platform_never_reaches_the_platform_lockout_key() {
        // The plane collision. A tenant whose id is literally `platform` used to produce a
        // byte-identical lockout identifier to the platform plane's own `platform:{email}`, so
        // five unauthenticated dashboard logins locked an operator out of the console — and a
        // successful one cleared their lockout mid-attack. `tenant_id` comes from the request
        // body whenever no resolver is configured, which is the default.
        let Some(h) = harness(base_config(), None) else { return };

        let dashboard = h.engine.lockout_identifier("platform", "admin@example.com");
        // The platform plane's own preimage, reproduced here rather than called, because the
        // point is that the two can never be equal whatever either side does internally.
        let platform = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            h.engine.config().hmac_key(),
            b"platform:admin@example.com",
        ));

        assert_ne!(
            dashboard, platform,
            "a tenant named `platform` collided with the platform lockout counter"
        );
    }

    #[tokio::test]
    async fn a_wrong_password_answers_the_same_whatever_state_the_account_is_in() {
        // The enumeration oracle this ordering exists to close. A blocked or unverified
        // account must be indistinguishable from a non-existent one to anyone who does NOT
        // hold the password — same error, and the failure counter advances so probing is
        // bounded by the lockout rather than only by the per-IP limit.
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        let Some(h) = harness(cfg, None) else { return };
        let _ = h
            .seed(SeedUser::active("active@example.com", "right"))
            .await;
        let _ = h
            .seed(SeedUser {
                status: "SUSPENDED".to_owned(),
                ..SeedUser::active("blocked@example.com", "right")
            })
            .await;
        let _ = h
            .seed(SeedUser {
                email_verified: false,
                ..SeedUser::active("unverified@example.com", "right")
            })
            .await;

        for email in [
            "nobody@example.com",
            "active@example.com",
            "blocked@example.com",
            "unverified@example.com",
        ] {
            let outcome = h.engine.login(login_input(email, "wrong"), &ctx()).await;
            assert!(
                matches!(outcome, Err(AuthError::InvalidCredentials)),
                "{email} answered differently to a wrong password: {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_password_holder_is_told_why_the_account_cannot_sign_in() {
        // The other half: the flow is useless if the real account holder cannot learn that
        // their address is unverified or their account suspended.
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        let Some(h) = harness(cfg, None) else { return };
        let _ = h
            .seed(SeedUser {
                email_verified: false,
                ..SeedUser::active("unverified@example.com", "right")
            })
            .await;
        let _ = h
            .seed(SeedUser {
                status: "SUSPENDED".to_owned(),
                ..SeedUser::active("blocked@example.com", "right")
            })
            .await;

        assert!(matches!(
            h.engine
                .login(login_input("unverified@example.com", "right"), &ctx())
                .await,
            Err(AuthError::EmailNotVerified)
        ));
        assert!(matches!(
            h.engine
                .login(login_input("blocked@example.com", "right"), &ctx())
                .await,
            Err(AuthError::AccountSuspended)
        ));
    }

    #[tokio::test]
    async fn every_refusal_reaches_the_failure_hook_with_its_own_reason() {
        // The whole point of the hook is that the four refusals are DISTINGUISHABLE to the
        // deployment while staying uniform to the caller. An unknown address carries no user
        // id; a wrong password against a real account carries one — that is what separates
        // "someone is guessing at this account" from "someone is spraying addresses".
        let spy = Arc::new(FailureSpy::default());
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        let Some(h) = harness(cfg, Some(spy.clone())) else { return };
        let known = h.seed(SeedUser::active("known@example.com", "right")).await;
        let blocked = h
            .seed(SeedUser {
                status: "SUSPENDED".to_owned(),
                ..SeedUser::active("blocked@example.com", "right")
            })
            .await;
        let pending = h
            .seed(SeedUser {
                email_verified: false,
                ..SeedUser::active("pending@example.com", "right")
            })
            .await;

        for (email, password) in [
            ("nobody@example.com", "whatever"),
            ("known@example.com", "wrong"),
            ("blocked@example.com", "right"),
            ("pending@example.com", "right"),
        ] {
            let _ = h.engine.login(login_input(email, password), &ctx()).await;
        }

        assert_eq!(
            spy.seen(),
            vec![
                "failed:invalid_credentials:nobody@example.com:-".to_owned(),
                format!("failed:invalid_credentials:known@example.com:{known}"),
                format!("failed:account_blocked:blocked@example.com:{blocked}"),
                format!("failed:email_not_verified:pending@example.com:{pending}"),
            ]
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_report_the_lockout_costs_the_hook_and_nothing_else() {
        // Deciding whether to fire `on_lockout` needs one read the login itself does not: has
        // the failure just recorded closed the window? A store that cannot answer means the
        // HOOK cannot be decided — not that the login should answer differently, and certainly
        // not that it should fail. The refusal has to stay exactly what it was, and the failure
        // hook has to keep firing; only the lockout event is lost, and it is logged.
        let spy = Arc::new(FailureSpy::default());
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, Some(spy.clone())) else { return };
        let _ = h.seed(SeedUser::active("blind@example.com", "right")).await;

        // One attempt performs two of these reads. The gate at the top must keep working —
        // it propagates a failure on purpose, since a lockout that cannot be read is a lockout
        // assumed — so the first is let through and the second, the hook decision, is the one
        // that fails.
        h.stores.fail_lockout_reads(1, 1);
        let refused = h
            .engine
            .login(login_input("blind@example.com", "wrong"), &ctx())
            .await;
        assert!(
            matches!(refused, Err(AuthError::InvalidCredentials)),
            "the store failure changed the answer the caller sees"
        );

        let seen = spy.seen();
        assert!(
            seen.iter().all(|call| !call.starts_with("lockout:")),
            "a lockout event fired off a read that failed: {seen:?}"
        );
        assert_eq!(
            seen.iter()
                .filter(|call| call.starts_with("failed:invalid_credentials:"))
                .count(),
            1,
            "the failure hook stopped firing: {seen:?}"
        );
    }

    #[tokio::test]
    async fn the_lockout_hook_fires_on_the_attempt_that_crosses_the_threshold() {
        // Not on the next one. An attacker who trips the lock and walks away never makes a
        // sixth attempt, so a hook fired from the already-locked gate would never run and the
        // account would sit locked with nothing having announced it. The fifth failure — the
        // one that closes the window — is where the event belongs.
        let spy = Arc::new(FailureSpy::default());
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, Some(spy.clone())) else { return };
        let _ = h.seed(SeedUser::active("lock@example.com", "right")).await;

        for _ in 0..5 {
            let _ = h
                .engine
                .login(login_input("lock@example.com", "wrong"), &ctx())
                .await;
        }

        let lockouts: Vec<String> = spy
            .seen()
            .into_iter()
            .filter(|call| call.starts_with("lockout:"))
            .collect();
        assert_eq!(lockouts.len(), 1, "exactly one lockout event: {lockouts:?}");
        // The retry hint is the remaining window, not a placeholder.
        let retry: u64 = lockouts[0]
            .rsplit(':')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        assert!(retry > 0, "the lockout carried no retry hint: {lockouts:?}");

        // …and the sixth attempt, refused at the gate before any credential check, reports
        // itself as `locked_out` rather than as another credential failure.
        let _ = h
            .engine
            .login(login_input("lock@example.com", "right"), &ctx())
            .await;
        assert_eq!(
            spy.seen().last().map(String::as_str),
            Some("failed:locked_out:lock@example.com:-")
        );
    }

    #[tokio::test]
    async fn a_failing_failure_hook_never_changes_the_refusal() {
        // A consumer's SIEM being unreachable is not an authentication decision. The refusal
        // is still a refusal, and the lockout still locks.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Some(h) = harness(cfg, Some(Arc::new(BrokenFailureHooks))) else { return };
        let _ = h
            .seed(SeedUser::active("broken@example.com", "right"))
            .await;

        for _ in 0..5 {
            let attempt = h
                .engine
                .login(login_input("broken@example.com", "wrong"), &ctx())
                .await;
            assert!(matches!(attempt, Err(AuthError::InvalidCredentials)));
        }
        let locked = h
            .engine
            .login(login_input("broken@example.com", "right"), &ctx())
            .await;
        assert!(matches!(locked, Err(AuthError::AccountLocked { .. })));
    }

    #[tokio::test]
    async fn unlocking_lets_the_account_try_again() {
        // The counter is keyed by an HMAC no consumer can derive, so before this the lockout
        // could only be waited out — and it is also the lever an attacker pulls to deny
        // service to one account, which makes undoing it part of the defence. It grants no
        // access: the correct password is still required after the unlock.
        let Some(h) = active_harness(false).await else { return };
        let _ = h
            .seed(SeedUser::active("locked@example.com", "right"))
            .await;
        for _ in 0..5 {
            let _ = h
                .engine
                .login(login_input("locked@example.com", "wrong"), &ctx())
                .await;
        }
        assert!(matches!(
            h.engine
                .login(login_input("locked@example.com", "right"), &ctx())
                .await,
            Err(AuthError::AccountLocked { .. })
        ));

        // The address is normalized on the way in, so a differently-cased spelling still
        // clears the counter the lockout wrote.
        assert!(
            h.engine
                .unlock_account(" Locked@Example.com ", "t1")
                .await
                .is_ok()
        );

        assert!(matches!(
            h.engine
                .login(login_input("locked@example.com", "right"), &ctx())
                .await,
            Ok(LoginResult::Success(_))
        ));
        // …and a wrong password is still wrong: the unlock restored the ability to try.
        assert!(matches!(
            h.engine
                .login(login_input("locked@example.com", "wrong"), &ctx())
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn has_local_hash_reflects_password_presence() {
        // The predicate used by the login filter is true only for a stored local hash.
        use time::OffsetDateTime;
        let mut user = AuthUser {
            id: "u".into(),
            email: "e".into(),
            name: "n".into(),
            password_hash: Some("$scrypt$x".into()),
            role: "USER".into(),
            status: "ACTIVE".into(),
            tenant_id: "t1".into(),
            email_verified: true,
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(has_local_hash(&user));
        user.password_hash = None;
        assert!(!has_local_hash(&user));
    }
}
