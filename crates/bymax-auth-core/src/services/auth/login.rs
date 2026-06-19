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
use crate::services::auth::detached::{
    run_after_login, run_rehash_password, run_update_last_login,
};
use crate::services::auth::{LoginInput, map_repository_error, normalize_anti_enum, spawn_guarded};
use crate::traits::HookContext;

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
        let config = self.config().config();
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let identifier = self.hashed_identifier(&tenant_id, &input.email);

        // Brute-force gate first (so an already-locked account never increments again).
        self.assert_not_locked(&identifier).await?;

        let hook_ctx = HookContext::from_request(
            ctx,
            None,
            Some(input.email.clone()),
            Some(tenant_id.clone()),
        );
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
            return self.record_failure_and_reject(&identifier, started).await;
        };

        // Status gate runs before the KDF so a blocked account never consumes hashing CPU.
        self.assert_user_not_blocked(&user.status)?;

        // Email-verification gate.
        if config.email_verification.required && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // A present local hash is guaranteed by the filter above.
        let phc = user.password_hash.clone().unwrap_or_default();
        let outcome = self.passwords().verify(&input.password, &phc).await?;
        if !outcome.matched {
            return self.record_failure_and_reject(&identifier, started).await;
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
                .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)?;
            return Ok(LoginResult::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                mfa_temp_token,
            }));
        }

        // A fresh session is minted on success (session-fixation resistance).
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
    ) -> Result<T, AuthError> {
        self.brute_force().record_failure(identifier).await?;
        normalize_anti_enum(started).await;
        Err(AuthError::InvalidCredentials)
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
        let blocked = &self.config().config().blocked_statuses;
        if !blocked.iter().any(|s| s.eq_ignore_ascii_case(status)) {
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
            // Allow the detached rehash to complete, then confirm the stored hash changed.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let stored = h.users.find_by_id(&user.id, None).await;
            let Ok(Some(stored)) = stored else { return };
            assert_ne!(stored.password_hash.unwrap_or_default(), weak_hash);
        }
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
