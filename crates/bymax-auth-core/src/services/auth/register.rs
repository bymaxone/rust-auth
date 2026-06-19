//! The registration flow (§7.1.1). Registration always issues a full session — even when
//! email verification is required — so the host can render a "verify your email" screen for
//! an authenticated user; the *next* login after the access token expires is what enforces
//! verification.

use bymax_auth_types::{AuthError, AuthUser, CreateUserData, LoginResult, SafeAuthUser};

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::auth::detached::run_after_register;
use crate::services::auth::{RegisterInput, map_repository_error, spawn_guarded};
use crate::traits::{BeforeRegisterResult, HookContext, RegisterAttempt, RegisterOverrides};

impl AuthEngine {
    /// Register a new local (email + password) user, optionally dispatch a verification
    /// OTP, and issue a full session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] if the `before_register` hook rejects,
    /// [`AuthError::EmailAlreadyExists`] on a duplicate email within the tenant, or a
    /// hashing/store [`AuthError`]. Email verification never blocks registration.
    pub async fn register(
        &self,
        input: RegisterInput,
        ctx: &RequestContext,
    ) -> Result<LoginResult, AuthError> {
        // The resolver, when present, is authoritative — the body tenant is ignored (§24.8).
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let hook_ctx = HookContext::from_request(
            ctx,
            None,
            Some(input.email.clone()),
            Some(tenant_id.clone()),
        );

        // `before_register` is the one hook that can reject or override field defaults.
        let attempt = RegisterAttempt {
            email: input.email.clone(),
            name: input.name.clone(),
            tenant_id: tenant_id.clone(),
        };
        let overrides = match self.hooks().before_register(&attempt, &hook_ctx).await {
            Ok(BeforeRegisterResult::Allow(overrides)) => overrides,
            Ok(BeforeRegisterResult::Reject { .. }) | Err(_) => return Err(AuthError::Forbidden),
        };

        // Uniqueness-before-hash: never spend a memory-hard derivation on a duplicate email.
        if self
            .user_repository()
            .find_by_email(&input.email, &tenant_id)
            .await
            .map_err(map_repository_error)?
            .is_some()
        {
            return Err(AuthError::EmailAlreadyExists);
        }

        let user = self
            .provision_local_user(&input, &tenant_id, overrides)
            .await?;

        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens()
            .issue_tokens(&safe, &ctx.ip, &ctx.user_agent, false)
            .await?;

        // Enforce the concurrent-session cap (and fire the new-session hook) for the
        // just-issued session; a no-op when session tracking is disabled.
        self.enforce_sessions_after_issue(&result, &ctx.ip, &ctx.user_agent, &hook_ctx)
            .await?;

        // `after_register` is fire-and-forget under the timeout ceiling.
        spawn_guarded(run_after_register(self.hooks().clone(), safe, hook_ctx));

        Ok(LoginResult::Success(Box::new(result)))
    }

    /// Hash the password, persist the new user with the (possibly hook-overridden) fields,
    /// and — when verification is required — force the account unverified and dispatch a
    /// verification OTP (best-effort).
    ///
    /// # Errors
    ///
    /// Returns a hashing or store [`AuthError`] if the password cannot be hashed or the user
    /// cannot be created.
    async fn provision_local_user(
        &self,
        input: &RegisterInput,
        tenant_id: &str,
        overrides: RegisterOverrides,
    ) -> Result<AuthUser, AuthError> {
        let verification_required = self.config().config().email_verification.required;
        let password_hash = self.passwords().hash(&input.password).await?;

        // When verification is required the new account is forced unverified; otherwise an
        // explicit hook override (if any) is honored.
        let email_verified = if verification_required {
            Some(false)
        } else {
            overrides.email_verified
        };
        let create = CreateUserData {
            email: input.email.clone(),
            name: input.name.clone(),
            password_hash: Some(password_hash),
            role: overrides.role,
            status: overrides.status,
            tenant_id: tenant_id.to_owned(),
            email_verified,
        };
        let user = self
            .user_repository()
            .create(create)
            .await
            .map_err(map_repository_error)?;

        if verification_required {
            // Best-effort: an OTP-dispatch failure never fails registration.
            let _ = self
                .send_verification_otp(tenant_id, &user.email, &user.id)
                .await;
        }
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Environment};
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::{AuthHooks, HookError, NoOpAuthHooks};
    use secrecy::SecretString;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn base_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        #[cfg(not(feature = "scrypt"))]
        {
            cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
        }
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
        cfg
    }

    /// Build an engine from `cfg`; the fixtures always validate, so callers use `let-else`
    /// on the `Result` to stay panic-free under the workspace lints.
    fn engine(cfg: AuthConfig) -> Result<AuthEngine, crate::ConfigError> {
        AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(Arc::new(InMemoryUserRepository::new()))
            .redis_stores(Arc::new(InMemoryStores::new()))
            .build()
    }

    fn ctx() -> RequestContext {
        RequestContext::new(
            "203.0.113.4",
            "agent/1.0",
            std::collections::BTreeMap::new(),
        )
    }

    fn input(email: &str) -> RegisterInput {
        RegisterInput {
            email: email.to_owned(),
            name: "New User".to_owned(),
            password: "correct horse battery staple".to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    #[tokio::test]
    async fn happy_path_issues_a_session_without_requiring_verification() {
        // With verification off, registration creates the user and returns a full session.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Ok(engine) = engine(cfg) else { return };
        let result = engine.register(input("new@example.com"), &ctx()).await;
        assert!(matches!(&result, Ok(LoginResult::Success(_))));
        let Ok(LoginResult::Success(auth)) = result else { return };
        assert_eq!(auth.user.email, "new@example.com");
        assert!(!auth.access_token.is_empty());
        assert!(!auth.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn verification_required_forces_unverified_and_still_issues_tokens() {
        // With verification required the new account is unverified but still authenticated.
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        let Ok(engine) = engine(cfg) else { return };
        let result = engine.register(input("verify@example.com"), &ctx()).await;
        let Ok(LoginResult::Success(auth)) = result else { return };
        assert!(!auth.user.email_verified);
    }

    #[tokio::test]
    async fn duplicate_email_within_the_tenant_is_rejected() {
        // A second registration of the same email in the same tenant conflicts.
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let Ok(engine) = engine(cfg) else { return };
        let _ = engine.register(input("dup@example.com"), &ctx()).await;
        let again = engine.register(input("dup@example.com"), &ctx()).await;
        assert!(matches!(again, Err(AuthError::EmailAlreadyExists)));
    }

    /// A hook that rejects registration, to drive the `before_register` deny path.
    struct RejectingHooks;

    #[async_trait::async_trait]
    impl AuthHooks for RejectingHooks {
        async fn before_register(
            &self,
            _data: &RegisterAttempt,
            _ctx: &HookContext,
        ) -> Result<BeforeRegisterResult, HookError> {
            Ok(BeforeRegisterResult::Reject {
                reason: Some("no seats".to_owned()),
            })
        }
    }

    /// A hook whose blocking entry points fail, to drive the hook-error deny path.
    struct FailingHooks;

    #[async_trait::async_trait]
    impl AuthHooks for FailingHooks {
        async fn before_register(
            &self,
            _data: &RegisterAttempt,
            _ctx: &HookContext,
        ) -> Result<BeforeRegisterResult, HookError> {
            Err(HookError::Internal("boom".into()))
        }
    }

    fn engine_with_hooks(hooks: Arc<dyn AuthHooks>) -> Result<AuthEngine, crate::ConfigError> {
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(Arc::new(InMemoryUserRepository::new()))
            .redis_stores(Arc::new(InMemoryStores::new()))
            .hooks(hooks)
            .build()
    }

    #[tokio::test]
    async fn before_register_reject_and_error_both_forbid() {
        // A hook that returns Reject, and one that errors, both surface as Forbidden.
        let Ok(reject_engine) = engine_with_hooks(Arc::new(RejectingHooks)) else { return };
        let rejected = reject_engine.register(input("x@example.com"), &ctx()).await;
        assert!(matches!(rejected, Err(AuthError::Forbidden)));

        let Ok(fail_engine) = engine_with_hooks(Arc::new(FailingHooks)) else { return };
        let errored = fail_engine.register(input("y@example.com"), &ctx()).await;
        assert!(matches!(errored, Err(AuthError::Forbidden)));

        // The NoOp hooks allow registration (covers the Allow arm explicitly).
        let Ok(allow_engine) = engine_with_hooks(Arc::new(NoOpAuthHooks)) else { return };
        let allowed = allow_engine.register(input("z@example.com"), &ctx()).await;
        assert!(matches!(allowed, Ok(LoginResult::Success(_))));
    }
}
