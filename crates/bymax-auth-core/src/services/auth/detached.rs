//! The bodies of the flows' fire-and-forget side-effects, extracted into named async
//! functions so each is driven by a direct unit test (deterministic coverage) while the
//! flows schedule them detached via [`crate::services::auth::spawn_guarded`].
//!
//! Each function is a thin wrapper over a single hook/repository/email call (or, for the
//! rehash, the hash-then-persist pair). Errors are returned so the guarded spawn can log
//! and drop them; the flow itself never awaits these.

use std::sync::Arc;

use bymax_auth_types::{AuthError, SafeAuthUser};

use crate::RepositoryError;
use crate::services::auth::map_repository_error;
use crate::services::password::PasswordService;
use crate::traits::{AuthHooks, EmailError, EmailProvider, HookContext, HookError, UserRepository};

/// Invoke the `after_register` notification hook.
pub(crate) async fn run_after_register(
    hooks: Arc<dyn AuthHooks>,
    user: SafeAuthUser,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_register(&user, &ctx).await
}

/// Invoke the `after_login` notification hook.
pub(crate) async fn run_after_login(
    hooks: Arc<dyn AuthHooks>,
    user: SafeAuthUser,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_login(&user, &ctx).await
}

/// Invoke the `after_logout` notification hook.
pub(crate) async fn run_after_logout(
    hooks: Arc<dyn AuthHooks>,
    user_id: String,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_logout(&user_id, &ctx).await
}

/// Invoke the `after_email_verified` notification hook.
pub(crate) async fn run_after_email_verified(
    hooks: Arc<dyn AuthHooks>,
    user: SafeAuthUser,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_email_verified(&user, &ctx).await
}

/// Stamp the user's last successful login.
pub(crate) async fn run_update_last_login(
    repository: Arc<dyn UserRepository>,
    user_id: String,
) -> Result<(), RepositoryError> {
    repository.update_last_login(&user_id).await
}

/// Re-hash the just-proven plaintext with the current scheme and persist the upgrade — the
/// transparent rehash-on-verify path.
pub(crate) async fn run_rehash_password(
    passwords: Arc<PasswordService>,
    repository: Arc<dyn UserRepository>,
    password: String,
    user_id: String,
) -> Result<(), AuthError> {
    let new_hash = passwords.hash(&password).await?;
    repository
        .update_password(&user_id, &new_hash)
        .await
        .map_err(map_repository_error)
}

/// Send a verification OTP to the recipient.
pub(crate) async fn run_send_verification_email(
    provider: Arc<dyn EmailProvider>,
    email: String,
    otp: String,
) -> Result<(), EmailError> {
    provider
        .send_email_verification_otp(&email, &otp, None)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{SeedUser, base_config, harness};
    use crate::traits::{NoOpAuthHooks, NoOpEmailProvider, UserRepository};
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    fn safe_user(id: &str) -> SafeAuthUser {
        SafeAuthUser {
            id: id.to_owned(),
            email: "u@example.com".to_owned(),
            name: "U".to_owned(),
            role: "USER".to_owned(),
            status: "ACTIVE".to_owned(),
            tenant_id: "t1".to_owned(),
            email_verified: true,
            mfa_enabled: false,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn hook_ctx() -> HookContext {
        HookContext {
            user_id: Some("u1".to_owned()),
            email: Some("u@example.com".to_owned()),
            tenant_id: Some("t1".to_owned()),
            ip: "203.0.113.4".to_owned(),
            user_agent: "agent/1.0".to_owned(),
            sanitized_headers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn notification_hooks_run_against_the_noop_defaults() {
        // The four notification wrappers each invoke their hook and succeed on the NoOp impl.
        let hooks: Arc<dyn AuthHooks> = Arc::new(NoOpAuthHooks);
        assert!(
            run_after_register(hooks.clone(), safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_login(hooks.clone(), safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_logout(hooks.clone(), "u1".to_owned(), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_email_verified(hooks, safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn send_verification_email_invokes_the_provider() {
        // The email wrapper forwards to the provider (NoOp → Ok), never logging the OTP.
        let provider: Arc<dyn EmailProvider> = Arc::new(NoOpEmailProvider);
        assert!(
            run_send_verification_email(provider, "u@example.com".to_owned(), "123456".to_owned())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn update_last_login_stamps_the_user() {
        // The wrapper stamps last_login_at on the seeded user via the repository.
        let Some(h) = harness(base_config(), None) else { return };
        let id = h.seed(SeedUser::active("stamp@example.com", "pw")).await;
        assert!(
            run_update_last_login(h.users.clone(), id.clone())
                .await
                .is_ok()
        );
        let stored = h.users.find_by_id(&id, None).await;
        assert!(matches!(stored, Ok(Some(u)) if u.last_login_at.is_some()));
    }

    #[tokio::test]
    async fn rehash_password_persists_a_new_hash() {
        // The wrapper hashes the plaintext and replaces the stored hash with the upgrade.
        let Some(h) = harness(base_config(), None) else { return };
        let id = h.seed(SeedUser::active("rehash@example.com", "pw")).await;
        let before = h.users.find_by_id(&id, None).await;
        let Ok(Some(before)) = before else { return };
        let original = before.password_hash.clone().unwrap_or_default();
        assert!(
            run_rehash_password(
                h.engine.passwords().clone(),
                h.users.clone(),
                "pw".to_owned(),
                id.clone(),
            )
            .await
            .is_ok()
        );
        let after = h.users.find_by_id(&id, None).await;
        let Ok(Some(after)) = after else { return };
        // A fresh hash is produced (different salt), so the stored value changed.
        assert_ne!(after.password_hash.unwrap_or_default(), original);
    }
}
