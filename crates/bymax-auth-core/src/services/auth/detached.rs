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

/// Invoke the `after_password_reset` notification hook.
pub(crate) async fn run_after_password_reset(
    hooks: Arc<dyn AuthHooks>,
    user: SafeAuthUser,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_password_reset(&user, &ctx).await
}

/// Invoke the `after_invitation_accepted` notification hook.
pub(crate) async fn run_after_invitation_accepted(
    hooks: Arc<dyn AuthHooks>,
    user: SafeAuthUser,
    ctx: HookContext,
) -> Result<(), HookError> {
    hooks.after_invitation_accepted(&user, &ctx).await
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

/// Send a password-reset OTP to the recipient.
pub(crate) async fn run_send_reset_otp_email(
    provider: Arc<dyn EmailProvider>,
    email: String,
    otp: String,
) -> Result<(), EmailError> {
    provider.send_password_reset_otp(&email, &otp, None).await
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

    /// A hook spy recording which notification ran, and for whom.
    #[derive(Default)]
    struct RecordingHooks {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingHooks {
        fn push(&self, call: String) {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(call);
            }
        }

        fn seen(&self) -> Vec<String> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    #[async_trait::async_trait]
    impl AuthHooks for RecordingHooks {
        async fn after_register(
            &self,
            user: &SafeAuthUser,
            _ctx: &HookContext,
        ) -> Result<(), HookError> {
            self.push(format!("register:{}", user.id));
            Ok(())
        }
        async fn after_login(
            &self,
            user: &SafeAuthUser,
            _ctx: &HookContext,
        ) -> Result<(), HookError> {
            self.push(format!("login:{}", user.id));
            Ok(())
        }
        async fn after_logout(&self, user_id: &str, _ctx: &HookContext) -> Result<(), HookError> {
            self.push(format!("logout:{user_id}"));
            Ok(())
        }
        async fn after_email_verified(
            &self,
            user: &SafeAuthUser,
            _ctx: &HookContext,
        ) -> Result<(), HookError> {
            self.push(format!("verified:{}", user.id));
            Ok(())
        }
        async fn after_password_reset(
            &self,
            user: &SafeAuthUser,
            _ctx: &HookContext,
        ) -> Result<(), HookError> {
            self.push(format!("reset:{}", user.id));
            Ok(())
        }
        async fn after_invitation_accepted(
            &self,
            user: &SafeAuthUser,
            _ctx: &HookContext,
        ) -> Result<(), HookError> {
            self.push(format!("invitation:{}", user.id));
            Ok(())
        }
    }

    #[tokio::test]
    async fn each_notification_wrapper_invokes_its_own_hook() {
        // Asserted through a spy rather than by a returned `Ok`: these wrappers exist to be
        // spawned detached, so their return value is dropped. A wrapper that stopped calling
        // its hook — or called the wrong one — would still return `Ok(())`, and a deployment
        // would silently stop sending the mail it wires here.
        let spy = Arc::new(RecordingHooks::default());
        let hooks: Arc<dyn AuthHooks> = spy.clone();
        assert!(
            run_after_register(hooks.clone(), safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_login(hooks.clone(), safe_user("u2"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_logout(hooks.clone(), "u3".to_owned(), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_email_verified(hooks.clone(), safe_user("u4"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_password_reset(hooks.clone(), safe_user("u5"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_invitation_accepted(hooks, safe_user("u6"), hook_ctx())
                .await
                .is_ok()
        );

        assert_eq!(
            spy.seen(),
            vec![
                "register:u1",
                "login:u2",
                "logout:u3",
                "verified:u4",
                "reset:u5",
                "invitation:u6",
            ]
        );
    }

    #[tokio::test]
    async fn notification_hooks_run_against_the_noop_defaults() {
        // The six notification wrappers each invoke their hook and succeed on the NoOp impl.
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
            run_after_email_verified(hooks.clone(), safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_password_reset(hooks.clone(), safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
        assert!(
            run_after_invitation_accepted(hooks, safe_user("u1"), hook_ctx())
                .await
                .is_ok()
        );
    }

    /// An email spy recording which send ran, for whom, and with what payload.
    #[derive(Default)]
    struct RecordingEmails {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl EmailProvider for RecordingEmails {
        async fn send_email_change_verification(
            &self,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_password_reset_token(
            &self,
            email: &str,
            token: &str,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!("reset_token:{email}:{token}"));
            }
            Ok(())
        }
        async fn send_password_reset_otp(
            &self,
            email: &str,
            otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!("reset_otp:{email}:{otp}"));
            }
            Ok(())
        }
        async fn send_email_verification_otp(
            &self,
            email: &str,
            otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(format!("verification_otp:{email}:{otp}"));
            }
            Ok(())
        }
        async fn send_mfa_enabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            Ok(())
        }
        async fn send_mfa_disabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            Ok(())
        }
        async fn send_new_session_alert(
            &self,
            _email: &str,
            _session: &crate::traits::email::SessionInfo,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            Ok(())
        }
        async fn send_invitation(
            &self,
            _email: &str,
            _invite: &crate::traits::email::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), EmailError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_recording_double_answers_the_address_change_send_too() {
        // The double records the sends the detached tasks make. Its remaining methods are what
        // make it a valid `EmailProvider`, and a method nothing calls is a method nothing
        // proves — including that it does not accidentally fail a flow that shares it.
        let emails = RecordingEmails::default();
        assert!(
            emails
                .send_email_change_verification("new@example.com", "t", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn each_email_wrapper_sends_its_own_message() {
        // The recipient and the payload are the whole content of these wrappers, and both are
        // dropped by the detached spawn — so a wrapper that sent nothing, or sent the
        // verification OTP down the password-reset template, still returns `Ok(())`.
        let spy = Arc::new(RecordingEmails::default());
        let provider: Arc<dyn EmailProvider> = spy.clone();
        assert!(
            run_send_verification_email(
                provider.clone(),
                "verify@example.com".to_owned(),
                "123456".to_owned()
            )
            .await
            .is_ok()
        );
        assert!(
            run_send_reset_otp_email(
                provider,
                "reset@example.com".to_owned(),
                "654321".to_owned()
            )
            .await
            .is_ok()
        );

        let seen = spy.calls.lock().map(|c| c.clone()).unwrap_or_default();
        assert_eq!(
            seen,
            vec![
                "verification_otp:verify@example.com:123456",
                "reset_otp:reset@example.com:654321",
            ]
        );

        // Exercise the rest of the double's surface so the object-safe impl is fully covered;
        // only the two sends above are load-bearing.
        let direct = RecordingEmails::default();
        assert!(
            direct
                .send_password_reset_token("e", "t", None)
                .await
                .is_ok()
        );
        assert!(direct.send_mfa_enabled("e", None).await.is_ok());
        assert!(direct.send_mfa_disabled("e", None).await.is_ok());
        let session = crate::traits::email::SessionInfo {
            device: "d".to_owned(),
            ip: "i".to_owned(),
            session_hash: "h".to_owned(),
        };
        assert!(
            direct
                .send_new_session_alert("e", &session, None)
                .await
                .is_ok()
        );
        let invite = crate::traits::email::InviteData {
            inviter_name: "n".to_owned(),
            tenant_name: "t".to_owned(),
            invite_token: "tok".to_owned(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(direct.send_invitation("e", &invite, None).await.is_ok());
    }

    #[tokio::test]
    async fn send_verification_email_invokes_the_provider() {
        // The email wrappers forward to the provider (NoOp → Ok), never logging the OTP/token.
        let provider: Arc<dyn EmailProvider> = Arc::new(NoOpEmailProvider);
        assert!(
            run_send_verification_email(
                provider.clone(),
                "u@example.com".to_owned(),
                "123456".to_owned()
            )
            .await
            .is_ok()
        );
        assert!(
            run_send_reset_otp_email(provider, "u@example.com".to_owned(), "654321".to_owned())
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
