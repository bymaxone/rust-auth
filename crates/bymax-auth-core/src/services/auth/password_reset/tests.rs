//! Harnesses and doubles shared by the password reset and password change tests
//! (layer: core services, test support).

use super::*;
use crate::services::auth::LoginInput;
use crate::services::auth::test_support::{Harness, SeedUser, base_config, ctx, harness};
use crate::traits::{EmailProvider, PasswordResetStore, SessionKind, SessionStore, UserRepository};
use bymax_auth_types::{AuthResult, CreateUserData, LoginResult};
use std::time::Duration;
use time::OffsetDateTime;

mod anti_enumeration_tests;
mod change_password_tests;
mod notification_tests;
mod order_contract;
mod proof_tests;
mod request_failure_tests;

fn token_harness() -> Option<Harness> {
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Token;
    harness(cfg, None)
}

fn otp_harness() -> Option<Harness> {
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Otp;
    harness(cfg, None)
}

/// Read back the live password hash for a user, for before/after comparisons.
async fn stored_hash(h: &Harness, id: &str) -> Option<String> {
    h.users
        .find_by_id(id, None)
        .await
        .ok()
        .flatten()
        .and_then(|user| user.password_hash)
}

fn forgot(email: &str) -> ForgotPasswordInput {
    ForgotPasswordInput {
        email: email.to_owned(),
        tenant_id: Some("t1".to_owned()),
    }
}

struct FailingResetEmail;

#[async_trait::async_trait]
impl crate::traits::EmailProvider for FailingResetEmail {
    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _new_email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }

    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Err(crate::traits::EmailError::Delivery("down".into()))
    }
    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_new_session_alert(
        &self,
        _tenant_id: &str,
        _email: &str,
        _session: &crate::traits::SessionInfo,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _email: &str,
        _invite: &crate::traits::InviteData,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
}

/// An email provider that keeps the reset token it was asked to deliver, so a test can
/// drive the flow with the token a real recipient would have received.
#[derive(Default)]
struct CapturingResetEmail {
    token: std::sync::Mutex<Option<String>>,
    /// Every "your password changed" notice, as the `(tenant_id, recipient)` it was sent
    /// with — the pair a multi-tenant channel routes on.
    password_changed: std::sync::Mutex<Vec<(String, String)>>,
}

impl CapturingResetEmail {
    /// The recorded notices; a poisoned lock (test-only) reads as none rather than panics.
    fn changed_notices(&self) -> Vec<(String, String)> {
        self.password_changed
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl crate::traits::EmailProvider for CapturingResetEmail {
    async fn send_password_changed(
        &self,
        tenant_id: &str,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        if let Ok(mut seen) = self.password_changed.lock() {
            seen.push((tenant_id.to_owned(), email.to_owned()));
        }
        Ok(())
    }

    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _new_email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }

    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        token: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        if let Ok(mut slot) = self.token.lock() {
            *slot = Some(token.to_owned());
        }
        Ok(())
    }
    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_new_session_alert(
        &self,
        _tenant_id: &str,
        _email: &str,
        _session: &crate::traits::SessionInfo,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _email: &str,
        _invite: &crate::traits::InviteData,
        _locale: Option<&str>,
    ) -> Result<(), crate::traits::EmailError> {
        Ok(())
    }
}

/// A hook spy recording the subject of every `after_password_reset` notification.
#[derive(Default)]
struct ResetHookSpy {
    subjects: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl crate::traits::AuthHooks for ResetHookSpy {
    async fn after_password_reset(
        &self,
        user: &SafeAuthUser,
        _ctx: &crate::traits::HookContext,
    ) -> Result<(), crate::traits::HookError> {
        if let Ok(mut subjects) = self.subjects.lock() {
            subjects.push(user.id.clone());
        }
        Ok(())
    }
}

/// A user repository whose `find_by_email` always fails with a backend error, to drive the
/// infra-error timing path of the anti-enumerating flows.
struct FailingLookupRepo;

#[async_trait::async_trait]
impl UserRepository for FailingLookupRepo {
    async fn update_email(
        &self,
        _id: &str,
        _tenant_id: &str,
        _email: &str,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }

    async fn find_by_id(
        &self,
        _id: &str,
        _tenant_id: Option<&str>,
    ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
        Ok(None)
    }
    async fn find_by_email(
        &self,
        _email: &str,
        _tenant_id: &str,
    ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
        Err(crate::RepositoryError::Backend("db down".into()))
    }
    async fn create(
        &self,
        _data: bymax_auth_types::CreateUserData,
    ) -> Result<bymax_auth_types::AuthUser, crate::RepositoryError> {
        Err(crate::RepositoryError::Backend("db down".into()))
    }
    async fn update_password(
        &self,
        _id: &str,
        _tenant_id: &str,
        _password_hash: &str,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn update_mfa(
        &self,
        _id: &str,
        _tenant_id: &str,
        _data: bymax_auth_types::UpdateMfaData,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn update_last_login(
        &self,
        _id: &str,
        _tenant_id: &str,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn update_status(
        &self,
        _id: &str,
        _tenant_id: &str,
        _status: &str,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn update_email_verified(
        &self,
        _id: &str,
        _tenant_id: &str,
        _verified: bool,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn find_by_oauth_id(
        &self,
        _provider: &str,
        _provider_id: &str,
        _tenant_id: &str,
    ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
        Ok(None)
    }
    async fn link_oauth(
        &self,
        _user_id: &str,
        _tenant_id: &str,
        _provider: &str,
        _provider_id: &str,
    ) -> Result<(), crate::RepositoryError> {
        Ok(())
    }
    async fn create_with_oauth(
        &self,
        _data: bymax_auth_types::CreateWithOAuthData,
    ) -> Result<bymax_auth_types::AuthUser, crate::RepositoryError> {
        Err(crate::RepositoryError::Backend("db down".into()))
    }
}

/// A minimal `CreateUserData`, for exercising the failing repository's `create`.
fn create_data() -> bymax_auth_types::CreateUserData {
    bymax_auth_types::CreateUserData {
        email: "e@example.com".to_owned(),
        name: "E".to_owned(),
        password_hash: Some("$scrypt$x".to_owned()),
        role: None,
        status: None,
        tenant_id: "t1".to_owned(),
        email_verified: None,
    }
}

/// A minimal `CreateWithOAuthData`, for exercising the failing repository's
/// `create_with_oauth`.
fn oauth_data() -> bymax_auth_types::CreateWithOAuthData {
    bymax_auth_types::CreateWithOAuthData {
        email: "e@example.com".to_owned(),
        name: "E".to_owned(),
        role: None,
        status: None,
        tenant_id: "t1".to_owned(),
        email_verified: Some(true),
        oauth_provider: "google".to_owned(),
        oauth_provider_id: "g-1".to_owned(),
    }
}

/// Log in and return the session, or `None` — so a caller's `let-else` fits on one line.
/// (Coverage is per line: an `unreachable!()` on its own line inside a multi-line `let-else`
/// is never executed, and reads as a gap.)
async fn login_ok(h: &Harness, email: &str, password: &str) -> Option<AuthResult> {
    let input = LoginInput {
        email: email.to_owned(),
        password: password.to_owned(),
        tenant_id: Some("t1".to_owned()),
    };
    let result = h.engine.login(input, &ctx()).await;
    let Ok(LoginResult::Success(auth)) = result else { return None };
    Some(*auth)
}
