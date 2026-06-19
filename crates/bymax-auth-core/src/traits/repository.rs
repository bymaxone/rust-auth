//! The persistence contracts: [`UserRepository`] for dashboard/tenant users and
//! [`PlatformUserRepository`] for the operator layer. The engine owns no database — it
//! reaches storage only through these object-safe traits, which the host implements
//! against its own tables.
//!
//! Tenant scoping is expressed entirely through method parameters: an implementation
//! translates `tenant_id` into the appropriate predicate so a cross-tenant read returns
//! `Ok(None)`, never another tenant's row. A missing row is `Ok(None)`, not an error —
//! [`crate::RepositoryError`] is reserved for genuine datastore failures.

use async_trait::async_trait;
use bymax_auth_types::{
    AuthPlatformUser, AuthUser, CreateUserData, CreateWithOAuthData, UpdateMfaData,
    UpdatePlatformMfaData,
};

use crate::RepositoryError;

/// The dashboard/tenant persistence contract. Implemented once by the host against its
/// user table and held on the engine as `Arc<dyn UserRepository>`.
///
/// # Errors
///
/// Every method returns [`RepositoryError::Conflict`] for a unique-constraint violation
/// (mapped onward to `auth.email_already_exists`) and [`RepositoryError::Backend`] for
/// any other datastore failure. Reads return `Ok(None)` for a missing or cross-tenant
/// row rather than an error.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by internal id. When `tenant_id` is `Some`, the row must belong to
    /// that tenant or `Ok(None)` is returned; pass `None` only for internal admin flows
    /// where cross-tenant access is intentional.
    async fn find_by_id(
        &self,
        id: &str,
        tenant_id: Option<&str>,
    ) -> Result<Option<AuthUser>, RepositoryError>;

    /// Find a user by email within a tenant (case-insensitive comparison recommended).
    async fn find_by_email(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError>;

    /// Insert a new local user. `data.password_hash` is a crypto-layer PHC hash, never
    /// plaintext.
    async fn create(&self, data: CreateUserData) -> Result<AuthUser, RepositoryError>;

    /// Replace the stored password hash. The argument is a crypto-layer hash, never
    /// plaintext.
    async fn update_password(&self, id: &str, password_hash: &str) -> Result<(), RepositoryError>;

    /// Apply a new TOTP MFA configuration (enable / disable / clear).
    async fn update_mfa(&self, id: &str, data: UpdateMfaData) -> Result<(), RepositoryError>;

    /// Stamp the current time as the user's last successful login.
    async fn update_last_login(&self, id: &str) -> Result<(), RepositoryError>;

    /// Update the account lifecycle status (e.g. `"active"`, `"suspended"`).
    async fn update_status(&self, id: &str, status: &str) -> Result<(), RepositoryError>;

    /// Mark the email verified or unverified.
    async fn update_email_verified(&self, id: &str, verified: bool) -> Result<(), RepositoryError>;

    /// Find a user by OAuth identity. Query by BOTH provider and provider id to avoid
    /// cross-provider id collisions, scoped by tenant for isolation.
    async fn find_by_oauth_id(
        &self,
        provider: &str,
        provider_id: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError>;

    /// Link an existing user to an OAuth identity.
    async fn link_oauth(
        &self,
        user_id: &str,
        provider: &str,
        provider_id: &str,
    ) -> Result<(), RepositoryError>;

    /// Insert a new user originating from OAuth (no local password).
    async fn create_with_oauth(
        &self,
        data: CreateWithOAuthData,
    ) -> Result<AuthUser, RepositoryError>;
}

/// The operator-layer persistence contract, required only when `platform.enabled`. It is
/// narrower than [`UserRepository`]: platform admins are not tenant-scoped, are
/// provisioned directly (no email verification), and authenticate with a local password
/// only (no OAuth).
///
/// # Errors
///
/// Same contract as [`UserRepository`]: `Ok(None)` for a missing row,
/// [`RepositoryError`] for a genuine datastore failure.
#[async_trait]
pub trait PlatformUserRepository: Send + Sync {
    /// Find a platform admin by internal id.
    async fn find_by_id(&self, id: &str) -> Result<Option<AuthPlatformUser>, RepositoryError>;

    /// Find a platform admin by email (case-insensitive recommended), used during login
    /// to locate the account before verifying the password.
    async fn find_by_email(&self, email: &str)
    -> Result<Option<AuthPlatformUser>, RepositoryError>;

    /// Stamp the current time as the admin's last successful login.
    async fn update_last_login(&self, id: &str) -> Result<(), RepositoryError>;

    /// Apply a new TOTP MFA configuration. The caller has already encrypted the secret
    /// (AES-256-GCM) and keyed-hashed the recovery codes (HMAC-SHA-256).
    async fn update_mfa(
        &self,
        id: &str,
        data: UpdatePlatformMfaData,
    ) -> Result<(), RepositoryError>;

    /// Replace the stored password hash (crypto-layer hash, never plaintext).
    async fn update_password(&self, id: &str, password_hash: &str) -> Result<(), RepositoryError>;

    /// Update the account lifecycle status.
    async fn update_status(&self, id: &str, status: &str) -> Result<(), RepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A trivial repository whose methods all succeed with empty results. It exists only
    /// to prove both repository traits are object-safe (storable as `Arc<dyn _>`).
    struct DummyRepo;

    #[async_trait]
    impl UserRepository for DummyRepo {
        async fn find_by_id(
            &self,
            _id: &str,
            _tenant_id: Option<&str>,
        ) -> Result<Option<AuthUser>, RepositoryError> {
            Ok(None)
        }
        async fn find_by_email(
            &self,
            _email: &str,
            _tenant_id: &str,
        ) -> Result<Option<AuthUser>, RepositoryError> {
            Ok(None)
        }
        async fn create(&self, _data: CreateUserData) -> Result<AuthUser, RepositoryError> {
            Err(RepositoryError::Conflict("dummy".into()))
        }
        async fn update_password(
            &self,
            _id: &str,
            _password_hash: &str,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_mfa(&self, _id: &str, _data: UpdateMfaData) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_last_login(&self, _id: &str) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_status(&self, _id: &str, _status: &str) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_email_verified(
            &self,
            _id: &str,
            _verified: bool,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn find_by_oauth_id(
            &self,
            _provider: &str,
            _provider_id: &str,
            _tenant_id: &str,
        ) -> Result<Option<AuthUser>, RepositoryError> {
            Ok(None)
        }
        async fn link_oauth(
            &self,
            _user_id: &str,
            _provider: &str,
            _provider_id: &str,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn create_with_oauth(
            &self,
            _data: CreateWithOAuthData,
        ) -> Result<AuthUser, RepositoryError> {
            Err(RepositoryError::Conflict("dummy".into()))
        }
    }

    #[async_trait]
    impl PlatformUserRepository for DummyRepo {
        async fn find_by_id(&self, _id: &str) -> Result<Option<AuthPlatformUser>, RepositoryError> {
            Ok(None)
        }
        async fn find_by_email(
            &self,
            _email: &str,
        ) -> Result<Option<AuthPlatformUser>, RepositoryError> {
            Ok(None)
        }
        async fn update_last_login(&self, _id: &str) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_mfa(
            &self,
            _id: &str,
            _data: UpdatePlatformMfaData,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_password(
            &self,
            _id: &str,
            _password_hash: &str,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn update_status(&self, _id: &str, _status: &str) -> Result<(), RepositoryError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn repository_traits_are_object_safe_and_callable() {
        // Storing the impls behind `Arc<dyn _>` only compiles if both traits are
        // object-safe; calling through the trait objects exercises the dispatch.
        let users: Arc<dyn UserRepository> = Arc::new(DummyRepo);
        let platform: Arc<dyn PlatformUserRepository> = Arc::new(DummyRepo);
        assert!(matches!(users.find_by_id("x", Some("t")).await, Ok(None)));
        assert!(matches!(users.find_by_email("e", "t").await, Ok(None)));
        assert!(users.create(sample_create()).await.is_err());
        assert!(users.update_password("x", "h").await.is_ok());
        assert!(
            users
                .update_mfa(
                    "x",
                    UpdateMfaData {
                        mfa_enabled: false,
                        mfa_secret: None,
                        mfa_recovery_codes: None
                    }
                )
                .await
                .is_ok()
        );
        assert!(users.update_last_login("x").await.is_ok());
        assert!(users.update_status("x", "ACTIVE").await.is_ok());
        assert!(users.update_email_verified("x", true).await.is_ok());
        assert!(matches!(
            users.find_by_oauth_id("google", "1", "t").await,
            Ok(None)
        ));
        assert!(users.link_oauth("x", "google", "1").await.is_ok());
        assert!(users.create_with_oauth(sample_oauth()).await.is_err());
        assert!(matches!(platform.find_by_id("p").await, Ok(None)));
        assert!(matches!(platform.find_by_email("e").await, Ok(None)));
        assert!(platform.update_last_login("p").await.is_ok());
        assert!(
            platform
                .update_mfa(
                    "p",
                    UpdatePlatformMfaData {
                        mfa_enabled: false,
                        mfa_secret: None,
                        mfa_recovery_codes: None
                    }
                )
                .await
                .is_ok()
        );
        assert!(platform.update_password("p", "h").await.is_ok());
        assert!(platform.update_status("p", "ACTIVE").await.is_ok());
    }

    fn sample_create() -> CreateUserData {
        CreateUserData {
            email: "e@example.com".into(),
            name: "E".into(),
            password_hash: Some("$scrypt$x".into()),
            role: None,
            status: None,
            tenant_id: "t".into(),
            email_verified: None,
        }
    }

    fn sample_oauth() -> CreateWithOAuthData {
        CreateWithOAuthData {
            email: "e@example.com".into(),
            name: "E".into(),
            role: None,
            status: None,
            tenant_id: "t".into(),
            email_verified: Some(true),
            oauth_provider: "google".into(),
            oauth_provider_id: "google-1".into(),
        }
    }
}
