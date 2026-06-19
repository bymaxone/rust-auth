//! In-memory implementations of the host-pluggable traits, used by this crate's own
//! coverage tier and exposed (under the `testing` feature) for downstream integration
//! tests that need a working engine without a real database, Redis, or HTTP backend.
//!
//! The store double reproduces the trait-level semantics the real Redis implementation
//! guarantees — single-use rotation with a grace pointer, ownership-checked revoke, OTP
//! attempt counting and single-use consume, fixed-window brute-force counters, and
//! single-use WebSocket tickets — over plain `Mutex<HashMap>` state.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_types::{
    AuthError, AuthPlatformUser, AuthUser, CreateUserData, CreateWithOAuthData, UpdateMfaData,
    UpdatePlatformMfaData,
};
use time::OffsetDateTime;

use crate::RepositoryError;
use crate::traits::{
    BruteForceStore, HttpClient, HttpError, HttpRequest, HttpResponse, OAuthProfile, OAuthProvider,
    OAuthProviderError, OAuthTokens, OtpPurpose, OtpStore, PlatformUserRepository, RotateOutcome,
    SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore, UserRepository,
    WsTicketSnapshot, WsTicketStore,
};

pub use crate::traits::{NoOpAuthHooks, NoOpEmailProvider};

/// Acquire a mutex guard, recovering the inner value if the lock was poisoned (a test
/// double never needs to escalate a poisoned lock to a panic).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An in-memory [`UserRepository`] backed by a `Mutex<HashMap>` keyed on user id.
#[derive(Debug, Default)]
pub struct InMemoryUserRepository {
    users: Mutex<HashMap<String, AuthUser>>,
    next_id: AtomicU64,
}

impl InMemoryUserRepository {
    /// Create an empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh, monotonically-increasing user id.
    fn allocate_id(&self) -> String {
        format!("user-{}", self.next_id.fetch_add(1, Ordering::Relaxed))
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_id(
        &self,
        id: &str,
        tenant_id: Option<&str>,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        let users = lock(&self.users);
        Ok(users
            .get(id)
            .filter(|u| match tenant_id {
                Some(tenant) => u.tenant_id == tenant,
                None => true,
            })
            .cloned())
    }

    async fn find_by_email(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        let users = lock(&self.users);
        Ok(users
            .values()
            .find(|u| u.email.eq_ignore_ascii_case(email) && u.tenant_id == tenant_id)
            .cloned())
    }

    async fn create(&self, data: CreateUserData) -> Result<AuthUser, RepositoryError> {
        let mut users = lock(&self.users);
        if users
            .values()
            .any(|u| u.email.eq_ignore_ascii_case(&data.email) && u.tenant_id == data.tenant_id)
        {
            return Err(RepositoryError::Conflict("email already exists".to_owned()));
        }
        let id = self.allocate_id();
        let user = AuthUser {
            id: id.clone(),
            email: data.email,
            name: data.name,
            password_hash: data.password_hash,
            role: data.role.unwrap_or_else(|| "USER".to_owned()),
            status: data.status.unwrap_or_else(|| "pending".to_owned()),
            tenant_id: data.tenant_id,
            email_verified: data.email_verified.unwrap_or(false),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        users.insert(id, user.clone());
        Ok(user)
    }

    async fn update_password(&self, id: &str, password_hash: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.password_hash = Some(password_hash.to_owned());
        }
        Ok(())
    }

    async fn update_mfa(&self, id: &str, data: UpdateMfaData) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.mfa_enabled = data.mfa_enabled;
            user.mfa_secret = data.mfa_secret;
            user.mfa_recovery_codes = data.mfa_recovery_codes;
        }
        Ok(())
    }

    async fn update_last_login(&self, id: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.last_login_at = Some(OffsetDateTime::UNIX_EPOCH);
        }
        Ok(())
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.status = status.to_owned();
        }
        Ok(())
    }

    async fn update_email_verified(&self, id: &str, verified: bool) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.email_verified = verified;
        }
        Ok(())
    }

    async fn find_by_oauth_id(
        &self,
        provider: &str,
        provider_id: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        let users = lock(&self.users);
        Ok(users
            .values()
            .find(|u| {
                u.tenant_id == tenant_id
                    && u.oauth_provider.as_deref() == Some(provider)
                    && u.oauth_provider_id.as_deref() == Some(provider_id)
            })
            .cloned())
    }

    async fn link_oauth(
        &self,
        user_id: &str,
        provider: &str,
        provider_id: &str,
    ) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(user_id) {
            user.oauth_provider = Some(provider.to_owned());
            user.oauth_provider_id = Some(provider_id.to_owned());
        }
        Ok(())
    }

    async fn create_with_oauth(
        &self,
        data: CreateWithOAuthData,
    ) -> Result<AuthUser, RepositoryError> {
        let mut users = lock(&self.users);
        if users
            .values()
            .any(|u| u.email.eq_ignore_ascii_case(&data.email) && u.tenant_id == data.tenant_id)
        {
            return Err(RepositoryError::Conflict("email already exists".to_owned()));
        }
        let id = self.allocate_id();
        let user = AuthUser {
            id: id.clone(),
            email: data.email,
            name: data.name,
            password_hash: None,
            role: data.role.unwrap_or_else(|| "USER".to_owned()),
            status: data.status.unwrap_or_else(|| "active".to_owned()),
            tenant_id: data.tenant_id,
            email_verified: data.email_verified.unwrap_or(false),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: Some(data.oauth_provider),
            oauth_provider_id: Some(data.oauth_provider_id),
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        users.insert(id, user.clone());
        Ok(user)
    }
}

/// An in-memory [`PlatformUserRepository`].
#[derive(Debug, Default)]
pub struct InMemoryPlatformUserRepository {
    users: Mutex<HashMap<String, AuthPlatformUser>>,
}

impl InMemoryPlatformUserRepository {
    /// Create an empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a platform admin (platform admins are provisioned directly, not created
    /// through the trait).
    pub fn insert(&self, user: AuthPlatformUser) {
        lock(&self.users).insert(user.id.clone(), user);
    }
}

#[async_trait]
impl PlatformUserRepository for InMemoryPlatformUserRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<AuthPlatformUser>, RepositoryError> {
        Ok(lock(&self.users).get(id).cloned())
    }

    async fn find_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AuthPlatformUser>, RepositoryError> {
        Ok(lock(&self.users)
            .values()
            .find(|u| u.email.eq_ignore_ascii_case(email))
            .cloned())
    }

    async fn update_last_login(&self, id: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.last_login_at = Some(OffsetDateTime::UNIX_EPOCH);
        }
        Ok(())
    }

    async fn update_mfa(
        &self,
        id: &str,
        data: UpdatePlatformMfaData,
    ) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.mfa_enabled = data.mfa_enabled;
            user.mfa_secret = data.mfa_secret;
            user.mfa_recovery_codes = data.mfa_recovery_codes;
        }
        Ok(())
    }

    async fn update_password(&self, id: &str, password_hash: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.password_hash = password_hash.to_owned();
        }
        Ok(())
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<(), RepositoryError> {
        if let Some(user) = lock(&self.users).get_mut(id) {
            user.status = status.to_owned();
        }
        Ok(())
    }
}

/// In-memory state backing every store trait, reproducing the atomic semantics the real
/// Redis implementation provides. A single handle satisfies `SessionStore + OtpStore +
/// BruteForceStore + WsTicketStore`, so it wires through `redis_stores`.
#[derive(Debug, Default)]
pub struct InMemoryStores {
    sessions: Mutex<HashMap<(SessionKind, String), SessionRecord>>,
    session_index: Mutex<HashMap<(SessionKind, String), Vec<SessionDetail>>>,
    grace: Mutex<HashMap<(SessionKind, String), SessionRecord>>,
    blacklist: Mutex<HashSet<String>>,
    otps: Mutex<HashMap<(OtpPurpose, String), (String, u32)>>,
    resend: Mutex<HashSet<(OtpPurpose, String)>>,
    brute_force: Mutex<HashMap<String, (i64, u64)>>,
    tickets: Mutex<HashMap<String, WsTicketSnapshot>>,
    ticket_counter: AtomicU64,
}

impl InMemoryStores {
    /// Create an empty store backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemoryStores {
    async fn create_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
        detail: &SessionRecord,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.sessions).insert((kind, token_hash.to_owned()), detail.clone());
        lock(&self.session_index)
            .entry((kind, detail.user_id.clone()))
            .or_default()
            .push(SessionDetail {
                session_hash: token_hash.to_owned(),
                device: detail.device.clone(),
                ip: detail.ip.clone(),
                created_at: detail.created_at,
                last_activity_at: detail.created_at,
            });
        Ok(())
    }

    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError> {
        let mut sessions = lock(&self.sessions);
        if let Some(old_record) = sessions.remove(&(kind, rotation.old_hash.clone())) {
            sessions.insert(
                (kind, rotation.new_hash.clone()),
                rotation.new_record.clone(),
            );
            lock(&self.grace).insert(
                (kind, rotation.old_hash.clone()),
                rotation.new_record.clone(),
            );
            let mut index = lock(&self.session_index);
            if let Some(details) = index.get_mut(&(kind, old_record.user_id.clone())) {
                details.retain(|d| d.session_hash != rotation.old_hash);
                details.push(SessionDetail {
                    session_hash: rotation.new_hash.clone(),
                    device: rotation.new_record.device.clone(),
                    ip: rotation.new_record.ip.clone(),
                    created_at: rotation.new_record.created_at,
                    last_activity_at: rotation.new_record.created_at,
                });
            }
            return Ok(RotateOutcome::Rotated(old_record));
        }
        if let Some(recovered) = lock(&self.grace).get(&(kind, rotation.old_hash.clone())) {
            return Ok(RotateOutcome::Grace(recovered.clone()));
        }
        Ok(RotateOutcome::Invalid)
    }

    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        Ok(lock(&self.sessions)
            .get(&(kind, token_hash.to_owned()))
            .cloned())
    }

    async fn list_sessions(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        Ok(lock(&self.session_index)
            .get(&(kind, user_id.to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        user_id: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        let mut index = lock(&self.session_index);
        let details = index
            .get_mut(&(kind, user_id.to_owned()))
            .ok_or(AuthError::SessionNotFound)?;
        let before = details.len();
        details.retain(|d| d.session_hash != session_hash);
        if details.len() == before {
            return Err(AuthError::SessionNotFound);
        }
        lock(&self.sessions).remove(&(kind, session_hash.to_owned()));
        Ok(())
    }

    async fn revoke_all(&self, kind: SessionKind, user_id: &str) -> Result<(), AuthError> {
        if let Some(details) = lock(&self.session_index).remove(&(kind, user_id.to_owned())) {
            let mut sessions = lock(&self.sessions);
            for detail in details {
                sessions.remove(&(kind, detail.session_hash));
            }
        }
        Ok(())
    }

    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        _remaining_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.blacklist).insert(jti_or_hash.to_owned());
        Ok(())
    }

    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError> {
        Ok(lock(&self.blacklist).contains(jti_or_hash))
    }
}

#[async_trait]
impl OtpStore for InMemoryStores {
    async fn put(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.otps).insert((purpose, identifier.to_owned()), (code.to_owned(), 0));
        Ok(())
    }

    async fn verify(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        max_attempts: u32,
    ) -> Result<(), AuthError> {
        let mut otps = lock(&self.otps);
        let key = (purpose, identifier.to_owned());
        let Some((stored, attempts)) = otps.get_mut(&key) else {
            return Err(AuthError::OtpExpired);
        };
        if *attempts >= max_attempts {
            otps.remove(&key);
            return Err(AuthError::OtpMaxAttempts);
        }
        if constant_time_eq(stored.as_bytes(), code.as_bytes()) {
            otps.remove(&key);
            return Ok(());
        }
        *attempts += 1;
        Err(AuthError::OtpInvalid)
    }

    async fn try_begin_resend(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        _cooldown_secs: u64,
    ) -> Result<bool, AuthError> {
        Ok(lock(&self.resend).insert((purpose, identifier.to_owned())))
    }
}

#[async_trait]
impl BruteForceStore for InMemoryStores {
    async fn is_locked(&self, identifier: &str, max_attempts: u32) -> Result<bool, AuthError> {
        Ok(lock(&self.brute_force)
            .get(identifier)
            .is_some_and(|(count, _)| *count >= i64::from(max_attempts)))
    }

    async fn record_failure(&self, identifier: &str, window_secs: u64) -> Result<i64, AuthError> {
        let mut counters = lock(&self.brute_force);
        let entry = counters
            .entry(identifier.to_owned())
            .or_insert((0, window_secs));
        entry.0 += 1;
        entry.1 = window_secs;
        Ok(entry.0)
    }

    async fn reset(&self, identifier: &str) -> Result<(), AuthError> {
        lock(&self.brute_force).remove(identifier);
        Ok(())
    }

    /// Returns the stored window while a counter exists (mirroring the real store, whose
    /// counter key carries the window TTL from the first failure), else `0`.
    async fn remaining_lockout_secs(&self, identifier: &str) -> Result<u64, AuthError> {
        Ok(lock(&self.brute_force)
            .get(identifier)
            .map_or(0, |(count, window)| if *count > 0 { *window } else { 0 }))
    }
}

#[async_trait]
impl WsTicketStore for InMemoryStores {
    async fn mint(&self, snapshot: &WsTicketSnapshot, _ttl_secs: u64) -> Result<String, AuthError> {
        let ticket = format!(
            "wst-{}",
            self.ticket_counter.fetch_add(1, Ordering::Relaxed)
        );
        lock(&self.tickets).insert(ticket.clone(), snapshot.clone());
        Ok(ticket)
    }

    async fn redeem(&self, ticket: &str) -> Result<Option<WsTicketSnapshot>, AuthError> {
        Ok(lock(&self.tickets).remove(ticket))
    }
}

/// A mock [`HttpClient`] that returns a fixed, configurable response.
#[derive(Debug, Clone)]
pub struct MockHttpClient {
    status: u16,
    body: Vec<u8>,
}

impl MockHttpClient {
    /// A client that always responds with the given status and body.
    #[must_use]
    pub fn with_body(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// A client that always responds `200 OK` with an empty body.
    #[must_use]
    pub fn ok() -> Self {
        Self::with_body(200, Vec::new())
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(&self, _req: HttpRequest) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

/// A mock [`OAuthProvider`] that returns canned tokens and a canned profile.
#[derive(Debug, Clone)]
pub struct MockOAuthProvider {
    name: String,
}

impl MockOAuthProvider {
    /// A provider registered under `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorize_url(&self, state: &str, code_challenge: Option<&str>) -> String {
        match code_challenge {
            Some(challenge) => {
                format!("https://mock.test/auth?state={state}&code_challenge={challenge}")
            }
            None => format!("https://mock.test/auth?state={state}"),
        }
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<OAuthTokens, OAuthProviderError> {
        Ok(OAuthTokens {
            access_token: "mock-access".to_owned(),
            token_type: "bearer".to_owned(),
            expires_in: Some(3600),
            scope: Some("openid email".to_owned()),
            id_token: None,
            refresh_token: None,
        })
    }

    async fn fetch_profile(&self, _access_token: &str) -> Result<OAuthProfile, OAuthProviderError> {
        Ok(OAuthProfile {
            provider: self.name.clone(),
            provider_id: "mock-123".to_owned(),
            email: "mock@example.com".to_owned(),
            name: Some("Mock User".to_owned()),
            avatar: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_data() -> CreateUserData {
        CreateUserData {
            email: "user@example.com".to_owned(),
            name: "User".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: None,
            status: None,
            tenant_id: "t1".to_owned(),
            email_verified: None,
        }
    }

    #[tokio::test]
    async fn user_repository_covers_create_find_update_and_oauth() {
        let repo = InMemoryUserRepository::new();
        // create + duplicate conflict.
        let created = repo.create(create_data()).await;
        assert!(matches!(&created, Ok(u) if u.role == "USER" && u.status == "pending"));
        let Ok(user) = created else { return };
        assert!(matches!(
            repo.create(create_data()).await,
            Err(RepositoryError::Conflict(_))
        ));

        // find_by_id: hit, tenant-mismatch miss, unknown miss.
        assert!(matches!(
            repo.find_by_id(&user.id, Some("t1")).await,
            Ok(Some(_))
        ));
        assert!(matches!(
            repo.find_by_id(&user.id, Some("other")).await,
            Ok(None)
        ));
        assert!(matches!(repo.find_by_id(&user.id, None).await, Ok(Some(_))));
        assert!(matches!(repo.find_by_id("missing", None).await, Ok(None)));

        // find_by_email: hit + miss.
        assert!(matches!(
            repo.find_by_email("user@example.com", "t1").await,
            Ok(Some(_))
        ));
        assert!(matches!(
            repo.find_by_email("nope@example.com", "t1").await,
            Ok(None)
        ));

        // updates on a present id, then on an absent id (no-op).
        assert!(repo.update_password(&user.id, "$scrypt$y").await.is_ok());
        assert!(repo.update_password("missing", "$scrypt$y").await.is_ok());
        assert!(
            repo.update_mfa(
                &user.id,
                UpdateMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some("enc".into()),
                    mfa_recovery_codes: Some(vec!["h".into()])
                }
            )
            .await
            .is_ok()
        );
        assert!(repo.update_last_login(&user.id).await.is_ok());
        assert!(repo.update_status(&user.id, "ACTIVE").await.is_ok());
        assert!(repo.update_email_verified(&user.id, true).await.is_ok());
        assert!(repo.update_last_login("missing").await.is_ok());
        assert!(repo.update_status("missing", "ACTIVE").await.is_ok());
        assert!(repo.update_email_verified("missing", true).await.is_ok());
        assert!(
            repo.update_mfa(
                "missing",
                UpdateMfaData {
                    mfa_enabled: false,
                    mfa_secret: None,
                    mfa_recovery_codes: None
                }
            )
            .await
            .is_ok()
        );

        // OAuth link + lookup, then a fresh OAuth user (and its conflict path).
        assert!(repo.link_oauth(&user.id, "google", "g-1").await.is_ok());
        assert!(repo.link_oauth("missing", "google", "g-1").await.is_ok());
        assert!(matches!(
            repo.find_by_oauth_id("google", "g-1", "t1").await,
            Ok(Some(_))
        ));
        assert!(matches!(
            repo.find_by_oauth_id("google", "absent", "t1").await,
            Ok(None)
        ));
        let oauth = CreateWithOAuthData {
            email: "oauth@example.com".to_owned(),
            name: "O".to_owned(),
            role: None,
            status: None,
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
            oauth_provider: "google".to_owned(),
            oauth_provider_id: "g-2".to_owned(),
        };
        assert!(
            matches!(repo.create_with_oauth(oauth.clone()).await, Ok(u) if u.status == "active")
        );
        assert!(matches!(
            repo.create_with_oauth(oauth).await,
            Err(RepositoryError::Conflict(_))
        ));
    }

    fn platform_user() -> AuthPlatformUser {
        AuthPlatformUser {
            id: "p1".to_owned(),
            email: "admin@example.com".to_owned(),
            name: "Admin".to_owned(),
            password_hash: "$scrypt$x".to_owned(),
            role: "PLATFORM_ADMIN".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            platform_id: None,
            last_login_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn platform_repository_covers_find_and_updates() {
        let repo = InMemoryPlatformUserRepository::new();
        repo.insert(platform_user());
        assert!(matches!(repo.find_by_id("p1").await, Ok(Some(_))));
        assert!(matches!(repo.find_by_id("missing").await, Ok(None)));
        assert!(matches!(
            repo.find_by_email("admin@example.com").await,
            Ok(Some(_))
        ));
        assert!(matches!(
            repo.find_by_email("nope@example.com").await,
            Ok(None)
        ));
        assert!(repo.update_last_login("p1").await.is_ok());
        assert!(
            repo.update_mfa(
                "p1",
                UpdatePlatformMfaData {
                    mfa_enabled: true,
                    mfa_secret: Some("enc".into()),
                    mfa_recovery_codes: None
                }
            )
            .await
            .is_ok()
        );
        assert!(repo.update_password("p1", "$scrypt$y").await.is_ok());
        assert!(repo.update_status("p1", "SUSPENDED").await.is_ok());
        // Absent-id no-ops.
        assert!(repo.update_last_login("missing").await.is_ok());
        assert!(
            repo.update_mfa(
                "missing",
                UpdatePlatformMfaData {
                    mfa_enabled: false,
                    mfa_secret: None,
                    mfa_recovery_codes: None
                }
            )
            .await
            .is_ok()
        );
        assert!(repo.update_password("missing", "h").await.is_ok());
        assert!(repo.update_status("missing", "X").await.is_ok());
    }

    fn record(user: &str) -> SessionRecord {
        SessionRecord {
            user_id: user.to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            device: "Chrome".to_owned(),
            ip: "203.0.113.4".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn session_store_covers_create_rotate_revoke_and_blacklist() {
        let store = InMemoryStores::new();
        let kind = SessionKind::Dashboard;
        assert!(
            store
                .create_session(kind, "h1", &record("u1"), 60)
                .await
                .is_ok()
        );
        assert!(matches!(store.find_session(kind, "h1").await, Ok(Some(_))));
        assert!(matches!(store.find_session(kind, "absent").await, Ok(None)));
        assert!(matches!(store.list_sessions(kind, "u1").await, Ok(v) if v.len() == 1));

        // Rotate h1 -> h2 (Rotated), then a second rotate of h1 hits the grace pointer.
        let rotation = SessionRotation {
            old_hash: "h1".to_owned(),
            new_hash: "h2".to_owned(),
            new_raw: "raw2".to_owned(),
            new_record: record("u1"),
            refresh_ttl: 60,
            grace_ttl: 30,
        };
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Rotated(_))
        ));
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Grace(_))
        ));
        // An unknown token rotates to Invalid.
        let unknown = SessionRotation {
            old_hash: "ghost".to_owned(),
            ..rotation
        };
        assert!(matches!(
            store.rotate(kind, &unknown).await,
            Ok(RotateOutcome::Invalid)
        ));

        // Ownership-checked revoke: unknown user, unknown hash, then the real one.
        assert!(matches!(
            store.revoke_session(kind, "ghost", "h2").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(matches!(
            store.revoke_session(kind, "u1", "absent").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(store.revoke_session(kind, "u1", "h2").await.is_ok());

        // revoke_all clears the remaining index entry (and the no-op empty case).
        assert!(
            store
                .create_session(kind, "h3", &record("u1"), 60)
                .await
                .is_ok()
        );
        assert!(store.revoke_all(kind, "u1").await.is_ok());
        assert!(store.revoke_all(kind, "nobody").await.is_ok());

        // Access blacklist.
        assert!(matches!(store.is_blacklisted("jti").await, Ok(false)));
        assert!(store.blacklist_access("jti", 30).await.is_ok());
        assert!(matches!(store.is_blacklisted("jti").await, Ok(true)));
    }

    #[tokio::test]
    async fn otp_store_covers_put_verify_outcomes_and_resend() {
        let store = InMemoryStores::new();
        let purpose = OtpPurpose::EmailVerification;
        assert!(matches!(
            store.verify(purpose, "id", "123456", 5).await,
            Err(AuthError::OtpExpired)
        ));
        assert!(store.put(purpose, "id", "123456", 600).await.is_ok());
        // A wrong code bumps attempts; the right code consumes.
        assert!(matches!(
            store.verify(purpose, "id", "000000", 5).await,
            Err(AuthError::OtpInvalid)
        ));
        assert!(store.verify(purpose, "id", "123456", 5).await.is_ok());
        // After consume the record is gone.
        assert!(matches!(
            store.verify(purpose, "id", "123456", 5).await,
            Err(AuthError::OtpExpired)
        ));
        // Max-attempts path: cap at 1, one wrong guess exhausts it.
        assert!(store.put(purpose, "max", "123456", 600).await.is_ok());
        assert!(matches!(
            store.verify(purpose, "max", "000000", 1).await,
            Err(AuthError::OtpInvalid)
        ));
        assert!(matches!(
            store.verify(purpose, "max", "123456", 1).await,
            Err(AuthError::OtpMaxAttempts)
        ));
        // Resend cooldown: first true, second false.
        assert!(matches!(
            store.try_begin_resend(purpose, "id", 60).await,
            Ok(true)
        ));
        assert!(matches!(
            store.try_begin_resend(purpose, "id", 60).await,
            Ok(false)
        ));
    }

    #[tokio::test]
    async fn brute_force_store_counts_within_a_fixed_window() {
        let store = InMemoryStores::new();
        assert!(matches!(store.is_locked("id", 3).await, Ok(false)));
        assert!(matches!(store.remaining_lockout_secs("id").await, Ok(0)));
        assert!(matches!(store.record_failure("id", 900).await, Ok(1)));
        assert!(matches!(store.record_failure("id", 900).await, Ok(2)));
        assert!(matches!(store.record_failure("id", 900).await, Ok(3)));
        assert!(matches!(store.is_locked("id", 3).await, Ok(true)));
        assert!(matches!(store.remaining_lockout_secs("id").await, Ok(900)));
        assert!(store.reset("id").await.is_ok());
        assert!(matches!(store.is_locked("id", 3).await, Ok(false)));
    }

    #[tokio::test]
    async fn ws_ticket_store_is_single_use() {
        let store = InMemoryStores::new();
        let snapshot = WsTicketSnapshot {
            sub: "u1".to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
        };
        let ticket = store.mint(&snapshot, 30).await;
        assert!(matches!(&ticket, Ok(t) if t.starts_with("wst-")));
        let Ok(ticket) = ticket else { return };
        assert!(matches!(store.redeem(&ticket).await, Ok(Some(_))));
        // A second redeem of the same ticket finds nothing (single-use).
        assert!(matches!(store.redeem(&ticket).await, Ok(None)));
    }

    #[tokio::test]
    async fn mock_http_client_and_oauth_provider_return_canned_values() {
        let client: Arc<dyn HttpClient> = Arc::new(MockHttpClient::with_body(200, b"hi".to_vec()));
        let res = client
            .send(HttpRequest {
                method: crate::traits::HttpMethod::Get,
                url: "https://mock.test".to_owned(),
                headers: Vec::new(),
                body: None,
            })
            .await;
        assert!(matches!(&res, Ok(r) if r.status == 200 && r.body == b"hi"));

        let provider = MockOAuthProvider::new("google");
        assert_eq!(provider.name(), "google");
        assert!(provider.authorize_url("s", None).contains("state=s"));
        assert!(
            provider
                .authorize_url("s", Some("c"))
                .contains("code_challenge=c")
        );
        assert!(
            matches!(provider.exchange_code("code", Some("v")).await, Ok(t) if t.token_type == "bearer")
        );
        assert!(matches!(provider.fetch_profile("tok").await, Ok(p) if p.provider == "google"));
    }
}
