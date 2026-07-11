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
    BruteForceStore, HttpClient, HttpError, HttpRequest, HttpResponse, InvitationStore,
    OAuthProfile, OAuthProvider, OAuthProviderError, OAuthTokens, OtpPurpose, OtpStore,
    PasswordResetStore, PlatformUserRepository, ResetContext, RotateOutcome, SessionDetail,
    SessionKind, SessionRecord, SessionRotation, SessionStore, StoredInvitation, UserRepository,
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
    /// `cf:` consumed-token markers: an already-rotated token's hash → the family it belonged
    /// to. Outlives the grace pointer (which the real store keys with the shorter grace TTL),
    /// so a post-grace replay of the consumed token is detected as a reuse rather than a plain
    /// invalid. Keyed by `(kind, old_hash)`.
    consumed: Mutex<HashMap<(SessionKind, String), String>>,
    /// `fam:` family index: a family id → the set of its live session hashes, so a whole
    /// lineage can be revoked on reuse detection. Keyed by `(kind, family_id)`.
    families: Mutex<HashMap<(SessionKind, String), HashSet<String>>>,
    /// `ep:`/`pep:` per-user token epoch (generation counter), keyed by `(kind, user_id)`. A
    /// bump invalidates every access token stamped below the new value. Absent reads as `0`.
    epochs: Mutex<HashMap<(SessionKind, String), u64>>,
    blacklist: Mutex<HashSet<String>>,
    otps: Mutex<HashMap<(OtpPurpose, String), (String, u32)>>,
    resend: Mutex<HashSet<(OtpPurpose, String)>>,
    brute_force: Mutex<HashMap<String, (i64, u64)>>,
    tickets: Mutex<HashMap<String, WsTicketSnapshot>>,
    ticket_counter: AtomicU64,
    reset_tokens: Mutex<HashMap<String, ResetContext>>,
    reset_verified: Mutex<HashMap<String, ResetContext>>,
    invitations: Mutex<HashMap<String, StoredInvitation>>,
    /// `mfa_setup:` — the AES-protected pending-setup record keyed by `hmac_sha256(user_id)`.
    #[cfg(feature = "mfa")]
    mfa_setup: Mutex<HashMap<String, String>>,
    /// `mfa:` — the MFA temp-token single-use marker keyed by `sha256(jti)`.
    #[cfg(feature = "mfa")]
    mfa_temp: Mutex<HashMap<String, String>>,
    /// `tu:` — the TOTP anti-replay markers keyed by `hmac_sha256("{user_id}:{code}")`.
    #[cfg(feature = "mfa")]
    mfa_replay: Mutex<HashSet<String>>,
    /// `os:` — the single-use OAuth `state` + PKCE payload keyed by `sha256(state)`.
    #[cfg(feature = "oauth")]
    oauth_state: Mutex<HashMap<String, String>>,
}

impl InMemoryStores {
    /// Create an empty store backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the stored OTP code for a purpose + identifier without consuming it. A test-only
    /// inspection helper (the real store never exposes a stored code), used to drive the
    /// verification flow end to end against the in-memory double.
    #[must_use]
    pub fn peek_otp(&self, purpose: OtpPurpose, identifier: &str) -> Option<String> {
        lock(&self.otps)
            .get(&(purpose, identifier.to_owned()))
            .map(|(code, _attempts)| code.clone())
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
        // Register the new session in its family index (a fresh login, or the grace-path fork),
        // so the whole lineage is revocable on reuse detection. A legacy record with no family
        // simply carries no index entry.
        if !detail.family_id.is_empty() {
            lock(&self.families)
                .entry((kind, detail.family_id.clone()))
                .or_default()
                .insert(token_hash.to_owned());
        }
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
            // Family bookkeeping: mark the consumed old token (so a post-grace replay is caught
            // as a reuse, not a plain invalid) and move the family membership from old to new.
            // Old and new share the inherited family id.
            if !old_record.family_id.is_empty() {
                lock(&self.consumed).insert(
                    (kind, rotation.old_hash.clone()),
                    old_record.family_id.clone(),
                );
                if let Some(members) =
                    lock(&self.families).get_mut(&(kind, old_record.family_id.clone()))
                {
                    members.remove(&rotation.old_hash);
                    members.insert(rotation.new_hash.clone());
                }
            }
            return Ok(RotateOutcome::Rotated(old_record));
        }
        if let Some(recovered) = lock(&self.grace).get(&(kind, rotation.old_hash.clone())) {
            return Ok(RotateOutcome::Grace(recovered.clone()));
        }
        // Neither live nor in grace: a surviving consumed-token marker means this token was
        // validly issued and already rotated — a reuse of a consumed token (its grace window
        // has closed). Surface the compromised family for the caller to revoke.
        if let Some(family) = lock(&self.consumed).get(&(kind, rotation.old_hash.clone())) {
            return Ok(RotateOutcome::Reused(family.clone()));
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

    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        // The grace pointer is keyed by the OLD token's hash; deleting it (idempotently) blocks a
        // post-logout grace-window recovery, mirroring the real store's `DEL rp:`/`prp:`.
        lock(&self.grace).remove(&(kind, session_hash.to_owned()));
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

    async fn revoke_family(&self, kind: SessionKind, family_id: &str) -> Result<(), AuthError> {
        // Idempotent: an empty, unknown, or already-cleared family drops nothing.
        if family_id.is_empty() {
            return Ok(());
        }
        let Some(hashes) = lock(&self.families).remove(&(kind, family_id.to_owned())) else {
            return Ok(());
        };
        let mut sessions = lock(&self.sessions);
        let mut index = lock(&self.session_index);
        for hash in hashes {
            // Every live descendant of the compromised login is deleted, and pruned from its
            // owner's session index (all family members share one user).
            if let Some(record) = sessions.remove(&(kind, hash.clone()))
                && let Some(details) = index.get_mut(&(kind, record.user_id.clone()))
            {
                details.retain(|detail| detail.session_hash != hash);
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

    async fn current_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError> {
        Ok(lock(&self.epochs)
            .get(&(kind, user_id.to_owned()))
            .copied()
            .unwrap_or(0))
    }

    async fn bump_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError> {
        let mut epochs = lock(&self.epochs);
        let entry = epochs.entry((kind, user_id.to_owned())).or_insert(0);
        *entry += 1;
        Ok(*entry)
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
        // The window is recorded once, when the counter is created on the first failure —
        // a fixed window that does not slide as later failures arrive.
        let entry = counters
            .entry(identifier.to_owned())
            .or_insert((0, window_secs));
        entry.0 += 1;
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

/// Hash an opaque token to its store-key form, mirroring the real store's
/// "the raw token is never a key" guarantee (so the test double exercises the same
/// hash-then-key path the engine relies on).
fn token_key(token: &str) -> String {
    let mut out = String::with_capacity(64);
    for byte in bymax_auth_crypto::mac::sha256(token.as_bytes()) {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

#[async_trait]
impl PasswordResetStore for InMemoryStores {
    async fn put_token(
        &self,
        token: &str,
        context: &ResetContext,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.reset_tokens).insert(token_key(token), context.clone());
        Ok(())
    }

    async fn consume_token(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        Ok(lock(&self.reset_tokens).remove(&token_key(token)))
    }

    async fn delete_token(&self, token: &str) -> Result<(), AuthError> {
        lock(&self.reset_tokens).remove(&token_key(token));
        Ok(())
    }

    async fn put_verified(
        &self,
        token: &str,
        context: &ResetContext,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.reset_verified).insert(token_key(token), context.clone());
        Ok(())
    }

    async fn consume_verified(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        Ok(lock(&self.reset_verified).remove(&token_key(token)))
    }
}

#[async_trait]
impl InvitationStore for InMemoryStores {
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &StoredInvitation,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.invitations).insert(token_key(token), invitation.clone());
        Ok(())
    }

    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        Ok(lock(&self.invitations).remove(&token_key(token)))
    }
}

#[cfg(feature = "mfa")]
#[async_trait]
impl crate::traits::MfaStore for InMemoryStores {
    async fn put_setup_nx(
        &self,
        user_id_hash: &str,
        value: &str,
        _ttl: u64,
    ) -> Result<bool, AuthError> {
        let mut setups = lock(&self.mfa_setup);
        // Reproduce `SET NX`: write only when absent, reporting whether this call created it.
        if setups.contains_key(user_id_hash) {
            return Ok(false);
        }
        setups.insert(user_id_hash.to_owned(), value.to_owned());
        Ok(true)
    }

    async fn get_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError> {
        Ok(lock(&self.mfa_setup).get(user_id_hash).cloned())
    }

    async fn take_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError> {
        // Reproduce `GETDEL`: read and remove in one critical section so the completion gate
        // admits exactly one winner.
        Ok(lock(&self.mfa_setup).remove(user_id_hash))
    }

    async fn put_temp(&self, jti_hash: &str, user_id: &str, _ttl: u64) -> Result<(), AuthError> {
        lock(&self.mfa_temp).insert(jti_hash.to_owned(), user_id.to_owned());
        Ok(())
    }

    async fn get_temp(&self, jti_hash: &str) -> Result<Option<String>, AuthError> {
        Ok(lock(&self.mfa_temp).get(jti_hash).cloned())
    }

    async fn del_temp(&self, jti_hash: &str) -> Result<(), AuthError> {
        lock(&self.mfa_temp).remove(jti_hash);
        Ok(())
    }

    async fn mark_totp_used(&self, replay_id: &str, _ttl: u64) -> Result<bool, AuthError> {
        // `HashSet::insert` returns whether the value was newly added — exactly the `SET NX`
        // "was it new?" decision the real `tu:` marker reports.
        Ok(lock(&self.mfa_replay).insert(replay_id.to_owned()))
    }

    async fn challenge_consume(
        &self,
        replay_id: &str,
        jti_hash: &str,
        _ttl: u64,
    ) -> Result<bool, AuthError> {
        // Fuse the marker-set and the temp-token consume under one lock pair so the two are
        // inseparable, mirroring the atomic Lua. The temp-token removal is the single-consume
        // gate: success requires BOTH that this code was freshly marked AND that the temp token
        // was still present to remove.
        let mut replay = lock(&self.mfa_replay);
        if !replay.insert(replay_id.to_owned()) {
            // The code was already used: a replay. Leave both maps untouched.
            return Ok(false);
        }
        // A distinct still-valid code that lost the race for an already-consumed temp token must
        // not be burned: only confirm success when the temp-token marker actually went away, and
        // otherwise roll back the marker we just inserted.
        if lock(&self.mfa_temp).remove(jti_hash).is_some() {
            Ok(true)
        } else {
            replay.remove(replay_id);
            Ok(false)
        }
    }
}

#[cfg(feature = "oauth")]
#[async_trait]
impl crate::traits::OAuthStateStore for InMemoryStores {
    async fn put_state(
        &self,
        state_hash: &str,
        payload: &str,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.oauth_state).insert(state_hash.to_owned(), payload.to_owned());
        Ok(())
    }

    async fn take_state(&self, state_hash: &str) -> Result<Option<String>, AuthError> {
        // Reproduce `GETDEL`: read and remove in one critical section so a captured `state`
        // can be consumed exactly once.
        Ok(lock(&self.oauth_state).remove(state_hash))
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
        record_in_family(user, "fam-1")
    }

    fn record_in_family(user: &str, family: &str) -> SessionRecord {
        SessionRecord {
            user_id: user.to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            device: "Chrome".to_owned(),
            ip: "203.0.113.4".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            family_id: family.to_owned(),
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
    async fn session_store_detects_reuse_and_revokes_the_family() {
        let store = InMemoryStores::new();
        let kind = SessionKind::Dashboard;
        // A login in family "famA", then a rotation h1 -> h2 (same inherited family).
        assert!(
            store
                .create_session(kind, "h1", &record_in_family("u1", "famA"), 60)
                .await
                .is_ok()
        );
        let rotation = SessionRotation {
            old_hash: "h1".to_owned(),
            new_hash: "h2".to_owned(),
            new_raw: "raw2".to_owned(),
            new_record: record_in_family("u1", "famA"),
            refresh_ttl: 60,
            grace_ttl: 30,
        };
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Rotated(_))
        ));
        // Inside the grace window, replaying the consumed token recovers rather than trips reuse.
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Grace(_))
        ));
        // Once the grace pointer is gone (the window has closed), the surviving consumed marker
        // makes the same replay a REUSE carrying the compromised family id.
        assert!(store.delete_grace_pointer(kind, "h1").await.is_ok());
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Reused(family)) if family == "famA"
        ));
        // The live descendant h2 is present until the family is revoked; revoke_family then
        // deletes it and clears the owner's index, and is idempotent on unknown/empty families.
        assert!(matches!(store.find_session(kind, "h2").await, Ok(Some(_))));
        assert!(store.revoke_family(kind, "famA").await.is_ok());
        assert!(matches!(store.find_session(kind, "h2").await, Ok(None)));
        assert!(matches!(store.list_sessions(kind, "u1").await, Ok(v) if v.is_empty()));
        assert!(store.revoke_family(kind, "famA").await.is_ok());
        assert!(store.revoke_family(kind, "").await.is_ok());

        // A legacy session with no family plants no consumed marker, so a post-grace replay is a
        // plain Invalid, never a reuse.
        assert!(
            store
                .create_session(kind, "g1", &record_in_family("u2", ""), 60)
                .await
                .is_ok()
        );
        let legacy = SessionRotation {
            old_hash: "g1".to_owned(),
            new_hash: "g2".to_owned(),
            new_raw: "rawg".to_owned(),
            new_record: record_in_family("u2", ""),
            refresh_ttl: 60,
            grace_ttl: 30,
        };
        assert!(matches!(
            store.rotate(kind, &legacy).await,
            Ok(RotateOutcome::Rotated(_))
        ));
        assert!(store.delete_grace_pointer(kind, "g1").await.is_ok());
        assert!(matches!(
            store.rotate(kind, &legacy).await,
            Ok(RotateOutcome::Invalid)
        ));
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
    async fn password_reset_store_consumes_tokens_single_use() {
        // The reset-link and verified tokens both store a context, consume once (getdel), and
        // the link token can be deleted out-of-band after an undeliverable email.
        let store = InMemoryStores::new();
        let context = ResetContext {
            user_id: "u1".to_owned(),
            email: "u@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
        };
        assert!(store.put_token("tok", &context, 600).await.is_ok());
        assert!(matches!(
            store.consume_token("tok").await,
            Ok(Some(c)) if c.user_id == "u1"
        ));
        // Single-use: a second consume finds nothing.
        assert!(matches!(store.consume_token("tok").await, Ok(None)));

        // delete_token removes an unconsumed token (the undeliverable-email cleanup path).
        assert!(
            store
                .put_token("undeliverable", &context, 600)
                .await
                .is_ok()
        );
        assert!(store.delete_token("undeliverable").await.is_ok());
        assert!(matches!(
            store.consume_token("undeliverable").await,
            Ok(None)
        ));

        // The verified token mirrors the same single-use semantics on its own keyspace.
        assert!(store.put_verified("vtok", &context, 300).await.is_ok());
        assert!(matches!(
            store.consume_verified("vtok").await,
            Ok(Some(c)) if c.email == "u@example.com"
        ));
        assert!(matches!(store.consume_verified("vtok").await, Ok(None)));
    }

    #[tokio::test]
    async fn invitation_store_consumes_invitations_single_use() {
        // An invitation is stored and consumed exactly once.
        let store = InMemoryStores::new();
        let invitation = StoredInvitation {
            email: "invitee@example.com".to_owned(),
            role: "MEMBER".to_owned(),
            tenant_id: "t1".to_owned(),
            inviter_user_id: "owner".to_owned(),
        };
        assert!(
            store
                .put_invitation("inv-tok", &invitation, 600)
                .await
                .is_ok()
        );
        assert!(matches!(
            store.consume_invitation("inv-tok").await,
            Ok(Some(i)) if i.role == "MEMBER"
        ));
        assert!(matches!(
            store.consume_invitation("inv-tok").await,
            Ok(None)
        ));
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

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn oauth_state_store_consumes_state_single_use() {
        // The `os:` payload is stored under its state hash and consumed exactly once (getdel).
        use crate::traits::OAuthStateStore;
        let store = InMemoryStores::new();
        assert!(store.put_state("statehash", "payload", 600).await.is_ok());
        assert!(matches!(
            store.take_state("statehash").await,
            Ok(Some(p)) if p == "payload"
        ));
        // A second take finds nothing (single-use), as does an unknown hash.
        assert!(matches!(store.take_state("statehash").await, Ok(None)));
        assert!(matches!(store.take_state("absent").await, Ok(None)));
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
