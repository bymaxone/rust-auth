//! In-memory implementations of the host-pluggable traits, used by this crate's own
//! coverage tier and exposed (under the `testing` feature) for downstream integration
//! tests that need a working engine without a real database, Redis, or HTTP backend.
//!
//! The store double reproduces the trait-level semantics the real Redis implementation
//! guarantees — single-use rotation with a grace pointer, ownership-checked revoke, OTP
//! attempt counting and single-use consume, fixed-window brute-force counters, and
//! single-use WebSocket tickets — over plain `Mutex<HashMap>` state.

// Only the MFA transition lock uses the entry API, and that lives behind the feature — an
// unconditional import is an unused one under `--no-default-features --features testing`.
#[cfg(feature = "mfa")]
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_types::{
    AuthError, AuthPlatformUser, AuthUser, CreateUserData, CreateWithOAuthData, UpdateMfaData,
    UpdatePlatformMfaData,
};
use time::OffsetDateTime;

use crate::RepositoryError;
use crate::traits::{
    BruteForceStore, EmailChangeContext, HttpClient, HttpError, HttpRequest, HttpResponse,
    InvitationStore, OAuthProfile, OAuthProvider, OAuthProviderError, OAuthTokens, OtpPurpose,
    OtpStore, PasswordResetStore, PlatformUserRepository, ResetContext, RotateOutcome,
    SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore, StoredInvitation,
    UserRepository, WsTicketSnapshot, WsTicketStore,
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
    /// When set, `find_by_email` drops its `tenant_id` argument — reproducing the
    /// single-tenant host that writes `find_by_email(email)` and ignores the second parameter.
    /// The engine cannot make a consumer's repository scope correctly; it can only refuse an
    /// answer from the wrong tenant, and testing that refusal needs a repository that actually
    /// returns one.
    ignore_tenant_on_email_lookup: AtomicBool,
    /// When set and raised, every read reports the account with MFA gone.
    ///
    /// A transition re-reads the account inside its lock, and the mutation abandons when that
    /// re-read reports MFA gone — a `disable` that completed while the caller was in flight.
    /// Nothing single-threaded can land a write in that window, so the flag is raised BY the
    /// lock (see `InMemoryStores::raise_on_next_mfa_lock`), which is the boundary itself: the
    /// caller's copy is read before it, the transition's copy after.
    mfa_gone_flag: Mutex<Option<Arc<AtomicBool>>>,
    /// Armed count of `find_by_id` reads that must fail with a datastore error.
    ///
    /// Every authorization path that re-reads the account propagates a repository failure
    /// rather than treating it as "no such user" — the difference between refusing a request
    /// the store could not answer and silently deciding it. A double that always succeeds
    /// leaves that propagation unasserted.
    forced_read_failures: Mutex<usize>,
}

impl InMemoryUserRepository {
    /// Create an empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make `find_by_email` ignore its `tenant_id`, as a misconfigured consumer repository
    /// would. See the field of the same name.
    pub fn ignore_tenant_on_email(&self) {
        self.ignore_tenant_on_email_lookup
            .store(true, Ordering::SeqCst);
    }

    /// Report MFA gone on every read taken once `flag` is raised — the completed `disable` a
    /// transition's re-read has to see. The flag is raised by the MFA transition lock, which is
    /// the boundary: the caller's copy is read before it, the transition's copy after.
    pub fn report_mfa_gone_when(&self, flag: Arc<AtomicBool>) {
        *lock(&self.mfa_gone_flag) = Some(flag);
    }

    /// Fail the next `count` `find_by_id` reads with a datastore error, so a path that
    /// propagates a repository failure rather than reading it as "no such account" can be
    /// asserted against a store that would otherwise always succeed.
    pub fn fail_next_reads(&self, count: usize) {
        *lock(&self.forced_read_failures) = count;
    }

    /// Whether the armed flag is currently raised.
    fn mfa_reported_gone(&self) -> bool {
        lock(&self.mfa_gone_flag)
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
    }

    /// Delete a user outright, so a test can drive the "the account is gone but its session
    /// record outlived it" branch. Returns whether a row was removed.
    ///
    /// The `UserRepository` trait deliberately has no delete — account deletion is the host's
    /// domain — so this exists only on the double, and only to reach a branch the engine has
    /// to handle when a host does delete one.
    pub fn remove(&self, id: &str) -> bool {
        lock(&self.users).remove(id).is_some()
    }

    /// Move a user's authority — role, tenant, or both — the way an operator's own admin
    /// surface would, so a test can drive the "the account was demoted while a session was
    /// live" branch. Returns whether a row was updated.
    ///
    /// The `UserRepository` trait has no role or tenant mutator: who may do what is the
    /// host's domain, not the engine's. This exists only on the double, to reach a branch the
    /// engine has to handle once a host does move someone.
    pub fn set_authority(&self, id: &str, role: Option<&str>, tenant_id: Option<&str>) -> bool {
        let mut users = lock(&self.users);
        let Some(user) = users.get_mut(id) else { return false };
        if let Some(role) = role {
            user.role = role.to_owned();
        }
        if let Some(tenant_id) = tenant_id {
            user.tenant_id = tenant_id.to_owned();
        }
        true
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
        {
            let mut armed = lock(&self.forced_read_failures);
            if *armed > 0 {
                *armed -= 1;
                return Err(RepositoryError::Backend("forced read failure".into()));
            }
        }
        let users = lock(&self.users);
        let answer = users
            .get(id)
            .filter(|u| match tenant_id {
                Some(scope) => u.tenant_id == scope,
                None => true,
            })
            .cloned();
        drop(users);
        // The flag is raised by the transition lock, so a read taken before it sees the account
        // as it was and a read taken after it sees the `disable` that completed in between.
        if self.mfa_reported_gone() {
            return Ok(answer.map(|mut user| {
                user.mfa_enabled = false;
                user.mfa_secret = None;
                user.mfa_recovery_codes = None;
                user
            }));
        }
        Ok(answer)
    }

    async fn find_by_email(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        let users = lock(&self.users);
        let scoped = !self.ignore_tenant_on_email_lookup.load(Ordering::SeqCst);
        Ok(users
            .values()
            .find(|u| u.email.eq_ignore_ascii_case(email) && (!scoped || u.tenant_id == tenant_id))
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

    async fn update_mfa(
        &self,
        id: &str,
        tenant_id: Option<&str>,
        data: UpdateMfaData,
    ) -> Result<(), RepositoryError> {
        // Scoped like `find_by_id`, and deliberately so: a fixture repository that honoured the
        // tenant on reads but ignored it on writes would let a cross-tenant write test pass
        // while the property it asserts does not hold. The fixture has to be at least as strict
        // as the contract the trait states, or it tests the fixture instead of the library.
        if let Some(user) = lock(&self.users)
            .get_mut(id)
            .filter(|user| tenant_id.is_none_or(|scope| user.tenant_id == scope))
        {
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

    async fn update_email(&self, id: &str, email: &str) -> Result<(), RepositoryError> {
        // The address is proven before this runs, so the account stays verified across the
        // change — a store that cleared the flag here would sign the user out of a state it
        // had just proved.
        let mut users = lock(&self.users);
        if let Some(user) = users.get_mut(id) {
            user.email = email.to_owned();
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
    /// The platform twin of the dashboard repository's MFA-gone flag, for the transitions that
    /// route to this repository.
    mfa_gone_flag: Mutex<Option<Arc<AtomicBool>>>,
}

impl InMemoryPlatformUserRepository {
    /// Report MFA gone on every read taken once `flag` is raised. See
    /// [`InMemoryUserRepository::report_mfa_gone_when`].
    pub fn report_mfa_gone_when(&self, flag: Arc<AtomicBool>) {
        *lock(&self.mfa_gone_flag) = Some(flag);
    }

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

    /// Delete an admin outright, so a test can drive the "the account is gone but its session
    /// record outlived it" branch. Returns whether a row was removed.
    ///
    /// `PlatformUserRepository` deliberately has no delete — provisioning operators is the
    /// host's domain — so this exists only on the double, and only to reach a branch the engine
    /// has to handle when a host does remove one.
    pub fn remove(&self, id: &str) -> bool {
        lock(&self.users).remove(id).is_some()
    }
}

#[async_trait]
impl PlatformUserRepository for InMemoryPlatformUserRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<AuthPlatformUser>, RepositoryError> {
        let answer = lock(&self.users).get(id).cloned();
        let gone = lock(&self.mfa_gone_flag)
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst));
        if gone {
            return Ok(answer.map(|mut admin| {
                admin.mfa_enabled = false;
                admin.mfa_secret = None;
                admin.mfa_recovery_codes = None;
                admin
            }));
        }
        Ok(answer)
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
    /// `sess:`/`psess:` — the per-account session index, keyed by `(kind, subject_hash)`. The
    /// subject hash is what the real store keys on, so the double keys on it too: keying the
    /// double on the bare user id while production keyed on the subject is precisely the shape
    /// of divergence that lets a test pass against the double and the deployment misbehave.
    session_index: Mutex<HashMap<(SessionKind, String), Vec<SessionDetail>>>,
    /// `rp:`/`prp:` — rotation grace pointers, keyed by `(kind, old_hash)` and carrying the
    /// owner's subject hash beside the recovered record.
    ///
    /// The subject is stored rather than recomputed because this double holds no hashing key,
    /// and both `revoke_all` and `sweep_grace_pointers` have to find every pointer ONE account
    /// owns — the real store finds them as members of that account's `sess:` set, which is the
    /// same question asked a different way.
    grace: Mutex<HashMap<(SessionKind, String), (String, SessionRecord)>>,
    /// `cf:` consumed-token markers: an already-rotated token's hash → the family it belonged
    /// to. Outlives the grace pointer (which the real store keys with the shorter grace TTL),
    /// so a post-grace replay of the consumed token is detected as a reuse rather than a plain
    /// invalid. Keyed by `(kind, old_hash)`.
    consumed: Mutex<HashMap<(SessionKind, String), String>>,
    /// Recent-authentication markers, keyed by plane + id hash. No TTL is modelled: the double
    /// is driven by explicit calls, so expiry is expressed by not planting one.
    recent_auth: Mutex<HashMap<String, ()>>,
    /// `fam:` family index: a family id → the set of its live session hashes, so a whole
    /// lineage can be revoked on reuse detection. Keyed by `(kind, family_id)`.
    families: Mutex<HashMap<(SessionKind, String), HashSet<String>>>,
    /// How many upcoming best-effort cleanup writes must fail with a backend error, set
    /// through [`InMemoryStores::fail_next_cleanup_writes`]. Zero — the default — means every
    /// call behaves normally.
    forced_write_failures: Mutex<usize>,
    /// Armed count of `create_recovered_session` calls that must report the account swept.
    ///
    /// The real refusal is a race: a `revoke_all` landing between the grace pointer's read and
    /// the recovery's write. A coherent store cannot produce it single-threaded — this one
    /// refuses the grace arm outright once the lineage is dead, so the write is never reached
    /// with a dead account — and the engine's answer to it (refuse, do not mint) is exactly the
    /// behaviour worth pinning. Arming the answer is what makes that reachable.
    forced_recovery_refusals: Mutex<usize>,
    /// Raised the first time the MFA transition lock is granted, so a test can place a
    /// completed `disable` in the one window `transition_mfa_record` re-reads across.
    disable_mfa_on_lock: Mutex<Option<Arc<AtomicBool>>>,
    /// Armed count of `bump_epoch` calls that must fail.
    ///
    /// The bump is the second half of a device revoke, and it runs after the session is already
    /// gone — so a failure there leaves the operation visibly incomplete rather than silently
    /// half-done, and the caller has to hear about it. A store that always succeeds leaves that
    /// propagation unasserted.
    forced_epoch_bump_failures: Mutex<usize>,
    /// `ep:`/`pep:` per-account token epoch (generation counter), keyed by
    /// `(kind, subject_hash)`. A bump invalidates every access token stamped below the new
    /// value. Absent reads as `0`.
    epochs: Mutex<HashMap<(SessionKind, String), u64>>,
    /// The refresh TTL the last `rotate` was given, in seconds — the session-touch path's
    /// copy of the same lifetime, wired separately from the token manager's.
    last_rotate_ttl_secs: Mutex<Option<u64>>,
    /// The TTL the last `create_session` was given, in seconds. The real store turns this
    /// into the key's expiry — the only thing that makes a session end on its own — so it is
    /// recorded rather than discarded, and read back through [`InMemoryStores::peek_session_ttl`].
    last_session_ttl_secs: Mutex<Option<u64>>,
    blacklist: Mutex<HashSet<String>>,
    otps: Mutex<HashMap<(OtpPurpose, String), (String, u32)>>,
    resend: Mutex<HashSet<(OtpPurpose, String)>>,
    brute_force: Mutex<HashMap<String, (i64, u64)>>,
    /// `(reads still to let through, reads to fail after them)` for `is_locked`, set through
    /// [`InMemoryStores::fail_lockout_reads`]. `(0, 0)` — the default — reads normally.
    forced_lockout_read_failures: Mutex<(usize, usize)>,
    tickets: Mutex<HashMap<String, WsTicketSnapshot>>,
    ticket_counter: AtomicU64,
    reset_tokens: Mutex<HashMap<String, ResetContext>>,
    reset_verified: Mutex<HashMap<String, ResetContext>>,
    invitations: Mutex<HashMap<String, StoredInvitation>>,
    /// The invitee index: `{tenantId}:{sha256(email)}` -> the invitation's token hash.
    invitation_index: Mutex<HashMap<String, String>>,
    /// Pending address changes (`ec:`), keyed by the token hash.
    email_changes: Mutex<HashMap<String, EmailChangeContext>>,
    /// `mfa_setup:` — the AES-protected pending-setup record keyed by `hmac_sha256(user_id)`.
    #[cfg(feature = "mfa")]
    mfa_setup: Mutex<HashMap<String, String>>,
    /// `mfa:` — the MFA temp-token single-use marker keyed by `sha256(jti)`.
    #[cfg(feature = "mfa")]
    mfa_temp: Mutex<HashMap<String, String>>,
    /// `tu:` — the TOTP anti-replay markers keyed by `hmac_sha256("{user_id}:{code}")`.
    #[cfg(feature = "mfa")]
    mfa_replay: Mutex<HashSet<String>>,
    /// Single-use claims on MFA recovery codes (`rcu:`).
    #[cfg(feature = "mfa")]
    recovery_claims: Mutex<HashSet<String>>,
    /// Held per-account MFA transition locks (`mfalock:`), each mapped to the token of the call
    /// holding it. A separate keyspace from the recovery claims: a code claim and a transition
    /// lock must never contend. The token is stored, not discarded, because the release is a
    /// compare-and-delete — a double that dropped it would accept a release from any caller and
    /// so could never fail the way the real store can.
    #[cfg(feature = "mfa")]
    mfa_locks: Mutex<HashMap<String, String>>,
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

    /// Make the next `count` best-effort cleanup writes fail with a backend error.
    ///
    /// Covers the calls the library deliberately swallows — `revoke_session`,
    /// `delete_grace_pointer`, and the reset-token rollback `delete_token` — because logout,
    /// over-cap eviction, and an undeliverable reset link must not fail on the store's account.
    /// That swallowing leaves those paths unreachable against a double that always succeeds,
    /// and so unasserted. Arming a finite number of failures is what lets a test prove the
    /// failure is handled and reported rather than merely assumed to be. Counts down per
    /// affected call; the default of zero leaves every call behaving normally.
    pub fn fail_next_cleanup_writes(&self, count: usize) {
        *lock(&self.forced_write_failures) = count;
    }

    /// Make the next `count` `create_recovered_session` calls report the account swept — the
    /// race a coherent store cannot produce single-threaded, since it refuses the grace arm
    /// outright once the lineage is dead, so the write is never reached with a dead account.
    pub fn refuse_next_recovered_writes(&self, count: usize) {
        *lock(&self.forced_recovery_refusals) = count;
    }

    /// Raise `flag` when the next MFA transition lock is granted, placing a completed `disable`
    /// in the one window `transition_mfa_record` re-reads across.
    pub fn raise_on_next_mfa_lock(&self, flag: Arc<AtomicBool>) {
        *lock(&self.disable_mfa_on_lock) = Some(flag);
    }

    /// Fail the next `count` `bump_epoch` calls. The bump is the second half of a device
    /// revoke and runs after the session is already gone, so a failure there has to reach the
    /// caller rather than leave the operation silently half-done.
    pub fn fail_next_epoch_bumps(&self, count: usize) {
        *lock(&self.forced_epoch_bump_failures) = count;
    }

    /// Let the next `skip` `is_locked` reads through, then fail `count` of them.
    ///
    /// `skip` is what makes this usable: one login performs two of these reads, and they are
    /// answered very differently. The gate at the top propagates a store failure — a lockout
    /// that cannot be read is a lockout assumed, which is the safe direction. The second read
    /// decides whether the failure just recorded closed the window, and THAT one is swallowed:
    /// a store that cannot say means the *hook* cannot be decided, not that the login should
    /// answer differently. Skipping the gate read is the only way to reach the swallowed arm,
    /// which is otherwise unreachable against a double that always succeeds.
    pub fn fail_lockout_reads(&self, skip: usize, count: usize) {
        *lock(&self.forced_lockout_read_failures) = (skip, count);
    }

    /// Consume one armed lockout-read failure, if any.
    fn take_forced_lockout_read_failure(&self) -> Result<(), AuthError> {
        let mut armed = lock(&self.forced_lockout_read_failures);
        let (skip, remaining) = *armed;
        if skip > 0 {
            *armed = (skip - 1, remaining);
            return Ok(());
        }
        if remaining == 0 {
            return Ok(());
        }
        *armed = (0, remaining - 1);
        Err(AuthError::Internal("brute-force store unavailable".into()))
    }

    /// Consume one armed failure, if any, returning the error the caller should surface.
    fn take_forced_failure(&self) -> Result<(), AuthError> {
        let mut remaining = lock(&self.forced_write_failures);
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(AuthError::Internal("session store unavailable".into()))
    }

    /// The TTL the last created session was stored with, in seconds. A test-only inspection
    /// helper: the double cannot expire anything, so without this the lifetime the engine
    /// computes would be unobservable.
    #[must_use]
    pub fn peek_session_ttl(&self) -> Option<u64> {
        *lock(&self.last_session_ttl_secs)
    }

    /// The refresh TTL the last rotation was stored with, in seconds. A test-only inspection
    /// helper, for the same reason as [`InMemoryStores::peek_session_ttl`].
    #[must_use]
    pub fn peek_rotate_ttl(&self) -> Option<u64> {
        *lock(&self.last_rotate_ttl_secs)
    }

    /// Drop the resend-cooldown marker for `(purpose, identifier)`, letting a test drive a
    /// second issuance without waiting out the window. Returns whether a marker was held.
    ///
    /// Production has no such door: the cooldown is what keeps a caller from re-minting an OTP
    /// (and with it a fresh `attempts: 0`) as often as they like. A test that needs two
    /// issuances is testing something else and says so by calling this.
    pub fn expire_resend_cooldown(&self, purpose: OtpPurpose, identifier: &str) -> bool {
        lock(&self.resend).remove(&(purpose, identifier.to_owned()))
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
    async fn create_recovered_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<bool, AuthError> {
        // The real store gates the write on the per-user index still existing, because
        // `invalidate_user_sessions` deletes that set once it has emptied it. The in-memory
        // twin models the same witness: `revoke_all` removes the entry, so its absence is
        // exactly "a revoke-all ran while this recovery was in flight".
        {
            let mut armed = lock(&self.forced_recovery_refusals);
            if *armed > 0 {
                *armed -= 1;
                return Ok(false);
            }
        }
        if !lock(&self.session_index).contains_key(&(kind, subject_hash.to_owned())) {
            return Ok(false);
        }
        if !detail.family_id.is_empty()
            && !lock(&self.families).contains_key(&(kind, detail.family_id.clone()))
        {
            return Ok(false);
        }
        self.create_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await?;
        Ok(true)
    }

    async fn create_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        *lock(&self.last_session_ttl_secs) = Some(ttl_secs);
        lock(&self.sessions).insert((kind, token_hash.to_owned()), detail.clone());
        lock(&self.session_index)
            .entry((kind, subject_hash.to_owned()))
            .or_default()
            .push(SessionDetail {
                session_hash: token_hash.to_owned(),
                device: detail.device.clone(),
                ip: detail.ip.clone(),
                created_at: detail.created_at,
                last_activity_at: detail.created_at,
            });
        // Register the new session in its family index (a fresh login, or the grace-path fork),
        // so the whole lineage is revocable on reuse detection. A record with no family
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
        *lock(&self.last_rotate_ttl_secs) = Some(rotation.refresh_ttl);
        let mut sessions = lock(&self.sessions);
        if let Some(old_record) = sessions.remove(&(kind, rotation.old_hash.clone())) {
            sessions.insert(
                (kind, rotation.new_hash.clone()),
                rotation.new_record.clone(),
            );
            lock(&self.grace).insert(
                (kind, rotation.old_hash.clone()),
                (rotation.subject_hash.clone(), rotation.new_record.clone()),
            );
            let mut index = lock(&self.session_index);
            if let Some(details) = index.get_mut(&(kind, rotation.subject_hash.clone())) {
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
        // The grace window is single-shot, and only recovers into a lineage that is still alive.
        // Removing the pointer keeps one captured token from minting a fresh session on every
        // request for the whole window; the family check closes the resurrection path, where a
        // pointer planted by an earlier rotation of a lineage outlives the reuse detection that
        // revoked it and would hand the thief back the family the lockout just killed. Both
        // mirror the Redis store, whose script consumes the pointer and whose host side runs the
        // same `family_is_alive` test — the in-memory store is what the conformance tier and
        // nest-auth's end-to-end tier run against, so a weaker rule here would let a divergence
        // ship unnoticed. A record that names no family recovers as
        // before.
        if let Some((_subject, recovered)) =
            lock(&self.grace).remove(&(kind, rotation.old_hash.clone()))
        {
            if recovered.family_id.is_empty()
                || lock(&self.families).contains_key(&(kind, recovered.family_id.clone()))
            {
                return Ok(RotateOutcome::Grace(recovered));
            }
            return Ok(RotateOutcome::Invalid);
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
        subject_hash: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        Ok(lock(&self.session_index)
            .get(&(kind, subject_hash.to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.take_forced_failure()?;
        let mut index = lock(&self.session_index);
        let details = index
            .get_mut(&(kind, subject_hash.to_owned()))
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
        self.take_forced_failure()?;
        // The grace pointer is keyed by the OLD token's hash; deleting it (idempotently) blocks a
        // post-logout grace-window recovery, mirroring the real store's `DEL rp:`/`prp:`.
        lock(&self.grace).remove(&(kind, session_hash.to_owned()));
        Ok(())
    }

    async fn sweep_grace_pointers(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<(), AuthError> {
        self.take_forced_failure()?;
        // Every pointer this account owns, not just one hash: the real store reads the `rp:`
        // members out of the account's session index, and each pointer here carries the subject
        // whose index it was added to, so the in-memory twin filters on that.
        lock(&self.grace)
            .retain(|(entry_kind, _), (owner, _)| *entry_kind != kind || owner != subject_hash);
        Ok(())
    }

    async fn revoke_all(&self, kind: SessionKind, subject_hash: &str) -> Result<(), AuthError> {
        if let Some(details) = lock(&self.session_index).remove(&(kind, subject_hash.to_owned())) {
            let mut sessions = lock(&self.sessions);
            for detail in details {
                sessions.remove(&(kind, detail.session_hash));
            }
        }
        // Every grace pointer the user holds goes too. The real store deletes them because they
        // are members of the same `sess:` index the sweep walks (`invalidate_user_sessions.lua`),
        // and they are keyed by the SUPERSEDED hash — which is not the hash the index carries
        // after a rotation, so mirroring this by index membership alone would miss them. A
        // double that keeps them is *weaker* than production: a token inside its grace window
        // would still recover a session after "sign out everywhere", a password reset, or an
        // MFA change, which is the exact property those flows exist to guarantee.
        lock(&self.grace).retain(|(k, _), (owner, _)| *k != kind || owner != subject_hash);
        Ok(())
    }

    async fn find_family_owner(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        if family_id.is_empty() {
            return Ok(None);
        }
        let families = lock(&self.families);
        let Some(hashes) = families.get(&(kind, family_id.to_owned())) else {
            return Ok(None);
        };
        let sessions = lock(&self.sessions);
        Ok(hashes
            .iter()
            .filter_map(|hash| sessions.get(&(kind, hash.clone())))
            .find(|record| !record.user_id.is_empty())
            .cloned())
    }

    async fn revoke_family(
        &self,
        kind: SessionKind,
        family_id: &str,
        owner_subject_hash: Option<&str>,
    ) -> Result<(), AuthError> {
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
            // owner's session index (all family members share one login, so one subject).
            sessions.remove(&(kind, hash.clone()));
            if let Some(owner) = owner_subject_hash
                && let Some(details) = index.get_mut(&(kind, owner.to_owned()))
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

    async fn current_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        Ok(lock(&self.epochs)
            .get(&(kind, subject_hash.to_owned()))
            .copied()
            .unwrap_or(0))
    }

    async fn mark_recent_auth(&self, user_id_hash: &str, _ttl: u64) -> Result<(), AuthError> {
        lock(&self.recent_auth).insert(user_id_hash.to_owned(), ());
        Ok(())
    }

    async fn has_recent_auth(&self, user_id_hash: &str) -> Result<bool, AuthError> {
        Ok(lock(&self.recent_auth).contains_key(user_id_hash))
    }

    async fn bump_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        {
            let mut armed = lock(&self.forced_epoch_bump_failures);
            if *armed > 0 {
                *armed -= 1;
                return Err(AuthError::Internal("forced epoch bump failure".into()));
            }
        }
        let mut epochs = lock(&self.epochs);
        let entry = epochs.entry((kind, subject_hash.to_owned())).or_insert(0);
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
        self.take_forced_lockout_read_failure()?;
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
    /// counter key carries the window TTL from the first failure), else `0`. A stored counter
    /// is always at least 1 — `record_failure` inserts and increments under one lock, and
    /// `reset` removes the entry outright — so the entry's existence is the whole condition.
    async fn remaining_lockout_secs(&self, identifier: &str) -> Result<u64, AuthError> {
        Ok(lock(&self.brute_force)
            .get(identifier)
            .map_or(0, |(_, window)| *window))
    }
}

#[async_trait]
impl WsTicketStore for InMemoryStores {
    async fn mint(&self, snapshot: &WsTicketSnapshot, _ttl_secs: u64) -> Result<String, AuthError> {
        // The real store mints `generate_secure_token(32)` — 64 lower-case hex — and the engine
        // shape-checks a presented ticket before hashing it, so a double that minted `wst-0`
        // produced tickets its own engine refuses. A double whose output shape differs from the
        // real one cannot exercise the guard it is supposed to pass through. The counter still
        // rides along so a test can tell two tickets apart by their prefix.
        let ticket = bymax_auth_crypto::token::generate_secure_token(32);
        let _ = self.ticket_counter.fetch_add(1, Ordering::Relaxed);
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
/// The invitee index key, mirroring the Redis store's `invidx:{tenantId}:{invitee_hash}`.
/// The identifier arrives already derived, and is used verbatim — see
/// [`crate::traits::InvitationStore::put_invitation_index`].
fn invitee_key(tenant_id: &str, invitee_hash: &str) -> String {
    format!("{tenant_id}:{invitee_hash}")
}

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
    async fn put_email_change(
        &self,
        token: &str,
        context: &EmailChangeContext,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.email_changes).insert(token_key(token), context.clone());
        Ok(())
    }

    async fn consume_email_change(
        &self,
        token: &str,
    ) -> Result<Option<EmailChangeContext>, AuthError> {
        Ok(lock(&self.email_changes).remove(&token_key(token)))
    }

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
        self.take_forced_failure()?;
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

    async fn put_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
        token_hash: &str,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        lock(&self.invitation_index).insert(invitee_key(tenant_id, email), token_hash.to_owned());
        Ok(())
    }

    async fn read_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<String>, AuthError> {
        Ok(lock(&self.invitation_index)
            .get(&invitee_key(tenant_id, email))
            .cloned())
    }

    async fn take_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<String>, AuthError> {
        Ok(lock(&self.invitation_index).remove(&invitee_key(tenant_id, email)))
    }

    async fn read_invitation_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredInvitation>, AuthError> {
        Ok(lock(&self.invitations).get(token_hash).cloned())
    }

    async fn delete_invitation_by_hash(&self, token_hash: &str) -> Result<bool, AuthError> {
        Ok(lock(&self.invitations).remove(token_hash).is_some())
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

    async fn del_temp(&self, jti_hash: &str) -> Result<bool, AuthError> {
        // `HashMap::remove` answers with the previous value — present exactly for the caller
        // that removed it, which is the same exactly-once signal Redis's `DEL` count gives.
        Ok(lock(&self.mfa_temp).remove(jti_hash).is_some())
    }

    async fn mark_totp_used(&self, replay_id: &str, _ttl: u64) -> Result<bool, AuthError> {
        // `HashSet::insert` returns whether the value was newly added — exactly the `SET NX`
        // "was it new?" decision the real `tu:` marker reports.
        Ok(lock(&self.mfa_replay).insert(replay_id.to_owned()))
    }

    async fn claim_recovery_code(&self, claim_id: &str, _ttl: u64) -> Result<bool, AuthError> {
        // Same "was it new?" decision as the TOTP marker, over its own set so a code and a
        // TOTP value can never collide into one another's claim.
        Ok(lock(&self.recovery_claims).insert(claim_id.to_owned()))
    }

    async fn acquire_mfa_lock(
        &self,
        lock_id: &str,
        token: &str,
        _ttl: u64,
    ) -> Result<bool, AuthError> {
        // The same "was it new?" decision, over its own keyspace: a transition lock and a
        // recovery claim must never contend with one another. `Entry::Vacant` is the in-memory
        // spelling of `SET NX` — it writes the token only when nobody holds the lock.
        match lock(&self.mfa_locks).entry(lock_id.to_owned()) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(slot) => {
                slot.insert(token.to_owned());
                // Raised only on the GRANTED arm. Firing it on a refusal too would arm the
                // window for a caller that never entered it, which is the opposite of what the
                // flag models: the `disable` is supposed to land inside a lock somebody holds.
                if let Some(flag) = lock(&self.disable_mfa_on_lock).take() {
                    flag.store(true, Ordering::SeqCst);
                }
                Ok(true)
            }
        }
    }

    async fn release_mfa_lock(&self, lock_id: &str, token: &str) -> Result<(), AuthError> {
        // Compare-and-delete, mirroring the `release_lock` Lua: a lock whose token no longer
        // matches belongs to a successor, and removing it would let a third caller in beside it.
        let mut locks = lock(&self.mfa_locks);
        if locks.get(lock_id).is_some_and(|held| held == token) {
            locks.remove(lock_id);
        }
        Ok(())
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
    email_verified: bool,
}

impl MockOAuthProvider {
    /// A provider registered under `name`, reporting a verified email.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email_verified: true,
        }
    }

    /// The same provider, but reporting an email it has **not** verified — the shape of a
    /// provider like GitHub, which hands back unverified addresses.
    #[must_use]
    pub fn unverified(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email_verified: false,
        }
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
            email_verified: self.email_verified,
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
                None,
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
                None,
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
        // Read back rather than trusting the `Ok`: a fake that answers `Ok(())` and stores
        // nothing lets every test built on it pass while asserting nothing.
        let stored = repo.find_by_id("p1").await;
        assert!(matches!(&stored, Ok(Some(u)) if u.last_login_at.is_some()
                && u.status == "SUSPENDED"
                && u.password_hash == "$scrypt$y"
                && u.mfa_enabled));
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

    /// A stand-in session subject for `user`.
    ///
    /// The double treats the subject as an opaque suffix, exactly as the Redis store does — the
    /// real value is `hmac_sha256(identifier_key, user_subject)` and deriving it is the engine's
    /// job. A readable label keeps these assertions about the index rather than about hashing.
    fn subject(user: &str) -> String {
        format!("subj-{user}")
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
            mfa_enabled: false,
            family_id: family.to_owned(),
            family_created_at: Some(OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[tokio::test]
    async fn session_store_covers_create_rotate_revoke_and_blacklist() {
        let store = InMemoryStores::new();
        let kind = SessionKind::Dashboard;
        assert!(
            store
                .create_session(kind, &subject("u1"), "h1", &record("u1"), 60)
                .await
                .is_ok()
        );
        assert!(matches!(store.find_session(kind, "h1").await, Ok(Some(_))));
        assert!(matches!(store.find_session(kind, "absent").await, Ok(None)));
        assert!(matches!(store.list_sessions(kind, &subject("u1")).await, Ok(v) if v.len() == 1));

        // Rotate h1 -> h2 (Rotated), then a second rotate of h1 hits the grace pointer.
        let rotation = SessionRotation {
            old_hash: "h1".to_owned(),
            new_hash: "h2".to_owned(),
            new_raw: "raw2".to_owned(),
            new_record: record("u1"),
            subject_hash: subject("u1"),
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
            store.revoke_session(kind, &subject("ghost"), "h2").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(matches!(
            store.revoke_session(kind, &subject("u1"), "absent").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(
            store
                .revoke_session(kind, &subject("u1"), "h2")
                .await
                .is_ok()
        );

        // revoke_all clears the remaining index entry (and the no-op empty case).
        assert!(
            store
                .create_session(kind, &subject("u1"), "h3", &record("u1"), 60)
                .await
                .is_ok()
        );
        assert!(store.revoke_all(kind, &subject("u1")).await.is_ok());
        assert!(store.revoke_all(kind, &subject("nobody")).await.is_ok());

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
                .create_session(
                    kind,
                    &subject("u1"),
                    "h1",
                    &record_in_family("u1", "famA"),
                    60
                )
                .await
                .is_ok()
        );
        let rotation = SessionRotation {
            old_hash: "h1".to_owned(),
            new_hash: "h2".to_owned(),
            new_raw: "raw2".to_owned(),
            new_record: record_in_family("u1", "famA"),
            subject_hash: subject("u1"),
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
        // …and the account the family belonged to is readable BEFORE the revocation. That owner
        // is the only thing reuse detection can name its victim with: the replayed token's own
        // key was deleted when it was rotated, so the family index is the last surviving link to
        // an account — and the revocation needs the owner's subject to prune the right index.
        assert!(matches!(
            store.find_family_owner(kind, "famA").await,
            Ok(Some(owner)) if owner.user_id == "u1"
        ));
        assert!(
            store
                .revoke_family(kind, "famA", Some(&subject("u1")))
                .await
                .is_ok()
        );
        assert!(matches!(store.find_session(kind, "h2").await, Ok(None)));
        assert!(matches!(store.list_sessions(kind, &subject("u1")).await, Ok(v) if v.is_empty()));
        // A family with nothing left readable names nobody rather than someone, and revoking it
        // again is a no-op rather than an error.
        assert!(matches!(
            store.find_family_owner(kind, "famA").await,
            Ok(None)
        ));
        assert!(matches!(store.find_family_owner(kind, "").await, Ok(None)));
        assert!(store.revoke_family(kind, "famA", None).await.is_ok());
        assert!(store.revoke_family(kind, "", None).await.is_ok());

        // A member whose record carries no owner is skipped rather than reported: an event
        // naming the empty string is worse than no event, because a consumer would act on it.
        // One member only — the family index is a set, so a family holding both an anonymous
        // and a named record would be read in whichever order the set happened to yield, and
        // the assertion would pass or fail by luck.
        assert!(
            store
                .create_session(
                    kind,
                    &subject(""),
                    "anon",
                    &record_in_family("", "famB"),
                    60
                )
                .await
                .is_ok()
        );
        assert!(matches!(
            store.find_family_owner(kind, "famB").await,
            Ok(None)
        ));
        assert!(store.revoke_family(kind, "famB", None).await.is_ok());

        // A session with no family plants no consumed marker, so a post-grace replay is a
        // plain Invalid, never a reuse.
        assert!(
            store
                .create_session(kind, &subject("u2"), "g1", &record_in_family("u2", ""), 60)
                .await
                .is_ok()
        );
        let familyless = SessionRotation {
            old_hash: "g1".to_owned(),
            new_hash: "g2".to_owned(),
            new_raw: "rawg".to_owned(),
            new_record: record_in_family("u2", ""),
            subject_hash: subject("u2"),
            refresh_ttl: 60,
            grace_ttl: 30,
        };
        assert!(matches!(
            store.rotate(kind, &familyless).await,
            Ok(RotateOutcome::Rotated(_))
        ));
        assert!(store.delete_grace_pointer(kind, "g1").await.is_ok());
        assert!(matches!(
            store.rotate(kind, &familyless).await,
            Ok(RotateOutcome::Invalid)
        ));
    }

    /// The three lineages both scoping tests need: the target account, another account on the
    /// same plane, and the target's id on the OTHER plane. Each is created and rotated once, so
    /// each owns a grace pointer keyed by its superseded hash.
    ///
    /// Shared because `revoke_all` and `sweep_grace_pointers` carry the same two-part predicate
    /// (`kind` AND `subject`) over the same map. Two copies of this arrangement would be two
    /// things to keep in step, and the mutation gate proved they are not interchangeable: the
    /// version that tested only one of the two left the other's predicate unpinned.
    async fn plant_grace_lineages(store: &InMemoryStores) {
        for (kind, hash, user, family) in [
            (SessionKind::Dashboard, "a1", "u1", "famA"),
            (SessionKind::Dashboard, "b1", "u2", "famB"),
            (SessionKind::Platform, "p1", "u1", "famP"),
        ] {
            assert!(
                store
                    .create_session(
                        kind,
                        &subject(user),
                        hash,
                        &record_in_family(user, family),
                        60
                    )
                    .await
                    .is_ok()
            );
        }
        for (kind, old, new, user, family) in [
            (SessionKind::Dashboard, "a1", "a2", "u1", "famA"),
            (SessionKind::Dashboard, "b1", "b2", "u2", "famB"),
            (SessionKind::Platform, "p1", "p2", "u1", "famP"),
        ] {
            assert!(matches!(
                store
                    .rotate(kind, &grace_replay(old, new, user, family))
                    .await,
                Ok(RotateOutcome::Rotated(_))
            ));
        }
    }

    /// A rotation bundle presenting `old` again — the replay whose outcome reports whether that
    /// lineage's grace pointer survived: `Grace` while the pointer is there, `Reused` once it has
    /// been swept and only the consumed-family marker is left.
    fn grace_replay(old: &str, new: &str, user: &str, family: &str) -> SessionRotation {
        SessionRotation {
            old_hash: old.to_owned(),
            new_hash: new.to_owned(),
            new_raw: String::new(),
            new_record: record_in_family(user, family),
            subject_hash: subject(user),
            refresh_ttl: 60,
            grace_ttl: 30,
        }
    }

    /// Assert that the target's grace pointer is gone and the other two survive — the property
    /// both scoping predicates have to hold.
    async fn assert_only_the_target_was_swept(store: &InMemoryStores) {
        assert!(matches!(
            store
                .rotate(
                    SessionKind::Dashboard,
                    &grace_replay("a1", "a-replay", "u1", "famA")
                )
                .await,
            Ok(RotateOutcome::Reused(family)) if family == "famA"
        ));
        // Bound before the assertion, not inlined into it: a two-argument `assert!` whose
        // condition contains the `.await` leaves that region counted only on the FAILING path,
        // which shows up as an uncovered line under a 100% gate. The same reason the message can
        // now name the value it saw.
        let other_account = store
            .rotate(
                SessionKind::Dashboard,
                &grace_replay("b1", "b-replay", "u2", "famB"),
            )
            .await;
        assert!(
            matches!(other_account, Ok(RotateOutcome::Grace(_))),
            "another account's grace pointer was swept: {other_account:?}"
        );
        let other_plane = store
            .rotate(
                SessionKind::Platform,
                &grace_replay("p1", "p-replay", "u1", "famP"),
            )
            .await;
        assert!(
            matches!(other_plane, Ok(RotateOutcome::Grace(_))),
            "a dashboard sweep reached the platform keyspace: {other_plane:?}"
        );
    }

    #[tokio::test]
    async fn revoke_all_sweeps_only_the_named_accounts_grace_pointers() {
        // `revoke_all` deletes the account's grace pointers as well as its sessions, because the
        // real store finds them as members of the same `sess:` set. The predicate that picks them
        // is `kind` AND `subject`, and neither half was pinned.
        //
        // Both directions matter. Sweeping too little leaves a token rotated away moments before
        // "sign out everywhere" able to recover a full session for its whole grace window.
        // Sweeping too much silently signs out a stranger — the cross-tenant revocation this
        // keyspace moved to prevent, reintroduced one layer up in the double.
        let store = InMemoryStores::new();
        plant_grace_lineages(&store).await;

        assert!(
            store
                .revoke_all(SessionKind::Dashboard, &subject("u1"))
                .await
                .is_ok()
        );

        assert_only_the_target_was_swept(&store).await;
    }

    #[tokio::test]
    async fn sweep_grace_pointers_touches_only_the_named_account() {
        // The same two-part predicate as `revoke_all`, on the call `revoke_all_except_current`
        // uses — and it needs its own test rather than inheriting that one's: they are separate
        // `retain` closures, and the mutation gate kills them separately. This is the arm that
        // runs when the caller KEEPS a session, so over-sweeping here signs out a stranger while
        // the caller's own device carries on, which is the shape that reads as working.
        let store = InMemoryStores::new();
        plant_grace_lineages(&store).await;

        assert!(
            store
                .sweep_grace_pointers(SessionKind::Dashboard, &subject("u1"))
                .await
                .is_ok()
        );

        assert_only_the_target_was_swept(&store).await;
    }

    #[tokio::test]
    async fn armed_cleanup_failures_are_finite() {
        // The point of arming a COUNT is that it runs out. A counter that never reached zero
        // would leave the store failing for the rest of the test, and every assertion that
        // follows would be measuring an outage instead of the behaviour it names — silently,
        // because these are exactly the writes the library swallows. So the third call here is
        // the assertion that matters: it must behave normally again.
        let store = InMemoryStores::new();
        let kind = SessionKind::Dashboard;
        assert!(
            store
                .create_session(kind, &subject("u9"), "a1", &record("u9"), 60)
                .await
                .is_ok()
        );

        store.fail_next_cleanup_writes(2);
        // Armed: a backend error, not the `SessionNotFound` an absent session would give.
        assert!(matches!(
            store.revoke_session(kind, &subject("u9"), "a1").await,
            Err(AuthError::Internal(_))
        ));
        assert!(matches!(
            store.delete_grace_pointer(kind, "a1").await,
            Err(AuthError::Internal(_))
        ));
        // Disarmed: the session is still there (both armed calls failed before touching it),
        // so this one succeeds — which it could not if the counter had grown or stalled.
        assert!(
            store
                .revoke_session(kind, &subject("u9"), "a1")
                .await
                .is_ok()
        );
        assert!(store.delete_grace_pointer(kind, "a1").await.is_ok());
    }

    #[tokio::test]
    async fn session_store_grace_is_single_shot_and_refuses_a_revoked_lineage() {
        let kind = SessionKind::Dashboard;

        // A grace pointer recovers exactly once. Were it repeatable, one captured token would
        // mint a fresh session on every request for the whole window instead of covering the
        // single retry where the old token was consumed but the new one never arrived.
        let store = InMemoryStores::new();
        assert!(
            store
                .create_session(
                    kind,
                    &subject("u3"),
                    "s1",
                    &record_in_family("u3", "famB"),
                    60
                )
                .await
                .is_ok()
        );
        let rotation = SessionRotation {
            old_hash: "s1".to_owned(),
            new_hash: "s2".to_owned(),
            new_raw: "raws2".to_owned(),
            new_record: record_in_family("u3", "famB"),
            subject_hash: subject("u3"),
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
        // The second replay finds the pointer consumed and falls through to reuse detection.
        assert!(matches!(
            store.rotate(kind, &rotation).await,
            Ok(RotateOutcome::Reused(family)) if family == "famB"
        ));

        // A revoked family cannot be resurrected through a leftover grace pointer. Reuse
        // detection deletes the family index, but it cannot reach the `rp:` pointer of a hash
        // that already rotated out of it — so a still-live pointer in a locked-out lineage must
        // yield Invalid rather than Grace, or the replay would mint a fresh session in the very
        // family the lockout just killed.
        let store = InMemoryStores::new();
        assert!(
            store
                .create_session(
                    kind,
                    &subject("u4"),
                    "t1",
                    &record_in_family("u4", "famC"),
                    60
                )
                .await
                .is_ok()
        );
        assert!(matches!(
            store
                .rotate(
                    kind,
                    &SessionRotation {
                        old_hash: "t1".to_owned(),
                        new_hash: "t2".to_owned(),
                        new_raw: "rawt2".to_owned(),
                        new_record: record_in_family("u4", "famC"),
                        subject_hash: subject("u4"),
                        refresh_ttl: 60,
                        grace_ttl: 30,
                    },
                )
                .await,
            Ok(RotateOutcome::Rotated(_))
        ));
        assert!(
            store
                .revoke_family(kind, "famC", Some(&subject("u4")))
                .await
                .is_ok()
        );
        assert!(matches!(
            store
                .rotate(
                    kind,
                    &SessionRotation {
                        old_hash: "t1".to_owned(),
                        new_hash: "t3".to_owned(),
                        new_raw: "rawt3".to_owned(),
                        new_record: record_in_family("u4", "famC"),
                        subject_hash: subject("u4"),
                        refresh_ttl: 60,
                        grace_ttl: 30,
                    },
                )
                .await,
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
        // `peek_otp` is how the adapter suites drive a verification flow end to end, and it
        // is only ever read back through itself there — so it is pinned here, in the crate
        // that owns it, where the mutation gate can see it.
        assert_eq!(store.peek_otp(purpose, "id"), Some("123456".to_owned()));
        assert_eq!(store.peek_otp(purpose, "absent"), None);
        assert_eq!(store.peek_otp(OtpPurpose::PasswordReset, "id"), None);
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
        assert_eq!(store.peek_otp(purpose, "id"), None);
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
            password_fingerprint: String::new(),
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

        // Two live tokens do not collide: the key is derived from the token, so consuming one
        // leaves the other intact. A double that keyed everything the same way would round-trip
        // a single token perfectly and quietly lose the second.
        let other = ResetContext {
            user_id: "u2".to_owned(),
            ..context.clone()
        };
        assert!(store.put_token("first", &context, 600).await.is_ok());
        assert!(store.put_token("second", &other, 600).await.is_ok());
        assert!(matches!(
            store.consume_token("first").await,
            Ok(Some(c)) if c.user_id == "u1"
        ));
        assert!(matches!(
            store.consume_token("second").await,
            Ok(Some(c)) if c.user_id == "u2"
        ));
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
            created_at: OffsetDateTime::UNIX_EPOCH,
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
    async fn invitation_index_is_keyed_by_tenant_and_address() {
        // The double has to behave like the Redis store it stands in for, because a consumer
        // testing their own withdrawal flow against it is relying on exactly that. An index
        // keyed by anything less than (tenant, address) would let one tenant's withdrawal
        // reach another's invitation, and the double would report the flow as correct.
        let store = InMemoryStores::new();
        assert!(
            store
                .put_invitation_index("t1", "invitee@example.com", "hash-1", 600)
                .await
                .is_ok()
        );
        assert!(
            store
                .put_invitation_index("t2", "invitee@example.com", "hash-2", 600)
                .await
                .is_ok()
        );

        // Same address, different tenants: two entries, not one overwriting the other.
        assert!(matches!(
            store.read_invitation_index("t1", "invitee@example.com").await,
            Ok(Some(h)) if h == "hash-1"
        ));
        assert!(matches!(
            store.read_invitation_index("t2", "invitee@example.com").await,
            Ok(Some(h)) if h == "hash-2"
        ));
        // …and a different address in a tenant that has one names nothing.
        assert!(matches!(
            store.read_invitation_index("t1", "other@example.com").await,
            Ok(None)
        ));

        // Reading leaves the entry; taking removes it, exactly once.
        assert!(matches!(
            store
                .read_invitation_index("t1", "invitee@example.com")
                .await,
            Ok(Some(_))
        ));
        assert!(matches!(
            store.take_invitation_index("t1", "invitee@example.com").await,
            Ok(Some(h)) if h == "hash-1"
        ));
        assert!(matches!(
            store
                .take_invitation_index("t1", "invitee@example.com")
                .await,
            Ok(None)
        ));
        // …and taking one tenant's entry left the other's alone.
        assert!(matches!(
            store
                .read_invitation_index("t2", "invitee@example.com")
                .await,
            Ok(Some(_))
        ));
    }

    #[tokio::test]
    async fn an_invitation_is_readable_and_deletable_by_its_stored_hash() {
        // The revocation path reaches the record through the index rather than through a raw
        // token, so the double needs the by-hash pair the withdrawal actually calls.
        let store = InMemoryStores::new();
        let invitation = StoredInvitation {
            email: "invitee@example.com".to_owned(),
            role: "MEMBER".to_owned(),
            tenant_id: "t1".to_owned(),
            inviter_user_id: "owner".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(
            store
                .put_invitation("inv-tok", &invitation, 600)
                .await
                .is_ok()
        );
        let hash = token_key("inv-tok");

        assert!(matches!(
            store.read_invitation_by_hash(&hash).await,
            Ok(Some(i)) if i.role == "MEMBER"
        ));
        assert!(matches!(
            store.read_invitation_by_hash("never-stored").await,
            Ok(None)
        ));

        // The delete reports whether THIS call removed it, so a withdrawal cannot report
        // success over an invitation that was already accepted.
        assert!(matches!(
            store.delete_invitation_by_hash(&hash).await,
            Ok(true)
        ));
        assert!(matches!(
            store.delete_invitation_by_hash(&hash).await,
            Ok(false)
        ));
        // …and the accept path no longer finds it either.
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
        // Same shape the real store mints — 64 lower-case hex — because the engine
        // shape-checks a presented ticket before hashing it, and a double whose output the
        // engine would refuse cannot exercise the path it stands in for.
        assert!(
            matches!(&ticket, Ok(t) if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
            "{ticket:?}"
        );
        let Ok(ticket) = ticket else { return };
        assert!(matches!(store.redeem(&ticket).await, Ok(Some(_))));
        // A second redeem of the same ticket finds nothing (single-use).
        assert!(matches!(store.redeem(&ticket).await, Ok(None)));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn mfa_store_reproduces_set_nx_and_getdel() {
        // The double stands in for `SET NX` and `GETDEL`, and the enrolment gate is built on
        // exactly those two: the first writer wins the setup slot, and the completion reads it
        // away so only one caller can finish. A double that swallowed the value or always
        // reported "already there" would make that gate untestable.
        use crate::traits::MfaStore;
        let store = InMemoryStores::new();
        assert!(matches!(store.get_setup("uh").await, Ok(None)));
        assert!(matches!(
            store.put_setup_nx("uh", "enc-secret", 300).await,
            Ok(true)
        ));
        assert!(matches!(store.get_setup("uh").await, Ok(Some(v)) if v == "enc-secret"));
        // Second writer loses and does not overwrite.
        assert!(matches!(
            store.put_setup_nx("uh", "other", 300).await,
            Ok(false)
        ));
        assert!(matches!(store.get_setup("uh").await, Ok(Some(v)) if v == "enc-secret"));
        // GETDEL: the value comes back once, and the slot is free again.
        assert!(matches!(store.take_setup("uh").await, Ok(Some(v)) if v == "enc-secret"));
        assert!(matches!(store.take_setup("uh").await, Ok(None)));
        assert!(matches!(
            store.put_setup_nx("uh", "third", 300).await,
            Ok(true)
        ));
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
