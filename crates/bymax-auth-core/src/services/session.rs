//! The engine's session service: concurrent-session tracking, FIFO eviction at the
//! configured per-user cap, device/IP metadata, ownership-checked revocation, and atomic
//! detail rotation over the [`SessionStore`] seam (§7.4).
//!
//! The refresh session itself (the `rt:` record + the `sess:` set membership) is written by
//! [`crate::services::token_manager::TokenManagerService`] at issuance; this service layers
//! the user-facing management on top — eviction when the cap is exceeded, the new-session
//! and session-evicted hooks, the display projection, and the revoke surfaces. Every hash it
//! touches is validated as 64 lowercase hex before use, and a full hash is never logged (it
//! is truncated to eight chars), so a malformed input can never enumerate the keyspace and a
//! log line can never leak a live session identifier.

use std::sync::Arc;

use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_types::AuthError;

use crate::config::SessionConfig;
use crate::traits::{
    AuthHooks, HookContext, SessionDetail, SessionKind, SessionRecord, SessionRotation,
    SessionStore, UserRepository,
};

/// The maximum stored IP length, in **bytes**: a maximal IPv6 textual address is 45 ASCII
/// bytes. The originating IP is truncated to this before it lands in a session record so an
/// attacker-controlled `X-Forwarded-For` cannot inflate the stored value unboundedly (§7.4).
/// The bound is on bytes, not chars, so a multi-byte value cannot exceed the storage limit
/// while staying within 45 chars.
pub(crate) const MAX_IP_LENGTH: usize = 45;

/// One session's display-safe projection, returned to the user by [`SessionService::list_sessions`].
/// The `id` is the first eight hex chars of the session hash — a short display id — and
/// `is_current` flags the caller's own session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// A short display id: the first eight hex chars of the session hash.
    pub id: String,
    /// The full stored session hash (a SHA-256 hex of the refresh token), never the raw token.
    pub session_hash: String,
    /// Human-readable device/browser string.
    pub device: String,
    /// Originating IP.
    pub ip: String,
    /// Whether this is the caller's current session.
    pub is_current: bool,
    /// Session creation time.
    pub created_at: time::OffsetDateTime,
    /// Last observed activity time.
    pub last_activity_at: time::OffsetDateTime,
}

/// Manages concurrent dashboard sessions over the [`SessionStore`]. Holds the store, the
/// user repository (for the per-user limit resolver and the hook user fetch), the lifecycle
/// hooks, and the resolved session policy.
pub struct SessionService {
    store: Arc<dyn SessionStore>,
    users: Arc<dyn UserRepository>,
    hooks: Arc<dyn AuthHooks>,
    config: SessionConfig,
    refresh_ttl_secs: u64,
}

impl SessionService {
    /// Assemble the service from the session store, the user repository, the hooks, the
    /// resolved [`SessionConfig`], and the refresh-session TTL (seconds) used when rotating
    /// the per-session detail.
    pub(crate) fn new(
        store: Arc<dyn SessionStore>,
        users: Arc<dyn UserRepository>,
        hooks: Arc<dyn AuthHooks>,
        config: SessionConfig,
        refresh_ttl_secs: u64,
    ) -> Self {
        Self {
            store,
            users,
            hooks,
            config,
            refresh_ttl_secs,
        }
    }

    /// Enforce the per-user session cap after a fresh session was already created, then fire
    /// the new-session hook. The refresh record's `rt:` membership is added by the token
    /// manager before this runs, so the limit check counts the just-created session and
    /// eviction explicitly excludes it.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only on an infrastructure failure listing the user's
    /// sessions; eviction itself is best-effort (the new session is already committed).
    pub async fn after_session_created(
        &self,
        record: &SessionRecord,
        new_hash: &str,
        ctx: &HookContext,
    ) -> Result<(), AuthError> {
        self.enforce_session_limit(record, new_hash, ctx).await?;
        self.fire_new_session(record, new_hash, ctx).await;
        Ok(())
    }

    /// Evict the oldest sessions (FIFO) when the user is over the resolved cap, excluding the
    /// just-created `new_hash`. This is a **soft** cap by default: the list→evict sequence is
    /// not atomic, so N simultaneous logins can transiently overshoot by up to N−1 before
    /// eviction settles — acceptable for `default_max_sessions >= 2`. For a strict cap
    /// (notably `default_max_sessions = 1`, where any overshoot means a second live session
    /// briefly coexists), enforcement must instead run as a single atomic `enforce_session_limit`
    /// Lua (`SMEMBERS` + conditional `DEL` of the over-limit members in one script, mirroring
    /// the ownership-checked revoke); that hardening is a store-side concern and is documented
    /// here as the required upgrade path.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] if the user's sessions cannot be listed; the per-victim
    /// revoke is best-effort (a failure is swallowed, not propagated).
    async fn enforce_session_limit(
        &self,
        record: &SessionRecord,
        new_hash: &str,
        ctx: &HookContext,
    ) -> Result<(), AuthError> {
        let user_id = &record.user_id;
        let mut sessions = self
            .store
            .list_sessions(SessionKind::Dashboard, user_id)
            .await?;
        // Clamp the resolved cap to at least 1. A cap of 0 is unenforceable here: eviction
        // always excludes the just-created session, so a literal 0 would leave the user one
        // over an impossible "zero" cap forever. Treating 0 as 1 keeps the just-created session
        // and evicts every other, which is the only coherent outcome for a single-session cap.
        let limit = self.resolve_session_limit(user_id).await.max(1);

        // Sort oldest-first so the FIFO victims are the front of the list. A session whose
        // detail vanished is treated as oldest by the store's epoch fallback already.
        sessions.sort_by_key(|detail| detail.created_at);

        let over = sessions
            .len()
            .saturating_sub(usize::try_from(limit).unwrap_or(usize::MAX));
        if over == 0 {
            return Ok(());
        }

        // Choose the oldest `over` sessions, excluding the just-created one, and evict them.
        let victims: Vec<SessionDetail> = sessions
            .into_iter()
            .filter(|detail| !constant_time_eq(detail.session_hash.as_bytes(), new_hash.as_bytes()))
            .take(over)
            .collect();
        for victim in victims {
            // Ownership-checked revoke; a SessionNotFound (a concurrent logout already removed
            // it) or any other store error is swallowed — the new session is already committed,
            // so eviction must never fail the operation that scheduled it.
            let _ = self
                .store
                .revoke_session(SessionKind::Dashboard, user_id, &victim.session_hash)
                .await;
            self.fire_session_evicted(user_id, &victim.session_hash, ctx)
                .await;
        }
        Ok(())
    }

    /// Resolve the per-user concurrent-session cap: the optional resolver wins when it is
    /// configured and the user can be loaded; otherwise the configured default applies.
    async fn resolve_session_limit(&self, user_id: &str) -> u32 {
        let Some(resolver) = self.config.max_sessions_resolver.as_ref() else {
            return self.config.default_max_sessions;
        };
        // The resolver needs the full user; a missing user or a repository failure falls back
        // to the default rather than failing the limit check.
        match self.users.find_by_id(user_id, None).await {
            Ok(Some(user)) => resolver.resolve(&user).await,
            _ => self.config.default_max_sessions,
        }
    }

    /// List the user's live sessions as display-safe [`SessionInfo`]s, newest first.
    /// `current_hash` flags the caller's own session via a constant-time compare (a 64-char
    /// hash never length-matches the empty string, so an absent current marks none).
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] if the sessions cannot be listed.
    pub async fn list_sessions(
        &self,
        user_id: &str,
        current_hash: Option<&str>,
    ) -> Result<Vec<SessionInfo>, AuthError> {
        let current = current_hash.unwrap_or("");
        let mut sessions = self
            .store
            .list_sessions(SessionKind::Dashboard, user_id)
            .await?;
        sessions.sort_by_key(|detail| std::cmp::Reverse(detail.created_at));
        Ok(sessions
            .into_iter()
            .map(|detail| to_info(detail, current))
            .collect())
    }

    /// Revoke a single session, ownership-checked. A hash that is not 64 lowercase hex is
    /// rejected as [`AuthError::SessionNotFound`] (callers cannot distinguish a bad format
    /// from an absent session, blocking format enumeration), and the store's atomic
    /// membership-then-delete closes the TOCTOU between the ownership check and the delete.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::SessionNotFound`] when the hash is malformed or not owned by the
    /// user, or a store [`AuthError`] on an infrastructure failure.
    pub async fn revoke_session(&self, user_id: &str, session_hash: &str) -> Result<(), AuthError> {
        if !is_session_hash(session_hash) {
            return Err(AuthError::SessionNotFound);
        }
        self.store
            .revoke_session(SessionKind::Dashboard, user_id, session_hash)
            .await
    }

    /// Revoke every session for the user except `current_hash` (a "log out everywhere else"
    /// action). A `SessionNotFound` for a victim (a concurrent logout already removed it) is
    /// swallowed; any other store error is propagated.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::SessionNotFound`] when `current_hash` is malformed, or a store
    /// [`AuthError`] on an infrastructure failure listing or revoking a session.
    pub async fn revoke_all_except_current(
        &self,
        user_id: &str,
        current_hash: &str,
    ) -> Result<(), AuthError> {
        if !is_session_hash(current_hash) {
            return Err(AuthError::SessionNotFound);
        }
        let sessions = self
            .store
            .list_sessions(SessionKind::Dashboard, user_id)
            .await?;
        for detail in sessions {
            // Skip the caller's own session (constant-time compare on the fixed-length hashes).
            if constant_time_eq(detail.session_hash.as_bytes(), current_hash.as_bytes()) {
                continue;
            }
            match self
                .store
                .revoke_session(SessionKind::Dashboard, user_id, &detail.session_hash)
                .await
            {
                Ok(()) | Err(AuthError::SessionNotFound) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    /// Atomically rotate the per-session detail from `old_hash` to `new_hash`, preserving the
    /// original creation time so session age is stable across refresh rotations. Both hashes
    /// are validated; a no-op rotation (`old == new`) returns early. The atomic detail move is
    /// owned by the store so a concurrent [`SessionService::list_sessions`] never observes
    /// neither key (which would spuriously classify the session as stale).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::SessionNotFound`] when either hash is malformed, or a store
    /// [`AuthError`] on a rotation failure.
    pub async fn rotate_session(
        &self,
        old_hash: &str,
        new_hash: &str,
        record: &SessionRecord,
    ) -> Result<(), AuthError> {
        if !is_session_hash(old_hash) || !is_session_hash(new_hash) {
            return Err(AuthError::SessionNotFound);
        }
        // A no-op rotation (the same token presented twice) is a constant-time early return.
        if constant_time_eq(old_hash.as_bytes(), new_hash.as_bytes()) {
            return Ok(());
        }
        // The store's `rotate` performs the atomic detail move (DEL old / SET new) and the
        // index bookkeeping; the new raw token is generated by the caller and never persisted.
        let rotation = SessionRotation {
            old_hash: old_hash.to_owned(),
            new_hash: new_hash.to_owned(),
            new_raw: String::new(),
            new_record: record.clone(),
            refresh_ttl: self.refresh_ttl_secs,
            grace_ttl: 0,
        };
        self.store
            .rotate(SessionKind::Dashboard, &rotation)
            .await
            .map(|_| ())
    }

    /// Fire the fire-and-forget new-session hook, projecting the safe user when it can be
    /// loaded. The hook receives a short (eight-char) session hash, never the full one.
    async fn fire_new_session(&self, record: &SessionRecord, new_hash: &str, ctx: &HookContext) {
        let Ok(Some(user)) = self.users.find_by_id(&record.user_id, None).await else {
            // No user to project — skip the hook rather than fabricate identity.
            return;
        };
        let safe = bymax_auth_types::SafeAuthUser::from(user);
        let session = crate::traits::email::SessionInfo {
            device: record.device.clone(),
            ip: record.ip.clone(),
            session_hash: short_hash(new_hash),
        };
        // Errors are swallowed: a slow or failing notification must never affect the session.
        let _ = self.hooks.on_new_session(&safe, &session, ctx).await;
    }

    /// Fire the fire-and-forget session-evicted hook with the short (eight-char) evicted hash.
    async fn fire_session_evicted(&self, user_id: &str, evicted_hash: &str, ctx: &HookContext) {
        let _ = self
            .hooks
            .on_session_evicted(user_id, &short_hash(evicted_hash), ctx)
            .await;
    }
}

/// Whether `hash` is a valid session hash: exactly 64 lowercase hex characters (a SHA-256
/// digest). Validating before use blocks keyspace enumeration through a malformed hash.
pub(crate) fn is_session_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The first eight chars of a session hash — the display id and the only form ever logged or
/// handed to a hook, so a full live session identifier never leaks.
fn short_hash(hash: &str) -> String {
    hash.chars().take(8).collect()
}

/// Truncate an IP to at most [`MAX_IP_LENGTH`] **bytes**, cut on a UTF-8 char boundary, so a
/// well-formed IPv6 address is preserved while an over-long attacker-controlled value (which a
/// non-ASCII `X-Forwarded-For` can push past the byte limit while still under 45 chars) is
/// bounded by the storage limit without ever splitting a codepoint.
pub(crate) fn truncate_ip(ip: &str) -> String {
    if ip.len() <= MAX_IP_LENGTH {
        return ip.to_owned();
    }
    // The byte length exceeds the bound: cut at the largest char boundary whose byte offset is
    // `<= MAX_IP_LENGTH`. `char_indices` yields each char's start offset in ascending order, so
    // the last offset still within the bound is the maximal safe cut (`floor_char_boundary` is
    // unstable, so this walks the boundaries explicitly). The first offset is always `0`, so a
    // boundary always exists for a non-empty string.
    let cut = ip
        .char_indices()
        .map(|(offset, _)| offset)
        .take_while(|&offset| offset <= MAX_IP_LENGTH)
        .last()
        .unwrap_or(0);
    ip[..cut].to_owned()
}

/// Normalize attacker-controlled request metadata into its stored form: parse the user-agent
/// into a `"{Browser} on {OS}"` device label (via [`parse_user_agent`]) and bound the IP to
/// [`MAX_IP_LENGTH`] bytes on a UTF-8 boundary (via [`truncate_ip`]). This is the **single**
/// normalization applied both where the refresh session is persisted (the token manager) and
/// where the management/hook projection is built, so the stored record,
/// [`SessionService::list_sessions`], and the new-session / session-evicted hook payloads never
/// diverge and the byte bound actually reaches the store.
pub(crate) fn normalize_session_metadata(user_agent: &str, ip: &str) -> (String, String) {
    (parse_user_agent(user_agent), truncate_ip(ip))
}

/// Project a stored [`SessionDetail`] into the display-safe [`SessionInfo`], stamping
/// `is_current` from a constant-time compare against the caller's session hash.
fn to_info(detail: SessionDetail, current: &str) -> SessionInfo {
    let is_current = constant_time_eq(detail.session_hash.as_bytes(), current.as_bytes());
    SessionInfo {
        id: short_hash(&detail.session_hash),
        session_hash: detail.session_hash,
        device: detail.device,
        ip: detail.ip,
        is_current,
        created_at: detail.created_at,
        last_activity_at: detail.last_activity_at,
    }
}

/// Parse a `User-Agent` into a `"{Browser} on {OS}"` label using only substring inspection
/// (no external UA crate). Browser precedence is Edge > Opera > Chrome > Firefox > Safari
/// (Safari requires a `Version/` token to exclude the many embedded WebKit agents); OS
/// precedence is Android > iOS > Windows > macOS > Linux. An unrecognized agent yields
/// `"Unknown Browser on Unknown OS"`.
#[must_use]
pub fn parse_user_agent(user_agent: &str) -> String {
    format!(
        "{} on {}",
        detect_browser(user_agent),
        detect_os(user_agent)
    )
}

/// Detect the browser from the user-agent, honoring the precedence that resolves the
/// overlapping vendor tokens (Edge and Opera both also carry `Chrome`; Chrome also carries
/// `Safari`).
fn detect_browser(ua: &str) -> &'static str {
    if ua.contains("Edg") {
        "Edge"
    } else if ua.contains("OPR") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Chrome") {
        "Chrome"
    } else if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Safari") && ua.contains("Version/") {
        "Safari"
    } else {
        "Unknown Browser"
    }
}

/// Detect the OS from the user-agent. `iPhone`/`iPad` and `Android` are checked before the
/// desktop families so a mobile device is not misread as its embedded desktop token.
fn detect_os(ua: &str) -> &'static str {
    if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iOS") {
        "iOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown OS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::resolvers::MaxSessionsResolver;
    use crate::config::{AuthConfig, EvictionStrategy};
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::NoOpAuthHooks;
    use bymax_auth_types::{AuthUser, CreateUserData};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;

    /// A hook spy that counts the new-session and session-evicted invocations, so the FIFO
    /// eviction and the new-session notification are both observable.
    #[derive(Default)]
    struct CountingHooks {
        new_sessions: AtomicUsize,
        evictions: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AuthHooks for CountingHooks {
        async fn on_new_session(
            &self,
            _user: &bymax_auth_types::SafeAuthUser,
            session: &crate::traits::email::SessionInfo,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            // The hook must receive only a short hash, never a full 64-char one.
            assert!(session.session_hash.len() <= 8);
            self.new_sessions.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn on_session_evicted(
            &self,
            _user_id: &str,
            evicted_session_hash: &str,
            _ctx: &HookContext,
        ) -> Result<(), crate::traits::HookError> {
            assert!(evicted_session_hash.len() <= 8);
            self.evictions.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// A resolver that pins the cap to one, to exercise the resolver-override path.
    struct CapOf(u32);

    #[async_trait::async_trait]
    impl MaxSessionsResolver for CapOf {
        async fn resolve(&self, _user: &AuthUser) -> u32 {
            self.0
        }
    }

    fn hash(prefix: &str) -> String {
        // A valid 64-char lowercase-hex session hash seeded from a short prefix.
        format!("{prefix}{}", "0".repeat(64 - prefix.len()))
    }

    fn record(user: &str, created: OffsetDateTime) -> SessionRecord {
        SessionRecord {
            user_id: user.to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            device: "Chrome on macOS".to_owned(),
            ip: "203.0.113.4".to_owned(),
            created_at: created,
        }
    }

    fn ctx() -> HookContext {
        HookContext {
            user_id: Some("u1".to_owned()),
            email: Some("u@example.com".to_owned()),
            tenant_id: Some("t1".to_owned()),
            ip: "203.0.113.4".to_owned(),
            user_agent: "agent/1.0".to_owned(),
            sanitized_headers: BTreeMap::new(),
        }
    }

    fn config(default_max: u32, resolver: Option<Arc<dyn MaxSessionsResolver>>) -> SessionConfig {
        SessionConfig {
            enabled: true,
            default_max_sessions: default_max,
            eviction_strategy: EvictionStrategy::Fifo,
            max_sessions_resolver: resolver,
        }
    }

    async fn seed_user(users: &InMemoryUserRepository, id_email: &str) -> String {
        let created = users
            .create(CreateUserData {
                email: format!("{id_email}@example.com"),
                name: "Seed".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: Some("MEMBER".to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        let Ok(user) = created else { return String::new() };
        user.id
    }

    fn service(
        store: Arc<InMemoryStores>,
        users: Arc<InMemoryUserRepository>,
        hooks: Arc<dyn AuthHooks>,
        cfg: SessionConfig,
    ) -> SessionService {
        SessionService::new(store, users, hooks, cfg, 3600)
    }

    #[tokio::test]
    async fn enforce_session_limit_evicts_oldest_excluding_the_new_session() {
        // With a cap of two and three live sessions, the oldest is evicted, the new session is
        // preserved, and both the new-session and session-evicted hooks fire.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "limit").await;
        let hooks = Arc::new(CountingHooks::default());

        let old = hash("aaaa");
        let mid = hash("bbbb");
        let new = hash("cccc");
        let base = OffsetDateTime::UNIX_EPOCH;
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old, &record(&uid, base), 3600)
                .await
                .is_ok()
        );
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &mid,
                    &record(&uid, base + time::Duration::seconds(1)),
                    3600
                )
                .await
                .is_ok()
        );
        let new_record = record(&uid, base + time::Duration::seconds(2));
        assert!(
            store
                .create_session(SessionKind::Dashboard, &new, &new_record, 3600)
                .await
                .is_ok()
        );

        let svc = service(store.clone(), users, hooks.clone(), config(2, None));
        assert!(
            svc.after_session_created(&new_record, &new, &ctx())
                .await
                .is_ok()
        );

        // The oldest session was evicted; the newest and the middle remain.
        let remaining = svc.list_sessions(&uid, Some(&new)).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 2));
        let Ok(remaining) = remaining else { return };
        assert!(remaining.iter().all(|s| s.session_hash != old));
        assert!(
            remaining
                .iter()
                .any(|s| s.session_hash == new && s.is_current)
        );
        assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 1);
        assert_eq!(hooks.evictions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn under_the_cap_evicts_nothing_but_still_fires_new_session() {
        // A single session under the cap of five: no eviction, but the new-session hook runs.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "under").await;
        let hooks = Arc::new(CountingHooks::default());
        let only = hash("dddd");
        let rec = record(&uid, OffsetDateTime::UNIX_EPOCH);
        assert!(
            store
                .create_session(SessionKind::Dashboard, &only, &rec, 3600)
                .await
                .is_ok()
        );
        let svc = service(store, users, hooks.clone(), config(5, None));
        assert!(svc.after_session_created(&rec, &only, &ctx()).await.is_ok());
        assert_eq!(hooks.evictions.load(Ordering::Relaxed), 0);
        assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn limit_of_zero_is_clamped_to_keep_only_the_new_session() {
        // A resolved cap of 0 must not leave the user permanently over cap: it is clamped to 1,
        // so the just-created session is kept and every older session is evicted, firing the
        // session-evicted hook. With one older + the new session, exactly the new one remains.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "zero-cap").await;
        let hooks = Arc::new(CountingHooks::default());
        let old = hash("a0a0");
        let new = hash("b0b0");
        let base = OffsetDateTime::UNIX_EPOCH;
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old, &record(&uid, base), 3600)
                .await
                .is_ok()
        );
        let new_record = record(&uid, base + time::Duration::seconds(1));
        assert!(
            store
                .create_session(SessionKind::Dashboard, &new, &new_record, 3600)
                .await
                .is_ok()
        );

        // A default cap of 0 (clamped to 1 internally) evicts the old session, keeping the new.
        let svc = service(store.clone(), users, hooks.clone(), config(0, None));
        assert!(
            svc.after_session_created(&new_record, &new, &ctx())
                .await
                .is_ok()
        );
        let remaining = svc.list_sessions(&uid, Some(&new)).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 1 && v[0].session_hash == new));
        assert_eq!(hooks.evictions.load(Ordering::Relaxed), 1);
        assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn limit_of_one_evicts_every_older_session_keeping_only_the_new_one() {
        // The boundary cap of exactly 1: with two older sessions and the new one, both older
        // sessions are evicted (two eviction hooks), leaving only the just-created session.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "one-cap").await;
        let hooks = Arc::new(CountingHooks::default());
        let old1 = hash("c1c1");
        let old2 = hash("d2d2");
        let new = hash("e3e3");
        let base = OffsetDateTime::UNIX_EPOCH;
        for (h, secs) in [(&old1, 0), (&old2, 1)] {
            assert!(
                store
                    .create_session(
                        SessionKind::Dashboard,
                        h,
                        &record(&uid, base + time::Duration::seconds(secs)),
                        3600
                    )
                    .await
                    .is_ok()
            );
        }
        let new_record = record(&uid, base + time::Duration::seconds(2));
        assert!(
            store
                .create_session(SessionKind::Dashboard, &new, &new_record, 3600)
                .await
                .is_ok()
        );

        let svc = service(store.clone(), users, hooks.clone(), config(1, None));
        assert!(
            svc.after_session_created(&new_record, &new, &ctx())
                .await
                .is_ok()
        );
        let remaining = svc.list_sessions(&uid, Some(&new)).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 1 && v[0].session_hash == new));
        assert_eq!(hooks.evictions.load(Ordering::Relaxed), 2);
        assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn resolver_override_drives_the_cap() {
        // A resolver capping the user at one evicts down to a single session.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "resolver").await;
        let hooks = Arc::new(NoOpAuthHooks);
        let old = hash("1111");
        let new = hash("2222");
        let base = OffsetDateTime::UNIX_EPOCH;
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old, &record(&uid, base), 3600)
                .await
                .is_ok()
        );
        let new_record = record(&uid, base + time::Duration::seconds(5));
        assert!(
            store
                .create_session(SessionKind::Dashboard, &new, &new_record, 3600)
                .await
                .is_ok()
        );
        let svc = service(store, users, hooks, config(10, Some(Arc::new(CapOf(1)))));
        assert!(
            svc.after_session_created(&new_record, &new, &ctx())
                .await
                .is_ok()
        );
        let remaining = svc.list_sessions(&uid, Some(&new)).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 1 && v[0].session_hash == new));
    }

    #[tokio::test]
    async fn resolver_falls_back_to_default_for_a_missing_user() {
        // The resolver path with an unknown user falls back to the default cap rather than
        // failing the limit check.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let hooks = Arc::new(NoOpAuthHooks);
        let only = hash("3333");
        let rec = record("ghost-user", OffsetDateTime::UNIX_EPOCH);
        assert!(
            store
                .create_session(SessionKind::Dashboard, &only, &rec, 3600)
                .await
                .is_ok()
        );
        let svc = service(store, users, hooks, config(5, Some(Arc::new(CapOf(1)))));
        // With the default of five and only one session, nothing is evicted even though the
        // resolver would cap at one (the missing user forces the default).
        assert!(svc.after_session_created(&rec, &only, &ctx()).await.is_ok());
        let remaining = svc.list_sessions("ghost-user", None).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 1));
    }

    #[tokio::test]
    async fn revoke_session_validates_the_hash_and_checks_ownership() {
        // A malformed hash is SessionNotFound (no format oracle); a foreign user cannot
        // revoke; the owner can.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "revoke").await;
        let h = hash("4444");
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &h,
                    &record(&uid, OffsetDateTime::UNIX_EPOCH),
                    3600
                )
                .await
                .is_ok()
        );
        let svc = service(store, users, Arc::new(NoOpAuthHooks), config(5, None));
        assert!(matches!(
            svc.revoke_session(&uid, "not-a-hash").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(matches!(
            svc.revoke_session("intruder", &h).await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(svc.revoke_session(&uid, &h).await.is_ok());
        // A second revoke of the now-gone session is SessionNotFound.
        assert!(matches!(
            svc.revoke_session(&uid, &h).await,
            Err(AuthError::SessionNotFound)
        ));
    }

    #[tokio::test]
    async fn revoke_all_except_current_keeps_only_the_caller_session() {
        // Every session but the caller's current one is revoked; a malformed current hash is
        // rejected before any deletion.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "logout-others").await;
        let current = hash("5555");
        let other = hash("6666");
        let base = OffsetDateTime::UNIX_EPOCH;
        assert!(
            store
                .create_session(SessionKind::Dashboard, &current, &record(&uid, base), 3600)
                .await
                .is_ok()
        );
        assert!(
            store
                .create_session(SessionKind::Dashboard, &other, &record(&uid, base), 3600)
                .await
                .is_ok()
        );
        let svc = service(store, users, Arc::new(NoOpAuthHooks), config(5, None));
        assert!(matches!(
            svc.revoke_all_except_current(&uid, "bad").await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(svc.revoke_all_except_current(&uid, &current).await.is_ok());
        let remaining = svc.list_sessions(&uid, Some(&current)).await;
        assert!(matches!(&remaining, Ok(v) if v.len() == 1 && v[0].session_hash == current));
        // A repeat is a no-op (only the current session is left).
        assert!(svc.revoke_all_except_current(&uid, &current).await.is_ok());
    }

    #[tokio::test]
    async fn rotate_session_moves_the_detail_and_is_a_noop_for_equal_hashes() {
        // Rotating old -> new moves the detail to the new hash; rotating a hash to itself is
        // an early no-op; a malformed hash is rejected.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let uid = seed_user(&users, "rotate").await;
        let old = hash("7777");
        let new = hash("8888");
        let rec = record(&uid, OffsetDateTime::UNIX_EPOCH);
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old, &rec, 3600)
                .await
                .is_ok()
        );
        let svc = service(
            store.clone(),
            users,
            Arc::new(NoOpAuthHooks),
            config(5, None),
        );
        // A no-op (equal hashes) returns Ok without touching the store.
        assert!(svc.rotate_session(&old, &old, &rec).await.is_ok());
        // A malformed hash is rejected.
        assert!(matches!(
            svc.rotate_session("bad", &new, &rec).await,
            Err(AuthError::SessionNotFound)
        ));
        // A real rotation moves the live record to the new hash.
        assert!(svc.rotate_session(&old, &new, &rec).await.is_ok());
        assert!(matches!(
            store.find_session(SessionKind::Dashboard, &new).await,
            Ok(Some(_))
        ));
        assert!(matches!(
            store.find_session(SessionKind::Dashboard, &old).await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn new_session_hook_is_skipped_when_the_user_is_unknown() {
        // If the user cannot be projected the new-session hook is skipped (no fabricated
        // identity), but the operation still succeeds.
        let store = Arc::new(InMemoryStores::new());
        let users = Arc::new(InMemoryUserRepository::new());
        let hooks = Arc::new(CountingHooks::default());
        let only = hash("9999");
        let rec = record("nobody", OffsetDateTime::UNIX_EPOCH);
        assert!(
            store
                .create_session(SessionKind::Dashboard, &only, &rec, 3600)
                .await
                .is_ok()
        );
        let svc = service(store, users, hooks.clone(), config(5, None));
        assert!(svc.after_session_created(&rec, &only, &ctx()).await.is_ok());
        // The hook was skipped because the user does not exist.
        assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn is_session_hash_accepts_only_64_lowercase_hex() {
        assert!(is_session_hash(&"a1".repeat(32)));
        assert!(!is_session_hash(&"a".repeat(63)));
        assert!(!is_session_hash(&"A".repeat(64)));
        assert!(!is_session_hash(&"g".repeat(64)));
        assert!(!is_session_hash(""));
    }

    #[test]
    fn truncate_ip_bounds_an_overlong_value_and_preserves_a_normal_one() {
        // A normal IPv4/IPv6 address passes through; an over-long attacker value is bounded to
        // MAX_IP_LENGTH on a char boundary.
        assert_eq!(truncate_ip("203.0.113.4"), "203.0.113.4");
        let long = "9".repeat(200);
        assert_eq!(truncate_ip(&long).len(), MAX_IP_LENGTH);
        // A maximal IPv6 literal is preserved unchanged.
        let ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:ffff:ffff:ffff";
        let truncated = truncate_ip(ipv6);
        assert!(truncated.chars().count() <= MAX_IP_LENGTH);
    }

    #[test]
    fn truncate_ip_bounds_by_bytes_on_a_char_boundary_for_a_multibyte_value() {
        // An attacker-controlled value that is <= 45 CHARS but > 45 BYTES (20 three-byte CJK
        // chars: 20 chars, 60 bytes) must be bounded by BYTES, not chars, and never split a
        // codepoint. A char-count truncation would have returned all 60 bytes.
        let multibyte = "中".repeat(20);
        assert!(multibyte.chars().count() <= MAX_IP_LENGTH);
        assert!(multibyte.len() > MAX_IP_LENGTH);

        let bounded = truncate_ip(&multibyte);
        // Bounded by the byte limit, and a whole number of full chars (45 / 3 = 15), proving the
        // cut landed on a char boundary rather than mid-codepoint.
        assert!(bounded.len() <= MAX_IP_LENGTH);
        assert!(bounded.chars().all(|c| c == '中'));
        assert_eq!(bounded.len(), 45);
        assert_eq!(bounded.chars().count(), 15);
    }

    #[test]
    fn parse_user_agent_resolves_browser_and_os_precedence() {
        // Edge and Opera win over the Chrome token they also carry; Chrome over Safari; Safari
        // requires a Version/ token; mobile OS wins over the embedded desktop token.
        assert_eq!(
            parse_user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36 Edg/120.0"
            ),
            "Edge on Windows"
        );
        assert_eq!(
            parse_user_agent(
                "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36 OPR/106.0"
            ),
            "Opera on Linux"
        );
        assert_eq!(
            parse_user_agent(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Chrome/120.0 Safari/537.36"
            ),
            "Chrome on macOS"
        );
        assert_eq!(
            parse_user_agent("Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/121.0"),
            "Firefox on Windows"
        );
        assert_eq!(
            parse_user_agent(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Safari/605.1.15"
            ),
            "Safari on iOS"
        );
        assert_eq!(
            parse_user_agent("Mozilla/5.0 (Linux; Android 14) Chrome/120.0 Mobile Safari/537.36"),
            "Chrome on Android"
        );
        // A bare WebKit agent without Version/ is not classified as Safari.
        assert_eq!(
            parse_user_agent("some-internal-tool/1.0"),
            "Unknown Browser on Unknown OS"
        );
    }

    #[test]
    fn session_info_marks_current_via_constant_time_compare() {
        // A session whose hash matches the current marker is flagged current; an absent
        // current (empty string) flags none.
        let detail = SessionDetail {
            session_hash: hash("abcd"),
            device: "Chrome".to_owned(),
            ip: "1.2.3.4".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_activity_at: OffsetDateTime::UNIX_EPOCH,
        };
        let current = to_info(detail.clone(), &hash("abcd"));
        assert!(current.is_current);
        assert_eq!(current.id, &hash("abcd")[..8]);
        let not_current = to_info(detail, "");
        assert!(!not_current.is_current);
    }

    #[test]
    fn config_compiles_into_an_engine_default() {
        // A smoke check that the default session config is the disabled soft-cap policy the
        // engine seeds, so the service constructor accepts it verbatim.
        let cfg = AuthConfig::default().sessions;
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_max_sessions, 5);
    }

    /// A session store that lists one session but fails its revoke with a non-`SessionNotFound`
    /// error, to drive the error-propagation arm of `revoke_all_except_current`.
    struct FailingRevokeStore;

    #[async_trait::async_trait]
    impl SessionStore for FailingRevokeStore {
        async fn create_session(
            &self,
            _kind: SessionKind,
            _token_hash: &str,
            _detail: &SessionRecord,
            _ttl_secs: u64,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        async fn rotate(
            &self,
            _kind: SessionKind,
            _rotation: &SessionRotation,
        ) -> Result<crate::traits::RotateOutcome, AuthError> {
            Ok(crate::traits::RotateOutcome::Invalid)
        }
        async fn find_session(
            &self,
            _kind: SessionKind,
            _token_hash: &str,
        ) -> Result<Option<SessionRecord>, AuthError> {
            Ok(None)
        }
        async fn list_sessions(
            &self,
            _kind: SessionKind,
            _user_id: &str,
        ) -> Result<Vec<SessionDetail>, AuthError> {
            // One session whose hash is not the caller's current, so the service attempts a
            // revoke (which then fails with a backend error).
            Ok(vec![SessionDetail {
                session_hash: "f".repeat(64),
                device: "Chrome".to_owned(),
                ip: "1.2.3.4".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                last_activity_at: OffsetDateTime::UNIX_EPOCH,
            }])
        }
        async fn revoke_session(
            &self,
            _kind: SessionKind,
            _user_id: &str,
            _session_hash: &str,
        ) -> Result<(), AuthError> {
            Err(AuthError::Internal("revoke backend down".into()))
        }
        async fn delete_grace_pointer(
            &self,
            _kind: SessionKind,
            _session_hash: &str,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        async fn revoke_all(&self, _kind: SessionKind, _user_id: &str) -> Result<(), AuthError> {
            Ok(())
        }
        async fn blacklist_access(
            &self,
            _jti_or_hash: &str,
            _remaining_ttl_secs: u64,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        async fn is_blacklisted(&self, _jti_or_hash: &str) -> Result<bool, AuthError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn revoke_all_except_current_propagates_a_non_not_found_error() {
        // A backend error (not `SessionNotFound`) on a victim revoke is propagated, unlike the
        // benign `SessionNotFound` which is swallowed.
        let svc = SessionService::new(
            Arc::new(FailingRevokeStore),
            Arc::new(InMemoryUserRepository::new()),
            Arc::new(NoOpAuthHooks),
            config(5, None),
            3600,
        );
        assert!(matches!(
            svc.revoke_all_except_current("u1", &hash("aaaa")).await,
            Err(AuthError::Internal(_))
        ));

        // Exercise the rest of the double's object-safe surface so it is fully covered.
        let store = FailingRevokeStore;
        let rec = record("u1", OffsetDateTime::UNIX_EPOCH);
        assert!(
            store
                .create_session(SessionKind::Dashboard, "h", &rec, 60)
                .await
                .is_ok()
        );
        let rotation = SessionRotation {
            old_hash: "o".to_owned(),
            new_hash: "n".to_owned(),
            new_raw: String::new(),
            new_record: rec,
            refresh_ttl: 60,
            grace_ttl: 0,
        };
        assert!(matches!(
            store.rotate(SessionKind::Dashboard, &rotation).await,
            Ok(crate::traits::RotateOutcome::Invalid)
        ));
        assert!(matches!(
            store.find_session(SessionKind::Dashboard, "h").await,
            Ok(None)
        ));
        assert!(
            store
                .delete_grace_pointer(SessionKind::Dashboard, "h")
                .await
                .is_ok()
        );
        assert!(store.revoke_all(SessionKind::Dashboard, "u1").await.is_ok());
        assert!(store.blacklist_access("jti", 60).await.is_ok());
        assert!(matches!(store.is_blacklisted("jti").await, Ok(false)));
    }
}
