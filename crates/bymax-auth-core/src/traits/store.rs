//! The Redis-store abstraction: the domain-level, intent-named store traits the engine
//! services depend on, keyed by [`SessionKind`] rather than low-level Redis verbs. The
//! canonical implementation lives in `bymax-auth-redis`; the seam exists so the backing
//! store is swappable and each trait can be exercised by an in-memory fake under test.
//!
//! The key prefixes, the stored JSON shapes, the `{namespace}:` prefixing, and the
//! atomic Lua scripts are implementation details owned by the store impl — they never
//! appear on these traits. Every fallible method returns [`AuthError`], the same error
//! the engine surfaces.

use async_trait::async_trait;
use bymax_auth_types::AuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Selects the identity domain a store operation targets, which in turn selects the Redis
/// prefix pair (`rt`/`prt`, `rp`/`prp`, `sess`/`psess`, `sd`/`psd`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// Dashboard/tenant sessions.
    Dashboard,
    /// Platform-admin sessions.
    Platform,
}

/// The purpose namespace an OTP record belongs to. Its [`OtpPurpose::as_str`] form is the
/// `{purpose}` segment of the Redis key, byte-identical to nest-auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpPurpose {
    /// OTP-based password reset.
    PasswordReset,
    /// Email-verification OTP.
    EmailVerification,
}

impl OtpPurpose {
    /// The stable wire form used as the OTP key's purpose segment.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::EmailVerification => "email_verification",
        }
    }
}

/// The stored refresh-session record. Holds everything needed to reissue an access token
/// without a database hit. `tenant_id` is absent for platform sessions. JSON is camelCase
/// for byte-parity with nest-auth payloads already in Redis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    /// The owning user id.
    pub user_id: String,
    /// The tenant scope; absent for platform sessions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tenant_id: Option<String>,
    /// The user's role at session creation.
    pub role: String,
    /// Human-readable device/browser string.
    pub device: String,
    /// Originating IP (trusted-proxy resolved).
    pub ip: String,
    /// Session creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Whether MFA was enabled on the account when the session was created.
    ///
    /// Persisted so a rotation can propagate it into the rotated access claims. Without
    /// it every rotation would mint `mfa_enabled: false`, and since the MFA gate only
    /// refuses a token whose claims say `mfa_enabled && !mfa_verified`, one routine
    /// refresh would silently disable second-factor enforcement for an enrolled account.
    ///
    /// `mfa_verified` is deliberately NOT stored: it must stay `false` in a rotated token
    /// so clearing the second factor always goes back through the MFA challenge.
    ///
    /// Required on the wire, deliberately. Defaulting a missing value to `false` would turn a
    /// truncated or corrupt record into a silent second-factor bypass — the gate only refuses a
    /// token whose claims say `mfa_enabled && !mfa_verified`, so an absent field reads as "this
    /// account has no second factor" and the rotated token clears every MFA-gated route. A
    /// record that cannot be read is treated as no session at all, which costs the holder a
    /// login and costs an attacker the bypass.
    pub mfa_enabled: bool,
    /// The refresh-token **family** (login lineage) this session belongs to. Minted at login
    /// and inherited unchanged across every rotation, so all descendants of one login share it.
    /// It is the unit of reuse-detection revocation: presenting an already-consumed refresh
    /// token (post-grace) revokes the whole family (section 12.5.2). Empty only on the
    /// placeholder a replayed token produces, which is never stored — such a record carries no
    /// family and is never a reuse-revocation target; it is omitted from the wire when empty
    /// for byte-parity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_id: String,
    /// When the **family** was born — the moment of the login this session descends from.
    ///
    /// Distinct from [`SessionRecord::created_at`], which is this session's own creation and is
    /// reset on every rotation. Carried unchanged through the lineage so the absolute-lifetime
    /// cap has something to measure: without it, a client rotating every fifteen minutes renews
    /// its lifetime forever and a session established once never has to be established again.
    ///
    /// Serialized as an ISO-8601 string alongside `family_id`, and omitted with it on a
    /// family-less record — such a session is simply not capped.
    #[serde(
        default,
        with = "optional_rfc3339",
        skip_serializing_if = "Option::is_none"
    )]
    pub family_created_at: Option<OffsetDateTime>,
}

/// Serde adapter for an optional RFC 3339 instant, so a record with no family birth time
/// round-trips as `None` rather than failing the whole record.
pub mod optional_rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    /// Write the instant as an RFC 3339 string, or nothing when absent.
    ///
    /// # Errors
    ///
    /// Propagates whatever the serializer reports, or a formatting failure.
    pub fn serialize<S>(value: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(instant) => instant
                .format(&Rfc3339)
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Read an RFC 3339 string back, treating an absent field as `None`.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the field is present but not RFC 3339.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|value| OffsetDateTime::parse(&value, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Serde adapter carrying an [`OffsetDateTime`] as a **Unix-millisecond number**.
///
/// This is the encoding nest-auth uses for the `sd:`/`psd:` per-session detail record: it
/// writes `createdAt`/`lastActivityAt` with `Date.now()` and re-reads them under a
/// `typeof === 'number'` guard, so an RFC 3339 string in those fields makes the record
/// unreadable — and, because a member whose detail fails to parse is treated as stale, it
/// makes the session disappear from the other backend's listing. Both backends must therefore
/// agree on the numeric form for the shared-Redis promise to hold.
///
/// Note this is deliberately **not** how [`SessionRecord::created_at`] is encoded: nest-auth
/// writes that one as an ISO-8601 string (`new Date().toISOString()`), so `rt:`/`prt:` records
/// keep the RFC 3339 adapter.
pub mod unix_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Nanoseconds in one millisecond — the scale factor between `time`'s native
    /// `unix_timestamp_nanos` and the millisecond wire form.
    const NANOS_PER_MILLI: i128 = 1_000_000;

    /// Write the instant as a Unix-millisecond `i64`, saturating at the `i64` bounds. The
    /// clamp preserves the sign, so a pre-epoch instant stays negative instead of flipping to
    /// `i64::MAX` on overflow.
    ///
    /// # Errors
    ///
    /// Propagates whatever the serializer reports while emitting the number.
    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let millis = (value.unix_timestamp_nanos() / NANOS_PER_MILLI)
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        serializer.serialize_i64(millis)
    }

    /// Read a Unix-millisecond number back into an instant.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the field is not an integer, or when the
    /// millisecond count is outside the range `OffsetDateTime` can represent.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = i64::deserialize(deserializer)?;
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * NANOS_PER_MILLI)
            .map_err(serde::de::Error::custom)
    }
}

/// How long a [`SessionStore`] must keep a bumped token epoch readable, in seconds (30 days).
///
/// The epoch record is what makes an already-issued access token verifiable as stale. If it can
/// lapse while a pre-bump token is still inside its own `exp` window, [`SessionStore::current_epoch`]
/// falls back to `0`, the `token.epoch < stored` test stops firing, and a token revoked by a
/// password reset becomes valid again — a fail-open. Startup validation therefore rejects an
/// `jwt.access_expires_in` longer than this bound, which lets a store safely expire the record
/// rather than retaining it forever.
pub const TOKEN_EPOCH_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// One session's display detail, returned by [`SessionStore::list_sessions`]. The
/// `session_hash` is the bare SHA-256 hex of the refresh token (the `sess:`-set member is that
/// hash under its `rt:`/`prt:` prefix), never the raw token.
///
/// The two timestamps are Unix-millisecond numbers on the wire — the encoding nest-auth writes
/// for `sd:`/`psd:` (see [`unix_millis`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    /// The stored session hash (set member); a display id, never the raw token.
    pub session_hash: String,
    /// Human-readable device/browser string.
    pub device: String,
    /// Originating IP.
    pub ip: String,
    /// Session creation time, as Unix milliseconds on the wire.
    #[serde(with = "unix_millis")]
    pub created_at: OffsetDateTime,
    /// Last observed activity time, as Unix milliseconds on the wire.
    #[serde(with = "unix_millis")]
    pub last_activity_at: OffsetDateTime,
}

/// The parameters of an atomic refresh rotation, grouped so [`SessionStore::rotate`]
/// takes a single value instead of a long positional argument list. The new **raw** token
/// is generated by the caller; only its `new_hash` ever becomes a key — the raw value is
/// never written to the store. The `Debug` impl redacts `new_raw` so the live credential
/// cannot leak into a log.
#[derive(Clone)]
pub struct SessionRotation {
    /// Hash of the presented (old) refresh token.
    pub old_hash: String,
    /// Hash of the freshly-minted (new) refresh token.
    pub new_hash: String,
    /// The new raw refresh token (used by the caller, never persisted as a key).
    pub new_raw: String,
    /// The session record bound to the new token.
    pub new_record: SessionRecord,
    /// TTL for the new refresh session, in seconds.
    pub refresh_ttl: u64,
    /// TTL for the rotation grace pointer, in seconds.
    pub grace_ttl: u64,
}

impl std::fmt::Debug for SessionRotation {
    /// Redacts `new_raw` (the live refresh token); the hashes and record are display-safe.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRotation")
            .field("old_hash", &self.old_hash)
            .field("new_hash", &self.new_hash)
            .field("new_raw", &"[REDACTED]")
            .field("new_record", &self.new_record)
            .field("refresh_ttl", &self.refresh_ttl)
            .field("grace_ttl", &self.grace_ttl)
            .finish()
    }
}

/// The outcome of an atomic refresh rotation (`refresh_rotate`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The old token was present and consumed. Carries the **consumed (old) session
    /// record**, from which the caller derives the user id to update the session
    /// bookkeeping; the freshly-minted token is bound to the new record that was supplied in
    /// the [`SessionRotation`] and is already stored.
    Rotated(SessionRecord),
    /// The old token was already rotated but is inside the grace window; the caller mints
    /// a fresh token for this recovered record without planting a new grace pointer.
    Grace(SessionRecord),
    /// The old token was validly issued and already rotated, and its grace window has since
    /// closed — a **reuse of a consumed refresh token**, the signature of a stolen token being
    /// replayed. Carries the compromised **family id**; the caller revokes the whole family
    /// (every live descendant of that login) and rejects the request, forcing re-authentication
    /// (OWASP refresh-token rotation with automatic reuse detection, section 12.5.2).
    Reused(String),
    /// Neither the live token, a grace pointer, nor a consumed-family marker was found — the
    /// refresh was never issued (or has fully aged out): a plain invalid refresh, not a reuse.
    Invalid,
}

/// A verified-claims snapshot minted into a single-use WebSocket upgrade ticket. The
/// value is a snapshot, never a token. JSON is camelCase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsTicketSnapshot {
    /// The subject (user id).
    pub sub: String,
    /// The tenant scope; absent for platform tickets.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tenant_id: Option<String>,
    /// The user's role.
    pub role: String,
    /// The account status at mint time.
    pub status: String,
    /// Whether MFA is enabled on the account.
    pub mfa_enabled: bool,
    /// Whether the originating session had satisfied MFA.
    pub mfa_verified: bool,
}

/// Refresh-session lifecycle plus access-JWT revocation. Backs the `rt`/`prt`, `rp`/`prp`,
/// `sess`/`psess`, `sd`/`psd`, and `rv` keyspaces.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure; ownership-checked operations return the
/// matching typed variant (e.g. [`AuthError::SessionNotFound`] from
/// [`SessionStore::revoke_session`], [`AuthError::RefreshTokenInvalid`] surfaced by the
/// caller on [`RotateOutcome::Invalid`]).
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Persist a freshly-issued refresh session and register it in the user's session set.
    async fn create_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomic rotation with a grace window, driven by a [`SessionRotation`] bundle.
    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError>;

    /// Look up a live session by refresh-token hash, without rotating it.
    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError>;

    /// List all live sessions for a user.
    async fn list_sessions(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<Vec<SessionDetail>, AuthError>;

    /// Ownership-checked single revoke. Returns [`AuthError::SessionNotFound`] when the
    /// hash is not owned by the user.
    async fn revoke_session(
        &self,
        kind: SessionKind,
        user_id: &str,
        session_hash: &str,
    ) -> Result<(), AuthError>;

    /// Delete the rotation grace pointer for a refresh-token hash (`rp:`/`prp:`), if any, so a
    /// just-rotated token cannot still recover a session through the grace window after the
    /// owner has logged out. Idempotent: a no-op when no grace pointer exists. This complements
    /// [`SessionStore::revoke_session`], which deletes only the primary refresh keys; logout
    /// calls both so BOTH the primary and grace keys are cleaned.
    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError>;

    /// Revoke every session for a user in one transaction.
    async fn revoke_all(&self, kind: SessionKind, user_id: &str) -> Result<(), AuthError>;

    /// Revoke every live session in a refresh-token **family** (one login lineage), deleting
    /// each descendant's refresh/detail keys and clearing the family index. Called on
    /// reuse-detection ([`RotateOutcome::Reused`]) to lock out a stolen token's whole chain.
    /// Idempotent: an unknown or already-cleared family is a no-op.
    ///
    /// Returns the id of the account the family belonged to, or `None` when no member record
    /// was readable. The owner is reported because the reuse-detection caller cannot obtain it
    /// any other way: the replayed token's own `rt:` key was deleted when it was rotated, so
    /// the family index is the only surviving link between that token and an account — and an
    /// implementation already has to read a member to find the session index it prunes.
    async fn revoke_family(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<Option<String>, AuthError>;

    /// Add a JTI (preferred) or full-JWT hash to the access-token blacklist for its
    /// remaining lifetime.
    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Whether an access JTI or JWT hash is blacklisted — consulted on every protected
    /// request.
    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError>;

    /// The user's current token **epoch** (generation counter), or `0` when none is stored.
    /// Stamped into a freshly-issued access token and re-read on every verification: a token
    /// whose stamped epoch is below this value was issued before an invalidating event and is
    /// rejected. The `0` default keeps the mechanism inert for a user who has never had a bump.
    async fn current_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError>;

    /// Atomically increment the user's token epoch and return the new value, invalidating every
    /// outstanding access token for that user at once (a password reset or a sign-out-everywhere).
    /// Idempotent in effect: each call advances the generation, and only tokens stamped at or
    /// above the new value remain valid.
    async fn bump_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError>;
}

/// One-time-password records for email verification and OTP-based password reset.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure; [`OtpStore::verify`] returns the typed
/// outcome ([`AuthError::OtpExpired`], [`AuthError::OtpInvalid`],
/// [`AuthError::OtpMaxAttempts`], or `Ok(())` on success).
#[async_trait]
pub trait OtpStore: Send + Sync {
    /// Store an OTP code for a purpose+identifier with a TTL.
    async fn put(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomically verify the code, bump the attempt counter, and consume on success.
    async fn verify(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        max_attempts: u32,
    ) -> Result<(), AuthError>;

    /// Begin a resend if the cooldown has elapsed; `false` means a resend already
    /// happened inside the cooldown window.
    async fn try_begin_resend(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        cooldown_secs: u64,
    ) -> Result<bool, AuthError>;
}

/// Fixed-window failed-attempt counters keyed by an HMAC of `tenant:email`.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure.
#[async_trait]
pub trait BruteForceStore: Send + Sync {
    /// Whether the identifier has reached `max_attempts` within its window.
    async fn is_locked(&self, identifier: &str, max_attempts: u32) -> Result<bool, AuthError>;

    /// Atomically increment the failure counter (setting the window TTL only on the first
    /// failure) and return the new count.
    async fn record_failure(&self, identifier: &str, window_secs: u64) -> Result<i64, AuthError>;

    /// Reset the counter (on a successful authentication).
    async fn reset(&self, identifier: &str) -> Result<(), AuthError>;

    /// Seconds remaining on this identifier's fixed window — the TTL of its failure counter,
    /// which exists from the first failure — or `0` when no counter is recorded. Callers
    /// compute a `Retry-After` from this after [`BruteForceStore::is_locked`] confirms a
    /// lockout.
    async fn remaining_lockout_secs(&self, identifier: &str) -> Result<u64, AuthError>;
}

/// The single-use WebSocket upgrade-ticket store. A ticket is minted from an
/// already-authorized, MFA-satisfied session and redeemed exactly once at the WS
/// handshake, so an access JWT never appears in a URL.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure.
#[async_trait]
pub trait WsTicketStore: Send + Sync {
    /// Mint a single-use ticket holding the verified-claims snapshot, returning the raw
    /// ticket the client presents at the handshake.
    async fn mint(&self, snapshot: &WsTicketSnapshot, ttl_secs: u64) -> Result<String, AuthError>;

    /// Redeem and consume a ticket (single-use), returning its snapshot or `None` when the
    /// ticket is unknown or already consumed.
    async fn redeem(&self, ticket: &str) -> Result<Option<WsTicketSnapshot>, AuthError>;
}

/// The identity bound to a password-reset proof (a link token or the OTP-flow verified
/// token). Stored under `pw_reset:`/`pw_vtok:` keyed by `sha256(token)` — the raw token is never a
/// key — and read back on consume so the reset can re-bind the proof to the same account.
/// JSON is camelCase for parity with nest-auth payloads already in Redis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetContext {
    /// The account the reset proof was issued for.
    pub user_id: String,
    /// The email the reset proof was issued for (re-checked on consume).
    pub email: String,
    /// The tenant scope the reset proof was issued for (re-checked on consume).
    pub tenant_id: String,
    /// A digest of the password hash this proof was issued against, binding it to that password.
    ///
    /// Several reset tokens can be alive at once — a 60-second send cooldown against a
    /// 600-second TTL allows up to ten — and completing one used to leave the rest valid. That
    /// is the wrong end state precisely when it matters: a victim who resets *because* an
    /// attacker read a link from their mailbox had not closed the link the attacker read. The
    /// binding makes the first completed rotation invalidate all of them, with no per-user
    /// index to keep in step.
    ///
    /// Empty when the account had no password at issue time. **Absent** on a record written by
    /// an older build, or by a sibling that has not taken this change, which `serde` reads as
    /// empty — accepted as "no binding" so a rolling deploy does not break resets in flight.
    #[serde(default)]
    pub password_fingerprint: String,
}

/// The trusted metadata stored for a pending invitation under `inv:` keyed by
/// `sha256(token)` — the raw token is never a key. Read back on accept; because the payload
/// is trusted, the accept flow re-validates `role` against the hierarchy as anti-tamper (a
/// deployment that does not fully trust Redis SHOULD additionally HMAC-sign this record).
/// JSON is camelCase for parity with nest-auth payloads already in Redis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredInvitation {
    /// The invited email (already normalized: trimmed + lower-cased).
    pub email: String,
    /// The role the invitee is granted on accept (re-validated against the hierarchy).
    pub role: String,
    /// The tenant the invitee joins.
    pub tenant_id: String,
    /// The user id of the inviter (for audit / the accepted hook).
    pub inviter_user_id: String,
    /// When the invitation was issued, as an RFC 3339 string on the wire.
    ///
    /// Mandatory for cross-backend parity: nest-auth writes `createdAt` (an
    /// ISO-8601 string from `new Date().toISOString()`) and its `isStoredInvitation` guard
    /// **rejects** a record without it. Because acceptance consumes the record with a
    /// single-use `GETDEL`, a nest-auth backend reading an invitation that lacks the field
    /// fails validation *after* the token is already gone — destroying the invitation
    /// instead of accepting it. Encoded as RFC 3339 (not Unix millis like `sd:`) because
    /// that is what nest-auth stores here.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Single-use password-reset proof storage: the link token (`pw_reset:`) and the OTP-flow
/// verified token (`pw_vtok:`). Both store a [`ResetContext`] keyed by `sha256(token)` and are
/// consumed atomically with `getdel`, so a proof is valid exactly once. The OTP records
/// themselves are owned by [`OtpStore`] — this store backs only the two opaque-token
/// keyspaces.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure; a `consume_*` of an absent/expired/already-used
/// proof is the non-error `Ok(None)`, not an error.
#[async_trait]
pub trait PasswordResetStore: Send + Sync {
    /// Store a reset-link-token context under `pw_reset:{sha256(token)}` with a TTL.
    async fn put_token(
        &self,
        token: &str,
        context: &ResetContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomically consume (`getdel`) a reset-link-token context. `None` when the token is
    /// unknown, expired, or already consumed.
    async fn consume_token(&self, token: &str) -> Result<Option<ResetContext>, AuthError>;

    /// Delete a reset-link token without consuming its value, used to clean up after an
    /// undeliverable email so an unusable token does not linger in a Redis snapshot.
    async fn delete_token(&self, token: &str) -> Result<(), AuthError>;

    /// Store an OTP-flow verified-token context under `pw_vtok:{sha256(token)}` with a TTL.
    async fn put_verified(
        &self,
        token: &str,
        context: &ResetContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomically consume (`getdel`) a verified-token context. `None` when the token is
    /// unknown, expired, or already consumed.
    async fn consume_verified(&self, token: &str) -> Result<Option<ResetContext>, AuthError>;
}

/// Single-use invitation storage. A [`StoredInvitation`] is held under `inv:{sha256(token)}`
/// and consumed atomically with `getdel`, so an invitation is accepted exactly once.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure; a `consume` of an absent/expired/already-used
/// invitation is the non-error `Ok(None)`, not an error.
#[async_trait]
pub trait InvitationStore: Send + Sync {
    /// Store an invitation under `inv:{sha256(token)}` with a TTL. The raw token is never
    /// persisted — only its hash becomes a key.
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &StoredInvitation,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomically consume (`getdel`) an invitation. `None` when the token is unknown,
    /// expired, or already consumed.
    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError>;

    /// Point the invitee index (`invidx:{tenantId}:{sha256(email)}`) at a pending
    /// invitation's token hash, with the invitation's own TTL so the pair expires together.
    ///
    /// The index is what makes an invitation manageable at all: the record is keyed by the
    /// hash of a token only the invitee's mailbox ever held, so without it nobody on the
    /// issuing side can name a pending invitation, let alone withdraw one. The email is
    /// hashed by the implementation — a dump of the keyspace must not enumerate who a tenant
    /// has been inviting.
    async fn put_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Read the token hash the invitee index points at, leaving the entry in place.
    async fn read_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<String>, AuthError>;

    /// Atomically take (`getdel`) the invitee index entry.
    async fn take_invitation_index(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<String>, AuthError>;

    /// Read an invitation by its stored token **hash**, without consuming it — the revocation
    /// path, which reaches the record through the index rather than through a raw token.
    async fn read_invitation_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredInvitation>, AuthError>;

    /// Delete an invitation by its stored token **hash**. `true` when a record was removed.
    async fn delete_invitation_by_hash(&self, token_hash: &str) -> Result<bool, AuthError>;
}

/// The MFA storage seam: the AES-protected pending-setup record, the short-lived MFA
/// temp-token marker, and the TOTP anti-replay marker — backing the `mfa_setup:`, `mfa:`,
/// and `tu:` keyspaces (§12.4). Every value is hashed/encrypted by the engine before it
/// reaches this trait; the store never sees a plaintext secret, recovery code, or `jti`.
///
/// The setup record (`put_setup_nx`/`get_setup`/`take_setup`) is the AES-256-GCM wire
/// string the [`crate::services`] MFA layer produced — this trait stores it opaquely. The
/// `mark_totp_used` and `challenge_consume` operations are the two anti-replay forms: the
/// standalone marker for the enable/disable/regenerate paths, and the **fused** marker-set
/// plus temp-token consume that the login/OAuth challenge path runs in one atomic step so a
/// replayed TOTP code can never consume a second token (§7.5.6).
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure. The boolean results carry the atomic decision
/// (whether the `SET NX` won, whether the replay marker was newly created) rather than an
/// error, so the caller can branch without a second round-trip.
#[cfg(feature = "mfa")]
#[async_trait]
pub trait MfaStore: Send + Sync {
    /// Store the pending-setup record under `mfa_setup:{user_id_hash}` only if absent
    /// (atomic `SET NX EX`). Returns `true` when this call created the record, `false` when
    /// one already existed (a concurrent `setup` won the race).
    async fn put_setup_nx(
        &self,
        user_id_hash: &str,
        value: &str,
        ttl: u64,
    ) -> Result<bool, AuthError>;

    /// Read the pending-setup record at `mfa_setup:{user_id_hash}` without consuming it
    /// (the idempotent `setup` fast-path). `None` when absent or expired.
    async fn get_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError>;

    /// Atomically consume (`GETDEL`) the pending-setup record at `mfa_setup:{user_id_hash}`
    /// — the completion gate for `verify_and_enable`. `None` when a concurrent enable already
    /// consumed it.
    async fn take_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError>;

    /// Write the MFA temp-token marker `mfa:{jti_hash} = user_id` with a TTL, enforcing
    /// single-use of the challenge temp token.
    async fn put_temp(&self, jti_hash: &str, user_id: &str, ttl: u64) -> Result<(), AuthError>;

    /// Read the MFA temp-token marker at `mfa:{jti_hash}` with `GET` (never `GETDEL`), so a
    /// mistyped code leaves the token alive for a retry (§7.3.5). `None` when absent/expired.
    async fn get_temp(&self, jti_hash: &str) -> Result<Option<String>, AuthError>;

    /// Delete the MFA temp-token marker at `mfa:{jti_hash}`, reporting whether **this** call
    /// was the one that removed it.
    ///
    /// The boolean is what makes the recovery-code path single-use. That path has no `tu:`
    /// marker to fuse against (unlike TOTP, see [`MfaStore::challenge_consume`]), so it
    /// consumes the temp token standalone — and when the delete reported nothing, two
    /// concurrent challenges carrying the same temp token and the same recovery code both saw
    /// the marker, both "consumed" it, and both issued a full session. Gating success on the
    /// deletion gives that path the same exactly-once property the fused TOTP step has.
    ///
    /// Idempotent: a second call for the same `jti_hash` returns `false` rather than erroring.
    async fn del_temp(&self, jti_hash: &str) -> Result<bool, AuthError>;

    /// Set the standalone anti-replay marker `tu:{replay_id} = "1"` with `NX EX ttl`.
    /// Returns `true` when the marker was newly created (the code had not been seen) and
    /// `false` when it already existed (a replay). Used by `verify_and_enable` / `disable` /
    /// `regenerate_recovery_codes`, which have no temp token to consume.
    async fn mark_totp_used(&self, replay_id: &str, ttl: u64) -> Result<bool, AuthError>;

    /// The **fused** challenge step (§7.5.6): set `tu:{replay_id}` `NX EX ttl` and, *iff* that
    /// marker was newly created, delete the temp token `mfa:{jti_hash}` — in one atomic Lua
    /// script. The temp-token deletion is the single-consume gate: returns `true` only when this
    /// call **both** freshly marked the code **and** removed a still-present temp token (the sole
    /// winner). It returns `false` on a replayed code (the marker already existed) **and** when a
    /// distinct still-valid code loses the race for an already-consumed token — in that case the
    /// just-set marker is rolled back so the unused code is not burned. This makes "mark the code
    /// used" and "consume the temp token" inseparable, so neither a replayed code nor two
    /// distinct still-valid codes (different `replay_id`s) sharing one temp token can ever issue
    /// more than one session.
    async fn challenge_consume(
        &self,
        replay_id: &str,
        jti_hash: &str,
        ttl: u64,
    ) -> Result<bool, AuthError>;
}

/// Single-use OAuth `state` + PKCE storage backing the `os:` keyspace (§11.3, §12.4). On
/// initiate the engine writes `os:{sha256(state)} = <payload>` with a short TTL (600 s); on
/// callback it consumes the key atomically with `getdel`, so a captured `state` cannot be
/// replayed. Only the `sha256` of the raw `state` is ever a key, and the payload (the tenant
/// scope plus the PKCE `code_verifier`) is opaque to this trait — the engine owns its
/// encoding so the verifier never leaves the server in cleartext.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure; a `take_state` of an absent / expired /
/// already-consumed key is the non-error `Ok(None)`, not an error.
#[cfg(feature = "oauth")]
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    /// Store the opaque state payload under `os:{state_hash}` with a TTL. `state_hash` is the
    /// hex `sha256` of the raw `state`; the raw `state` is never persisted.
    async fn put_state(
        &self,
        state_hash: &str,
        payload: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Atomically read-and-delete (`getdel`) the payload at `os:{state_hash}` — the single
    /// step that both verifies the `state` and consumes it. `None` when the key is unknown,
    /// expired, or already consumed (an invalid / forged / replayed `state`).
    async fn take_state(&self, state_hash: &str) -> Result<Option<String>, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_record() -> SessionRecord {
        SessionRecord {
            user_id: "u1".into(),
            tenant_id: Some("t1".into()),
            role: "MEMBER".into(),
            device: "Chrome on macOS".into(),
            ip: "203.0.113.4".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            mfa_enabled: false,
            family_id: "fam-1".into(),
            family_created_at: Some(OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn the_epoch_retention_window_is_thirty_days_to_the_second() {
        // Pinned to the literal, never recomputed from the same expression the constant uses.
        // Every other test of this bound reads it back through the constant — the startup rule
        // is checked with `TOKEN_EPOCH_RETENTION_SECS + 1` and `== TOKEN_EPOCH_RETENTION_SECS` —
        // so a typo in the arithmetic would round-trip perfectly and the validation would go on
        // "passing" while enforcing a ceiling nobody chose. This is the only assertion that can
        // see that, and the number is a contract: nest-auth's `TOKEN_EPOCH_RETENTION_SECONDS`
        // and the 30 days both READMEs promise have to be the same value.
        assert_eq!(TOKEN_EPOCH_RETENTION_SECS, 2_592_000);
    }

    #[test]
    fn the_optional_birth_time_adapter_round_trips_both_arms() {
        // On a `SessionRecord` the field is skipped when absent, so the `None` arm of the
        // serializer is unreachable there. It is still the adapter's contract, and a caller
        // that uses it without `skip_serializing_if` must get `null` rather than a panic —
        // this pins both directions independently of how the record happens to use it.
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct Wrapper {
            #[serde(with = "optional_rfc3339")]
            at: Option<OffsetDateTime>,
        }

        let absent = Wrapper { at: None };
        let json = serde_json::to_string(&absent).unwrap_or_default();
        assert_eq!(json, r#"{"at":null}"#);
        assert!(matches!(
            serde_json::from_str::<Wrapper>(&json),
            Ok(back) if back == absent
        ));

        let present = Wrapper {
            at: Some(OffsetDateTime::UNIX_EPOCH),
        };
        let json = serde_json::to_string(&present).unwrap_or_default();
        assert_eq!(json, r#"{"at":"1970-01-01T00:00:00Z"}"#);
        assert!(matches!(
            serde_json::from_str::<Wrapper>(&json),
            Ok(back) if back == present
        ));

        // A present-but-malformed value is an error, not a silent `None`: a record whose birth
        // time cannot be read is a record whose cap cannot be judged, and quietly dropping it
        // would uncap the session.
        assert!(serde_json::from_str::<Wrapper>(r#"{"at":"not-a-date"}"#).is_err());
    }

    #[test]
    fn otp_purpose_wire_strings_are_stable() {
        // The purpose segment is part of the Redis key contract shared with nest-auth.
        assert_eq!(OtpPurpose::PasswordReset.as_str(), "password_reset");
        assert_eq!(OtpPurpose::EmailVerification.as_str(), "email_verification");
    }
    #[test]
    fn a_record_without_the_mfa_flag_is_refused_rather_than_defaulted() {
        // Defaulting a missing `mfaEnabled` to `false` would turn a truncated or corrupt record
        // into a silent second-factor bypass: the gate refuses only a token whose claims say
        // `mfaEnabled && !mfaVerified`, so an absent field reads as "no second factor here" and
        // the rotated token clears every MFA-gated route. Refusing the record costs the holder
        // a login; defaulting it costs the account.
        let without_flag = r#"{"userId":"u1","tenantId":"t1","role":"MEMBER","device":"Chrome",
            "ip":"1.2.3.4","createdAt":"1970-01-01T00:00:00Z"}"#;
        let parsed: Result<SessionRecord, _> = serde_json::from_str(without_flag);
        assert!(parsed.is_err());
    }

    #[test]
    fn session_kind_variants_are_distinct() {
        // The kind selects the prefix pair; the two domains must never compare equal.
        assert_eq!(SessionKind::Dashboard, SessionKind::Dashboard);
        assert_ne!(SessionKind::Dashboard, SessionKind::Platform);
        assert_eq!(format!("{:?}", SessionKind::Platform), "Platform");
    }

    #[test]
    fn session_record_serializes_camel_case_and_omits_absent_tenant() -> serde_json::Result<()> {
        // Wire parity: fields are camelCase and a platform record (no tenant) omits the
        // `tenantId` key entirely rather than emitting null.
        let dashboard = session_record();
        let json = serde_json::to_string(&dashboard)?;
        assert!(json.contains("\"userId\":\"u1\""));
        assert!(json.contains("\"tenantId\":\"t1\""));
        assert!(json.contains("\"createdAt\":"));
        // A present family id is on the wire as camelCase `familyId`.
        assert!(json.contains("\"familyId\":\"fam-1\""));

        let platform = SessionRecord {
            tenant_id: None,
            ..session_record()
        };
        assert!(!serde_json::to_string(&platform)?.contains("tenantId"));

        // The MFA flag is always emitted (nest-auth writes it unconditionally), so the two
        // implementations produce the same key set for the same session.
        assert!(json.contains("\"mfaEnabled\":false"));

        // An empty family id is omitted from the wire for byte-parity, and a
        // record with no `familyId` key deserializes back to an empty family.
        let familyless = SessionRecord {
            family_id: String::new(),
            family_created_at: Some(OffsetDateTime::UNIX_EPOCH),
            ..session_record()
        };
        let familyless_json = serde_json::to_string(&familyless)?;
        assert!(!familyless_json.contains("familyId"));
        let familyless_back: SessionRecord = serde_json::from_str(&familyless_json)?;
        assert_eq!(familyless_back.family_id, "");

        // Round-trip parity for the full record.
        let back: SessionRecord = serde_json::from_str(&json)?;
        assert_eq!(back, dashboard);
        Ok(())
    }

    #[test]
    fn session_detail_round_trips() -> serde_json::Result<()> {
        // The detail record is read back from Redis on `list_sessions`; the serde shape
        // must round-trip every field.
        let detail = SessionDetail {
            session_hash: "abc123".into(),
            device: "Firefox".into(),
            ip: "198.51.100.7".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_activity_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&detail)?;
        assert!(json.contains("\"sessionHash\":\"abc123\""));
        assert!(json.contains("\"lastActivityAt\":"));
        let back: SessionDetail = serde_json::from_str(&json)?;
        assert_eq!(back, detail);
        Ok(())
    }

    #[test]
    fn session_detail_timestamps_are_unix_millisecond_numbers() -> serde_json::Result<()> {
        // Parity gate for the `sd:`/`psd:` record: nest-auth writes `createdAt`/`lastActivityAt`
        // as `Date.now()` NUMBERS and drops any detail record whose fields are not numbers, so an
        // RFC 3339 string here would make every rust-written session invisible to nest-auth (and
        // vice versa). Pin the numeric encoding in both directions.
        let detail = SessionDetail {
            session_hash: "abc123".into(),
            device: "Firefox".into(),
            ip: "198.51.100.7".into(),
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            last_activity_at: OffsetDateTime::from_unix_timestamp(1_700_000_060)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        };
        // Anchored to the shared contract, which declares this record's timestamps numeric while
        // declaring the refresh session's ISO-8601: the two disagree deliberately, and reading the
        // declaration here is what stops a well-meaning "make the encodings uniform" change from
        // passing both suites while splitting the keyspace.
        assert_eq!(
            contract_section("sessionDetail")
                .get("createdAt")
                .and_then(serde_json::Value::as_str),
            Some("unix-milliseconds-number")
        );
        assert_eq!(
            contract_section("sessionDetail")
                .get("lastActivityAt")
                .and_then(serde_json::Value::as_str),
            Some("unix-milliseconds-number")
        );
        let json = serde_json::to_string(&detail)?;
        for field in contract_fields("sessionDetail") {
            assert!(
                json.contains(&format!("\"{field}\":")),
                "sessionDetail field `{field}` is named in the wire contract but absent from the record"
            );
        }
        assert!(json.contains("\"createdAt\":1700000000000"));
        assert!(json.contains("\"lastActivityAt\":1700000060000"));
        // No quotes around the values — a stringly-typed timestamp is exactly the divergence.
        assert!(!json.contains("\"createdAt\":\""));

        // A nest-auth-written record (numbers, sub-second precision) reads back exactly.
        // Asserted on the `Result` rather than unwrapped with `?`: the literal always parses,
        // so the `?` operator's error arm would sit on its own line as dead, uncovered code.
        let from_nest: serde_json::Result<SessionDetail> = serde_json::from_str(
            r#"{"sessionHash":"abc123","device":"Firefox","ip":"198.51.100.7","createdAt":1700000000123,"lastActivityAt":1700000060456}"#,
        );
        assert!(matches!(
            from_nest,
            Ok(ref detail)
                if detail.created_at.unix_timestamp_nanos() / 1_000_000 == 1_700_000_000_123
                    && detail.last_activity_at.unix_timestamp_nanos() / 1_000_000
                        == 1_700_000_060_456
        ));
        Ok(())
    }

    #[test]
    fn unix_millis_preserves_pre_epoch_instants_and_rejects_non_numbers() {
        // The clamp in `unix_millis::serialize` must keep a pre-epoch instant NEGATIVE rather
        // than saturating it to `i64::MAX`, and the reader must refuse a stringly-typed
        // timestamp instead of silently defaulting — an RFC 3339 `sd:` record has to fail
        // loudly (and be swept as stale) rather than decode to a bogus time.
        let detail = SessionDetail {
            session_hash: "abc123".into(),
            device: "Firefox".into(),
            ip: "198.51.100.7".into(),
            created_at: OffsetDateTime::from_unix_timestamp(-1_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            last_activity_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&detail).unwrap_or_default();
        assert!(json.contains("\"createdAt\":-1000000"));
        assert!(json.contains("\"lastActivityAt\":0"));

        let rfc3339: Result<SessionDetail, _> = serde_json::from_str(
            r#"{"sessionHash":"abc123","device":"Firefox","ip":"198.51.100.7","createdAt":"1970-01-01T00:00:00Z","lastActivityAt":0}"#,
        );
        assert!(rfc3339.is_err());
    }

    #[test]
    fn ws_ticket_snapshot_round_trips() -> serde_json::Result<()> {
        // The snapshot is the stored ticket value; camelCase + omit-absent-tenant parity.
        let snap = WsTicketSnapshot {
            sub: "u1".into(),
            tenant_id: Some("t1".into()),
            role: "MEMBER".into(),
            status: "ACTIVE".into(),
            mfa_enabled: true,
            mfa_verified: true,
        };
        let json = serde_json::to_string(&snap)?;
        assert!(json.contains("\"mfaEnabled\":true"));
        assert!(json.contains("\"mfaVerified\":true"));
        let back: WsTicketSnapshot = serde_json::from_str(&json)?;
        assert_eq!(back, snap);
        Ok(())
    }

    #[test]
    fn session_rotation_debug_redacts_the_raw_token() {
        // The raw refresh token must never appear in a `{:?}` of the rotation parameters.
        let rotation = SessionRotation {
            old_hash: "oldhash".to_owned(),
            new_hash: "newhash".to_owned(),
            new_raw: "live-refresh-token".to_owned(),
            new_record: session_record(),
            refresh_ttl: 60,
            grace_ttl: 30,
        };
        let rendered = format!("{rotation:?}");
        assert!(!rendered.contains("live-refresh-token"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("newhash"));
    }

    #[test]
    fn rotate_outcome_variants_carry_the_record() {
        // The three outcomes drive distinct caller behavior; pattern-matching each proves
        // the payloads are reachable.
        let record = session_record();
        assert!(matches!(
            RotateOutcome::Rotated(record.clone()),
            RotateOutcome::Rotated(_)
        ));
        // Reuse carries the compromised family id the caller revokes.
        assert!(matches!(
            RotateOutcome::Reused("fam-1".to_owned()),
            RotateOutcome::Reused(family) if family == "fam-1"
        ));
        assert!(matches!(
            RotateOutcome::Grace(record),
            RotateOutcome::Grace(_)
        ));
        assert!(matches!(RotateOutcome::Invalid, RotateOutcome::Invalid));
    }

    #[test]
    fn reset_context_round_trips_camel_case() -> serde_json::Result<()> {
        // The `pw_reset:`/`pw_vtok:` value is camelCase and round-trips every field so the consume
        // path can re-bind the proof to the same account.
        let context = ResetContext {
            user_id: "u1".into(),
            email: "user@example.com".into(),
            tenant_id: "t1".into(),
            password_fingerprint: String::new(),
        };
        let json = serde_json::to_string(&context)?;
        assert!(json.contains("\"userId\":\"u1\""));
        assert!(json.contains("\"tenantId\":\"t1\""));
        let back: ResetContext = serde_json::from_str(&json)?;
        assert_eq!(back, context);
        Ok(())
    }

    #[test]
    fn stored_invitation_round_trips_camel_case() -> serde_json::Result<()> {
        // The `inv:` value is camelCase and round-trips so accept can re-validate the role.
        let invitation = StoredInvitation {
            email: "invitee@example.com".into(),
            role: "MEMBER".into(),
            tenant_id: "t1".into(),
            inviter_user_id: "owner-1".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&invitation)?;
        assert!(json.contains("\"tenantId\":\"t1\""));
        assert!(json.contains("\"inviterUserId\":\"owner-1\""));
        let back: StoredInvitation = serde_json::from_str(&json)?;
        assert_eq!(back, invitation);
        Ok(())
    }

    #[test]
    fn stored_invitation_carries_created_at_and_reads_a_nest_written_record()
    -> serde_json::Result<()> {
        // Parity gate for the `inv:` value. nest-auth's `isStoredInvitation` requires a STRING
        // `createdAt`; omitting it made a nest-auth accept of a rust-written invitation fail
        // validation *after* the single-use `GETDEL` had already removed the token — destroying
        // the invitation. Assert the field is emitted as a string and that a record written by
        // nest-auth (ISO-8601 with a `Z` offset) deserializes.
        let invitation = StoredInvitation {
            email: "invitee@example.com".into(),
            role: "MEMBER".into(),
            tenant_id: "t1".into(),
            inviter_user_id: "owner-1".into(),
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        };
        let json = serde_json::to_string(&invitation)?;
        assert!(json.contains("\"createdAt\":\"2023-11-14T22:13:20"));

        // Same idiom as above: assert on the `Result` so the `?` error arm is not left as an
        // uncovered line the 100% gate then trips over.
        let from_nest: serde_json::Result<StoredInvitation> = serde_json::from_str(
            r#"{"email":"invitee@example.com","role":"MEMBER","tenantId":"t1","inviterUserId":"owner-1","createdAt":"2023-11-14T22:13:20.000Z"}"#,
        );
        assert!(matches!(
            from_nest,
            Ok(ref stored)
                if stored.created_at == invitation.created_at && stored.inviter_user_id == "owner-1"
        ));
        Ok(())
    }

    /// Read a section of the shared cross-implementation wire contract.
    ///
    /// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
    /// can back the same deployment over the same Redis. Reading it here rather than repeating
    /// its values means a field rename or an encoding change on either side turns that side red
    /// immediately, instead of surfacing later as a record the sibling backend cannot parse.
    fn contract_section(section: &str) -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root.get("recordEncodings")
            .and_then(|r| r.get(section))
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }

    /// The field names the contract declares for one record, in declaration order.
    ///
    /// Panics on an empty list. A contract that failed to load reads as "no fields to check",
    /// which would make every assertion below pass over nothing — the one failure mode a
    /// conformance test cannot afford, since it looks identical to conformance.
    fn contract_fields(section: &str) -> Vec<String> {
        let fields: Vec<String> = contract_section(section)
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !fields.is_empty(),
            "the wire contract declared no fields for `{section}` — it did not load"
        );
        fields
    }

    #[test]
    fn the_refresh_session_record_matches_the_shared_wire_contract() -> serde_json::Result<()> {
        // Every field the contract names must be on the wire, spelled the way the contract spells
        // it. A record the sibling backend cannot read is not a parse error there — the reader
        // evicts what it cannot parse, so a drifted field name silently logs the user out.
        let json: serde_json::Value = serde_json::to_value(session_record())?;
        for field in contract_fields("refreshSession") {
            assert!(
                json.get(&field).is_some(),
                "refreshSession field `{field}` is named in the wire contract but absent from the record"
            );
        }

        // `createdAt` is an ISO-8601 string here, unlike the session DETAIL below. The split is
        // the trap the contract exists to pin: the two records disagree on purpose.
        assert_eq!(
            contract_section("refreshSession")
                .get("createdAt")
                .and_then(serde_json::Value::as_str),
            Some("iso8601-string")
        );
        assert_eq!(
            json.get("createdAt").and_then(serde_json::Value::as_str),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            json.get("familyCreatedAt")
                .and_then(serde_json::Value::as_str),
            Some("1970-01-01T00:00:00Z")
        );

        // `mfaEnabled` must survive a rotation: the MFA gate refuses only a token whose claims
        // say `mfaEnabled && !mfaVerified`, so a record that drops it turns one routine refresh
        // into a silent second-factor bypass.
        assert_eq!(
            json.get("mfaEnabled"),
            Some(&serde_json::Value::Bool(false))
        );

        // An empty family is omitted from the wire entirely, never written as `""` — nest-auth
        // omits it the same way, and a record differing by that one key is not byte-identical.
        let familyless = SessionRecord {
            family_id: String::new(),
            family_created_at: None,
            ..session_record()
        };
        let familyless_json: serde_json::Value = serde_json::to_value(familyless)?;
        assert!(familyless_json.get("familyId").is_none());
        assert!(familyless_json.get("familyCreatedAt").is_none());
        Ok(())
    }

    #[test]
    fn the_ws_ticket_snapshot_matches_the_shared_wire_contract() -> serde_json::Result<()> {
        // A ticket minted by one backend is redeemed by whichever one receives the upgrade, so
        // the snapshot's field names are a contract, not an internal detail. It is a snapshot
        // and not a token by design: no `jti` to revoke, no signature to re-verify, nothing the
        // holder could present back to the REST surface.
        let snapshot = WsTicketSnapshot {
            sub: "u1".into(),
            tenant_id: Some("t1".into()),
            role: "MEMBER".into(),
            status: "ACTIVE".into(),
            mfa_enabled: true,
            mfa_verified: true,
        };
        let json: serde_json::Value = serde_json::to_value(&snapshot)?;
        for field in contract_fields("wsTicket") {
            assert!(
                json.get(&field).is_some(),
                "wsTicket field `{field}` is named in the wire contract but absent from the record"
            );
        }
        assert_eq!(
            contract_section("wsTicket")
                .get("key")
                .and_then(serde_json::Value::as_str),
            Some("wst:{sha256(ticket)}")
        );

        // A ticket with no tenant scope omits the field entirely rather than writing null —
        // nest-auth omits it the same way, and a record differing by that one key is not
        // byte-identical.
        let platform = WsTicketSnapshot {
            tenant_id: None,
            ..snapshot
        };
        let json: serde_json::Value = serde_json::to_value(platform)?;
        assert!(json.get("tenantId").is_none());
        Ok(())
    }

    #[test]
    fn the_invitation_and_reset_context_records_match_the_shared_wire_contract()
    -> serde_json::Result<()> {
        // An invitation is consumed with a single-use GETDEL, so a record the reader rejects is
        // destroyed rather than retried: a missing field loses the invitation outright.
        let invitation = StoredInvitation {
            email: "invitee@example.com".into(),
            role: "MEMBER".into(),
            tenant_id: "t1".into(),
            inviter_user_id: "owner-1".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json: serde_json::Value = serde_json::to_value(invitation)?;
        for field in contract_fields("invitation") {
            assert!(
                json.get(&field).is_some(),
                "invitation field `{field}` is named in the wire contract but absent from the record"
            );
        }
        assert_eq!(
            json.get("createdAt").and_then(serde_json::Value::as_str),
            Some("1970-01-01T00:00:00Z")
        );

        let context = ResetContext {
            user_id: "u1".into(),
            email: "u1@example.com".into(),
            tenant_id: "t1".into(),
            password_fingerprint: String::new(),
        };
        let json: serde_json::Value = serde_json::to_value(context)?;
        for field in contract_fields("passwordResetContext") {
            assert!(
                json.get(&field).is_some(),
                "passwordResetContext field `{field}` is named in the wire contract but absent from the record"
            );
        }
        Ok(())
    }
}
