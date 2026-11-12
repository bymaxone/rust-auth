//! The names, the entry and the lifetime of the workspace-membership cache (layer: domain).
//!
//! The cache is three keys per membership, shared with `@bymax-one/nest-auth` on one Redis: a
//! workspace version counter (`wsv`), a membership version counter (`wmv`), and the cached entry
//! (`wm`), whose name carries BOTH versions. A reader reads the two counters first and names the
//! entry by them, so an entry filled after a concurrent change lands under a name nobody reads.
//! Everything here is pure: deriving the names, encoding and parsing the entry, and validating the
//! configured lifetime. The store seam is [`crate::traits::MembershipCacheStore`] and the read and
//! refill rule is [`crate::services::membership_cache`].

use std::num::NonZeroU64;

use serde_json::Value;

use crate::workspace::domain::{MembershipRef, MembershipStatus};
use crate::workspace::keys::{BlankPart, membership_version_id, workspace_version_id};
use crate::workspace::limits::{
    MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS, MEMBERSHIP_CACHE_TTL_MAX_SECONDS,
};

/// One of the two version counters a cached entry is named by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionCounter {
    /// The workspace's counter (`wsv`), bumped by an event that changes the whole workspace.
    Workspace,
    /// The membership's counter (`wmv`), bumped by a change to that one membership.
    Membership,
}

/// The values of the two counters, as a reader saw them. A counter that does not exist reads `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MembershipVersions {
    /// The value of the workspace counter.
    pub workspace: u64,
    /// The value of the membership counter.
    pub membership: u64,
}

impl std::fmt::Display for MembershipVersions {
    /// `{workspace}:{membership}`, the suffix the two versions add to the entry's name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.workspace, self.membership)
    }
}

/// The key identifiers of one membership's cache: the `{id}` segments that
/// `NamespacedRedis::key` places after the namespace and the prefix.
///
/// They are HMACs of the tenant-scoped subjects, so neither carries an identifier in the clear and
/// a store never needs the hashing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipCacheIds {
    /// The `{id}` of the workspace counter: `hmac_sha256(identifierKey, workspaceSubject)`.
    pub workspace: String,
    /// The `{id}` of the membership counter: `hmac_sha256(identifierKey, membershipSubject)`.
    pub membership: String,
}

impl MembershipCacheIds {
    /// Derives the identifiers of `member`'s cache.
    ///
    /// # Errors
    ///
    /// [`BlankPart`] when the tenant, the workspace or the user is blank; nothing is derived then.
    pub fn derive(identifier_key: &[u8; 64], member: MembershipRef<'_>) -> Result<Self, BlankPart> {
        let membership = membership_version_id(
            identifier_key,
            member.tenant_id,
            member.workspace_id,
            member.user_id,
        )?;
        let workspace =
            workspace_version_id(identifier_key, member.tenant_id, member.workspace_id)?;
        Ok(Self {
            workspace,
            membership,
        })
    }

    /// The `{id}` of a counter.
    #[must_use]
    pub fn counter(&self, counter: VersionCounter) -> &str {
        match counter {
            VersionCounter::Workspace => &self.workspace,
            VersionCounter::Membership => &self.membership,
        }
    }

    /// The `{id}` of the entry named by `versions`: `{membership id}:{workspace}:{membership}`.
    #[must_use]
    pub fn entry(&self, versions: MembershipVersions) -> String {
        format!("{}:{versions}", self.membership)
    }
}

/// The cached value for an active member holding `role`: `{"role":"<role>","status":"active"}`.
///
/// Only an active membership of an active workspace is ever cached, so the status written is
/// always `active`; the role is a JSON string, escaped as JSON escapes it.
#[must_use]
pub fn entry_value(role: &str) -> String {
    let role = Value::String(role.to_owned());
    let status = MembershipStatus::Active.as_str();
    format!("{{\"role\":{role},\"status\":\"{status}\"}}")
}

/// The role an entry caches, or `None` when the entry is a miss.
///
/// The entry is read by PARSING, never compared as text, so either library may write it with any
/// key order or spacing. A value that is not valid JSON, whose `role` is not a string, or whose
/// `status` is not `active` is a miss.
#[must_use]
pub fn entry_role(raw: &str) -> Option<String> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let status = value.get("status").and_then(Value::as_str);
    let role = value.get("role").and_then(Value::as_str)?;
    (status == Some(MembershipStatus::Active.as_str())).then(|| role.to_owned())
}

/// A configured lifetime over [`MEMBERSHIP_CACHE_TTL_MAX_SECONDS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "workspaces.membershipCacheTtlSeconds must be at most {max} seconds (got {seconds})",
    max = MEMBERSHIP_CACHE_TTL_MAX_SECONDS
)]
pub struct MembershipCacheTtlTooLong {
    /// The refused value.
    pub seconds: u64,
}

/// The lifetime of a cached entry (`workspaces.membershipCacheTtlSeconds`): from 0 to
/// [`MEMBERSHIP_CACHE_TTL_MAX_SECONDS`], [`MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS`] by default.
///
/// It applies to the entry only; the counters keep their own retention. `0` disables the cache:
/// every request then reads the repositories, and the cache is neither read nor written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipCacheTtl(u64);

impl MembershipCacheTtl {
    /// The cache turned off.
    pub const DISABLED: Self = Self(0);

    /// Validates a configured lifetime in seconds.
    ///
    /// # Errors
    ///
    /// [`MembershipCacheTtlTooLong`] above [`MEMBERSHIP_CACHE_TTL_MAX_SECONDS`].
    pub const fn new(seconds: u64) -> Result<Self, MembershipCacheTtlTooLong> {
        if seconds > MEMBERSHIP_CACHE_TTL_MAX_SECONDS {
            Err(MembershipCacheTtlTooLong { seconds })
        } else {
            Ok(Self(seconds))
        }
    }

    /// The lifetime in seconds; `0` when the cache is disabled.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }

    /// The lifetime of an entry, or `None` when the cache is disabled.
    #[must_use]
    pub const fn entry_ttl(self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.0)
    }
}

impl Default for MembershipCacheTtl {
    /// [`MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS`].
    fn default() -> Self {
        Self(MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS)
    }
}
