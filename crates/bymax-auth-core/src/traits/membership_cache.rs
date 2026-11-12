//! The versioned cache of one workspace membership, shared with nest-auth (layer: store seam).
//!
//! The keys, the value and the order of the reads are pinned by `workspaceMembershipCache` in the
//! shared wire contract, because a deployment that runs both libraries reads and writes one
//! keyspace: a bump issued by one side that names a different key than the other reads raises
//! nothing and serves a removed member's role until the entry expires.

use std::num::NonZeroU64;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::workspace::membership_cache::{MembershipCacheIds, MembershipVersions, entry_role};

/// What one read found: the two versions and the entry they name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipCacheRead {
    /// The versions read, an absent counter as `0`. A refill is written under these.
    pub versions: MembershipVersions,
    /// The raw entry named by [`Self::versions`], or `None` when there is none.
    pub entry: Option<String>,
}

impl MembershipCacheRead {
    /// The role the entry caches, or `None` on a miss. The rule is [`entry_role`]: an entry that is
    /// not valid JSON, whose role is not a string or whose status is not `active` is a miss.
    #[must_use]
    pub fn cached_role(&self) -> Option<String> {
        self.entry.as_deref().and_then(entry_role)
    }
}

/// What a fill did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillOutcome {
    /// Both counters still held the versions read; the entry is written.
    Written,
    /// A counter moved since the read; nothing is written, since nobody could read the entry.
    Moved,
}

/// The three keys of one membership's cache: the workspace counter (`wsv`), the membership counter
/// (`wmv`) and the entry (`wm`), named by both versions.
///
/// Every method takes identifiers the caller derived with [`MembershipCacheIds::derive`], which
/// refuses a blank tenant, workspace or user; the store never sees a raw id and never holds the
/// hashing key. Every counter carries the retention
/// [`crate::workspace::limits::VERSION_RETENTION_SECONDS`] and every entry the lifetime its fill
/// names.
///
/// A store evicting keys under memory pressure breaks the cache's guarantee: a counter evicted
/// restarts at 0 and can make an entry written under an earlier `0:0` readable again for up to its
/// lifetime. Run the backing store with a no-eviction policy for the auth keyspace.
///
/// # Errors
///
/// Every method returns [`AuthError`] on a store failure. A failed read or fill is advisory to the
/// caller, which answers from the repositories; a failed bump is not, because a change must never
/// be reported as invalidated when it was not.
#[async_trait]
pub trait MembershipCacheStore: Send + Sync {
    /// Reads the workspace counter, then the membership counter, then the entry those two values
    /// name, as separate single-key reads in that order (pipelined or not). An absent counter
    /// reads `0`, and a read never creates a counter.
    async fn read(&self, ids: &MembershipCacheIds) -> Result<MembershipCacheRead, AuthError>;

    /// Writes the entry for an active member holding `role` under `versions` with lifetime `ttl`,
    /// only if both counters still hold `versions` (an absent counter counts as `0`), and in the
    /// same atomic step extends every counter that exists to the retention. A counter that does not
    /// exist is left absent. A fill that finds a counter moved writes nothing.
    async fn fill(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, AuthError>;

    /// Increments the workspace counter named by `workspace_id` (an [`MembershipCacheIds::workspace`])
    /// and sets its expiry to the retention, atomically, and returns the new value.
    async fn bump_workspace(&self, workspace_id: &str) -> Result<u64, AuthError>;

    /// Increments the membership counter named by `membership_id` (an
    /// [`MembershipCacheIds::membership`]) and sets its expiry to the retention, atomically, and
    /// returns the new value.
    async fn bump_membership(&self, membership_id: &str) -> Result<u64, AuthError>;
}
