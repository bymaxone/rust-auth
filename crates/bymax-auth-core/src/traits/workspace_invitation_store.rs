//! Where workspace invitations live: the record, the index that names an address's live
//! invitation, and the set a workspace lists its pending ones from (layer: store seam).
//!
//! The keys, the record and the order of the steps are pinned by `workspaceInvitations` in the
//! shared wire contract, because a deployment that runs both libraries reads and writes one
//! keyspace: an index one side points at a record the other does not find is an invitation that
//! cannot be accepted. The store makes no authorization decision; it keeps the three structures
//! consistent.
//!
//! Every method takes identifiers the caller derived with [`crate::workspace::keys`]: the store
//! never sees a raw tenant, workspace or address and never holds the hashing key.

use std::num::NonZeroU64;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::workspace::invitation::InvitationRecord;

/// The identifiers that place one address's invitation in one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationPlace {
    /// The `{id}` of the invitee index (`winvidx`), from
    /// [`crate::workspace::keys::invitation_index_id`].
    pub index_id: String,
    /// The `{id}` of the workspace's pending set (`winvset`), from
    /// [`crate::workspace::keys::invitation_set_id`].
    pub set_id: String,
}

/// Which records a removal may delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// Only a record the place owns: a revoke, which read the record's key from that place.
    Owned,
    /// The record whatever place it is asked under: the spend that follows an acceptance, where a
    /// single-use record must go even when its set or its index no longer names it.
    Spend,
}

/// What an address's index names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedInvitation {
    /// The record key the index holds, as stored: `winv:{sha256(token)}`.
    pub record_key: String,
    /// The record under that key, or `None` when the key is gone or holds a value that is not a
    /// record.
    pub record: Option<InvitationRecord>,
    /// Whether the key exists and holds a value that is not a record. It tells an unreadable
    /// record, which no later step can trust, from one that has expired or been deleted, which is
    /// simply no invitation.
    pub unreadable: bool,
}

/// One live invitation of a workspace, with the time it has left. The token is never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvitation {
    /// The record key, `winv:{sha256(token)}`.
    pub record_key: String,
    /// The stored record.
    pub record: InvitationRecord,
    /// Seconds until the record expires.
    pub ttl_seconds: u64,
}

/// What a publication did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The record is written, the index points at it, it is in the set, and the record it replaced
    /// is gone.
    Published,
    /// The index no longer held the key the writer read: another writer got there first, and
    /// nothing was written.
    Lost,
    /// The workspace holds the most pending invitations it may and this is not a replacement:
    /// nothing was written.
    Full,
}

/// One record to publish.
#[derive(Debug, Clone, Copy)]
pub struct Publication<'a> {
    /// Where the address's invitation lives.
    pub place: &'a InvitationPlace,
    /// The new record key, `winv:{sha256(token)}`.
    pub record_key: &'a str,
    /// What to store.
    pub record: &'a InvitationRecord,
    /// How long the record, the index and the set live from this write.
    pub ttl: NonZeroU64,
    /// The most pending invitations the workspace may hold, or `0` for no limit. The caller passes
    /// `0` when it replaces a record that is still alive, because the set does not grow.
    pub pending_limit: u32,
    /// The record key the index held when the writer read it, or `None` when it held none. The
    /// publication happens only while the index still holds exactly this.
    pub expected_key: Option<&'a str>,
}

/// The workspace invitation store.
///
/// # Errors
///
/// Every method returns [`AuthError`] on a store failure.
#[async_trait]
pub trait WorkspaceInvitationStore: Send + Sync {
    /// The record under `record_key`, or `None` when there is none, it has expired, or the value is
    /// not a record this library or `@bymax-one/nest-auth` wrote.
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError>;

    /// What the address's index names, or `None` when the address has no index.
    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError>;

    /// Publishes a record in one atomic step: it writes only while the index still holds
    /// `expected_key`, and, when the limit is not `0`, only while the set holds fewer members than
    /// the limit. It then writes the record, points the index at it, adds the record to the set,
    /// deletes the record it replaces and that record's place in the set, and sets the lifetimes.
    /// Members of the set whose record is gone are dropped before the limit is counted, so an
    /// index naming a gone record is a first invitation for the cap.
    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError>;

    /// Deletes the record, its place in the set, and the index only while it still names this
    /// record, in one atomic step. With [`Removal::Owned`] only a record `place` owns goes: its set
    /// holds the key or its index names it, so a place and a record key that do not belong together
    /// delete nothing. With [`Removal::Spend`] the record goes whatever place it is asked under.
    /// Answers whether the index named it: `false` means another writer had moved or deleted the
    /// index (or that nothing was owned), and a deleted record's own key is gone either way.
    async fn remove(
        &self,
        place: &InvitationPlace,
        record_key: &str,
        removal: Removal,
    ) -> Result<bool, AuthError>;

    /// The workspace's live invitations, in no particular order. A set member whose record is gone
    /// is dropped from the set.
    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError>;

    /// Counts one invitation against an inviter's hour (`rate_id` from
    /// [`crate::workspace::keys::inviter_rate_id`]): increments the counter and sets its lifetime
    /// to [`crate::workspace::limits::INVITER_WINDOW_SECONDS`] on the first increment only, in one
    /// atomic step, and returns the new count.
    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError>;
}
