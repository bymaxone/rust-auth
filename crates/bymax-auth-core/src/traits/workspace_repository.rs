//! The workspace persistence contract: the record of a workspace inside a tenant, and the writes
//! that create it, rename it and move it through its lifecycle.
//!
//! Every method carries both halves of the workspace key, and every mutating one receives the
//! audit event for its change and persists it in the same transaction. A result other than success
//! means nothing was written, the audit row included.

use async_trait::async_trait;

use crate::RepositoryError;
use crate::workspace::audit::WorkspaceAuditEvent;
use crate::workspace::domain::{ActingMember, Workspace, WorkspaceRef, WorkspaceStatus};

use time::OffsetDateTime;

/// Input to [`WorkspaceRepository::create_with_owner`].
#[derive(Debug, Clone)]
pub struct CreateWorkspaceWithOwner<'a> {
    /// The tenant and the new workspace's id, which the library generates.
    pub workspace: WorkspaceRef<'a>,
    /// Display name.
    pub name: &'a str,
    /// The creator, who becomes a member holding `owner_role`.
    pub owner_user_id: &'a str,
    /// The role that makes the creator the owner.
    pub owner_role: &'a str,
    /// The most workspaces the creator may own, `0` for no limit.
    ///
    /// The library checks it before calling, which is advisory under concurrency: two creates can
    /// pass the check together. A host that needs an exact cap counts the creator's owned
    /// workspaces under a lock inside this call's transaction and answers
    /// [`CreateWorkspaceOutcome::LimitReached`]; a host that ignores the value keeps the advisory
    /// behaviour.
    pub max_workspaces_per_user: u32,
    /// The `workspace.created` event, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of [`WorkspaceRepository::create_with_owner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateWorkspaceOutcome {
    /// Created, active, with the creator's owner membership.
    Created(Workspace),
    /// The creator already owns `max_workspaces_per_user` workspaces and the host enforces the cap
    /// here. Nothing was written.
    LimitReached,
}

/// Input to [`WorkspaceRepository::rename`].
#[derive(Debug, Clone)]
pub struct RenameWorkspace<'a> {
    /// The workspace.
    pub workspace: WorkspaceRef<'a>,
    /// The new display name.
    pub name: &'a str,
    /// The member whose role authorized the rename.
    pub actor: ActingMember<'a>,
    /// The `workspace.renamed` event, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of [`WorkspaceRepository::rename`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameOutcome {
    /// Renamed.
    Done,
    /// No such workspace.
    NotFound,
    /// The actor no longer holds the role the rename was judged against.
    ActorChanged,
}

/// Input to [`WorkspaceRepository::update_status`].
#[derive(Debug, Clone)]
pub struct UpdateWorkspaceStatus<'a> {
    /// The workspace.
    pub workspace: WorkspaceRef<'a>,
    /// The member whose role authorized the change, or `None` for a change no member made, such as
    /// the host job that finalizes a deletion.
    pub actor: Option<ActingMember<'a>>,
    /// The state to move to.
    pub status: WorkspaceStatus,
    /// The state the caller read. The write applies only while the workspace is still in it, so a
    /// restore cannot overwrite a finalize that landed first.
    pub expected_status: WorkspaceStatus,
    /// The scheduled-deletion instant the caller read, `Some(None)` for none. When present, the
    /// write also applies only while the stored instant equals it, so a finalizer that read one
    /// schedule cannot delete a workspace whose deletion was restored and scheduled again. `None`
    /// means the instant is not compared.
    pub expected_deletion_scheduled_at: Option<Option<OffsetDateTime>>,
    /// The scheduled-deletion instant to store, or `None` to clear it.
    pub deletion_scheduled_at: Option<OffsetDateTime>,
    /// The event for this transition, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of [`WorkspaceRepository::update_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatusOutcome {
    /// Applied.
    Done,
    /// No such workspace.
    NotFound,
    /// The stored status or, when compared, the stored instant differs from what the caller read.
    StatusConflict,
    /// The actor no longer holds the role the change was judged against.
    ActorChanged,
}

/// The workspace persistence contract, implemented once by the host and held on the engine as
/// `Arc<dyn WorkspaceRepository>`.
///
/// # Tenant scoping
///
/// Every method takes the tenant, and an implementation MUST restrict the read and the write to it:
/// a workspace id is unique only within its tenant, so a statement keyed on the id alone lands on a
/// homonym in another tenant.
///
/// # Reads the library decides on
///
/// A read the cache is filled from, or an access decision is made on, MUST come from the primary or
/// be read-your-writes. A lagging replica would cache a removed member as present under the new
/// version.
///
/// # Time bounds
///
/// A call the engine makes while holding a short lock must stay well under it, as
/// [`UserRepository::update_mfa`](crate::traits::UserRepository::update_mfa) documents.
///
/// # Errors
///
/// [`RepositoryError`] is for a datastore failure; every outcome the rules define is a value of the
/// method's outcome type.
#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    /// Creates the workspace and the creator's owner membership atomically, persisting `audit` in
    /// the same transaction. The library generates the workspace id and passes it in the key, so the
    /// event is complete before the write; store it as given.
    async fn create_with_owner(
        &self,
        params: CreateWorkspaceWithOwner<'_>,
    ) -> Result<CreateWorkspaceOutcome, RepositoryError>;

    /// Reads one workspace in any status: the library decides access.
    ///
    /// Returns `None` when none matches both halves of the key.
    async fn find_by_id(
        &self,
        workspace: WorkspaceRef<'_>,
    ) -> Result<Option<Workspace>, RepositoryError>;

    /// Renames a workspace, persisting `audit` in the same transaction.
    ///
    /// The same transaction MUST check that the actor still holds `actor.expected_role` as an
    /// active member of this workspace, because the library judged the rename from a role it read
    /// before the write; answer [`RenameOutcome::ActorChanged`] otherwise and write nothing. A host
    /// that ignores the actor keeps the check-then-write window.
    async fn rename(&self, params: RenameWorkspace<'_>) -> Result<RenameOutcome, RepositoryError>;

    /// Moves a workspace to another status, persisting `audit` in the same transaction.
    ///
    /// Compare-and-set: it applies only while the stored status equals `expected_status` and, when
    /// `expected_deletion_scheduled_at` is given, while the stored instant equals it too (two
    /// instants are equal when they are the same moment), decided in the same statement as the
    /// write.
    ///
    /// When `actor` is given, the same transaction MUST also check that the actor still holds
    /// `actor.expected_role` as an active member of this workspace and answer
    /// [`UpdateStatusOutcome::ActorChanged`] otherwise, with the same lock as
    /// [`WorkspaceRepository::rename`]. Nothing is written for any refusal.
    async fn update_status(
        &self,
        params: UpdateWorkspaceStatus<'_>,
    ) -> Result<UpdateStatusOutcome, RepositoryError>;
}
