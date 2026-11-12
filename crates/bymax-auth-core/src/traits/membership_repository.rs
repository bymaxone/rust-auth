//! The membership persistence contract: who belongs to which workspace with which role, and the
//! writes that change it, including the owner-protecting ones the library cannot make atomic
//! itself.
//!
//! Every method carries the full key of what it names, and every mutating one receives the audit
//! event for its change and persists it in the same transaction. A result other than success means
//! nothing was written: no change and no audit row, so a refused write leaves no trace of an event
//! that did not happen.

use async_trait::async_trait;

use crate::RepositoryError;
use crate::workspace::audit::WorkspaceAuditEvent;
use crate::workspace::domain::{
    ActingMember, Membership, MembershipRef, MembershipWithWorkspace, Page, Workspace, WorkspaceRef,
};

/// Input to [`MembershipRepository::list_for_user`].
#[derive(Debug, Clone, Copy)]
pub struct ListForUser<'a> {
    /// The tenant the member belongs to.
    pub tenant_id: &'a str,
    /// The member whose memberships are listed.
    pub user_id: &'a str,
    /// The `next_cursor` of the previous page, or `None` for the first.
    pub cursor: Option<&'a str>,
    /// Page size, bounded by the library to 1 through 100.
    pub limit: u32,
}

/// Input to [`MembershipRepository::list_for_workspace`].
#[derive(Debug, Clone, Copy)]
pub struct ListForWorkspace<'a> {
    /// The workspace.
    pub workspace: WorkspaceRef<'a>,
    /// The `next_cursor` of the previous page, or `None` for the first.
    pub cursor: Option<&'a str>,
    /// Page size, bounded by the library to 1 through 100.
    pub limit: u32,
}

/// Input to [`MembershipRepository::create`].
#[derive(Debug, Clone)]
pub struct CreateMembership<'a> {
    /// The membership to add.
    pub member: MembershipRef<'a>,
    /// The role to grant.
    pub role: &'a str,
    /// The inviter, or `None` when none.
    pub invited_by_user_id: Option<&'a str>,
    /// The event for this change, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of [`MembershipRepository::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMembershipOutcome {
    /// Added.
    Done,
    /// The user already belongs to the workspace, in any status.
    AlreadyMember,
    /// The workspace does not exist.
    WorkspaceNotFound,
}

/// Input to [`MembershipRepository::change_role`].
#[derive(Debug, Clone)]
pub struct ChangeRole<'a> {
    /// The member whose role changes.
    pub member: MembershipRef<'a>,
    /// The role to set.
    pub role: &'a str,
    /// The role the member held when the library judged the change; the write applies only while
    /// it still does.
    pub expected_role: &'a str,
    /// The actor whose role authorized the change.
    pub actor: ActingMember<'a>,
    /// The role that owns a workspace, so the last-owner rule is decided with the write.
    pub owner_role: &'a str,
    /// The `member.role_changed` event, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Input to [`MembershipRepository::remove`].
#[derive(Debug, Clone)]
pub struct RemoveMembership<'a> {
    /// The member to remove.
    pub member: MembershipRef<'a>,
    /// The role the member held when the library judged the removal; the write applies only while
    /// it still does. `None` when a member leaves, since nobody's role authorized it.
    pub expected_role: Option<&'a str>,
    /// The actor whose role authorized the removal; `None` when a member leaves.
    pub actor: Option<ActingMember<'a>>,
    /// The role that owns a workspace, so the last-owner rule is decided with the write.
    pub owner_role: &'a str,
    /// The `member.removed` or `member.left` event, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of a write an actor's role authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberChangeOutcome {
    /// Applied.
    Done,
    /// No such active membership holding the role the call was judged against.
    NotFound,
    /// The change would leave the workspace with no active member holding the owner role.
    LastOwner,
    /// The actor no longer holds the role the call was judged against.
    ActorChanged,
}

/// Input to [`MembershipRepository::transfer_ownership`].
#[derive(Debug, Clone)]
pub struct TransferOwnership<'a> {
    /// The workspace.
    pub workspace: WorkspaceRef<'a>,
    /// The current owner handing over.
    pub from_user_id: &'a str,
    /// The member who becomes an owner; must already be an active member.
    pub to_user_id: &'a str,
    /// The role that owns a workspace.
    pub owner_role: &'a str,
    /// The role `from_user_id` takes afterwards, or `None` to keep them an owner alongside the new
    /// one.
    pub demote_from_to: Option<&'a str>,
    /// The `ownership.transferred` event, to persist in the same transaction.
    pub audit: &'a WorkspaceAuditEvent,
}

/// Outcome of [`MembershipRepository::transfer_ownership`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    /// Transferred.
    Done,
    /// The workspace does not exist, or the `from_user_id` membership does not exist or is not an
    /// active owner.
    NotFound,
    /// `to_user_id` is not an active member.
    TargetNotMember,
}

/// Input to [`MembershipRepository::count_owned`].
#[derive(Debug, Clone, Copy)]
pub struct OwnedBy<'a> {
    /// The tenant the member belongs to.
    pub tenant_id: &'a str,
    /// The member.
    pub user_id: &'a str,
    /// The role that owns a workspace.
    pub owner_role: &'a str,
}

/// Input to [`MembershipRepository::list_sole_owned`].
#[derive(Debug, Clone, Copy)]
pub struct ListSoleOwned<'a> {
    /// The member and the owner role.
    pub owner: OwnedBy<'a>,
    /// The `next_cursor` of the previous page, or `None` for the first.
    pub cursor: Option<&'a str>,
    /// Page size, bounded by the library to 1 through 100.
    pub limit: u32,
}

/// The event persisted for each membership [`MembershipRepository::remove_all_for_user`] deletes.
/// The repository stores one `member.removed` event per removed membership, naming that
/// membership's workspace, and nothing else is added to it.
#[derive(Debug, Clone)]
pub struct AccountRemovalAudit<'a> {
    /// The tenant of the account.
    pub tenant_id: &'a str,
    /// Who authorized the removal: the member themselves, an administrator, or `None` for a job.
    pub actor_user_id: Option<&'a str>,
    /// The account whose memberships are removed.
    pub user_id: &'a str,
    /// When the removal was decided, as one ISO-8601 UTC instant for the whole call.
    pub at: &'a str,
}

/// Input to [`MembershipRepository::remove_all_for_user`].
#[derive(Debug, Clone)]
pub struct RemoveAllForUser<'a> {
    /// The tenant of the account.
    pub tenant_id: &'a str,
    /// The account whose memberships are removed.
    pub user_id: &'a str,
    /// The role that owns a workspace, so the last-owner rule is decided with the write.
    pub owner_role: &'a str,
    /// The event to persist for each membership removed.
    pub audit: AccountRemovalAudit<'a>,
}

/// One membership an account removal deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedMembership {
    /// The workspace the membership was in.
    pub workspace_id: String,
    /// The role the account held there.
    pub role: String,
}

/// Outcome of [`MembershipRepository::remove_all_for_user`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveAllOutcome {
    /// Every membership was removed.
    Removed(Vec<RemovedMembership>),
    /// The account is the only active owner of these workspaces, which block the removal. Nothing
    /// was removed.
    LastOwner(Vec<String>),
}

/// The membership persistence contract, implemented once by the host and held on the engine as
/// `Arc<dyn MembershipRepository>`.
///
/// # Tenant scoping
///
/// Every method takes the tenant, and an implementation MUST restrict the read and the write to
/// it: a user id is unique only within its tenant, so a statement keyed on the user alone merges
/// two unrelated accounts.
///
/// # Reads the library decides on
///
/// Reads the library uses to decide access MUST come from the primary or be read-your-writes: a
/// replica that lags a removal would cache the removed member as present under the new cache
/// version.
///
/// # Atomic ownership rules
///
/// The last owner of a workspace cannot leave, be removed or be demoted, and the check and the
/// change are one atomic operation in the repository, not a read followed by a write. The library
/// pre-checks only to return a friendlier error; the repository's answer decides. The same holds
/// for the transfer of ownership.
///
/// # Compare-and-set on change
///
/// A role change and a removal are conditional on the role the actor read (`expected_role`) and on
/// the actor's own standing, so two concurrent actors cannot both succeed against a stale view.
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
pub trait MembershipRepository: Send + Sync {
    /// Reads one membership in any status: the library decides access. Returns `None` when none
    /// matches all parts of the key.
    async fn find(&self, member: MembershipRef<'_>) -> Result<Option<Membership>, RepositoryError>;

    /// Lists a member's memberships with their workspaces, for the workspace picker.
    ///
    /// Returns only active memberships of active workspaces, ordered by membership creation instant
    /// and then workspace id, ascending. The cursor is opaque to the library and valid only for the
    /// same tenant and member; a malformed cursor, or one issued for another query, restarts from
    /// the first page and never widens the scope.
    async fn list_for_user(
        &self,
        params: ListForUser<'_>,
    ) -> Result<Page<MembershipWithWorkspace>, RepositoryError>;

    /// Lists the members of a workspace in every membership status, so an administrator can see a
    /// suspended member.
    ///
    /// Ordered by membership creation instant and then user id, ascending. The cursor is opaque to
    /// the library and valid only for the same workspace; a malformed cursor, or one issued for
    /// another query, restarts from the first page and never widens the scope.
    async fn list_for_workspace(
        &self,
        params: ListForWorkspace<'_>,
    ) -> Result<Page<Membership>, RepositoryError>;

    /// Adds a member, persisting `audit` in the same transaction.
    async fn create(
        &self,
        params: CreateMembership<'_>,
    ) -> Result<CreateMembershipOutcome, RepositoryError>;

    /// Changes a member's role, persisting `audit` in the same transaction.
    ///
    /// MUST answer [`MemberChangeOutcome::LastOwner`] when the change would leave the workspace
    /// with no active member holding `owner_role`. The check and the write happen in one
    /// transaction (for example `SELECT ... FOR UPDATE` on the workspace's owner rows): two owners
    /// demoting each other at the same moment is the race this rule exists for.
    ///
    /// The same transaction MUST also hold the two roles the library judged the change against,
    /// because it read them before the write and either may have changed since: the actor still
    /// holds `actor.expected_role` as an active member, else answer
    /// [`MemberChangeOutcome::ActorChanged`]; the member still holds `expected_role`, else answer
    /// [`MemberChangeOutcome::NotFound`]. Lock the actor's row and the member's row together in one
    /// fixed order, so two members acting on each other cannot deadlock. A host that ignores both
    /// keeps the check-then-write window. Nothing is written for any result other than `Done`.
    async fn change_role(
        &self,
        params: ChangeRole<'_>,
    ) -> Result<MemberChangeOutcome, RepositoryError>;

    /// Removes a member, persisting `audit` in the same transaction.
    ///
    /// The same atomic last-owner rule as [`MembershipRepository::change_role`] applies, and so
    /// does its pair of role conditions when `expected_role` and `actor` are given. A member leaving
    /// passes neither, since no role authorized it.
    async fn remove(
        &self,
        params: RemoveMembership<'_>,
    ) -> Result<MemberChangeOutcome, RepositoryError>;

    /// Removes every membership of an account, in every membership status and in every workspace
    /// status, persisting one audit event per removed membership in the same transaction.
    ///
    /// For the host that is about to delete or anonymise a user. [`list_for_user`] shows only
    /// active memberships of active workspaces, so only the repository can find the rest.
    ///
    /// The last-owner rule is decided inside the transaction: when the account is the only active
    /// owner of a workspace whose status blocks the removal
    /// ([`WorkspaceStatus::blocks_account_removal`](crate::workspace::domain::WorkspaceStatus::blocks_account_removal)),
    /// nothing is removed, no audit row is written and the answer names those workspaces. A
    /// workspace pending deletion does not block: no one can finalize it early, and its owner must
    /// not wait out the grace period to delete their account.
    ///
    /// [`list_for_user`]: MembershipRepository::list_for_user
    async fn remove_all_for_user(
        &self,
        params: RemoveAllForUser<'_>,
    ) -> Result<RemoveAllOutcome, RepositoryError>;

    /// Hands ownership from one member to another in one transaction, persisting `audit` with it.
    ///
    /// `from_user_id` must be an active member holding `owner_role`, and `to_user_id` an active
    /// member; the target takes `owner_role`, and the previous owner takes `demote_from_to` when it
    /// is set.
    async fn transfer_ownership(
        &self,
        params: TransferOwnership<'_>,
    ) -> Result<TransferOutcome, RepositoryError>;

    /// Counts the workspaces a member owns, for the per-user cap: those in which the member is an
    /// active owner and that are not `deleted`, so one pending deletion still counts. Read from the
    /// primary, like every read the library decides on.
    async fn count_owned(&self, params: OwnedBy<'_>) -> Result<u64, RepositoryError>;

    /// Lists the workspaces whose only active owner is this member, so a host can block or route an
    /// account deletion that would orphan them.
    ///
    /// Excludes `deleted` workspaces. Ordered by workspace creation instant and then workspace id,
    /// ascending. The cursor is opaque to the library and valid only for the same tenant and
    /// member; a malformed cursor, or one issued for another query, restarts from the first page and
    /// never widens the scope.
    async fn list_sole_owned(
        &self,
        params: ListSoleOwned<'_>,
    ) -> Result<Page<Workspace>, RepositoryError>;

    /// Optional: the workspace this member last switched to, for the post-sign-in landing. The
    /// default records nothing.
    async fn last_active_workspace_id(
        &self,
        _tenant_id: &str,
        _user_id: &str,
    ) -> Result<Option<String>, RepositoryError> {
        Ok(None)
    }

    /// Optional: remembers the workspace this member last switched to. The default records
    /// nothing.
    async fn set_last_active_workspace_id(
        &self,
        _tenant_id: &str,
        _user_id: &str,
        _workspace_id: &str,
    ) -> Result<(), RepositoryError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository that answers every required method with a refusal, so the two optional ones
    /// run as the trait defines them.
    struct Bare;

    fn refused<T>() -> Result<T, RepositoryError> {
        Err(RepositoryError::Conflict("not modelled".to_owned()))
    }

    #[async_trait]
    impl MembershipRepository for Bare {
        async fn find(&self, _: MembershipRef<'_>) -> Result<Option<Membership>, RepositoryError> {
            refused()
        }
        async fn list_for_user(
            &self,
            _: ListForUser<'_>,
        ) -> Result<Page<MembershipWithWorkspace>, RepositoryError> {
            refused()
        }
        async fn list_for_workspace(
            &self,
            _: ListForWorkspace<'_>,
        ) -> Result<Page<Membership>, RepositoryError> {
            refused()
        }
        async fn create(
            &self,
            _: CreateMembership<'_>,
        ) -> Result<CreateMembershipOutcome, RepositoryError> {
            refused()
        }
        async fn change_role(
            &self,
            _: ChangeRole<'_>,
        ) -> Result<MemberChangeOutcome, RepositoryError> {
            refused()
        }
        async fn remove(
            &self,
            _: RemoveMembership<'_>,
        ) -> Result<MemberChangeOutcome, RepositoryError> {
            refused()
        }
        async fn remove_all_for_user(
            &self,
            _: RemoveAllForUser<'_>,
        ) -> Result<RemoveAllOutcome, RepositoryError> {
            refused()
        }
        async fn transfer_ownership(
            &self,
            _: TransferOwnership<'_>,
        ) -> Result<TransferOutcome, RepositoryError> {
            refused()
        }
        async fn count_owned(&self, _: OwnedBy<'_>) -> Result<u64, RepositoryError> {
            refused()
        }
        async fn list_sole_owned(
            &self,
            _: ListSoleOwned<'_>,
        ) -> Result<Page<Workspace>, RepositoryError> {
            refused()
        }
    }

    fn audit() -> WorkspaceAuditEvent {
        WorkspaceAuditEvent {
            tenant_id: "t".into(),
            workspace_id: "w".into(),
            actor_user_id: None,
            at: "x".into(),
            kind: crate::workspace::audit::AuditKind::WorkspaceCreated,
        }
    }

    #[tokio::test]
    async fn a_repository_that_models_no_read_answers_with_its_own_error() {
        let repo = Bare;
        let m = MembershipRef {
            tenant_id: "t",
            workspace_id: "w",
            user_id: "u",
        };
        let workspace = m.workspace();
        let owned = OwnedBy {
            tenant_id: "t",
            user_id: "u",
            owner_role: "owner",
        };
        assert!(repo.find(m).await.is_err());
        let user = ListForUser {
            tenant_id: "t",
            user_id: "u",
            cursor: None,
            limit: 1,
        };
        assert!(repo.list_for_user(user).await.is_err());
        let list = ListForWorkspace {
            workspace,
            cursor: None,
            limit: 1,
        };
        assert!(repo.list_for_workspace(list).await.is_err());
        assert!(repo.count_owned(owned).await.is_err());
        let sole = ListSoleOwned {
            owner: owned,
            cursor: None,
            limit: 1,
        };
        assert!(repo.list_sole_owned(sole).await.is_err());
    }

    #[tokio::test]
    async fn a_repository_that_models_no_write_answers_with_its_own_error() {
        let repo = Bare;
        let m = MembershipRef {
            tenant_id: "t",
            workspace_id: "w",
            user_id: "u",
        };
        let event = audit();
        let create = CreateMembership {
            member: m,
            role: "r",
            invited_by_user_id: None,
            audit: &event,
        };
        assert!(repo.create(create).await.is_err());
        let actor = ActingMember {
            user_id: "a",
            expected_role: "r",
        };
        let change = ChangeRole {
            member: m,
            role: "r",
            expected_role: "r",
            actor,
            owner_role: "o",
            audit: &event,
        };
        assert!(repo.change_role(change).await.is_err());
        let remove = RemoveMembership {
            member: m,
            expected_role: None,
            actor: None,
            owner_role: "o",
            audit: &event,
        };
        assert!(repo.remove(remove).await.is_err());
    }

    #[tokio::test]
    async fn a_repository_that_models_no_account_removal_or_transfer_answers_with_its_own_error() {
        let repo = Bare;
        let m = MembershipRef {
            tenant_id: "t",
            workspace_id: "w",
            user_id: "u",
        };
        let event = audit();
        let all = RemoveAllForUser {
            tenant_id: "t",
            user_id: "u",
            owner_role: "o",
            audit: AccountRemovalAudit {
                tenant_id: "t",
                actor_user_id: None,
                user_id: "u",
                at: "x",
            },
        };
        assert!(repo.remove_all_for_user(all).await.is_err());
        let transfer = TransferOwnership {
            workspace: m.workspace(),
            from_user_id: "a",
            to_user_id: "b",
            owner_role: "o",
            demote_from_to: None,
            audit: &event,
        };
        assert!(repo.transfer_ownership(transfer).await.is_err());
    }

    #[tokio::test]
    async fn the_optional_last_active_workspace_records_nothing_by_default() {
        let repo: &dyn MembershipRepository = &Bare;
        assert!(matches!(
            repo.last_active_workspace_id("t", "u").await,
            Ok(None)
        ));
        assert!(
            repo.set_last_active_workspace_id("t", "u", "w")
                .await
                .is_ok()
        );
        assert!(matches!(
            repo.last_active_workspace_id("t", "u").await,
            Ok(None)
        ));
    }
}
