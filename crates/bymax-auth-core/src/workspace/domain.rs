//! The workspace and membership records, the statuses that gate access, and the keys that name
//! them (layer: domain).
//!
//! A workspace id is unique only inside its tenant and a user id only inside its tenant, so every
//! reference here carries every part it needs: [`WorkspaceRef`] the tenant and the workspace,
//! [`MembershipRef`] those and the member. A reference with fewer parts cannot scope the row it
//! names.

use time::OffsetDateTime;

/// Names a workspace. Both halves are required, because the id on its own can name a homonym in
/// another tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkspaceRef<'a> {
    /// The tenant the workspace lives in.
    pub tenant_id: &'a str,
    /// The workspace, unique within `tenant_id`.
    pub workspace_id: &'a str,
}

/// Names one member of a workspace: the workspace key and the user, who is unique only within the
/// tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MembershipRef<'a> {
    /// The tenant the workspace lives in.
    pub tenant_id: &'a str,
    /// The workspace, unique within `tenant_id`.
    pub workspace_id: &'a str,
    /// The member.
    pub user_id: &'a str,
}

impl<'a> MembershipRef<'a> {
    /// The workspace this member belongs to.
    #[must_use]
    pub const fn workspace(&self) -> WorkspaceRef<'a> {
        WorkspaceRef {
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
        }
    }
}

/// Where a workspace is in its life. Only [`WorkspaceStatus::Active`] grants access: any other
/// value reads as "not a member" to every caller, so a workspace nobody can reach and one that does
/// not exist look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceStatus {
    /// Open for use.
    Active,
    /// Scheduled for removal; only the owner can restore it, within the grace period.
    PendingDeletion,
    /// Held by the host (a billing or abuse decision); the library never sets it.
    Suspended,
    /// Finalized. The row may remain for audit; the host purges the data.
    Deleted,
}

impl WorkspaceStatus {
    /// The wire and storage name: `active`, `pending_deletion`, `suspended` or `deleted`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::PendingDeletion => "pending_deletion",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }

    /// Whether a member of a workspace in this status is granted anything.
    #[must_use]
    pub const fn grants_access(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether an account that is the only active owner of a workspace in this status blocks the
    /// removal of every membership of that account. A pending deletion never blocks, because no
    /// one can finalize it before its grace period ends, and a deleted workspace has nothing left
    /// to orphan.
    #[must_use]
    pub const fn blocks_account_removal(self) -> bool {
        matches!(self, Self::Active | Self::Suspended)
    }

    /// Whether the library moves a workspace from `self` to `to`: scheduling a deletion, restoring
    /// it, and finalizing it. A workspace the host suspended is changed only by the host, and a
    /// deleted one never moves again.
    #[must_use]
    pub const fn library_may_move_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Active, Self::PendingDeletion)
                | (Self::PendingDeletion, Self::Active | Self::Deleted)
        )
    }
}

/// Whether a membership grants access. Only [`MembershipStatus::Active`] does; any other value
/// reads as "not a member".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MembershipStatus {
    /// The member has access.
    Active,
    /// The member is held without access.
    Suspended,
}

impl MembershipStatus {
    /// The wire and storage name: `active` or `suspended`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// A workspace as the repository returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// Unique within `tenant_id`.
    pub id: String,
    /// The tenant the workspace lives in.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Lifecycle state.
    pub status: WorkspaceStatus,
    /// When the workspace was created.
    pub created_at: OffsetDateTime,
    /// When a scheduled deletion becomes final, or `None` when none is scheduled.
    pub deletion_scheduled_at: Option<OffsetDateTime>,
}

/// A membership as the repository returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The tenant of the workspace.
    pub tenant_id: String,
    /// The workspace the member belongs to.
    pub workspace_id: String,
    /// The member.
    pub user_id: String,
    /// The member's role in this workspace, one of the configured hierarchy's roles.
    pub role: String,
    /// Whether the membership grants access.
    pub status: MembershipStatus,
    /// The user who invited the member, or `None` for a creator or a system-made membership.
    pub invited_by_user_id: Option<String>,
    /// When the membership was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

impl Membership {
    /// The key that names this membership.
    #[must_use]
    pub fn key(&self) -> MembershipRef<'_> {
        MembershipRef {
            tenant_id: &self.tenant_id,
            workspace_id: &self.workspace_id,
            user_id: &self.user_id,
        }
    }
}

/// A membership with its workspace, as listed for the member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipWithWorkspace {
    /// The membership.
    pub membership: Membership,
    /// The workspace the membership is in.
    pub workspace: Workspace,
}

/// One page of a keyset-paginated list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows of this page.
    pub items: Vec<T>,
    /// The cursor for the next page, or `None` on the last one.
    pub next_cursor: Option<String>,
}

/// The member whose role authorized a write, and the role the library read for them.
///
/// The library decides what an actor may do from a role it read before the write. Handing it back
/// lets the repository check, in the write's own transaction, that the actor still holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActingMember<'a> {
    /// The actor, a member of the same workspace and tenant as the write.
    pub user_id: &'a str,
    /// The role the library read for the actor and judged the action against.
    pub expected_role: &'a str,
}
