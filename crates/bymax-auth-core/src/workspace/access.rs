//! The workspace access decision every surface makes about a caller and a workspace (layer:
//! domain).
//!
//! The decision is pinned by `workspaceRealtime.rules.accessDecision` of the shared contract and is
//! made in one fixed order from rows already read: a caller who is not an active member of an
//! active workspace, and every non-owner of a workspace pending deletion, is refused with the
//! IDENTICAL `404 auth.workspace_not_found`; the owner of a workspace pending deletion is refused
//! with `409 auth.workspace_pending_deletion` unless the surface admits pending workspaces, and is
//! then the only caller admitted to it; only after that is the role judged through the hierarchy
//! (`403 auth.insufficient_workspace_role`). Everything here is pure.

use bymax_auth_types::AuthError;

use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceRef, WorkspaceStatus,
};
use crate::workspace::roles::RoleHierarchy;

/// The roles a surface accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedRoles {
    /// Every active member, whatever their role.
    AnyMember,
    /// A member holding one of these roles, or a role whose hierarchy list names one. An empty
    /// list declares nothing, and a surface declaring nothing is refused before any lookup.
    Roles(Vec<String>),
}

impl AcceptedRoles {
    /// The roles `names`, judged through the hierarchy.
    #[must_use]
    pub fn roles<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Roles(names.into_iter().map(Into::into).collect())
    }

    /// Whether the surface declares no role at all.
    #[must_use]
    pub fn declares_nothing(&self) -> bool {
        matches!(self, Self::Roles(list) if list.is_empty())
    }

    /// Whether a member holding `held` is accepted.
    #[must_use]
    pub fn accepts(&self, held: &str, hierarchy: &RoleHierarchy) -> bool {
        match self {
            Self::AnyMember => true,
            Self::Roles(list) => list
                .iter()
                .any(|required| hierarchy.satisfies(held, required)),
        }
    }

    /// The first named role that is not a role of `hierarchy`.
    #[must_use]
    pub fn unknown_role<'a>(&'a self, hierarchy: &RoleHierarchy) -> Option<&'a str> {
        match self {
            Self::AnyMember => None,
            Self::Roles(list) => list
                .iter()
                .find(|role| !hierarchy.knows(role))
                .map(String::as_str),
        }
    }
}

/// A caller admitted to a workspace: the key of the membership and the role it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMember {
    /// The tenant, taken from the verified credential.
    pub tenant_id: String,
    /// The workspace the request named.
    pub workspace_id: String,
    /// The caller.
    pub user_id: String,
    /// The caller's role in that workspace.
    pub role: String,
}

impl WorkspaceMember {
    /// The workspace the member was admitted to.
    #[must_use]
    pub fn workspace(&self) -> WorkspaceRef<'_> {
        WorkspaceRef {
            tenant_id: &self.tenant_id,
            workspace_id: &self.workspace_id,
        }
    }

    /// The membership that admitted the member.
    #[must_use]
    pub fn key(&self) -> MembershipRef<'_> {
        MembershipRef {
            tenant_id: &self.tenant_id,
            workspace_id: &self.workspace_id,
            user_id: &self.user_id,
        }
    }
}

/// What the rows say about a caller's access, before the surface's rules are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAccess {
    /// An active member of an active workspace, holding `role`.
    Member {
        /// The role the member holds.
        role: String,
    },
    /// An active member holding the owner role of a workspace pending deletion. Only the owner is
    /// told the state, so a client can offer to restore it.
    PendingDeletionOwner {
        /// The role the member holds, which is the owner role.
        role: String,
    },
    /// Everything else: a missing workspace, an inactive one, a missing or suspended membership.
    Denied {
        /// Whether the workspace is pending deletion and the caller is an active member who does
        /// not own it: still denied as a stranger is, but the host is told why.
        pending_deletion: bool,
    },
}

/// Classifies the two rows a membership is decided from.
///
/// Only an ACTIVE membership counts, and only an ACTIVE workspace grants access. A workspace
/// pending deletion is told apart for its owner alone, whose role must be exactly `owner_role`.
#[must_use]
pub fn classify(
    workspace: Option<&Workspace>,
    membership: Option<&Membership>,
    owner_role: &str,
) -> ResolvedAccess {
    let not_member = ResolvedAccess::Denied {
        pending_deletion: false,
    };
    let (Some(workspace), Some(membership)) = (workspace, membership) else {
        return not_member;
    };
    if membership.status != MembershipStatus::Active {
        return not_member;
    }
    let role = membership.role.clone();
    match workspace.status {
        WorkspaceStatus::Active => ResolvedAccess::Member { role },
        WorkspaceStatus::PendingDeletion if role == owner_role => {
            ResolvedAccess::PendingDeletionOwner { role }
        }
        WorkspaceStatus::PendingDeletion => ResolvedAccess::Denied {
            pending_deletion: true,
        },
        WorkspaceStatus::Suspended | WorkspaceStatus::Deleted => not_member,
    }
}

/// The public code a refusal answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// `404 auth.workspace_not_found`.
    WorkspaceNotFound,
    /// `409 auth.workspace_pending_deletion`.
    WorkspacePendingDeletion,
    /// `403 auth.insufficient_workspace_role`.
    InsufficientWorkspaceRole,
}

impl RefusalCode {
    /// The error the caller is answered with.
    #[must_use]
    pub const fn to_error(self) -> AuthError {
        match self {
            Self::WorkspaceNotFound => AuthError::WorkspaceNotFound,
            Self::WorkspacePendingDeletion => AuthError::WorkspacePendingDeletion,
            Self::InsufficientWorkspaceRole => AuthError::InsufficientWorkspaceRole,
        }
    }
}

/// Why a decision refused, as only the host is told. It differs from the code exactly where the
/// disclosure rule hides the state: a non-owner of a workspace pending deletion is answered
/// `auth.workspace_not_found` and the reason is still [`RefusalReason::PendingDeletion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The caller is not an active member of an active workspace.
    NotMember,
    /// The workspace is pending deletion and the caller is an active member of it.
    PendingDeletion,
    /// The caller's role is below what the surface accepts.
    InsufficientRole,
}

/// A refused decision: what the caller is answered, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRefusal {
    /// The public code.
    pub code: RefusalCode,
    /// The reason the host alone is told.
    pub reason: RefusalReason,
}

/// What a surface accepts: the roles, and whether the owner of a workspace pending deletion is
/// admitted.
#[derive(Debug, Clone, Copy)]
pub struct SurfaceRules<'a> {
    /// The roles the surface accepts.
    pub accepted: &'a AcceptedRoles,
    /// Whether the owner of a workspace pending deletion is admitted.
    pub allow_pending: bool,
}

/// Turns a resolved access into the role it admits, or refuses it, in the contract's fixed order.
///
/// # Errors
///
/// A [`WorkspaceRefusal`] for every caller the surface does not admit.
pub fn decide(
    access: &ResolvedAccess,
    rules: SurfaceRules<'_>,
    hierarchy: &RoleHierarchy,
) -> Result<String, WorkspaceRefusal> {
    let role = match access {
        ResolvedAccess::Denied { pending_deletion } => {
            let reason = if *pending_deletion {
                RefusalReason::PendingDeletion
            } else {
                RefusalReason::NotMember
            };
            return Err(WorkspaceRefusal {
                code: RefusalCode::WorkspaceNotFound,
                reason,
            });
        }
        ResolvedAccess::PendingDeletionOwner { .. } if !rules.allow_pending => {
            return Err(WorkspaceRefusal {
                code: RefusalCode::WorkspacePendingDeletion,
                reason: RefusalReason::PendingDeletion,
            });
        }
        ResolvedAccess::Member { role } | ResolvedAccess::PendingDeletionOwner { role } => role,
    };
    if rules.accepted.accepts(role, hierarchy) {
        Ok(role.clone())
    } else {
        Err(WorkspaceRefusal {
            code: RefusalCode::InsufficientWorkspaceRole,
            reason: RefusalReason::InsufficientRole,
        })
    }
}
