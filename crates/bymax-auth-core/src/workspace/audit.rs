//! The audit event a workspace or membership write persists with its change (layer: domain).
//!
//! The library fills an event in completely before the write and the repository stores it as
//! given, in the same transaction as the change. Its tenant and workspace are the key of the call
//! that carries it.

/// One audit event: who did what to which workspace, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAuditEvent {
    /// The tenant of the workspace.
    pub tenant_id: String,
    /// The workspace the event is about.
    pub workspace_id: String,
    /// The member who made the change, or `None` for a job.
    pub actor_user_id: Option<String>,
    /// When the change was decided, as an ISO-8601 UTC string.
    pub at: String,
    /// What happened, with the fields that kind carries.
    pub kind: AuditKind,
}

/// What an audit event records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditKind {
    /// A workspace was created.
    WorkspaceCreated,
    /// A workspace was renamed.
    WorkspaceRenamed,
    /// A workspace's deletion was scheduled.
    WorkspaceDeletionScheduled,
    /// A scheduled deletion was cancelled.
    WorkspaceRestored,
    /// A scheduled deletion became final.
    WorkspaceDeleted,
    /// An invitation was issued.
    MemberInvited {
        /// The invitee's address.
        email: String,
        /// The role offered.
        role: String,
    },
    /// An invitation was sent again.
    InvitationResent {
        /// The invitee's address.
        email: String,
        /// The role offered.
        role: String,
    },
    /// An invitation was withdrawn.
    InvitationRevoked {
        /// The invitee's address.
        email: String,
        /// The role offered.
        role: String,
    },
    /// An invitation was accepted and the invitee became a member.
    InvitationAccepted {
        /// The invitee's address.
        email: String,
        /// The role granted.
        role: String,
        /// The new member.
        user_id: String,
        /// Whether another acceptance of the same invitation won the race.
        lost_consume_race: bool,
    },
    /// A member's role changed.
    MemberRoleChanged {
        /// The member.
        user_id: String,
        /// The role before.
        from: String,
        /// The role after.
        to: String,
    },
    /// A member was removed by someone else.
    MemberRemoved {
        /// The member.
        user_id: String,
    },
    /// A member left.
    MemberLeft {
        /// The member.
        user_id: String,
    },
    /// A member switched to this workspace.
    WorkspaceSwitched {
        /// The member.
        user_id: String,
    },
    /// Ownership moved from one member to another.
    OwnershipTransferred {
        /// The previous owner.
        from_user_id: String,
        /// The new owner.
        to_user_id: String,
    },
}

impl AuditKind {
    /// The event name stored and reported: `workspace.created`, `member.role_changed`, and so on.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::WorkspaceCreated => "workspace.created",
            Self::WorkspaceRenamed => "workspace.renamed",
            Self::WorkspaceDeletionScheduled => "workspace.deletion_scheduled",
            Self::WorkspaceRestored => "workspace.restored",
            Self::WorkspaceDeleted => "workspace.deleted",
            Self::MemberInvited { .. } => "member.invited",
            Self::InvitationResent { .. } => "invitation.resent",
            Self::InvitationRevoked { .. } => "invitation.revoked",
            Self::InvitationAccepted { .. } => "invitation.accepted",
            Self::MemberRoleChanged { .. } => "member.role_changed",
            Self::MemberRemoved { .. } => "member.removed",
            Self::MemberLeft { .. } => "member.left",
            Self::WorkspaceSwitched { .. } => "workspace.switched",
            Self::OwnershipTransferred { .. } => "ownership.transferred",
        }
    }
}
