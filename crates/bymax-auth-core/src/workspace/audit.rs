//! The workspace events: what a write persists and what the host hook receives (layer: domain).
//!
//! The library fills a write's event in completely before the write and the repository stores it as
//! given, in the same transaction as the change. Its tenant and workspace are the key of the call
//! that carries it, and its instant is written as `Date.prototype.toISOString` writes one, the
//! form `@bymax-one/nest-auth` stores, so a deployment running both reads one audit trail.

use time::{OffsetDateTime, UtcOffset};

use crate::workspace::access::{RefusalCode, RefusalReason};

/// An instant as `Date.prototype.toISOString` writes it: UTC, milliseconds, `Z`, and a six-digit
/// signed year outside 0 to 9999.
#[must_use]
pub fn iso_instant(at: OffsetDateTime) -> String {
    let utc = at.checked_to_offset(UtcOffset::UTC).unwrap_or(at);
    let year = utc.year();
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+07}")
    };
    format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    )
}

/// One audit event: who did what to which workspace, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAuditEvent {
    /// The tenant of the workspace.
    pub tenant_id: String,
    /// The workspace the event is about.
    pub workspace_id: String,
    /// The caller who made the change or was refused, or `None` for a job.
    pub actor_user_id: Option<String>,
    /// When the change was decided, as an ISO-8601 UTC string.
    pub at: String,
    /// What happened, with the fields that kind carries.
    pub kind: AuditKind,
}

/// Where a refused access was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSurface {
    /// A guarded HTTP route.
    Http,
    /// A stream verification.
    Verifier,
    /// A socket message.
    Ws,
}

impl AccessSurface {
    /// The name the event carries: `http`, `verifier` or `ws`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Verifier => "verifier",
            Self::Ws => "ws",
        }
    }
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
    /// A caller was refused a workspace. It reaches the hook only and is never persisted.
    AccessDenied {
        /// The refused account, which is also the actor.
        user_id: String,
        /// Where the refusal was decided.
        surface: AccessSurface,
        /// The code the caller was answered with.
        code: RefusalCode,
        /// Why, as only the host is told.
        reason: RefusalReason,
        /// The refusals of this account that went unreported since the last event.
        suppressed_count: u64,
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
            Self::AccessDenied { .. } => "access.denied",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::iso_instant;
    use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

    fn at(year: i32, offset_hours: i8) -> OffsetDateTime {
        let date = Date::from_calendar_date(year, Month::March, 4).unwrap_or(Date::MIN);
        let time = Time::from_hms_milli(5, 6, 7, 89).unwrap_or(Time::MIDNIGHT);
        let offset = UtcOffset::from_hms(offset_hours, 0, 0).unwrap_or(UtcOffset::UTC);
        PrimitiveDateTime::new(date, time).assume_offset(offset)
    }

    #[test]
    fn an_instant_is_written_the_way_to_iso_string_writes_it() {
        assert_eq!(iso_instant(at(2026, 0)), "2026-03-04T05:06:07.089Z");
        // Another offset is converted to UTC first.
        assert_eq!(iso_instant(at(2026, 2)), "2026-03-04T03:06:07.089Z");
        // The year keeps four digits down to 0 and takes a sign and six digits outside 0 to 9999.
        assert_eq!(iso_instant(at(7, 0)), "0007-03-04T05:06:07.089Z");
        assert_eq!(iso_instant(at(9999, 0)), "9999-03-04T05:06:07.089Z");
        assert_eq!(iso_instant(at(-1, 0)), "-000001-03-04T05:06:07.089Z");
    }
}
