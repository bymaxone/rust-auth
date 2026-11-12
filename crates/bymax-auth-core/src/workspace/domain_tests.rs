//! The workspace statuses, the role hierarchy and the audit names (layer: domain, tests).
//!
//! The account-removal blocking rule is read from `workspaceAccountRemoval.blockingVectors` in the
//! shared contract and compared with the status predicate for every status in both directions.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::audit::AuditKind;
use super::domain::{
    ActingMember, Membership, MembershipRef, MembershipStatus, WorkspaceRef, WorkspaceStatus,
};
use super::roles::{RoleHierarchy, RoleHierarchyError};

const STATUSES: [WorkspaceStatus; 4] = [
    WorkspaceStatus::Active,
    WorkspaceStatus::PendingDeletion,
    WorkspaceStatus::Suspended,
    WorkspaceStatus::Deleted,
];

fn contract() -> Value {
    let path = format!(
        "{}/../../conformance/wire-contract.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

fn status_named(name: &str) -> Option<WorkspaceStatus> {
    STATUSES.into_iter().find(|status| status.as_str() == name)
}

#[test]
fn the_blocking_rule_is_the_contracts_for_every_status() {
    let root = contract();
    let vectors = root["workspaceAccountRemoval"]["blockingVectors"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!vectors.is_empty());
    let mut sole_owner_statuses = BTreeSet::new();
    for vector in &vectors {
        let status = status_named(vector["workspaceStatus"].as_str().unwrap_or_default());
        assert!(status.is_some(), "an unknown status in {vector}");
        let Some(status) = status else { continue };
        let sole = vector["accountIsSoleOwner"].as_bool().unwrap_or(false);
        let blocks = vector["blocks"].as_bool().unwrap_or(false);
        // The status predicate decides for a sole owner; a co-owned workspace never blocks.
        assert_eq!(sole && status.blocks_account_removal(), blocks, "{vector}");
        if sole {
            sole_owner_statuses.insert(status.as_str());
        }
    }
    // Every status the library knows is covered by a sole-owner vector.
    let all: BTreeSet<&str> = STATUSES.iter().map(|s| s.as_str()).collect();
    assert_eq!(sole_owner_statuses, all);
}

#[test]
fn only_an_active_workspace_grants_access() {
    for status in STATUSES {
        assert_eq!(status.grants_access(), status == WorkspaceStatus::Active);
    }
}

#[test]
fn the_library_moves_a_workspace_only_along_schedule_restore_and_finalize() {
    let allowed = [
        (WorkspaceStatus::Active, WorkspaceStatus::PendingDeletion),
        (WorkspaceStatus::PendingDeletion, WorkspaceStatus::Active),
        (WorkspaceStatus::PendingDeletion, WorkspaceStatus::Deleted),
    ];
    for from in STATUSES {
        for to in STATUSES {
            assert_eq!(
                from.library_may_move_to(to),
                allowed.contains(&(from, to)),
                "{from:?} to {to:?}"
            );
        }
    }
}

#[test]
fn the_status_names_are_distinct_and_stable() {
    let names: Vec<&str> = STATUSES.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        names,
        ["active", "pending_deletion", "suspended", "deleted"]
    );
    assert_eq!(MembershipStatus::Active.as_str(), "active");
    assert_eq!(MembershipStatus::Suspended.as_str(), "suspended");
}

#[test]
fn a_reference_names_every_part_it_carries() {
    let member = MembershipRef {
        tenant_id: "t",
        workspace_id: "w",
        user_id: "u",
    };
    assert_eq!(
        member.workspace(),
        WorkspaceRef {
            tenant_id: "t",
            workspace_id: "w"
        }
    );
    let held = Membership {
        tenant_id: "t".into(),
        workspace_id: "w".into(),
        user_id: "u".into(),
        role: "owner".into(),
        status: MembershipStatus::Active,
        invited_by_user_id: None,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    assert_eq!(held.key(), member);
    let actor = ActingMember {
        user_id: "u",
        expected_role: "owner",
    };
    assert_eq!(actor.user_id, "u");
}

fn every_kind() -> Vec<AuditKind> {
    vec![
        AuditKind::WorkspaceCreated,
        AuditKind::WorkspaceRenamed,
        AuditKind::WorkspaceDeletionScheduled,
        AuditKind::WorkspaceRestored,
        AuditKind::WorkspaceDeleted,
        AuditKind::MemberInvited {
            email: "e".into(),
            role: "r".into(),
        },
        AuditKind::InvitationResent {
            email: "e".into(),
            role: "r".into(),
        },
        AuditKind::InvitationRevoked {
            email: "e".into(),
            role: "r".into(),
        },
        AuditKind::InvitationAccepted {
            email: "e".into(),
            role: "r".into(),
            user_id: "u".into(),
            lost_consume_race: false,
        },
        AuditKind::MemberRoleChanged {
            user_id: "u".into(),
            from: "a".into(),
            to: "b".into(),
        },
        AuditKind::MemberRemoved {
            user_id: "u".into(),
        },
        AuditKind::MemberLeft {
            user_id: "u".into(),
        },
        AuditKind::WorkspaceSwitched {
            user_id: "u".into(),
        },
        AuditKind::OwnershipTransferred {
            from_user_id: "a".into(),
            to_user_id: "b".into(),
        },
    ]
}

#[test]
fn every_audit_kind_has_its_own_name() {
    let kinds = every_kind();
    let names: Vec<&str> = kinds.iter().map(AuditKind::type_name).collect();
    assert_eq!(
        names,
        [
            "workspace.created",
            "workspace.renamed",
            "workspace.deletion_scheduled",
            "workspace.restored",
            "workspace.deleted",
            "member.invited",
            "invitation.resent",
            "invitation.revoked",
            "invitation.accepted",
            "member.role_changed",
            "member.removed",
            "member.left",
            "workspace.switched",
            "ownership.transferred",
        ]
    );
}

fn hierarchy(rows: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    rows.iter()
        .map(|(role, list)| {
            (
                (*role).to_owned(),
                list.iter().map(|name| (*name).to_owned()).collect(),
            )
        })
        .collect()
}

#[test]
fn a_hierarchy_with_the_owner_on_top_is_accepted_and_answers_inclusion() {
    let roles = RoleHierarchy::new(
        hierarchy(&[
            ("owner", &["admin", "member"]),
            ("admin", &["member"]),
            ("member", &[]),
        ]),
        "owner",
    );
    assert!(roles.is_ok());
    let Ok(roles) = roles else { return };
    assert_eq!(roles.owner_role(), "owner");
    assert!(roles.knows("admin"));
    assert!(!roles.knows("guest"));
    assert!(roles.satisfies("owner", "owner"));
    assert!(roles.satisfies("owner", "member"));
    assert!(roles.satisfies("admin", "member"));
    assert!(!roles.satisfies("member", "admin"));
    assert!(!roles.satisfies("admin", "owner"));
    // A role outside the hierarchy satisfies only itself.
    assert!(roles.satisfies("guest", "guest"));
    assert!(!roles.satisfies("guest", "member"));
}

#[test]
fn a_hierarchy_that_breaks_a_rule_names_the_rule() {
    let new = |rows: &[(&str, &[&str])], owner: &str| RoleHierarchy::new(hierarchy(rows), owner);
    assert_eq!(new(&[], "owner"), Err(RoleHierarchyError::Empty));
    assert_eq!(
        new(&[("owner", &["ghost"])], "owner"),
        Err(RoleHierarchyError::UnknownIncluded {
            role: "owner".into()
        })
    );
    assert_eq!(
        new(&[("owner", &[])], "boss"),
        Err(RoleHierarchyError::UnknownOwner)
    );
    assert_eq!(
        new(&[("owner", &["admin"]), ("admin", &["owner"])], "owner"),
        Err(RoleHierarchyError::IncludesOwner {
            role: "admin".into()
        })
    );
    assert_eq!(
        new(&[("owner", &[]), ("admin", &[])], "owner"),
        Err(RoleHierarchyError::OwnerMissesRole {
            role: "admin".into()
        })
    );
    // The owner including itself is not a rule breach.
    assert!(new(&[("owner", &["owner"])], "owner").is_ok());
}

#[test]
fn every_refusal_reads_as_a_sentence() {
    let errors = [
        RoleHierarchyError::Empty,
        RoleHierarchyError::UnknownIncluded { role: "a".into() },
        RoleHierarchyError::UnknownOwner,
        RoleHierarchyError::IncludesOwner { role: "a".into() },
        RoleHierarchyError::OwnerMissesRole { role: "a".into() },
    ];
    let texts: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), errors.len());
}
