//! The access decision against `workspaceRealtime.rules.accessDecision` of the shared contract
//! (layer: domain, tests).
//!
//! The rule is prose, so the test reads it from the file and requires each answer the table
//! expects to be one the rule names, with the status `errorCatalog` pins for its code. The table
//! then walks every row state through [`classify`] and [`decide`] in the rule's order.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::access::{
    AcceptedRoles, RefusalCode, RefusalReason, ResolvedAccess, SurfaceRules, WorkspaceRefusal,
    classify, decide,
};
use super::domain::{Membership, MembershipStatus, Workspace, WorkspaceStatus};
use super::roles::RoleHierarchy;
use super::tests::contract;

/// owner includes admin and member, admin includes member.
fn hierarchy() -> Option<RoleHierarchy> {
    let includes = BTreeMap::from([
        (
            "owner".to_owned(),
            vec!["admin".to_owned(), "member".to_owned()],
        ),
        ("admin".to_owned(), vec!["member".to_owned()]),
        ("member".to_owned(), Vec::new()),
    ]);
    RoleHierarchy::new(includes, "owner").ok()
}

fn workspace(status: WorkspaceStatus) -> Workspace {
    Workspace {
        id: "w1".to_owned(),
        tenant_id: "t1".to_owned(),
        name: "Acme".to_owned(),
        status,
        created_at: OffsetDateTime::UNIX_EPOCH,
        deletion_scheduled_at: None,
    }
}

fn membership(status: MembershipStatus, role: &str) -> Membership {
    Membership {
        tenant_id: "t1".to_owned(),
        workspace_id: "w1".to_owned(),
        user_id: "u1".to_owned(),
        role: role.to_owned(),
        status,
        invited_by_user_id: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// What a surface accepts in a row of the table.
#[derive(Clone, Copy)]
enum Accept {
    Any,
    Roles(&'static [&'static str]),
}

/// The answer a row expects: the admitted role, or the refusal.
type Expected = Result<&'static str, (RefusalCode, RefusalReason)>;

/// One state of the two rows and one surface, with the answer the rule gives.
struct Case {
    label: &'static str,
    workspace: Option<WorkspaceStatus>,
    membership: Option<(MembershipStatus, &'static str)>,
    accept: Accept,
    allow_pending: bool,
    expected: Expected,
}

use MembershipStatus as M;
use RefusalCode as C;
use RefusalReason as R;
use WorkspaceStatus as W;

const NOT_FOUND: Expected = Err((C::WorkspaceNotFound, R::NotMember));
const HIDDEN_PENDING: Expected = Err((C::WorkspaceNotFound, R::PendingDeletion));
const ADMIN: Accept = Accept::Roles(&["admin"]);

macro_rules! case {
    ($label:literal, $ws:expr, $m:expr, $accept:expr, $pending:expr, $expected:expr $(,)?) => {
        Case {
            label: $label,
            workspace: $ws,
            membership: $m,
            accept: $accept,
            allow_pending: $pending,
            expected: $expected,
        }
    };
}

const CASES: [Case; 18] = [
    case!("nothing exists", None, None, Accept::Any, false, NOT_FOUND),
    case!(
        "not a member",
        Some(W::Active),
        None,
        Accept::Any,
        false,
        NOT_FOUND
    ),
    case!(
        "workspace missing",
        None,
        Some((M::Active, "owner")),
        Accept::Any,
        false,
        NOT_FOUND
    ),
    case!(
        "suspended member",
        Some(W::Active),
        Some((M::Suspended, "owner")),
        Accept::Any,
        false,
        NOT_FOUND
    ),
    case!(
        "suspended workspace",
        Some(W::Suspended),
        Some((M::Active, "owner")),
        Accept::Any,
        true,
        NOT_FOUND
    ),
    case!(
        "deleted workspace",
        Some(W::Deleted),
        Some((M::Active, "owner")),
        Accept::Any,
        true,
        NOT_FOUND
    ),
    case!(
        "pending, non-owner",
        Some(W::PendingDeletion),
        Some((M::Active, "admin")),
        Accept::Any,
        false,
        HIDDEN_PENDING
    ),
    case!(
        "pending, non-owner, surface admits pending",
        Some(W::PendingDeletion),
        Some((M::Active, "admin")),
        Accept::Any,
        true,
        HIDDEN_PENDING
    ),
    case!(
        "pending, non-owner below the role",
        Some(W::PendingDeletion),
        Some((M::Active, "member")),
        ADMIN,
        false,
        HIDDEN_PENDING
    ),
    case!(
        "pending, suspended owner",
        Some(W::PendingDeletion),
        Some((M::Suspended, "owner")),
        Accept::Any,
        true,
        NOT_FOUND
    ),
    case!(
        "pending, owner",
        Some(W::PendingDeletion),
        Some((M::Active, "owner")),
        Accept::Any,
        false,
        Err((C::WorkspacePendingDeletion, R::PendingDeletion))
    ),
    case!(
        "pending, owner, surface admits pending",
        Some(W::PendingDeletion),
        Some((M::Active, "owner")),
        ADMIN,
        true,
        Ok("owner")
    ),
    case!(
        "member below the role",
        Some(W::Active),
        Some((M::Active, "member")),
        ADMIN,
        false,
        Err((C::InsufficientWorkspaceRole, R::InsufficientRole))
    ),
    case!(
        "a role the hierarchy includes",
        Some(W::Active),
        Some((M::Active, "owner")),
        ADMIN,
        false,
        Ok("owner")
    ),
    case!(
        "the role itself",
        Some(W::Active),
        Some((M::Active, "admin")),
        ADMIN,
        false,
        Ok("admin")
    ),
    case!(
        "any member",
        Some(W::Active),
        Some((M::Active, "member")),
        Accept::Any,
        false,
        Ok("member")
    ),
    case!(
        "one of several roles",
        Some(W::Active),
        Some((M::Active, "member")),
        Accept::Roles(&["admin", "member"]),
        false,
        Ok("member")
    ),
    case!(
        "a role outside the hierarchy",
        Some(W::Active),
        Some((M::Active, "ghost")),
        Accept::Roles(&["member"]),
        false,
        Err((C::InsufficientWorkspaceRole, R::InsufficientRole))
    ),
];

fn accepted(accept: Accept) -> AcceptedRoles {
    match accept {
        Accept::Any => AcceptedRoles::AnyMember,
        Accept::Roles(names) => AcceptedRoles::roles(names.iter().copied()),
    }
}

#[test]
fn every_row_state_is_decided_in_the_contracts_order() {
    let hierarchy = hierarchy();
    assert!(hierarchy.is_some());
    let Some(hierarchy) = hierarchy else { return };
    for case in CASES {
        let ws = case.workspace.map(workspace);
        let member = case
            .membership
            .map(|(status, role)| membership(status, role));
        let access = classify(ws.as_ref(), member.as_ref(), hierarchy.owner_role());
        let accepted = accepted(case.accept);
        let rules = SurfaceRules {
            accepted: &accepted,
            allow_pending: case.allow_pending,
        };
        let got = decide(&access, rules, &hierarchy);
        let expected = case
            .expected
            .map(str::to_owned)
            .map_err(|(code, reason)| WorkspaceRefusal { code, reason });
        assert_eq!(got, expected, "{}", case.label);
    }
}

#[test]
fn every_answer_of_the_table_is_one_the_contract_names_with_its_pinned_status() {
    let root = contract();
    let rule = root["workspaceRealtime"]["rules"]["accessDecision"]
        .as_str()
        .unwrap_or_default();
    assert!(rule.contains("in one fixed order"), "{rule}");
    let statuses = &root["errorCatalog"]["statuses"];
    for code in [
        C::WorkspaceNotFound,
        C::WorkspacePendingDeletion,
        C::InsufficientWorkspaceRole,
    ] {
        let error = code.to_error();
        let wire = serde_json::to_value(error.code()).unwrap_or_default();
        let name = wire.as_str().unwrap_or_default();
        let status = statuses[name].as_u64().unwrap_or_default();
        assert_eq!(u64::from(error.http_status()), status, "{name}");
        assert!(rule.contains(&format!("{status} {name}")), "{name} {rule}");
    }
    // The four refusals that share the 404 are one answer, IDENTICAL, which is the disclosure rule.
    assert!(rule.contains("IDENTICAL 404 auth.workspace_not_found"));
    assert!(rule.contains("only that owner is admitted"));
}

#[test]
fn an_empty_role_list_declares_nothing_and_any_member_declares_something() {
    assert!(AcceptedRoles::Roles(Vec::new()).declares_nothing());
    assert!(!AcceptedRoles::AnyMember.declares_nothing());
    assert!(!AcceptedRoles::roles(["member"]).declares_nothing());
    // Nothing is accepted from an empty list, so a surface declaring it admits no one.
    let hierarchy = hierarchy();
    assert!(hierarchy.is_some());
    let Some(hierarchy) = hierarchy else { return };
    assert!(!AcceptedRoles::Roles(Vec::new()).accepts("owner", &hierarchy));
}

#[test]
fn an_unknown_role_is_found_and_any_member_names_none() {
    let hierarchy = hierarchy();
    assert!(hierarchy.is_some());
    let Some(hierarchy) = hierarchy else { return };
    assert_eq!(AcceptedRoles::AnyMember.unknown_role(&hierarchy), None);
    assert_eq!(
        AcceptedRoles::roles(["admin", "ghost"]).unknown_role(&hierarchy),
        Some("ghost")
    );
    assert_eq!(
        AcceptedRoles::roles(["admin"]).unknown_role(&hierarchy),
        None
    );
}

#[test]
fn a_member_names_the_membership_and_the_workspace_it_was_admitted_to() {
    let member = super::access::WorkspaceMember {
        tenant_id: "t1".to_owned(),
        workspace_id: "w1".to_owned(),
        user_id: "u1".to_owned(),
        role: "owner".to_owned(),
    };
    assert_eq!(member.workspace().tenant_id, "t1");
    assert_eq!(member.workspace().workspace_id, "w1");
    assert_eq!(member.key().user_id, "u1");
    assert_eq!(member.key().workspace(), member.workspace());
}

#[test]
fn a_classification_carries_the_role_only_where_it_admits() {
    let active = membership(M::Active, "owner");
    let pending = workspace(W::PendingDeletion);
    assert_eq!(
        classify(Some(&pending), Some(&active), "owner"),
        ResolvedAccess::PendingDeletionOwner {
            role: "owner".to_owned()
        }
    );
    // The owner is the role exactly, not a role that includes it.
    assert_eq!(
        classify(Some(&pending), Some(&active), "admin"),
        ResolvedAccess::Denied {
            pending_deletion: true
        }
    );
}
