//! The membership half of the in-memory repositories against the rules a host's implementation is
//! held to: atomic ownership, compare-and-set on the roles a change was judged against, and the
//! listings (layer: test double, tests).

use super::InMemoryWorkspaces;
use super::workspace_tests::{
    OWNER, T, add, create, event, instant, seed_member, seed_workspace, who, ws,
};
use crate::traits::MembershipRepository;
use crate::traits::membership_repository::{
    AccountRemovalAudit, ChangeRole, ListForUser, ListForWorkspace, ListSoleOwned,
    MemberChangeOutcome, OwnedBy, RemoveAllForUser, RemoveAllOutcome, RemoveMembership,
    RemovedMembership, TransferOutcome, TransferOwnership,
};
use crate::workspace::audit::AuditKind;
use crate::workspace::domain::{
    ActingMember, Membership, MembershipRef, MembershipStatus, WorkspaceRef, WorkspaceStatus,
};

struct RoleCall<'a> {
    workspace: &'a str,
    user: &'a str,
    expected: &'a str,
    role: &'a str,
    actor: (&'a str, &'a str),
}

async fn change(repo: &InMemoryWorkspaces, call: RoleCall<'_>) -> Option<MemberChangeOutcome> {
    let audit = event(
        call.workspace,
        AuditKind::MemberRoleChanged {
            user_id: call.user.into(),
            from: call.expected.into(),
            to: call.role.into(),
        },
    );
    repo.change_role(ChangeRole {
        member: who(call.workspace, call.user),
        role: call.role,
        expected_role: call.expected,
        actor: ActingMember {
            user_id: call.actor.0,
            expected_role: call.actor.1,
        },
        owner_role: OWNER,
        audit: &audit,
    })
    .await
    .ok()
}

#[tokio::test]
async fn a_role_change_holds_both_roles_and_never_orphans_a_workspace() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    seed_member(&repo, "w1", "u3", "member", false);
    let call = |user, expected, role, actor| RoleCall {
        workspace: "w1",
        user,
        expected,
        role,
        actor,
    };
    let before = repo.audit_events().len();
    // The actor no longer holds the role it was judged against.
    let by_stale = change(&repo, call("u2", "member", "admin", ("u1", "admin"))).await;
    assert_eq!(by_stale, Some(MemberChangeOutcome::ActorChanged));
    // The member is gone, holds another role, or is not active.
    for (user, expected) in [("zz", "member"), ("u2", "admin"), ("u3", "member")] {
        let refused = change(&repo, call(user, expected, "admin", ("u1", OWNER))).await;
        assert_eq!(refused, Some(MemberChangeOutcome::NotFound), "{user}");
    }
    // The only owner cannot be demoted, by anyone.
    let demote = change(&repo, call("u1", OWNER, "member", ("u1", OWNER))).await;
    assert_eq!(demote, Some(MemberChangeOutcome::LastOwner));
    assert_eq!(repo.audit_events().len(), before);
    let promote = change(&repo, call("u2", "member", "admin", ("u1", OWNER))).await;
    assert_eq!(promote, Some(MemberChangeOutcome::Done));
    assert_eq!(repo.audit_events().len(), before + 1);
    assert_eq!(
        repo.membership(who("w1", "u2")).map(|m| m.role).as_deref(),
        Some("admin")
    );
    // With a second owner the first can step down, and an owner keeping the role is no demotion.
    let second = change(&repo, call("u2", "admin", OWNER, ("u1", OWNER))).await;
    assert_eq!(second, Some(MemberChangeOutcome::Done));
    let same = change(&repo, call("u2", OWNER, OWNER, ("u1", OWNER))).await;
    assert_eq!(same, Some(MemberChangeOutcome::Done));
    let step = change(&repo, call("u1", OWNER, "member", ("u2", OWNER))).await;
    assert_eq!(step, Some(MemberChangeOutcome::Done));
    // A suspended owner does not count, so the last active owner is the one left.
    seed_member(&repo, "w1", "u4", OWNER, false);
    let last = change(&repo, call("u2", OWNER, "member", ("u2", OWNER))).await;
    assert_eq!(last, Some(MemberChangeOutcome::LastOwner));
}

#[tokio::test]
async fn a_sole_owner_keeping_the_owner_role_is_no_demotion_and_each_write_moves_the_clock() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    let call = |user, expected, role| RoleCall {
        workspace: "w1",
        user,
        expected,
        role,
        actor: ("u1", OWNER),
    };
    let kept = change(&repo, call("u1", OWNER, OWNER)).await;
    assert_eq!(kept, Some(MemberChangeOutcome::Done));
    let first = repo.membership(who("w1", "u2")).map(|m| m.updated_at);
    let moved = change(&repo, call("u2", "member", "admin")).await;
    assert_eq!(moved, Some(MemberChangeOutcome::Done));
    let second = repo.membership(who("w1", "u2")).map(|m| m.updated_at);
    assert!(second > first);
    let again = change(&repo, call("u2", "admin", "member")).await;
    assert_eq!(again, Some(MemberChangeOutcome::Done));
    let third = repo.membership(who("w1", "u2")).map(|m| m.updated_at);
    assert!(third > second);
}

async fn remove(
    repo: &InMemoryWorkspaces,
    user: &str,
    expected: Option<&str>,
    actor: Option<(&str, &str)>,
) -> Option<MemberChangeOutcome> {
    let audit = event(
        "w1",
        AuditKind::MemberRemoved {
            user_id: user.into(),
        },
    );
    repo.remove(RemoveMembership {
        member: who("w1", user),
        expected_role: expected,
        actor: actor.map(|(user_id, expected_role)| ActingMember {
            user_id,
            expected_role,
        }),
        owner_role: OWNER,
        audit: &audit,
    })
    .await
    .ok()
}

async fn removal_workspace() -> InMemoryWorkspaces {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    add(&repo, "w1", "u3", "member").await;
    seed_member(&repo, "w1", "u4", "member", false);
    repo
}

#[tokio::test]
async fn a_removal_and_a_leave_that_break_a_rule_write_nothing() {
    let repo = removal_workspace().await;
    let before = repo.audit_events().len();
    let owner = Some(("u1", OWNER));
    type Case<'a> = (&'a str, Option<&'a str>, Option<(&'a str, &'a str)>);
    let cases: [(Case, MemberChangeOutcome); 6] = [
        (
            ("u2", Some("member"), Some(("u3", OWNER))),
            MemberChangeOutcome::ActorChanged,
        ),
        (("u2", Some("admin"), owner), MemberChangeOutcome::NotFound),
        (("u4", Some("member"), owner), MemberChangeOutcome::NotFound),
        (("zz", None, None), MemberChangeOutcome::NotFound),
        // The only owner can neither be removed nor leave.
        (("u1", Some(OWNER), owner), MemberChangeOutcome::LastOwner),
        (("u1", None, None), MemberChangeOutcome::LastOwner),
    ];
    for ((user, expected, actor), outcome) in cases {
        assert_eq!(
            remove(&repo, user, expected, actor).await,
            Some(outcome),
            "{user}"
        );
    }
    assert_eq!(repo.audit_events().len(), before);
}

#[tokio::test]
async fn a_member_leaves_unjudged_and_an_owner_leaves_once_another_owns() {
    let repo = removal_workspace().await;
    let before = repo.audit_events().len();
    let owner = Some(("u1", OWNER));
    let done = Some(MemberChangeOutcome::Done);
    assert_eq!(remove(&repo, "u2", Some("member"), owner).await, done);
    // A member leaves with no role judged.
    assert_eq!(remove(&repo, "u3", None, None).await, done);
    assert_eq!(repo.audit_events().len(), before + 2);
    add(&repo, "w1", "u5", OWNER).await;
    assert_eq!(remove(&repo, "u1", None, None).await, done);
    assert_eq!(repo.membership(who("w1", "u1")), None);
}

async fn remove_all(
    repo: &InMemoryWorkspaces,
    tenant: &str,
    user: &str,
) -> Option<RemoveAllOutcome> {
    repo.remove_all_for_user(RemoveAllForUser {
        tenant_id: tenant,
        user_id: user,
        owner_role: OWNER,
        audit: AccountRemovalAudit {
            tenant_id: tenant,
            actor_user_id: Some("admin"),
            user_id: user,
            at: "2026-02-02T00:00:00Z",
        },
    })
    .await
    .ok()
}

#[tokio::test]
async fn an_account_removal_is_blocked_by_a_sole_owned_workspace_of_a_blocking_status() {
    for (status, blocks) in [
        (WorkspaceStatus::Active, true),
        (WorkspaceStatus::Suspended, true),
        (WorkspaceStatus::PendingDeletion, false),
        (WorkspaceStatus::Deleted, false),
    ] {
        let repo = InMemoryWorkspaces::new();
        seed_workspace(&repo, "w1", status, 1);
        seed_member(&repo, "w1", "u1", OWNER, true);
        let outcome = remove_all(&repo, T, "u1").await;
        if blocks {
            assert_eq!(
                outcome,
                Some(RemoveAllOutcome::LastOwner(vec!["w1".into()]))
            );
            assert!(repo.membership(who("w1", "u1")).is_some(), "{status:?}");
            assert!(repo.audit_events().is_empty());
        } else {
            assert!(
                matches!(outcome, Some(RemoveAllOutcome::Removed(_))),
                "{status:?}"
            );
            assert_eq!(repo.membership(who("w1", "u1")), None);
        }
    }
}

fn account_with_memberships() -> InMemoryWorkspaces {
    let repo = InMemoryWorkspaces::new();
    seed_workspace(&repo, "wb", WorkspaceStatus::Active, 1);
    seed_workspace(&repo, "wa", WorkspaceStatus::Suspended, 2);
    seed_workspace(&repo, "wc", WorkspaceStatus::Active, 3);
    seed_member(&repo, "wb", "u1", "member", true);
    seed_member(&repo, "wa", "u1", "admin", false);
    // Co-owned, so it does not block.
    seed_member(&repo, "wc", "u1", OWNER, true);
    seed_member(&repo, "wc", "u2", OWNER, true);
    // A suspended owner does not make the active one a co-owner.
    seed_member(&repo, "wb", "u3", OWNER, false);
    seed_member(&repo, "wb", "u9", "member", true);
    // The same user id under another tenant is another account.
    repo.seed_membership(Membership {
        tenant_id: "t2".into(),
        workspace_id: "wb".into(),
        user_id: "u1".into(),
        role: OWNER.into(),
        status: MembershipStatus::Active,
        invited_by_user_id: None,
        created_at: instant(1),
        updated_at: instant(1),
    });
    repo
}

#[tokio::test]
async fn an_account_removal_reports_every_membership_in_the_tenant_by_workspace() {
    let repo = account_with_memberships();
    let outcome = remove_all(&repo, T, "u1").await;
    assert_eq!(
        outcome,
        Some(RemoveAllOutcome::Removed(vec![
            RemovedMembership {
                workspace_id: "wa".into(),
                role: "admin".into()
            },
            RemovedMembership {
                workspace_id: "wb".into(),
                role: "member".into()
            },
            RemovedMembership {
                workspace_id: "wc".into(),
                role: OWNER.into()
            },
        ]))
    );
}

#[tokio::test]
async fn an_account_removal_audits_each_membership_and_leaves_others_alone() {
    let repo = account_with_memberships();
    let outcome = remove_all(&repo, T, "u1").await;
    assert!(matches!(outcome, Some(RemoveAllOutcome::Removed(_))));
    let events = repo.audit_events();
    let named: Vec<(&str, &str)> = events
        .iter()
        .map(|e| (e.workspace_id.as_str(), e.kind.type_name()))
        .collect();
    assert_eq!(
        named,
        [
            ("wa", "member.removed"),
            ("wb", "member.removed"),
            ("wc", "member.removed")
        ]
    );
    assert!(events.iter().all(|e| e.tenant_id == T
        && e.actor_user_id.as_deref() == Some("admin")
        && e.at == "2026-02-02T00:00:00Z"
        && e.kind
            == AuditKind::MemberRemoved {
                user_id: "u1".into()
            }));
    assert!(repo.membership(who("wc", "u2")).is_some());
    let other = MembershipRef {
        tenant_id: "t2",
        workspace_id: "wb",
        user_id: "u1",
    };
    assert!(repo.membership(other).is_some());
    // Nothing left to remove the second time.
    assert_eq!(
        remove_all(&repo, T, "u1").await,
        Some(RemoveAllOutcome::Removed(vec![]))
    );
}

async fn transfer(
    repo: &InMemoryWorkspaces,
    workspace: &str,
    from: &str,
    to: &str,
    demote: Option<&str>,
) -> Option<TransferOutcome> {
    let audit = event(
        workspace,
        AuditKind::OwnershipTransferred {
            from_user_id: from.into(),
            to_user_id: to.into(),
        },
    );
    repo.transfer_ownership(TransferOwnership {
        workspace: ws(workspace),
        from_user_id: from,
        to_user_id: to,
        owner_role: OWNER,
        demote_from_to: demote,
        audit: &audit,
    })
    .await
    .ok()
}

fn role_of(repo: &InMemoryWorkspaces, user: &str) -> Option<String> {
    repo.membership(who("w1", user)).map(|m| m.role)
}

async fn transfer_workspace() -> InMemoryWorkspaces {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    seed_member(&repo, "w1", "u3", "member", false);
    seed_member(&repo, "w1", "u4", OWNER, false);
    repo
}

#[tokio::test]
async fn a_transfer_from_a_non_owner_or_to_a_non_member_writes_nothing() {
    let repo = transfer_workspace().await;
    let before = repo.audit_events().len();
    let cases = [
        ("w9", "u1", "u2", TransferOutcome::NotFound),
        ("w1", "u2", "u1", TransferOutcome::NotFound),
        ("w1", "zz", "u2", TransferOutcome::NotFound),
        // A suspended owner cannot hand over.
        ("w1", "u4", "u2", TransferOutcome::NotFound),
        ("w1", "u1", "zz", TransferOutcome::TargetNotMember),
        ("w1", "u1", "u3", TransferOutcome::TargetNotMember),
    ];
    for (workspace, from, to, outcome) in cases {
        assert_eq!(
            transfer(&repo, workspace, from, to, None).await,
            Some(outcome)
        );
    }
    assert_eq!(repo.audit_events().len(), before);
}

#[tokio::test]
async fn ownership_moves_between_active_members_and_the_previous_owner_may_step_down() {
    let repo = transfer_workspace().await;
    let before = repo.audit_events().len();
    let done = Some(TransferOutcome::Done);
    assert_eq!(transfer(&repo, "w1", "u1", "u2", None).await, done);
    assert_eq!(role_of(&repo, "u1").as_deref(), Some(OWNER));
    assert_eq!(role_of(&repo, "u2").as_deref(), Some(OWNER));
    assert_eq!(transfer(&repo, "w1", "u1", "u2", Some("admin")).await, done);
    assert_eq!(role_of(&repo, "u1").as_deref(), Some("admin"));
    assert_eq!(repo.audit_events().len(), before + 2);
    // Handing ownership to oneself leaves the owner an owner.
    assert_eq!(transfer(&repo, "w1", "u2", "u2", Some("admin")).await, done);
    assert_eq!(role_of(&repo, "u2").as_deref(), Some(OWNER));
}

#[tokio::test]
async fn listings_are_scoped_ordered_and_paged_by_an_opaque_cursor() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "wa", "u1", 0).await);
    assert!(create(&repo, "wb", "u1", 0).await);
    assert!(create(&repo, "wc", "u1", 0).await);
    seed_workspace(&repo, "wd", WorkspaceStatus::PendingDeletion, 50);
    seed_member(&repo, "wd", "u1", OWNER, true);
    assert!(create(&repo, "we", "u2", 0).await);
    add(&repo, "we", "u1", "member").await;
    seed_workspace(&repo, "wf", WorkspaceStatus::Active, 60);
    seed_member(&repo, "wf", "u1", "member", false);
    let page = |cursor: Option<String>, limit| {
        let repo = &repo;
        async move {
            repo.list_for_user(ListForUser {
                tenant_id: T,
                user_id: "u1",
                cursor: cursor.as_deref(),
                limit,
            })
            .await
            .ok()
        }
    };
    let first = page(None, 2).await;
    let ids = |p: &Option<crate::workspace::domain::Page<_>>| -> Vec<String> {
        p.as_ref()
            .map(
                |p: &crate::workspace::domain::Page<
                    crate::workspace::domain::MembershipWithWorkspace,
                >| { p.items.iter().map(|i| i.workspace.id.clone()).collect() },
            )
            .unwrap_or_default()
    };
    assert_eq!(ids(&first), ["wa", "wb"]);
    let cursor = first.and_then(|p| p.next_cursor);
    assert!(cursor.is_some());
    let second = page(cursor, 2).await;
    assert_eq!(ids(&second), ["wc", "we"]);
    assert_eq!(second.and_then(|p| p.next_cursor), None);
    // A malformed cursor restarts at the first page; a limit of zero still returns one row.
    assert_eq!(
        ids(&page(Some("garbage".to_owned()), 2).await),
        ["wa", "wb"]
    );
    assert_eq!(ids(&page(None, 0).await), ["wa"]);
    assert_eq!(ids(&page(None, 100).await).len(), 4);
}

async fn member_ids(repo: &InMemoryWorkspaces, workspace: WorkspaceRef<'_>) -> Vec<String> {
    let page = repo
        .list_for_workspace(ListForWorkspace {
            workspace,
            cursor: None,
            limit: 10,
        })
        .await
        .ok();
    page.map(|p| p.items.into_iter().map(|m| m.user_id).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_workspace_listing_shows_every_status_and_only_its_own_tenant() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    seed_member(&repo, "w1", "u3", "member", false);
    assert_eq!(member_ids(&repo, ws("w1")).await, ["u1", "u2", "u3"]);
    let foreign = WorkspaceRef {
        tenant_id: "t2",
        workspace_id: "w1",
    };
    assert!(member_ids(&repo, foreign).await.is_empty());
}

#[tokio::test]
async fn the_sole_owned_listing_names_only_live_workspaces_the_member_alone_owns() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    assert!(create(&repo, "w2", "u1", 0).await);
    seed_workspace(&repo, "w3", WorkspaceStatus::Deleted, 70);
    seed_member(&repo, "w3", "u1", OWNER, true);
    // w1 gains a second owner and stops being sole-owned.
    add(&repo, "w1", "u4", OWNER).await;
    let page = repo
        .list_sole_owned(ListSoleOwned {
            owner: OwnedBy {
                tenant_id: T,
                user_id: "u1",
                owner_role: OWNER,
            },
            cursor: None,
            limit: 10,
        })
        .await
        .ok();
    let ids: Vec<String> = page
        .map(|p| p.items.into_iter().map(|w| w.id).collect())
        .unwrap_or_default();
    assert_eq!(ids, ["w2"]);
}

#[tokio::test]
async fn the_last_active_workspace_is_remembered_per_tenant_and_member() {
    let repo = InMemoryWorkspaces::new();
    assert_eq!(
        repo.last_active_workspace_id(T, "u1").await.ok(),
        Some(None)
    );
    assert!(
        repo.set_last_active_workspace_id(T, "u1", "w1")
            .await
            .is_ok()
    );
    assert_eq!(
        repo.last_active_workspace_id(T, "u1").await.ok(),
        Some(Some("w1".to_owned()))
    );
    assert_eq!(
        repo.last_active_workspace_id("t2", "u1").await.ok(),
        Some(None)
    );
    assert_eq!(
        repo.last_active_workspace_id(T, "u2").await.ok(),
        Some(None)
    );
}

#[test]
fn only_a_cursor_in_the_shape_this_double_issues_is_followed() {
    let issued = super::workspace::sort_key(instant(7), "w1");
    assert!(super::workspace::well_formed(&issued));
    assert!(super::workspace::well_formed("00000000000000000007:"));
    assert!(!super::workspace::well_formed(""));
    assert!(!super::workspace::well_formed("0000000000000000000"));
    assert!(!super::workspace::well_formed("0000000000000000000x:w1"));
    assert!(!super::workspace::well_formed("00000000000000000007x"));
    assert!(!super::workspace::well_formed("000000000000000000070:w1"));
}
