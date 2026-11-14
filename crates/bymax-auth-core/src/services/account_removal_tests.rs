//! The account-removal service and the host-facing counter bump: every blocking vector of the
//! shared contract, a refusal that writes nothing, the statuses that never block, the audit events
//! and the instant they share, the atomic re-decision, the bumps attempted one by one, the hook
//! after the commit, and tenant isolation (layer: service, tests).

use bymax_auth_types::{AuthError, AuthErrorCode, BlockingWorkspace};
use serde_json::json;

use super::account_removal::{
    AccountRemoval, AccountRemovalError, BLOCKING_WORKSPACES_MAX, RemovalAuthority,
    RemovedMemberships,
};
use super::workspace_support_tests::{
    Fixture, active, build, config, contract, membership, workspace,
};
use crate::services::auth::test_support::ctx;
use crate::traits::membership_repository::RemovedMembership;
use crate::workspace::audit::AuditKind;
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, WorkspaceRef, WorkspaceStatus,
};
use crate::workspace::keys::membership_version_id;
use crate::workspace::membership_cache::VersionCounter;

/// One workspace of the account `u`: the workspace's status, the role `u` holds, the status of
/// that membership, and whether another active owner shares the workspace.
struct Place {
    id: String,
    status: WorkspaceStatus,
    role: &'static str,
    seat: MembershipStatus,
    co_owner: bool,
}

/// `u` holding `role` in the active, solely owned workspace `id`.
fn place(id: &str, status: WorkspaceStatus, role: &'static str) -> Place {
    Place {
        id: id.to_owned(),
        status,
        role,
        seat: MembershipStatus::Active,
        co_owner: false,
    }
}

/// Seeds `places` in tenant `t1` and the same rows, the same user included, in the tenant `t2`.
fn seeded(places: &[Place]) -> Option<Fixture> {
    let f = build(config())?;
    for tenant in ["t1", "t2"] {
        for (index, place) in (0_i64..).zip(places) {
            let tick = index * 3 + 1;
            let ws = workspace(tenant, &place.id, place.status, tick);
            f.repo.seed_workspace(ws);
            let mut seat = active(tenant, &place.id, "u", place.role);
            seat.status = place.seat;
            f.repo.seed_membership(membership(&seat, tick + 1));
            if place.co_owner {
                let co = active(tenant, &place.id, "o2", "owner");
                f.repo.seed_membership(membership(&co, tick + 2));
            }
        }
    }
    Some(f)
}

/// The membership of `user` in `workspace` of `tenant`, as stored.
fn stored(f: &Fixture, tenant: &str, workspace: &str, user: &str) -> Option<Membership> {
    f.repo.membership(MembershipRef {
        tenant_id: tenant,
        workspace_id: workspace,
        user_id: user,
    })
}

/// Removes every membership of `u` in `t1` on `authority`.
async fn remove(
    f: &Fixture,
    authority: RemovalAuthority<'_>,
) -> Result<RemovedMemberships, AccountRemovalError> {
    let removal = AccountRemoval {
        tenant_id: "t1",
        user_id: "u",
        authority,
    };
    f.engine
        .remove_workspace_memberships_for_user(removal, &ctx())
        .await
}

fn removed(workspace_id: &str, role: &str) -> RemovedMembership {
    RemovedMembership {
        workspace_id: workspace_id.to_owned(),
        role: role.to_owned(),
    }
}

/// Whether the membership counter of `u` in `workspace` of `t1` exists, which means it was bumped.
fn bumped(f: &Fixture, workspace: &str) -> bool {
    let key = f.engine.config().hmac_key();
    membership_version_id(key, "t1", workspace, "u").is_ok_and(|id| {
        f.cache
            .counter_ttl(VersionCounter::Membership, &id)
            .is_some()
    })
}

fn status_named(name: &str) -> Option<WorkspaceStatus> {
    [
        WorkspaceStatus::Active,
        WorkspaceStatus::PendingDeletion,
        WorkspaceStatus::Suspended,
        WorkspaceStatus::Deleted,
    ]
    .into_iter()
    .find(|status| status.as_str() == name)
}

#[tokio::test]
async fn every_blocking_vector_of_the_contract_decides_the_removal() {
    let vectors = contract()["workspaceAccountRemoval"]["blockingVectors"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!vectors.is_empty(), "the contract's vectors did not load");
    let mut sole_statuses = Vec::new();
    for vector in &vectors {
        let status = status_named(vector["workspaceStatus"].as_str().unwrap_or_default());
        assert!(status.is_some(), "an unknown status in {vector}");
        let Some(status) = status else { continue };
        let sole = vector["accountIsSoleOwner"].as_bool().unwrap_or(false);
        let blocks = vector["blocks"].as_bool().unwrap_or(false);
        let mut held = place("w1", status, "owner");
        held.co_owner = !sole;
        let Some(f) = seeded(&[held]) else { return };
        let outcome = remove(&f, RemovalAuthority::Account).await;
        let refused = matches!(outcome, Err(AccountRemovalError::Blocked { .. }));
        assert_eq!(refused, blocks, "{vector}: {outcome:?}");
        assert_eq!(outcome.is_ok(), !blocks, "{vector}: {outcome:?}");
        assert_eq!(stored(&f, "t1", "w1", "u").is_none(), !blocks, "{vector}");
        if sole {
            sole_statuses.push(status);
        }
    }
    // Every status of a workspace is covered by a sole-owner vector.
    assert_eq!(sole_statuses.len(), 4);
}

#[tokio::test]
async fn a_refusal_names_the_blockers_as_a_409_and_writes_nothing() {
    let places = [
        place("w1", WorkspaceStatus::Active, "owner"),
        place("w2", WorkspaceStatus::Active, "member"),
        place("w3", WorkspaceStatus::Suspended, "owner"),
        place("w4", WorkspaceStatus::PendingDeletion, "owner"),
    ];
    let Some(f) = seeded(&places) else { return };
    let outcome = remove(&f, RemovalAuthority::Account).await;
    let Err(error) = outcome else {
        assert!(outcome.is_err(), "removed despite the blockers");
        return;
    };
    let wire = AuthError::from(error);
    assert_eq!(wire.http_status(), 409);
    let body = wire.to_envelope().error;
    assert_eq!(body.code, AuthErrorCode::LastOwner);
    let named =
        |id: &str, name: &str, status: &str| json!({ "id": id, "name": name, "status": status });
    let expected = json!({
        "workspaces": [named("w1", "Workspace w1", "active"), named("w3", "Workspace w3", "suspended")]
    });
    assert_eq!(body.details, Some(expected));
    for place in &places {
        assert!(stored(&f, "t1", &place.id, "u").is_some(), "{}", place.id);
    }
    assert!(f.repo.audit_events().is_empty());
    assert!(f.cache.operations().is_empty());
    assert!(f.hooks.events(1).await.is_empty());
}

#[tokio::test]
async fn a_workspace_pending_deletion_or_deleted_never_blocks_and_every_membership_goes() {
    let mut suspended_seat = place("w3", WorkspaceStatus::Suspended, "admin");
    suspended_seat.seat = MembershipStatus::Suspended;
    suspended_seat.co_owner = true;
    let mut hidden = place("w4", WorkspaceStatus::Active, "member");
    hidden.seat = MembershipStatus::Suspended;
    let places = [
        place("w1", WorkspaceStatus::PendingDeletion, "owner"),
        place("w2", WorkspaceStatus::Deleted, "owner"),
        suspended_seat,
        hidden,
    ];
    let Some(f) = seeded(&places) else { return };
    let done = remove(&f, RemovalAuthority::Account).await;
    let expected = [
        removed("w1", "owner"),
        removed("w2", "owner"),
        removed("w3", "admin"),
        removed("w4", "member"),
    ];
    assert_eq!(done.map(|d| d.memberships).ok(), Some(expected.to_vec()));
    for place in &places {
        assert!(stored(&f, "t1", &place.id, "u").is_none(), "{}", place.id);
        // The same user id in the other tenant is a different account.
        assert!(stored(&f, "t2", &place.id, "u").is_some(), "{}", place.id);
        assert!(bumped(&f, &place.id), "{}", place.id);
    }
    assert!(f.repo.audit_events().iter().all(|e| e.tenant_id == "t1"));
    // The workspace pending deletion keeps no owner: its other members are untouched.
    assert!(stored(&f, "t1", "w3", "o2").is_some());
}

#[tokio::test]
async fn one_instant_and_one_event_per_removal_carry_the_authority_to_the_store_and_the_hook() {
    let authorities = [
        (RemovalAuthority::Account, Some("u")),
        (RemovalAuthority::Administrator("admin-1"), Some("admin-1")),
        (RemovalAuthority::Job, None),
    ];
    for (authority, actor) in authorities {
        let places = [
            place("w1", WorkspaceStatus::PendingDeletion, "owner"),
            place("w2", WorkspaceStatus::Active, "member"),
        ];
        let Some(f) = seeded(&places) else { return };
        let done = remove(&f, authority).await;
        let at = done.map(|d| d.at).unwrap_or_default();
        assert_eq!(at.len(), 24, "{at}");
        assert!(at.ends_with('Z'), "{at}");
        let events = f.repo.audit_events();
        let seen: Vec<(String, String, Option<String>, String)> = events
            .iter()
            .map(|e| {
                let user = match &e.kind {
                    AuditKind::MemberRemoved { user_id } => user_id.clone(),
                    other => format!("{other:?}"),
                };
                (
                    e.workspace_id.clone(),
                    user,
                    e.actor_user_id.clone(),
                    e.at.clone(),
                )
            })
            .collect();
        let actor = actor.map(str::to_owned);
        let expect = |ws: &str| (ws.to_owned(), "u".to_owned(), actor.clone(), at.clone());
        assert_eq!(seen, [expect("w1"), expect("w2")]);
        // The hook is told the same events, after the commit.
        let mut reported = f.hooks.events(2).await;
        reported.sort_by(|a, b| a.workspace_id.cmp(&b.workspace_id));
        assert_eq!(reported, events);
        let contexts = f.hooks.contexts();
        assert!(
            contexts
                .iter()
                .all(|c| c.tenant_id.as_deref() == Some("t1"))
        );
        assert!(contexts.iter().all(|c| c.user_id == actor));
    }
}

#[tokio::test]
async fn a_workspace_that_became_solely_owned_after_the_read_refuses_with_its_id_alone() {
    let places = [
        place("w1", WorkspaceStatus::Active, "owner"),
        place("w2", WorkspaceStatus::Active, "member"),
    ];
    let Some(f) = seeded(&places) else { return };
    // The read before the write saw nothing: the repository decides again with the write.
    f.repo.set_sole_owned_reads_stale(true);
    let outcome = remove(&f, RemovalAuthority::Account).await;
    let Err(error) = outcome else {
        assert!(outcome.is_err(), "removed an account that solely owns w1");
        return;
    };
    let wire = AuthError::from(error);
    assert_eq!(wire.http_status(), 409);
    assert_eq!(
        wire.details(),
        Some(json!({ "workspaces": [{ "id": "w1" }] }))
    );
    assert!(stored(&f, "t1", "w1", "u").is_some());
    assert!(stored(&f, "t1", "w2", "u").is_some());
    assert!(f.repo.audit_events().is_empty());
    assert!(f.cache.operations().is_empty());
}

#[tokio::test]
async fn a_refusal_names_at_most_the_number_of_workspaces_the_contract_allows() {
    let rule = contract()["workspaceAccountRemoval"]["rules"]["blocking"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        rule.contains(&format!("(at most {BLOCKING_WORKSPACES_MAX})")),
        "{rule}"
    );
    let places: Vec<Place> = (0..=BLOCKING_WORKSPACES_MAX)
        .map(|n| place(&format!("w{n:03}"), WorkspaceStatus::Active, "owner"))
        .collect();
    let Some(f) = seeded(&places) else { return };
    let outcome = remove(&f, RemovalAuthority::Account).await;
    let named: Vec<BlockingWorkspace> = match outcome {
        Err(AccountRemovalError::Blocked { workspaces }) => workspaces,
        _ => Vec::new(),
    };
    assert_eq!(named.len(), BLOCKING_WORKSPACES_MAX);
    assert!(named.iter().all(|w| w.name.is_some() && w.status.is_some()));
    assert!(f.repo.audit_events().is_empty());
}

#[test]
fn the_route_error_of_a_removal_is_the_409_for_a_refusal_and_the_opaque_error_for_the_rest() {
    let blocker = BlockingWorkspace {
        id: "w1".to_owned(),
        name: Some("One".to_owned()),
        status: Some("active".to_owned()),
    };
    let refused = AuthError::from(AccountRemovalError::Blocked {
        workspaces: vec![blocker.clone()],
    });
    assert!(matches!(&refused, AuthError::LastOwnerWithDetails(w) if *w == [blocker]));
    let bumps = AuthError::from(AccountRemovalError::BumpsFailed {
        removed: vec![removed("w1", "owner")],
        failed: vec!["w1".to_owned()],
    });
    assert_eq!(bumps.code(), AuthErrorCode::Internal);
    let other = AuthError::from(AccountRemovalError::Failed(AuthError::WorkspaceNotFound));
    assert!(matches!(other, AuthError::WorkspaceNotFound));
}

/// The blockers a refusal named, by id, and how many pages of the sole-owned read it took.
async fn refusal_and_reads(places: &[Place]) -> Option<(Vec<String>, usize)> {
    let f = seeded(places)?;
    let outcome = remove(&f, RemovalAuthority::Account).await;
    let ids = match outcome {
        Err(AccountRemovalError::Blocked { workspaces }) => {
            workspaces.into_iter().map(|w| w.id).collect()
        }
        _ => Vec::new(),
    };
    Some((ids, f.repo.sole_owned_reads()))
}

#[tokio::test]
async fn a_blocker_on_a_later_page_is_named_after_pages_that_hold_none() {
    // A page holds 100 workspaces, ordered by creation: the first page blocks nothing.
    let mut places: Vec<Place> = (0..101)
        .map(|n| {
            place(
                &format!("p{n:03}"),
                WorkspaceStatus::PendingDeletion,
                "owner",
            )
        })
        .collect();
    places.push(place("w-late", WorkspaceStatus::Active, "owner"));
    let Some((ids, reads)) = refusal_and_reads(&places).await else {
        return;
    };
    assert_eq!(ids, vec!["w-late".to_owned()]);
    assert_eq!(reads, 2);
}

#[tokio::test]
async fn a_single_page_of_workspaces_is_read_once() {
    let places = [place("w1", WorkspaceStatus::Active, "owner")];
    let Some((ids, reads)) = refusal_and_reads(&places).await else {
        return;
    };
    assert_eq!(ids, vec!["w1".to_owned()]);
    assert_eq!(reads, 1);
}

#[tokio::test]
async fn the_read_stops_paging_once_it_holds_the_cap_of_blockers() {
    let places: Vec<Place> = (0..BLOCKING_WORKSPACES_MAX * 2 + 50)
        .map(|n| place(&format!("w{n:03}"), WorkspaceStatus::Active, "owner"))
        .collect();
    let Some((ids, reads)) = refusal_and_reads(&places).await else {
        return;
    };
    assert_eq!(ids.len(), BLOCKING_WORKSPACES_MAX);
    assert_eq!(reads, 1);
}

#[tokio::test]
async fn every_bump_is_attempted_and_the_failure_carries_what_was_removed_and_what_failed() {
    let places = [
        place("w1", WorkspaceStatus::Active, "member"),
        place("w2", WorkspaceStatus::Active, "admin"),
        place("w3", WorkspaceStatus::PendingDeletion, "owner"),
    ];
    let Some(f) = seeded(&places) else { return };
    // The second bump the store receives is w2's.
    f.cache.fail_membership_bump(2);
    let outcome = remove(&f, RemovalAuthority::Account).await;
    let carried = match outcome {
        Err(AccountRemovalError::BumpsFailed { removed, failed }) => Some((removed, failed)),
        _ => None,
    };
    let all = vec![
        removed("w1", "member"),
        removed("w2", "admin"),
        removed("w3", "owner"),
    ];
    assert_eq!(carried, Some((all, vec!["w2".to_owned()])));
    assert_eq!(f.cache.operations(), ["bump_membership"; 3]);
    assert!(bumped(&f, "w1") && !bumped(&f, "w2") && bumped(&f, "w3"));
    // The removal is committed and reported; repeating it finds nothing to remove.
    assert!(stored(&f, "t1", "w2", "u").is_none());
    assert_eq!(f.hooks.events(3).await.len(), 3);
    let again = remove(&f, RemovalAuthority::Account).await;
    assert_eq!(again.map(|d| d.memberships).ok(), Some(Vec::new()));
}

#[tokio::test]
async fn a_failing_hook_changes_nothing_about_the_result() {
    let places = [place("w1", WorkspaceStatus::Active, "member")];
    let Some(f) = seeded(&places) else { return };
    f.hooks.fail_events();
    let done = remove(&f, RemovalAuthority::Account).await;
    assert_eq!(
        done.map(|d| d.memberships).ok(),
        Some(vec![removed("w1", "member")])
    );
    assert_eq!(f.hooks.events(1).await.len(), 1);
    assert!(stored(&f, "t1", "w1", "u").is_none());
    assert!(bumped(&f, "w1"));
}

#[tokio::test]
async fn a_blank_identifier_is_refused_before_anything_is_read() {
    let Some(f) = seeded(&[place("w1", WorkspaceStatus::Active, "member")]) else { return };
    let cases = [
        ("tenantId", " ", "u", RemovalAuthority::Account),
        ("userId", "t1", "", RemovalAuthority::Account),
        (
            "actorUserId",
            "t1",
            "u",
            RemovalAuthority::Administrator("  "),
        ),
    ];
    for (field, tenant_id, user_id, authority) in cases {
        let removal = AccountRemoval {
            tenant_id,
            user_id,
            authority,
        };
        let refused = f
            .engine
            .remove_workspace_memberships_for_user(removal, &ctx())
            .await;
        let named = match refused {
            Err(AccountRemovalError::Failed(AuthError::Validation { details })) => {
                details.first().map(|d| d.field.clone())
            }
            _ => None,
        };
        assert_eq!(named.as_deref(), Some(field));
    }
    assert!(stored(&f, "t1", "w1", "u").is_some());
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn a_membership_is_invalidated_by_hand_and_a_blank_identifier_is_refused() {
    let Some(f) = seeded(&[place("w1", WorkspaceStatus::Active, "member")]) else { return };
    let key = |tenant_id, workspace_id, user_id| MembershipRef {
        tenant_id,
        workspace_id,
        user_id,
    };
    for (field, member) in [
        ("tenantId", key("", "w1", "u")),
        ("workspaceId", key("t1", " ", "u")),
        ("userId", key("t1", "w1", "\t")),
    ] {
        let refused = f.engine.invalidate_membership(member).await;
        let named = match refused {
            Err(AuthError::Validation { details }) => details.first().map(|d| d.field.clone()),
            _ => None,
        };
        assert_eq!(named.as_deref(), Some(field));
    }
    assert!(f.cache.operations().is_empty());
    assert!(!bumped(&f, "w1"));
    assert!(
        f.engine
            .invalidate_membership(key("t1", "w1", "u"))
            .await
            .is_ok()
    );
    assert_eq!(f.cache.operations(), ["bump_membership"]);
    assert!(bumped(&f, "w1"));
    // Only that membership moved.
    let other = WorkspaceRef {
        tenant_id: "t2",
        workspace_id: "w1",
    };
    assert!(stored(&f, other.tenant_id, other.workspace_id, "u").is_some());
}

#[test]
fn every_rule_of_the_section_is_read_and_each_one_is_covered_here() {
    let section = contract()["workspaceAccountRemoval"].clone();
    let rules = section["rules"].as_object().cloned().unwrap_or_default();
    let named: std::collections::BTreeSet<&str> = rules.keys().map(String::as_str).collect();
    let covered = [
        "scope",
        "blocking",
        "pendingDeletion",
        "atomicity",
        "audit",
        "cache",
    ];
    assert_eq!(named, covered.into_iter().collect());
    // Each rule's load-bearing phrase, read from the contract and checked against what the
    // tests above exercise.
    let says = |rule: &str, phrase: &str| {
        let text = rules[rule].as_str().unwrap_or_default();
        assert!(text.contains(phrase), "{rule} no longer says {phrase:?}");
    };
    says("scope", "every membership status");
    says("blocking", "409 auth.last_owner");
    says("blocking", "`{id}` alone");
    says("pendingDeletion", "never blocks");
    says("atomicity", "re-decides the blocking rule inside it");
    says("audit", "one ISO-8601 UTC instant for the whole call");
    says("audit", "detached and best-effort");
    says("cache", "Every bump is attempted even when one fails");
    says("cache", "the full removed list and the failed list");
}
