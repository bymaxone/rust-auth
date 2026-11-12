//! The in-memory workspace repositories against the rules a host's implementation is held to:
//! tenant restriction, atomic ownership rules, compare-and-set on change, and no audit row for a
//! refused write (layer: test double, tests).

use time::{Duration, OffsetDateTime};

use super::InMemoryWorkspaces;
use crate::RepositoryError;
use crate::traits::membership_repository::{CreateMembership, CreateMembershipOutcome, OwnedBy};
use crate::traits::workspace_repository::{
    CreateWorkspaceOutcome, CreateWorkspaceWithOwner, RenameOutcome, RenameWorkspace,
    UpdateStatusOutcome, UpdateWorkspaceStatus,
};
use crate::traits::{MembershipRepository, WorkspaceRepository};
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent};
use crate::workspace::domain::{
    ActingMember, Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceRef,
    WorkspaceStatus,
};

pub(super) const T: &str = "t1";
pub(super) const OWNER: &str = "owner";

pub(super) fn ws(id: &str) -> WorkspaceRef<'_> {
    WorkspaceRef {
        tenant_id: T,
        workspace_id: id,
    }
}

pub(super) fn who<'a>(workspace: &'a str, user: &'a str) -> MembershipRef<'a> {
    MembershipRef {
        tenant_id: T,
        workspace_id: workspace,
        user_id: user,
    }
}

pub(super) fn event(workspace: &str, kind: AuditKind) -> WorkspaceAuditEvent {
    WorkspaceAuditEvent {
        tenant_id: T.to_owned(),
        workspace_id: workspace.to_owned(),
        actor_user_id: None,
        at: "2026-01-01T00:00:00Z".to_owned(),
        kind,
    }
}

pub(super) fn instant(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds)
}

pub(super) async fn create(repo: &InMemoryWorkspaces, id: &str, user: &str, cap: u32) -> bool {
    let audit = event(id, AuditKind::WorkspaceCreated);
    let outcome = repo
        .create_with_owner(CreateWorkspaceWithOwner {
            workspace: ws(id),
            name: "Name",
            owner_user_id: user,
            owner_role: OWNER,
            max_workspaces_per_user: cap,
            audit: &audit,
        })
        .await;
    matches!(outcome, Ok(CreateWorkspaceOutcome::Created(_)))
}

pub(super) async fn add(repo: &InMemoryWorkspaces, id: &str, user: &str, role: &str) {
    let audit = event(
        id,
        AuditKind::MemberInvited {
            email: "e".into(),
            role: role.into(),
        },
    );
    let outcome = repo
        .create(CreateMembership {
            member: who(id, user),
            role,
            invited_by_user_id: Some("inviter"),
            audit: &audit,
        })
        .await;
    assert!(matches!(outcome, Ok(CreateMembershipOutcome::Done)));
}

pub(super) fn seed_member(
    repo: &InMemoryWorkspaces,
    id: &str,
    user: &str,
    role: &str,
    active: bool,
) {
    repo.seed_membership(Membership {
        tenant_id: T.into(),
        workspace_id: id.into(),
        user_id: user.into(),
        role: role.into(),
        status: if active {
            MembershipStatus::Active
        } else {
            MembershipStatus::Suspended
        },
        invited_by_user_id: None,
        created_at: instant(100),
        updated_at: instant(100),
    });
}

pub(super) fn seed_workspace(
    repo: &InMemoryWorkspaces,
    id: &str,
    status: WorkspaceStatus,
    created: i64,
) {
    repo.seed_workspace(Workspace {
        id: id.into(),
        tenant_id: T.into(),
        name: "Seeded".into(),
        status,
        created_at: instant(created),
        deletion_scheduled_at: None,
    });
}

#[tokio::test]
async fn a_creation_writes_the_workspace_the_owner_and_the_event_together() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    let found = repo.find_by_id(ws("w1")).await.ok().flatten();
    assert_eq!(
        found.as_ref().map(|w| w.status),
        Some(WorkspaceStatus::Active)
    );
    assert_eq!(found.as_ref().map(|w| w.name.as_str()), Some("Name"));
    let owner = repo.membership(who("w1", "u1"));
    assert_eq!(owner.as_ref().map(|m| m.role.as_str()), Some(OWNER));
    assert_eq!(owner.map(|m| m.invited_by_user_id), Some(None));
    assert_eq!(repo.audit_events().len(), 1);
    // The same id again conflicts and writes nothing.
    let audit = event("w1", AuditKind::WorkspaceCreated);
    let again = repo
        .create_with_owner(CreateWorkspaceWithOwner {
            workspace: ws("w1"),
            name: "Other",
            owner_user_id: "u2",
            owner_role: OWNER,
            max_workspaces_per_user: 0,
            audit: &audit,
        })
        .await;
    assert!(matches!(again, Err(RepositoryError::Conflict(_))));
    assert_eq!(repo.audit_events().len(), 1);
}

#[tokio::test]
async fn the_cap_refuses_at_the_count_and_counts_a_pending_deletion_but_not_a_deleted_one() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 2).await);
    // One owned, cap two: allowed.
    assert!(create(&repo, "w2", "u1", 2).await);
    // Two owned, cap two: refused, and nothing is written.
    let before = repo.audit_events().len();
    assert!(!create(&repo, "w3", "u1", 2).await);
    assert_eq!(repo.audit_events().len(), before);
    assert_eq!(repo.find_by_id(ws("w3")).await.ok().flatten(), None);
    // Another account is not bound by it, and zero means no limit.
    assert!(create(&repo, "w3", "u2", 2).await);
    assert!(create(&repo, "w4", "u1", 0).await);
    let owned = OwnedBy {
        tenant_id: T,
        user_id: "u1",
        owner_role: OWNER,
    };
    assert_eq!(repo.count_owned(owned).await.ok(), Some(3));
    seed_workspace(&repo, "w1", WorkspaceStatus::PendingDeletion, 1);
    assert_eq!(repo.count_owned(owned).await.ok(), Some(3));
    seed_workspace(&repo, "w1", WorkspaceStatus::Deleted, 1);
    assert_eq!(repo.count_owned(owned).await.ok(), Some(2));
}

#[tokio::test]
async fn a_workspace_is_found_only_under_its_own_tenant() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    let other = WorkspaceRef {
        tenant_id: "t2",
        workspace_id: "w1",
    };
    assert_eq!(repo.find_by_id(other).await.ok().flatten(), None);
    let foreign = MembershipRef {
        tenant_id: "t2",
        workspace_id: "w1",
        user_id: "u1",
    };
    assert_eq!(repo.find(foreign).await.ok().flatten(), None);
    assert!(repo.find(who("w1", "u1")).await.ok().flatten().is_some());
}

#[tokio::test]
async fn a_rename_needs_the_actor_to_still_hold_the_role_it_was_judged_against() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    seed_member(&repo, "w1", "u3", OWNER, false);
    let audit = event("w1", AuditKind::WorkspaceRenamed);
    let rename = |workspace: &'static str, user: &'static str, role: &'static str| {
        let audit = &audit;
        let repo = &repo;
        async move {
            repo.rename(RenameWorkspace {
                workspace: ws(workspace),
                name: "New",
                actor: ActingMember {
                    user_id: user,
                    expected_role: role,
                },
                audit,
            })
            .await
            .ok()
        }
    };
    let before = repo.audit_events().len();
    assert_eq!(
        rename("w1", "u2", OWNER).await,
        Some(RenameOutcome::ActorChanged)
    );
    assert_eq!(
        rename("w1", "u3", OWNER).await,
        Some(RenameOutcome::ActorChanged)
    );
    assert_eq!(
        rename("w1", "nobody", OWNER).await,
        Some(RenameOutcome::ActorChanged)
    );
    assert_eq!(
        rename("w9", "u1", OWNER).await,
        Some(RenameOutcome::NotFound)
    );
    assert_eq!(repo.audit_events().len(), before);
    assert_eq!(name_of(&repo).await.as_deref(), Some("Name"));
    assert_eq!(rename("w1", "u1", OWNER).await, Some(RenameOutcome::Done));
    assert_eq!(name_of(&repo).await.as_deref(), Some("New"));
    assert_eq!(repo.audit_events().len(), before + 1);
}

async fn name_of(repo: &InMemoryWorkspaces) -> Option<String> {
    repo.find_by_id(ws("w1"))
        .await
        .ok()
        .flatten()
        .map(|w| w.name)
}

type Instant = Option<OffsetDateTime>;

struct Move {
    workspace: &'static str,
    actor: Option<ActingMember<'static>>,
    to: (WorkspaceStatus, Instant),
    expected: (WorkspaceStatus, Option<Instant>),
}

async fn mv(repo: &InMemoryWorkspaces, call: Move) -> Option<UpdateStatusOutcome> {
    let audit = event(call.workspace, AuditKind::WorkspaceDeletionScheduled);
    repo.update_status(UpdateWorkspaceStatus {
        workspace: ws(call.workspace),
        actor: call.actor,
        status: call.to.0,
        expected_status: call.expected.0,
        expected_deletion_scheduled_at: call.expected.1,
        deletion_scheduled_at: call.to.1,
        audit: &audit,
    })
    .await
    .ok()
}

const OWNER_ACTOR: Option<ActingMember<'static>> = Some(ActingMember {
    user_id: "u1",
    expected_role: OWNER,
});
const ACTIVE: WorkspaceStatus = WorkspaceStatus::Active;
const PENDING: WorkspaceStatus = WorkspaceStatus::PendingDeletion;

async fn scheduled_workspace() -> InMemoryWorkspaces {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    repo
}

#[tokio::test]
async fn a_status_change_that_reads_a_stale_state_or_actor_writes_nothing() {
    let repo = scheduled_workspace().await;
    let before = repo.audit_events().len();
    let when = Some(instant(5000));
    let stale = Some(ActingMember {
        user_id: "u2",
        expected_role: OWNER,
    });
    let attempt = |workspace, actor, expected| Move {
        workspace,
        actor,
        to: (PENDING, when),
        expected,
    };
    let refused = [
        (
            attempt("w9", OWNER_ACTOR, (ACTIVE, None)),
            UpdateStatusOutcome::NotFound,
        ),
        (
            attempt("w1", stale, (ACTIVE, None)),
            UpdateStatusOutcome::ActorChanged,
        ),
        (
            attempt("w1", OWNER_ACTOR, (PENDING, None)),
            UpdateStatusOutcome::StatusConflict,
        ),
        // The stored instant is none, and the caller read one.
        (
            attempt("w1", OWNER_ACTOR, (ACTIVE, Some(when))),
            UpdateStatusOutcome::StatusConflict,
        ),
    ];
    for (call, outcome) in refused {
        assert_eq!(mv(&repo, call).await, Some(outcome));
    }
    assert_eq!(repo.audit_events().len(), before);
}

#[tokio::test]
async fn a_status_change_applies_while_the_status_and_the_compared_instant_still_match() {
    let repo = scheduled_workspace().await;
    let when = Some(instant(5000));
    let schedule = Move {
        workspace: "w1",
        actor: OWNER_ACTOR,
        to: (PENDING, when),
        expected: (ACTIVE, Some(None)),
    };
    assert_eq!(mv(&repo, schedule).await, Some(UpdateStatusOutcome::Done));
    let stored = repo.find_by_id(ws("w1")).await.ok().flatten();
    assert_eq!(stored.as_ref().map(|w| w.status), Some(PENDING));
    assert_eq!(stored.and_then(|w| w.deletion_scheduled_at), when);
    let restore = |expected| Move {
        workspace: "w1",
        actor: None,
        to: (ACTIVE, None),
        expected: (PENDING, expected),
    };
    // A different stored instant refuses; the same instant, or none compared, applies.
    let wrong = restore(Some(Some(instant(1))));
    assert_eq!(
        mv(&repo, wrong).await,
        Some(UpdateStatusOutcome::StatusConflict)
    );
    assert_eq!(
        mv(&repo, restore(Some(when))).await,
        Some(UpdateStatusOutcome::Done)
    );
    let restored = repo.find_by_id(ws("w1")).await.ok().flatten();
    assert_eq!(restored.map(|w| w.deletion_scheduled_at), Some(None));
    let again = Move {
        workspace: "w1",
        actor: None,
        to: (PENDING, when),
        expected: (ACTIVE, None),
    };
    assert_eq!(mv(&repo, again).await, Some(UpdateStatusOutcome::Done));
}

#[tokio::test]
async fn a_membership_is_added_once_under_an_existing_workspace() {
    let repo = InMemoryWorkspaces::new();
    assert!(create(&repo, "w1", "u1", 0).await);
    add(&repo, "w1", "u2", "member").await;
    let held = repo.membership(who("w1", "u2"));
    assert_eq!(
        held.as_ref().map(|m| m.status),
        Some(MembershipStatus::Active)
    );
    assert_eq!(
        held.and_then(|m| m.invited_by_user_id).as_deref(),
        Some("inviter")
    );
    seed_member(&repo, "w1", "u3", "member", false);
    let audit = event(
        "w1",
        AuditKind::WorkspaceSwitched {
            user_id: "x".into(),
        },
    );
    let create = |workspace: &'static str, user: &'static str| {
        let (repo, audit) = (&repo, &audit);
        async move {
            repo.create(CreateMembership {
                member: who(workspace, user),
                role: "member",
                invited_by_user_id: None,
                audit,
            })
            .await
            .ok()
        }
    };
    let before = repo.audit_events().len();
    assert_eq!(
        create("w1", "u2").await,
        Some(CreateMembershipOutcome::AlreadyMember)
    );
    assert_eq!(
        create("w1", "u3").await,
        Some(CreateMembershipOutcome::AlreadyMember)
    );
    assert_eq!(
        create("w9", "u4").await,
        Some(CreateMembershipOutcome::WorkspaceNotFound)
    );
    assert_eq!(repo.audit_events().len(), before);
}
