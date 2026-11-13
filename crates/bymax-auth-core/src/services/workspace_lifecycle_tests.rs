//! The workspace lifecycle services: creation and the path it shares with a bootstrap acceptance,
//! rename, scheduling and undoing a deletion, and finalizing it, with the audit event each write
//! persists and the counter each bumps (layer: service, tests).

use bymax_auth_types::AuthError;
use time::{Duration, OffsetDateTime};

use super::workspace_lifecycle::{FinalizeOutcome, OwnedWorkspace, WORKSPACE_CREATE_REFUSED};
use super::workspace_test_support::{
    Fixture, PASSWORD, acting_member, active, build, config, contract, membership, seed_account,
    workspace,
};
use crate::services::auth::test_support::ctx;
use crate::traits::{BeforeWorkspaceCreateResult, HookContext, HookPlane};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent};
use crate::workspace::domain::{MembershipRef, WorkspaceRef, WorkspaceStatus};

/// An engine over the default workspace configuration.
fn fixture() -> Option<Fixture> {
    build(config())
}

/// Whether `at` is one instant written as `toISOString` writes it.
fn is_iso_instant(at: &str) -> bool {
    let shape = at.len() == 24 && at.ends_with('Z') && at.as_bytes().get(10) == Some(&b'T');
    let parsed = OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).is_ok();
    shape && parsed
}

/// The single audit event persisted, after checking its tenant, workspace and instant.
fn only_event(f: &Fixture, tenant: &str, workspace: &str) -> Option<WorkspaceAuditEvent> {
    let events = f.repo.audit_events();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = events.into_iter().next()?;
    assert_eq!(event.tenant_id, tenant);
    assert_eq!(event.workspace_id, workspace);
    assert!(is_iso_instant(&event.at), "{}", event.at);
    Some(event)
}

/// The `workspaceName` bounds of the shared contract.
fn name_bounds() -> (usize, usize) {
    let bounds = &contract()["requestFieldBounds"]["workspaceName"];
    let read = |key: &str| {
        bounds[key]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0)
    };
    (read("min"), read("max"))
}

#[tokio::test]
async fn a_created_workspace_is_owned_by_the_caller_with_its_audit_event_and_hook_event() {
    let Some(f) = fixture() else { return };
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    let created = f
        .engine
        .create_workspace("t1", &owner, "  Acme  ", &ctx())
        .await;
    assert!(created.is_ok(), "create refused: {created:?}");
    let Ok(created) = created else { return };
    assert_eq!(created.name, "Acme");
    assert_eq!(created.status, WorkspaceStatus::Active);
    assert_eq!(created.id.len(), 36);
    let key = MembershipRef {
        tenant_id: "t1",
        workspace_id: &created.id,
        user_id: &owner,
    };
    assert_eq!(
        f.repo.membership(key).map(|m| m.role),
        Some("owner".to_owned())
    );
    let event = only_event(&f, "t1", &created.id);
    assert_eq!(
        event.as_ref().map(|e| e.kind.clone()),
        Some(AuditKind::WorkspaceCreated)
    );
    assert_eq!(
        event.as_ref().and_then(|e| e.actor_user_id.clone()),
        Some(owner.clone())
    );
    // The host is told after the write, with the same event and a dashboard context.
    let reported = f.hooks.events(1).await;
    assert_eq!(reported, f.repo.audit_events());
    let contexts = f.hooks.contexts();
    assert!(contexts.iter().all(|c| c.plane == HookPlane::Dashboard));
    assert_eq!(f.hooks.asked(), ["Acme"]);
    // A creation ends nobody's cached access, so it bumps nothing.
    assert!(f.cache.operations().is_empty());
}

#[tokio::test]
async fn the_name_bound_applies_as_submitted_and_the_stored_name_is_trimmed() {
    let Some(f) = fixture() else { return };
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    let (min, max) = name_bounds();
    assert_eq!(min, 1);
    let create = |name: String| {
        let engine = &f.engine;
        let owner = owner.clone();
        async move { engine.create_workspace("t1", &owner, &name, &ctx()).await }
    };
    for accepted in ["a".repeat(max), "\u{1f600}".repeat(max), "x".repeat(min)] {
        assert!(create(accepted.clone()).await.is_ok(), "{accepted}");
    }
    let padded = format!(" {}", "a".repeat(max));
    for refused in [
        "a".repeat(max + 1),
        padded,
        "\tAcme".to_owned(),
        "Ac\u{7f}me".to_owned(),
        "Ac\u{85}me".to_owned(),
        "   ".to_owned(),
        "\u{3000}\u{feff}".to_owned(),
        String::new(),
    ] {
        let answer = create(refused.clone()).await;
        assert!(
            matches!(&answer, Err(AuthError::Validation { details })
                if details.iter().all(|d| d.field == "name")),
            "{refused:?}: {answer:?}"
        );
    }
    assert_eq!(f.repo.audit_events().len(), 3);
}

#[tokio::test]
async fn creation_refuses_a_caller_whose_account_is_gone_and_a_closed_self_serve_switch() {
    let mut closed = config();
    closed.workspaces.allow_create = false;
    let Some(f) = build(closed) else { return };
    let gone = f
        .engine
        .create_workspace("t1", "nobody", "Acme", &ctx())
        .await;
    assert!(matches!(gone, Err(AuthError::TokenInvalid)));
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    // The name is judged before the switch.
    let bad = f.engine.create_workspace("t1", &owner, "\t", &ctx()).await;
    assert!(matches!(bad, Err(AuthError::Validation { .. })));
    let refused = f
        .engine
        .create_workspace("t1", &owner, "Acme", &ctx())
        .await;
    assert!(matches!(refused, Err(AuthError::Forbidden)));
    assert!(f.repo.audit_events().is_empty());
    assert!(f.hooks.asked().is_empty());
}

/// An engine whose owner cap is `cap`, with an account `o` in `t1`.
async fn capped(cap: u32) -> Option<(Fixture, String)> {
    let mut capped = config();
    capped.workspaces.max_workspaces_per_user = cap;
    let f = build(capped)?;
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    Some((f, owner))
}

#[tokio::test]
async fn the_owner_cap_counts_owned_workspaces_including_one_pending_deletion() {
    let Some((f, owner)) = capped(1).await else { return };
    // Owning a deleted workspace, or being a non-owner member, does not count.
    f.repo
        .seed_workspace(workspace("t1", "gone", WorkspaceStatus::Deleted, 1));
    f.repo
        .seed_membership(membership(&active("t1", "gone", &owner, "owner"), 1));
    f.repo
        .seed_workspace(workspace("t1", "other", WorkspaceStatus::Active, 2));
    f.repo
        .seed_membership(membership(&active("t1", "other", &owner, "admin"), 2));
    // A homonym in another tenant owns a workspace: it is another account.
    f.repo
        .seed_workspace(workspace("t2", "w-t2", WorkspaceStatus::Active, 3));
    f.repo
        .seed_membership(membership(&active("t2", "w-t2", &owner, "owner"), 3));
    assert!(
        f.engine
            .create_workspace("t1", &owner, "One", &ctx())
            .await
            .is_ok()
    );
    let Some((f, owner)) = capped(1).await else { return };
    f.repo.seed_workspace(workspace(
        "t1",
        "w-pending",
        WorkspaceStatus::PendingDeletion,
        1,
    ));
    f.repo
        .seed_membership(membership(&active("t1", "w-pending", &owner, "owner"), 1));
    // The cap is judged before the host's hook, which a refusal never reaches.
    f.hooks
        .decide(Ok(BeforeWorkspaceCreateResult::Reject { reason: None }));
    let refused = f.engine.create_workspace("t1", &owner, "Two", &ctx()).await;
    assert!(
        matches!(refused, Err(AuthError::WorkspaceLimitReached)),
        "{refused:?}"
    );
    assert!(f.hooks.asked().is_empty());
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn a_host_refusal_is_forbidden_naming_the_name_with_its_reason_or_the_contracts_message() {
    // The fixed message is the one `bootstrapCreate` quotes.
    let rule = contract()["workspaceInvitations"]["rules"]["bootstrapCreate"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        rule.contains(&format!("'{WORKSPACE_CREATE_REFUSED}'")),
        "{rule}"
    );
    let Some(f) = fixture() else { return };
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    let cases = [
        (
            Ok(BeforeWorkspaceCreateResult::Reject {
                reason: Some("No seats".into()),
            }),
            "No seats",
        ),
        (
            Ok(BeforeWorkspaceCreateResult::Reject { reason: None }),
            WORKSPACE_CREATE_REFUSED,
        ),
        (Err("plan says no"), WORKSPACE_CREATE_REFUSED),
    ];
    for (decision, message) in cases {
        f.hooks.decide(decision);
        let refused = f
            .engine
            .create_workspace("t1", &owner, "Acme", &ctx())
            .await;
        assert!(refused.is_err(), "created despite the hook");
        let Err(error) = refused else { return };
        assert_eq!(error.http_status(), 403);
        let details = error.to_envelope().error.details.unwrap_or_default();
        assert_eq!(
            details,
            serde_json::json!([{ "field": "name", "message": message }])
        );
    }
    f.hooks.decide(Err("internal"));
    let failed = f
        .engine
        .create_workspace("t1", &owner, "Acme", &ctx())
        .await;
    assert!(matches!(failed, Err(AuthError::Internal(_))));
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn the_bootstrap_create_path_applies_the_cap_and_the_hook_but_never_the_switch() {
    // The rule names the cap, then the hook, then the write, and never the switch.
    let rule = contract()["workspaceInvitations"]["rules"]["bootstrapCreate"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let at = |needle: &str| rule.find(needle).unwrap_or(usize::MAX);
    assert!(at("first the owner cap") < at("then the host's `beforeWorkspaceCreate`"));
    assert!(at("then the host's `beforeWorkspaceCreate`") < at("then the workspace is created"));
    assert!(rule.contains("`allowCreate` is never consulted"));
    let mut closed = config();
    closed.workspaces.allow_create = false;
    closed.workspaces.max_workspaces_per_user = 1;
    let Some(f) = build(closed) else { return };
    let owner_id = seed_account(&f, "t1", "o@e.com", true).await;
    let owner = f.engine.workspace_caller("t1", &owner_id).await;
    let Ok(owner) = owner else { return };
    let hook_ctx = HookContext::detached(HookPlane::Dashboard, &owner_id, "", "");
    let request = |id: &'static str| OwnedWorkspace {
        workspace: WorkspaceRef {
            tenant_id: "t1",
            workspace_id: id,
        },
        name: " Reserved ",
        owner: &owner,
    };
    let created = f
        .engine
        .create_owned_workspace(request("w-reserved"), &hook_ctx)
        .await;
    assert!(matches!(&created, Ok(w) if w.id == "w-reserved" && w.name == "Reserved"));
    let again = f
        .engine
        .create_owned_workspace(request("w-second"), &hook_ctx)
        .await;
    assert!(matches!(again, Err(AuthError::WorkspaceLimitReached)));
    // The shared path reports nothing to the workspace-event hook: its caller does.
    assert!(f.hooks.events(1).await.is_empty());
}

#[tokio::test]
async fn a_rename_is_written_with_its_event_read_back_and_bumps_nothing() {
    let Some(f) = fixture() else { return };
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    f.repo
        .seed_membership(membership(&active("t1", "w1", "u1", "owner"), 1));
    f.repo
        .seed_workspace(workspace("t2", "w1", WorkspaceStatus::Active, 2));
    let member = acting_member("t1", "w1", "u1", "owner");
    let renamed = f.engine.rename_workspace(&member, " New ", &ctx()).await;
    assert!(matches!(&renamed, Ok(w) if w.name == "New"), "{renamed:?}");
    let event = only_event(&f, "t1", "w1");
    assert_eq!(event.map(|e| e.kind), Some(AuditKind::WorkspaceRenamed));
    assert!(f.cache.operations().is_empty());
    // The homonym in another tenant is untouched.
    let other = f
        .engine
        .workspace_runtime()
        .ok()
        .map(|r| r.workspaces.clone());
    let Some(other) = other else { return };
    let homonym = other
        .find_by_id(WorkspaceRef {
            tenant_id: "t2",
            workspace_id: "w1",
        })
        .await;
    assert!(matches!(homonym, Ok(Some(w)) if w.name == "Workspace w1"));
    // An actor whose role changed since the guard read it changes nothing.
    let stale = acting_member("t1", "w1", "u1", "admin");
    let refused = f.engine.rename_workspace(&stale, "Other", &ctx()).await;
    assert!(matches!(refused, Err(AuthError::InsufficientWorkspaceRole)));
    let missing = acting_member("t1", "w-none", "u1", "owner");
    let gone = f.engine.rename_workspace(&missing, "Other", &ctx()).await;
    assert!(matches!(gone, Err(AuthError::WorkspaceNotFound)));
    let bad = f.engine.rename_workspace(&member, "", &ctx()).await;
    assert!(matches!(bad, Err(AuthError::Validation { .. })));
    assert_eq!(f.repo.audit_events().len(), 1);
}

/// An engine with an active `w1` owned by an account with a password; the member and its id.
async fn owned(grace_days: u32) -> Option<(Fixture, WorkspaceMember)> {
    let mut grace = config();
    grace.workspaces.deletion_grace_days = grace_days;
    let f = build(grace)?;
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    f.repo
        .seed_membership(membership(&active("t1", "w1", &owner, "owner"), 1));
    let member = acting_member("t1", "w1", &owner, "owner");
    Some((f, member))
}

/// The workspace `w1` of `t1` as stored.
async fn stored(f: &Fixture) -> Option<crate::workspace::domain::Workspace> {
    let runtime = f.engine.workspace_runtime().ok()?;
    let read = runtime
        .workspaces
        .find_by_id(WorkspaceRef {
            tenant_id: "t1",
            workspace_id: "w1",
        })
        .await;
    read.ok().flatten()
}

#[tokio::test]
async fn scheduling_a_deletion_reproves_the_caller_then_writes_bumps_and_reports() {
    let Some((f, member)) = owned(14).await else { return };
    let wrong = f
        .engine
        .schedule_workspace_deletion(&member, Some("not-the-password"), &ctx())
        .await;
    assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
    let absent = f
        .engine
        .schedule_workspace_deletion(&member, None, &ctx())
        .await;
    assert!(matches!(absent, Err(AuthError::InvalidCredentials)));
    assert!(f.repo.audit_events().is_empty());
    let before = OffsetDateTime::now_utc();
    let scheduled = f
        .engine
        .schedule_workspace_deletion(&member, Some(PASSWORD), &ctx())
        .await;
    assert!(scheduled.is_ok(), "{scheduled:?}");
    let Ok(scheduled) = scheduled else { return };
    assert_eq!(scheduled.status, WorkspaceStatus::PendingDeletion);
    let due = scheduled.deletion_scheduled_at.unwrap_or(before);
    assert!(
        due >= before + Duration::days(14)
            && due <= before + Duration::days(14) + Duration::minutes(1)
    );
    let read = stored(&f).await;
    assert_eq!(
        read.map(|w| (w.status, w.deletion_scheduled_at)),
        Some((WorkspaceStatus::PendingDeletion, Some(due)))
    );
    let event = only_event(&f, "t1", "w1");
    assert_eq!(
        event.map(|e| e.kind),
        Some(AuditKind::WorkspaceDeletionScheduled)
    );
    assert_eq!(f.cache.operations(), ["bump_workspace"]);
    assert_eq!(f.hooks.events(1).await.len(), 1);
    // Scheduled already: the owner is told so.
    let twice = f
        .engine
        .schedule_workspace_deletion(&member, Some(PASSWORD), &ctx())
        .await;
    assert!(matches!(twice, Err(AuthError::WorkspacePendingDeletion)));
}

#[tokio::test]
async fn a_grace_period_of_zero_deletes_at_once_and_a_lost_write_is_answered_from_what_it_is_now() {
    let Some((f, member)) = owned(0).await else { return };
    let deleted = f
        .engine
        .schedule_workspace_deletion(&member, Some(PASSWORD), &ctx())
        .await;
    assert!(
        matches!(deleted, Ok(d) if d.status == WorkspaceStatus::Deleted && d.deletion_scheduled_at.is_none())
    );
    let event = only_event(&f, "t1", "w1");
    assert_eq!(event.map(|e| e.kind), Some(AuditKind::WorkspaceDeleted));
    let again = f
        .engine
        .schedule_workspace_deletion(&member, Some(PASSWORD), &ctx())
        .await;
    assert!(matches!(again, Err(AuthError::WorkspaceNotFound)));
    let Some((f, member)) = owned(14).await else { return };
    let stale = acting_member("t1", "w1", &member.user_id, "admin");
    let refused = f
        .engine
        .schedule_workspace_deletion(&stale, Some(PASSWORD), &ctx())
        .await;
    assert!(matches!(refused, Err(AuthError::InsufficientWorkspaceRole)));
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn a_passwordless_account_proves_a_recent_sign_in_instead() {
    let Some(f) = fixture() else { return };
    let owner = seed_account(&f, "t1", "oauth@e.com", false).await;
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    f.repo
        .seed_membership(membership(&active("t1", "w1", &owner, "owner"), 1));
    let member = acting_member("t1", "w1", &owner, "owner");
    let refused = f
        .engine
        .schedule_workspace_deletion(&member, None, &ctx())
        .await;
    assert!(matches!(refused, Err(AuthError::ReauthenticationRequired)));
    let gone = acting_member("t1", "w1", "no-account", "owner");
    let unknown = f
        .engine
        .schedule_workspace_deletion(&gone, None, &ctx())
        .await;
    assert!(matches!(unknown, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_failed_bump_is_an_error_and_the_committed_change_stays() {
    let Some((f, member)) = owned(14).await else { return };
    f.cache.set_unavailable(true);
    let failed = f
        .engine
        .schedule_workspace_deletion(&member, Some(PASSWORD), &ctx())
        .await;
    assert!(matches!(failed, Err(AuthError::Internal(_))));
    assert_eq!(
        stored(&f).await.map(|w| w.status),
        Some(WorkspaceStatus::PendingDeletion)
    );
    // Nothing is reported for a change that was not invalidated.
    assert!(f.hooks.events(1).await.is_empty());
}

/// Seeds `w1` pending deletion, due `due_in` from now.
fn pending(f: &Fixture, due_in: Duration) {
    let mut seeded = workspace("t1", "w1", WorkspaceStatus::PendingDeletion, 1);
    seeded.deletion_scheduled_at = Some(OffsetDateTime::now_utc() + due_in);
    f.repo.seed_workspace(seeded);
}

#[tokio::test]
async fn a_restore_within_the_grace_period_reactivates_bumps_and_reports() {
    let Some((f, member)) = owned(14).await else { return };
    pending(&f, Duration::days(3));
    let restored = f.engine.restore_workspace(&member, &ctx()).await;
    assert!(restored.is_ok(), "{restored:?}");
    let read = stored(&f).await;
    assert_eq!(
        read.map(|w| (w.status, w.deletion_scheduled_at)),
        Some((WorkspaceStatus::Active, None))
    );
    let event = only_event(&f, "t1", "w1");
    assert_eq!(event.map(|e| e.kind), Some(AuditKind::WorkspaceRestored));
    assert_eq!(f.cache.operations(), ["bump_workspace"]);
    // Active again: nothing to restore.
    let again = f.engine.restore_workspace(&member, &ctx()).await;
    assert!(matches!(again, Err(AuthError::WorkspaceNotFound)));
}

#[tokio::test]
async fn a_restore_past_the_grace_period_or_by_a_changed_actor_changes_nothing() {
    let Some((f, member)) = owned(14).await else { return };
    pending(&f, Duration::seconds(-1));
    let late = f.engine.restore_workspace(&member, &ctx()).await;
    assert!(matches!(late, Err(AuthError::WorkspaceNotFound)));
    pending(&f, Duration::days(1));
    let stale = acting_member("t1", "w1", &member.user_id, "admin");
    let refused = f.engine.restore_workspace(&stale, &ctx()).await;
    assert!(matches!(refused, Err(AuthError::InsufficientWorkspaceRole)));
    let missing = acting_member("t1", "w-none", &member.user_id, "owner");
    let gone = f.engine.restore_workspace(&missing, &ctx()).await;
    assert!(matches!(gone, Err(AuthError::WorkspaceNotFound)));
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn finalizing_deletes_only_a_due_pending_workspace_with_no_actor() {
    let Some(f) = fixture() else { return };
    let key = WorkspaceRef {
        tenant_id: "t1",
        workspace_id: "w1",
    };
    let missing = f.engine.finalize_workspace_deletion(key).await;
    assert!(matches!(missing, Ok(FinalizeOutcome::NotFound)));
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    let active = f.engine.finalize_workspace_deletion(key).await;
    assert!(matches!(active, Ok(FinalizeOutcome::NotPending)));
    pending(&f, Duration::days(1));
    let early = f.engine.finalize_workspace_deletion(key).await;
    assert!(matches!(early, Ok(FinalizeOutcome::NotDue)));
    pending(&f, Duration::seconds(-1));
    let done = f.engine.finalize_workspace_deletion(key).await;
    assert!(matches!(done, Ok(FinalizeOutcome::Deleted)));
    assert_eq!(
        stored(&f).await.map(|w| w.status),
        Some(WorkspaceStatus::Deleted)
    );
    let event = only_event(&f, "t1", "w1");
    assert_eq!(
        event.as_ref().map(|e| e.kind.clone()),
        Some(AuditKind::WorkspaceDeleted)
    );
    assert_eq!(event.and_then(|e| e.actor_user_id), None);
    assert_eq!(f.cache.operations(), ["bump_workspace"]);
    let contexts = f.hooks.events(1).await;
    assert_eq!(contexts.len(), 1);
    assert!(
        f.hooks
            .contexts()
            .iter()
            .all(|c| c.tenant_id.as_deref() == Some("t1"))
    );
}
