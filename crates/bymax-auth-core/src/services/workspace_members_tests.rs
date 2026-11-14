//! The membership services: a role change, a removal, leaving and an ownership hand-over, with
//! the atomic last-owner rule, the role ceiling, the compare-and-set on the roles read, the audit
//! event each write persists and the counter each bumps; and the outcome mappings and the
//! contract statements they answer to (layer: service, tests).

use std::sync::Arc;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::workspace_lifecycle::{FinalizeOutcome, created_workspace, rename_outcome};
use super::workspace_members::{OwnershipHandOver, transfer_outcome};
use super::workspace_support_tests::{
    Fixture, PASSWORD, acting_member, active, build, config, contract, membership, seed_account,
    workspace,
};
use super::workspace_writes::{
    WorkspaceEventHookFailed, member_change, run_on_workspace_event, status_refusal,
};
use crate::RepositoryError;
use crate::config::Environment;
use crate::engine::AuthEngine;
use crate::services::auth::test_support::ctx;
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use crate::traits::membership_repository::{MemberChangeOutcome, TransferOutcome};
use crate::traits::workspace_repository::{
    CreateWorkspaceOutcome, CreateWorkspaceWithOwner, RenameOutcome, RenameWorkspace,
    UpdateStatusOutcome, UpdateWorkspaceStatus,
};
use crate::traits::{AuthHooks, HookContext, HookPlane, NoOpAuthHooks, WorkspaceRepository};
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent};
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceRef, WorkspaceStatus,
};
use crate::workspace::keys::membership_version_id;
use crate::workspace::membership_cache::VersionCounter;

/// `w1` of `t1` with `(user, role, status)` members, and its homonym in `t2` with the same members.
fn seeded(members: &[(&str, &str, MembershipStatus)]) -> Option<Fixture> {
    let f = build(config())?;
    for tenant in ["t1", "t2"] {
        f.repo
            .seed_workspace(workspace(tenant, "w1", WorkspaceStatus::Active, 1));
        for (tick, (user, role, status)) in (2..).zip(members) {
            let mut seat = active(tenant, "w1", user, role);
            seat.status = *status;
            f.repo.seed_membership(membership(&seat, tick));
        }
    }
    Some(f)
}

/// The membership of `user` in `tenant`'s `w1`, as stored.
fn stored(f: &Fixture, tenant: &str, user: &str) -> Option<Membership> {
    f.repo.membership(MembershipRef {
        tenant_id: tenant,
        workspace_id: "w1",
        user_id: user,
    })
}

const ACTIVE: MembershipStatus = MembershipStatus::Active;

#[tokio::test]
async fn a_role_change_is_written_with_its_event_bumps_that_membership_and_answers_it() {
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "member", ACTIVE)]) else { return };
    let owner = acting_member("t1", "w1", "o", "owner");
    let changed = f
        .engine
        .change_member_role(&owner, "m", "admin", &ctx())
        .await;
    assert!(
        matches!(&changed, Ok(m) if m.role == "admin" && m.user_id == "m"),
        "{changed:?}"
    );
    let events = f.repo.audit_events();
    let expected = AuditKind::MemberRoleChanged {
        user_id: "m".into(),
        from: "member".into(),
        to: "admin".into(),
    };
    assert_eq!(
        events.iter().map(|e| e.kind.clone()).collect::<Vec<_>>(),
        [expected]
    );
    assert_eq!(events[0].actor_user_id.as_deref(), Some("o"));
    assert_eq!(f.cache.operations(), ["bump_membership"]);
    assert_eq!(f.hooks.events(1).await, events);
    // The homonym in the other tenant is untouched.
    assert_eq!(
        stored(&f, "t2", "m").map(|m| m.role),
        Some("member".to_owned())
    );
}

#[tokio::test]
async fn a_role_change_is_refused_in_the_order_the_ceiling_and_the_status_rule_give() {
    let members = [
        ("o", "owner", ACTIVE),
        ("a", "admin", ACTIVE),
        ("a2", "admin", ACTIVE),
        ("m", "member", ACTIVE),
        ("s", "member", MembershipStatus::Suspended),
    ];
    let Some(f) = seeded(&members) else { return };
    let admin = acting_member("t1", "w1", "a", "admin");
    let owner = acting_member("t1", "w1", "o", "owner");
    let cases: [RoleCase<'_>; 8] = [
        (&owner, " ", "admin", |e| field_is(e, "userId")),
        (&owner, "m", "ghost", |e| field_is(e, "role")),
        (&admin, "m", "admin", |e| {
            matches!(e, AuthError::InsufficientWorkspaceRole)
        }),
        (&admin, "o", "member", |e| {
            matches!(e, AuthError::InsufficientWorkspaceRole)
        }),
        (&admin, "a2", "member", |e| {
            matches!(e, AuthError::InsufficientWorkspaceRole)
        }),
        (&owner, "s", "admin", |e| {
            matches!(e, AuthError::WorkspaceNotFound)
        }),
        (&owner, "nobody", "admin", |e| {
            matches!(e, AuthError::WorkspaceNotFound)
        }),
        (&owner, "o", "admin", |e| matches!(e, AuthError::LastOwner)),
    ];
    for (actor, target, role, expected) in cases {
        let refused = f
            .engine
            .change_member_role(actor, target, role, &ctx())
            .await;
        let refused_as_expected = refused.as_ref().err().is_some_and(expected);
        assert!(refused_as_expected, "{target} -> {role}: {refused:?}");
    }
    assert!(f.repo.audit_events().is_empty());
    assert!(f.cache.operations().is_empty());
}

/// One refused role change: the actor, the target, the role asked for, and the refusal expected.
type RoleCase<'a> = (
    &'a WorkspaceMember,
    &'a str,
    &'a str,
    fn(&AuthError) -> bool,
);

/// Whether `error` is `auth.validation` naming exactly `field`.
fn field_is(error: &AuthError, field: &str) -> bool {
    matches!(error, AuthError::Validation { details } if details.len() == 1 && details[0].field == field)
}

use crate::workspace::access::WorkspaceMember;

#[tokio::test]
async fn the_last_owner_is_never_demoted_removed_or_let_go_and_a_second_owner_is() {
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "member", ACTIVE)]) else { return };
    let owner = acting_member("t1", "w1", "o", "owner");
    let demote = f
        .engine
        .change_member_role(&owner, "o", "member", &ctx())
        .await;
    assert!(matches!(demote, Err(AuthError::LastOwner)));
    let remove = f.engine.remove_workspace_member(&owner, "o", &ctx()).await;
    assert!(matches!(remove, Err(AuthError::LastOwner)));
    let leave = f.engine.leave_workspace(&owner, &ctx()).await;
    assert!(matches!(leave, Err(AuthError::LastOwner)));
    assert!(f.repo.audit_events().is_empty());
    // With a second owner, each is allowed.
    let promoted = f
        .engine
        .change_member_role(&owner, "m", "owner", &ctx())
        .await;
    assert!(promoted.is_ok());
    let demoted = f
        .engine
        .change_member_role(&owner, "o", "admin", &ctx())
        .await;
    assert!(matches!(demoted, Ok(m) if m.role == "admin"));
    let new_owner = acting_member("t1", "w1", "m", "owner");
    let removed = f
        .engine
        .remove_workspace_member(&new_owner, "o", &ctx())
        .await;
    assert!(removed.is_ok(), "{removed:?}");
    assert!(stored(&f, "t1", "o").is_none());
}

#[tokio::test]
async fn a_change_judged_on_a_stale_role_is_refused_with_the_contracts_codes() {
    let Some(f) = seeded(&[
        ("o", "owner", ACTIVE),
        ("a", "admin", ACTIVE),
        ("m", "member", ACTIVE),
    ]) else {
        return;
    };
    // The guard read the actor as owner; the repository now holds admin.
    let stale = acting_member("t1", "w1", "a", "owner");
    let changed = f
        .engine
        .change_member_role(&stale, "m", "admin", &ctx())
        .await;
    assert!(matches!(changed, Err(AuthError::InsufficientWorkspaceRole)));
    let removed = f.engine.remove_workspace_member(&stale, "m", &ctx()).await;
    assert!(matches!(removed, Err(AuthError::InsufficientWorkspaceRole)));
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn a_target_already_holding_the_role_is_not_written_and_its_cached_access_still_ends() {
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "admin", ACTIVE)]) else { return };
    let owner = acting_member("t1", "w1", "o", "owner");
    let same = f
        .engine
        .change_member_role(&owner, "m", "admin", &ctx())
        .await;
    assert!(matches!(same, Ok(m) if m.role == "admin"));
    assert!(f.repo.audit_events().is_empty());
    assert_eq!(f.cache.operations(), ["bump_membership"]);
}

#[tokio::test]
async fn a_removal_acts_only_on_an_active_member_below_the_actor() {
    let members = [
        ("o", "owner", ACTIVE),
        ("a", "admin", ACTIVE),
        ("m", "member", ACTIVE),
        ("s", "member", MembershipStatus::Suspended),
    ];
    let Some(f) = seeded(&members) else { return };
    let admin = acting_member("t1", "w1", "a", "admin");
    for (target, refused) in [
        ("s", AuthError::WorkspaceNotFound),
        ("o", AuthError::InsufficientWorkspaceRole),
        ("a", AuthError::InsufficientWorkspaceRole),
    ] {
        let answer = f
            .engine
            .remove_workspace_member(&admin, target, &ctx())
            .await;
        assert_eq!(
            answer.err().map(|e| e.code()),
            Some(refused.code()),
            "{target}"
        );
    }
    let blank = f
        .engine
        .remove_workspace_member(&admin, "\u{a0}", &ctx())
        .await;
    assert!(blank.err().is_some_and(|e| field_is(&e, "userId")));
    let removed = f.engine.remove_workspace_member(&admin, "m", &ctx()).await;
    assert!(removed.is_ok(), "{removed:?}");
    assert!(stored(&f, "t1", "m").is_none());
    assert!(stored(&f, "t2", "m").is_some());
    let events = f.repo.audit_events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].kind,
        AuditKind::MemberRemoved {
            user_id: "m".into()
        }
    );
    assert_eq!(events[0].actor_user_id.as_deref(), Some("a"));
    assert_eq!(f.cache.operations(), ["bump_membership"]);
    // Gone: a retry is the identical 404.
    let again = f.engine.remove_workspace_member(&admin, "m", &ctx()).await;
    assert!(matches!(again, Err(AuthError::WorkspaceNotFound)));
}

#[tokio::test]
async fn leaving_removes_the_callers_own_membership_with_its_event() {
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "member", ACTIVE)]) else { return };
    let member = acting_member("t1", "w1", "m", "member");
    assert!(f.engine.leave_workspace(&member, &ctx()).await.is_ok());
    assert!(stored(&f, "t1", "m").is_none());
    let events = f.repo.audit_events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].kind,
        AuditKind::MemberLeft {
            user_id: "m".into()
        }
    );
    assert_eq!(events[0].actor_user_id.as_deref(), Some("m"));
    assert_eq!(f.cache.operations(), ["bump_membership"]);
    let gone = f.engine.leave_workspace(&member, &ctx()).await;
    assert!(matches!(gone, Err(AuthError::WorkspaceNotFound)));
}

/// `w1` owned by an account with a password, with an active `m`, a suspended `s` and an admin `a`.
async fn hand_over_fixture() -> Option<(Fixture, WorkspaceMember)> {
    let f = build(config())?;
    let owner = seed_account(&f, "t1", "o@e.com", true).await;
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    for (tick, (user, role, status)) in (2..).zip([
        (owner.as_str(), "owner", ACTIVE),
        ("m", "member", ACTIVE),
        ("s", "member", MembershipStatus::Suspended),
        ("a", "admin", ACTIVE),
    ]) {
        let mut seat = active("t1", "w1", user, role);
        seat.status = status;
        f.repo.seed_membership(membership(&seat, tick));
    }
    let member = acting_member("t1", "w1", &owner, "owner");
    Some((f, member))
}

/// A hand-over to `to` keeping `keeps`, proven with `password`.
fn to<'a>(to: &'a str, keeps: Option<&'a str>, password: Option<&'a str>) -> OwnershipHandOver<'a> {
    OwnershipHandOver {
        to_user_id: to,
        demote_self_to: keeps,
        password,
    }
}

#[tokio::test]
async fn a_hand_over_is_refused_before_the_password_is_looked_at() {
    let Some((f, owner)) = hand_over_fixture().await else { return };
    let wrong = Some("not-the-password");
    let admin = acting_member("t1", "w1", "a", "admin");
    let not_owner = f
        .engine
        .transfer_workspace_ownership(&admin, to("m", None, wrong), &ctx())
        .await;
    assert!(matches!(
        not_owner,
        Err(AuthError::InsufficientWorkspaceRole)
    ));
    let user = owner.user_id.clone();
    for (hand_over, field) in [
        (to(&user, None, wrong), "userId"),
        (to("m", Some("owner"), wrong), "demoteSelfTo"),
        (to("m", Some("ghost"), wrong), "demoteSelfTo"),
        (to("s", None, wrong), "userId"),
        (to("nobody", None, wrong), "userId"),
        (to(" ", None, wrong), "userId"),
        (to("a\u{0}b", None, wrong), "userId"),
    ] {
        let refused = f
            .engine
            .transfer_workspace_ownership(&owner, hand_over, &ctx())
            .await;
        assert!(
            refused.as_ref().err().is_some_and(|e| field_is(e, field)),
            "{hand_over:?}: {refused:?}"
        );
    }
    // Only an acceptable receiver reaches the password.
    let proved = f
        .engine
        .transfer_workspace_ownership(&owner, to("m", None, wrong), &ctx())
        .await;
    assert!(matches!(proved, Err(AuthError::InvalidCredentials)));
    assert!(f.repo.audit_events().is_empty());
}

#[tokio::test]
async fn a_hand_over_promotes_the_receiver_demotes_the_giver_and_bumps_both() {
    let Some((f, owner)) = hand_over_fixture().await else { return };
    let done = f
        .engine
        .transfer_workspace_ownership(&owner, to("m", Some("admin"), Some(PASSWORD)), &ctx())
        .await;
    assert!(done.is_ok(), "{done:?}");
    assert_eq!(
        stored(&f, "t1", "m").map(|m| m.role),
        Some("owner".to_owned())
    );
    assert_eq!(
        stored(&f, "t1", &owner.user_id).map(|m| m.role),
        Some("admin".to_owned())
    );
    let events = f.repo.audit_events();
    let expected = AuditKind::OwnershipTransferred {
        from_user_id: owner.user_id.clone(),
        to_user_id: "m".into(),
    };
    assert_eq!(
        events.iter().map(|e| e.kind.clone()).collect::<Vec<_>>(),
        [expected]
    );
    assert_eq!(f.cache.operations(), ["bump_membership", "bump_membership"]);
    // The giver is no longer an owner: a second hand-over is the identical 404.
    let again = f
        .engine
        .transfer_workspace_ownership(&owner, to("a", None, Some(PASSWORD)), &ctx())
        .await;
    assert!(matches!(again, Err(AuthError::WorkspaceNotFound)));
}

/// Whether `user`'s membership version counter in `w1` of `t1` exists, which means it was bumped.
fn membership_bumped(f: &Fixture, user: &str) -> bool {
    let key = MembershipRef {
        tenant_id: "t1",
        workspace_id: "w1",
        user_id: user,
    };
    let id = membership_version_id(f.engine.config().hmac_key(), "t1", "w1", key.user_id);
    id.is_ok_and(|id| {
        f.cache
            .counter_ttl(VersionCounter::Membership, &id)
            .is_some()
    })
}

#[tokio::test]
async fn a_hand_over_ends_the_cached_access_of_the_giver_and_of_the_receiver_alone() {
    let Some((f, owner)) = hand_over_fixture().await else { return };
    let done = f
        .engine
        .transfer_workspace_ownership(&owner, to("m", None, Some(PASSWORD)), &ctx())
        .await;
    assert!(done.is_ok(), "{done:?}");
    assert!(membership_bumped(&f, &owner.user_id));
    assert!(membership_bumped(&f, "m"));
    // A member the hand-over did not name keeps its cached access.
    assert!(!membership_bumped(&f, "a"));
}

#[tokio::test]
async fn a_hand_over_without_a_demotion_keeps_both_owners() {
    let Some((f, owner)) = hand_over_fixture().await else { return };
    let done = f
        .engine
        .transfer_workspace_ownership(&owner, to("m", None, Some(PASSWORD)), &ctx())
        .await;
    assert!(done.is_ok());
    assert_eq!(
        stored(&f, "t1", &owner.user_id).map(|m| m.role),
        Some("owner".to_owned())
    );
    assert_eq!(
        stored(&f, "t1", "m").map(|m| m.role),
        Some("owner".to_owned())
    );
}

#[tokio::test]
async fn a_member_change_whose_bump_fails_is_an_error_after_the_write() {
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "member", ACTIVE)]) else { return };
    f.cache.set_unavailable(true);
    let owner = acting_member("t1", "w1", "o", "owner");
    let failed = f
        .engine
        .change_member_role(&owner, "m", "admin", &ctx())
        .await;
    assert!(matches!(failed, Err(AuthError::Internal(_))));
    assert_eq!(
        stored(&f, "t1", "m").map(|m| m.role),
        Some("admin".to_owned())
    );
    let removed = f.engine.remove_workspace_member(&owner, "m", &ctx()).await;
    assert!(matches!(removed, Err(AuthError::Internal(_))));
    assert!(stored(&f, "t1", "m").is_none());
    assert!(f.hooks.events(1).await.is_empty());
}

#[tokio::test]
async fn a_switch_reports_workspace_switched_to_the_hook_only() {
    let Some(f) = seeded(&[("m", "member", ACTIVE)]) else { return };
    let member = acting_member("t1", "w1", "m", "member");
    assert!(f.engine.switch_workspace(&member, &ctx()).await.is_ok());
    let reported = f.hooks.events(1).await;
    assert_eq!(reported.len(), 1);
    assert_eq!(
        reported[0].kind,
        AuditKind::WorkspaceSwitched {
            user_id: "m".into()
        }
    );
    assert_eq!(reported[0].actor_user_id.as_deref(), Some("m"));
    assert!(f.repo.audit_events().is_empty());
    let contexts = f.hooks.contexts();
    assert_eq!(contexts[0].user_id.as_deref(), Some("m"));
    assert_eq!(contexts[0].tenant_id.as_deref(), Some("t1"));
    assert_eq!(contexts[0].ip, "203.0.113.4");
}

#[tokio::test]
async fn a_failing_workspace_event_hook_is_named_by_the_event_type_alone() {
    let event = WorkspaceAuditEvent {
        tenant_id: "t1".into(),
        workspace_id: "w1".into(),
        actor_user_id: None,
        at: "1970-01-01T00:00:00.000Z".into(),
        kind: AuditKind::MemberInvited {
            email: "a@e.com".into(),
            role: "member".into(),
        },
    };
    let Some(f) = build(config()) else { return };
    f.hooks.fail_events();
    let hooks: Arc<dyn AuthHooks> = f.hooks.clone();
    let ctx = HookContext::detached(HookPlane::Dashboard, "u", "", "");
    let failed = run_on_workspace_event(hooks, event.clone(), ctx.clone()).await;
    let text = failed
        .err()
        .map(|e: WorkspaceEventHookFailed| e.to_string());
    assert_eq!(
        text.as_deref(),
        Some("the workspace-event hook failed for member.invited")
    );
    let quiet: Arc<dyn AuthHooks> = Arc::new(NoOpAuthHooks);
    assert!(run_on_workspace_event(quiet, event, ctx).await.is_ok());
}

#[test]
fn every_member_write_outcome_answers_its_catalog_code() {
    let code = |r: Result<(), AuthError>| r.err().map(|e| e.code());
    assert!(member_change(MemberChangeOutcome::Done).is_ok());
    for (outcome, error) in [
        (MemberChangeOutcome::NotFound, AuthError::WorkspaceNotFound),
        (MemberChangeOutcome::LastOwner, AuthError::LastOwner),
        (
            MemberChangeOutcome::ActorChanged,
            AuthError::InsufficientWorkspaceRole,
        ),
    ] {
        assert_eq!(code(member_change(outcome)), Some(error.code()));
    }
    assert!(transfer_outcome(TransferOutcome::Done).is_ok());
    assert_eq!(
        code(transfer_outcome(TransferOutcome::NotFound)),
        Some(AuthError::WorkspaceNotFound.code())
    );
    let target = transfer_outcome(TransferOutcome::TargetNotMember);
    assert!(target.err().is_some_and(|e| field_is(&e, "userId")));
}

#[test]
fn every_workspace_write_outcome_answers_its_catalog_code() {
    let code = |r: Result<(), AuthError>| r.err().map(|e| e.code());
    assert!(rename_outcome(RenameOutcome::Done).is_ok());
    assert_eq!(
        code(rename_outcome(RenameOutcome::NotFound)),
        Some(AuthError::WorkspaceNotFound.code())
    );
    let stale = rename_outcome(RenameOutcome::ActorChanged);
    assert_eq!(
        code(stale),
        Some(AuthError::InsufficientWorkspaceRole.code())
    );
    let limited = created_workspace(CreateWorkspaceOutcome::LimitReached);
    assert!(matches!(limited, Err(AuthError::WorkspaceLimitReached)));
    let status = |o, c| status_refusal(o, c).map(|e: AuthError| e.code());
    assert_eq!(status(UpdateStatusOutcome::Done, None), None);
    let pending = Some(WorkspaceStatus::PendingDeletion);
    let conflict = UpdateStatusOutcome::StatusConflict;
    assert_eq!(
        status(conflict, pending),
        Some(AuthError::WorkspacePendingDeletion.code())
    );
    assert_eq!(
        status(conflict, Some(WorkspaceStatus::Deleted)),
        Some(AuthError::WorkspaceNotFound.code())
    );
    assert_eq!(
        status(conflict, None),
        Some(AuthError::WorkspaceNotFound.code())
    );
    assert_eq!(
        status(UpdateStatusOutcome::NotFound, None),
        Some(AuthError::WorkspaceNotFound.code())
    );
    let changed = status(UpdateStatusOutcome::ActorChanged, None);
    assert_eq!(changed, Some(AuthError::InsufficientWorkspaceRole.code()));
}

/// The `NNN auth.code` the sentence of `rule` that contains `marker` names first.
fn named_answer(rule: &str, marker: &str) -> Option<(u16, String)> {
    let sentence = rule.split(". ").find(|s| s.contains(marker))?;
    let at = sentence.find(" auth.")?;
    let status = sentence[..at]
        .rsplit(' ')
        .next()?
        .trim_start_matches('(')
        .parse()
        .ok()?;
    let code: String = sentence[at + 1..]
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || *c == '.' || *c == '_')
        .collect();
    Some((status, code))
}

/// The status and wire code of `error`.
fn answer_of(error: &AuthError) -> (u16, String) {
    let code = serde_json::to_value(error.code().to_wire())
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    (error.http_status(), code)
}

#[tokio::test]
async fn the_membership_status_rule_is_what_the_services_answer() {
    let rule = contract()["workspaceInvitations"]["rules"]["membershipStatus"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let suspended = named_answer(&rule, "a suspended one answers");
    let receiver = named_answer(
        &rule,
        "The receiver of an ownership hand-over must be ACTIVE",
    );
    assert!(rule.contains("checked before the giver's password is looked at"));
    assert!(suspended.is_some() && receiver.is_some(), "{rule}");
    let Some((f, owner)) = hand_over_fixture().await else { return };
    let changed = f
        .engine
        .change_member_role(&owner, "s", "admin", &ctx())
        .await;
    let removed = f.engine.remove_workspace_member(&owner, "s", &ctx()).await;
    for answer in [changed.map(drop), removed] {
        assert_eq!(answer.err().map(|e| answer_of(&e)), suspended);
    }
    let handed = f
        .engine
        .transfer_workspace_ownership(&owner, to("s", None, Some("wrong")), &ctx())
        .await;
    assert_eq!(handed.err().map(|e| answer_of(&e)), receiver);
}

#[tokio::test]
async fn only_workspace_wide_events_bump_the_workspace_counter() {
    let rule = contract()["workspaceMembershipCache"]["workspaceWideEvents"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for clause in [
        "deleting",
        "scheduling the deletion of",
        "restoring",
        "suspending a workspace bumps the workspace version",
        "a change to one membership bumps that membership's version only",
    ] {
        assert!(rule.contains(clause), "{clause}: {rule}");
    }
    // Scheduling bumps the workspace; a membership change bumps that membership alone.
    let Some(f) = seeded(&[("o", "owner", ACTIVE), ("m", "member", ACTIVE)]) else { return };
    let owner = acting_member("t1", "w1", "o", "owner");
    assert!(
        f.engine
            .change_member_role(&owner, "m", "admin", &ctx())
            .await
            .is_ok()
    );
    assert!(
        f.engine
            .leave_workspace(&acting_member("t1", "w1", "m", "admin"), &ctx())
            .await
            .is_ok()
    );
    assert_eq!(f.cache.operations(), ["bump_membership", "bump_membership"]);
}

/// A workspace repository whose status write always answers `outcome`, over a real store for
/// every read.
struct ScriptedStatus {
    inner: Arc<InMemoryWorkspaces>,
    outcome: UpdateStatusOutcome,
}

#[async_trait]
impl WorkspaceRepository for ScriptedStatus {
    async fn create_with_owner(
        &self,
        params: CreateWorkspaceWithOwner<'_>,
    ) -> Result<CreateWorkspaceOutcome, RepositoryError> {
        self.inner.create_with_owner(params).await
    }
    async fn find_by_id(&self, w: WorkspaceRef<'_>) -> Result<Option<Workspace>, RepositoryError> {
        self.inner.find_by_id(w).await
    }
    async fn rename(&self, params: RenameWorkspace<'_>) -> Result<RenameOutcome, RepositoryError> {
        self.inner.rename(params).await
    }
    async fn update_status(
        &self,
        _: UpdateWorkspaceStatus<'_>,
    ) -> Result<UpdateStatusOutcome, RepositoryError> {
        Ok(self.outcome)
    }
}

/// An engine whose status writes answer `outcome`, with `w1` seeded due for finalization.
fn scripted(outcome: UpdateStatusOutcome) -> Option<(AuthEngine, Arc<InMemoryWorkspaces>)> {
    let repo = Arc::new(InMemoryWorkspaces::new());
    let mut due = workspace("t1", "w1", WorkspaceStatus::PendingDeletion, 1);
    due.deletion_scheduled_at = Some(time::OffsetDateTime::UNIX_EPOCH);
    repo.seed_workspace(due);
    let workspaces = Arc::new(ScriptedStatus {
        inner: repo.clone(),
        outcome,
    });
    let engine = AuthEngine::builder()
        .config(config())
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(workspaces, repo.clone())
        .membership_cache_store(Arc::new(InMemoryMembershipCache::new()))
        .build()
        .ok()?;
    Some((engine, repo))
}

#[tokio::test]
async fn a_finalize_that_loses_its_write_answers_from_what_the_workspace_is_now() {
    let key = WorkspaceRef {
        tenant_id: "t1",
        workspace_id: "w1",
    };
    let Some((engine, _)) = scripted(UpdateStatusOutcome::NotFound) else { return };
    let gone = engine.finalize_workspace_deletion(key).await;
    assert!(matches!(gone, Ok(FinalizeOutcome::NotFound)));
    let Some((engine, repo)) = scripted(UpdateStatusOutcome::StatusConflict) else { return };
    // Still due as read again: left for the next run.
    let due = engine.finalize_workspace_deletion(key).await;
    assert!(matches!(due, Ok(FinalizeOutcome::NotDue)));
    repo.seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    let lost = engine.finalize_workspace_deletion(key).await;
    assert!(matches!(lost, Ok(FinalizeOutcome::NotPending)));
    // Gone when read again.
    let Some(runtime) = engine.workspace_runtime().ok() else { return };
    let missing = WorkspaceRef {
        tenant_id: "t1",
        workspace_id: "w-none",
    };
    let vanished = engine.finalize_lost(runtime, missing).await;
    assert!(matches!(vanished, Ok(FinalizeOutcome::NotFound)));
}
