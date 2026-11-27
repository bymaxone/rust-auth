//! The `access.denied` report: what it carries, its per-account budget and what it never touches
//! (layer: domain, tests).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::{AuthError, MfaContext};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::access::{AcceptedRoles, RefusalCode, RefusalReason};
use super::audit::{AccessSurface, AuditKind, WorkspaceAuditEvent};
use super::denied::{SUPPRESSED_COUNT_TTL_SECONDS, suppressed_from, warning_due};
use super::domain::{Membership, MembershipStatus, Workspace, WorkspaceStatus};
use super::tests::{contract, hmac_key};
use crate::config::{AccessDeniedEventsConfig, AuthConfig, Environment};
use crate::engine::AuthEngine;
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;
use crate::services::user_subject_hash;
use crate::services::workspace::WorkspaceAccessRequest;
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use crate::traits::{AuthHooks, HookContext, HookError, HookPlane};

/// Every workspace event the engine hands the host, with its context.
#[derive(Default)]
struct Reports {
    seen: Mutex<Vec<(WorkspaceAuditEvent, HookContext)>>,
    failing: AtomicBool,
}

impl Reports {
    fn all(&self) -> Vec<(WorkspaceAuditEvent, HookContext)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl AuthHooks for Reports {
    async fn on_workspace_event(
        &self,
        event: &WorkspaceAuditEvent,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.push((event.clone(), ctx.clone()));
        if self.failing.load(Ordering::SeqCst) {
            return Err(HookError::Rejected("carries a@e.com".to_owned()));
        }
        Ok(())
    }
}

struct World {
    engine: AuthEngine,
    repo: Arc<InMemoryWorkspaces>,
    cache: Arc<InMemoryMembershipCache>,
    reports: Arc<Reports>,
}

/// An engine with the workspace layer on (owner over member) and the given event budget.
fn world(limits: AccessDeniedEventsConfig) -> Option<World> {
    let mut config: AuthConfig = base_config();
    config.workspaces.enabled = true;
    config.workspaces.roles.hierarchy = BTreeMap::from([
        ("owner".to_owned(), vec!["member".to_owned()]),
        ("member".to_owned(), Vec::new()),
    ]);
    config.workspaces.roles.owner_role = "owner".to_owned();
    config.workspaces.access_denied_events = limits;
    let repo = Arc::new(InMemoryWorkspaces::new());
    let cache = Arc::new(InMemoryMembershipCache::new());
    let reports = Arc::new(Reports::default());
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(cache.clone())
        .hooks(reports.clone())
        .build()
        .ok()?;
    cache.freeze_clock();
    Some(World {
        engine,
        repo,
        cache,
        reports,
    })
}

fn budget(max: u32) -> AccessDeniedEventsConfig {
    AccessDeniedEventsConfig {
        max,
        window_seconds: 60,
    }
}

impl World {
    fn workspace(&self, id: &str, status: WorkspaceStatus) {
        self.repo.seed_workspace(Workspace {
            id: id.to_owned(),
            tenant_id: "t1".to_owned(),
            name: "Space".to_owned(),
            status,
            created_at: OffsetDateTime::UNIX_EPOCH,
            deletion_scheduled_at: None,
        });
    }

    fn member(&self, workspace: &str, user: &str, role: &str) {
        self.repo.seed_membership(Membership {
            tenant_id: "t1".to_owned(),
            workspace_id: workspace.to_owned(),
            user_id: user.to_owned(),
            role: role.to_owned(),
            status: MembershipStatus::Active,
            invited_by_user_id: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        });
    }

    /// The access decision of a surface that accepts `owner`, then the detached work settled.
    async fn ask(&self, workspace: &str, user: &str) -> Result<(), AuthError> {
        let owners = AcceptedRoles::roles(["owner"]);
        let request = WorkspaceAccessRequest {
            workspace_id: workspace,
            accepted: &owners,
            allow_pending: false,
        };
        let answer = self.engine.authorize_workspace("t1", user, request).await;
        settle().await;
        answer.map(drop)
    }

    /// What each reported event said.
    fn denials(&self) -> Vec<(String, RefusalCode, RefusalReason, u64)> {
        let reported = self.reports.all().into_iter();
        reported
            .filter_map(|(event, _)| match event.kind {
                AuditKind::AccessDenied {
                    code,
                    reason,
                    suppressed_count,
                    ..
                } => Some((event.workspace_id, code, reason, suppressed_count)),
                _ => None,
            })
            .collect()
    }
}

/// Lets the detached reports run; nothing they await in memory waits on a timer.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// The one digest the store has counted.
fn only_digest(world: &World) -> String {
    let digests = world.cache.denial_digests();
    assert_eq!(digests.len(), 1, "{digests:?}");
    digests.into_iter().next().unwrap_or_default()
}

#[tokio::test]
async fn each_refusal_reports_the_code_answered_and_the_reason_decided() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    world.workspace("live", WorkspaceStatus::Active);
    world.workspace("leaving", WorkspaceStatus::PendingDeletion);
    world.member("live", "member", "member");
    world.member("leaving", "member", "member");
    world.member("leaving", "owner", "owner");
    for (workspace, user) in [
        ("live", "stranger"),
        ("leaving", "stranger"),
        ("live", "member"),
        ("leaving", "member"),
        ("leaving", "owner"),
    ] {
        assert!(world.ask(workspace, user).await.is_err());
    }
    let expected = [
        (
            "live",
            RefusalCode::WorkspaceNotFound,
            RefusalReason::NotMember,
        ),
        (
            "leaving",
            RefusalCode::WorkspaceNotFound,
            RefusalReason::NotMember,
        ),
        (
            "live",
            RefusalCode::InsufficientWorkspaceRole,
            RefusalReason::InsufficientRole,
        ),
        (
            "leaving",
            RefusalCode::WorkspaceNotFound,
            RefusalReason::PendingDeletion,
        ),
        (
            "leaving",
            RefusalCode::WorkspacePendingDeletion,
            RefusalReason::PendingDeletion,
        ),
    ]
    .map(|(workspace, code, reason)| (workspace.to_owned(), code, reason, 0));
    assert_eq!(world.denials(), expected);
}

#[tokio::test]
async fn the_event_names_the_caller_the_surface_and_the_instant_and_is_not_persisted() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    assert!(world.ask("w1", "u1").await.is_err());
    let seen = world.reports.all();
    assert_eq!(seen.len(), 1);
    let Some((event, ctx)) = seen.into_iter().next() else { unreachable!() };
    assert_eq!(event.kind.type_name(), "access.denied");
    assert_eq!(
        (event.tenant_id.as_str(), event.workspace_id.as_str()),
        ("t1", "w1")
    );
    assert_eq!(event.actor_user_id.as_deref(), Some("u1"));
    assert!(matches!(
        &event.kind,
        AuditKind::AccessDenied { user_id, surface: AccessSurface::Http, .. } if user_id == "u1"
    ));
    assert!(event.at.ends_with('Z') && OffsetDateTime::parse(&event.at, &Rfc3339).is_ok());
    assert!(matches!(ctx.plane, HookPlane::Dashboard));
    assert_eq!(ctx.user_id.as_deref(), Some("u1"));
    assert_eq!(ctx.tenant_id.as_deref(), Some("t1"));
    assert!(world.repo.audit_events().is_empty());
}

#[tokio::test]
async fn one_budget_covers_an_account_and_the_next_event_carries_what_was_left_out() {
    let Some(world) = world(budget(2)) else { unreachable!() };
    for workspace in ["w1", "w2", "w3", "w4", "w5"] {
        assert!(world.ask(workspace, "u1").await.is_err());
    }
    let reported: Vec<_> = world.denials().into_iter().map(|d| (d.0, d.3)).collect();
    assert_eq!(reported, [("w1".to_owned(), 0), ("w2".to_owned(), 0)]);
    let digest = only_digest(&world);
    let minute = Duration::from_secs(60);
    assert_eq!(
        world.cache.denial_counter(false, &digest),
        Some((5, minute))
    );
    let day = Duration::from_secs(SUPPRESSED_COUNT_TTL_SECONDS);
    assert_eq!(world.cache.denial_counter(true, &digest), Some((3, day)));

    // The window is fixed: the denial that reopens it is 60 seconds after the one that created it.
    world.cache.advance_clock(Duration::from_secs(59));
    assert!(world.ask("w6", "u1").await.is_err());
    assert_eq!(world.denials().len(), 2);
    world.cache.advance_clock(Duration::from_secs(1));
    assert!(world.ask("w7", "u1").await.is_err());
    assert_eq!(
        world.denials().last().map(|d| (d.0.clone(), d.3)),
        Some(("w7".to_owned(), 4))
    );
    assert_eq!(world.cache.denial_counter(true, &digest), None);
}

#[tokio::test]
async fn another_account_has_its_own_budget() {
    let Some(world) = world(budget(1)) else { unreachable!() };
    for user in ["u1", "u1", "u2"] {
        assert!(world.ask("w1", user).await.is_err());
    }
    assert_eq!(world.denials().len(), 2);
    assert_eq!(world.cache.denial_digests().len(), 2);
}

#[tokio::test]
async fn an_admitted_caller_and_a_request_refused_before_the_decision_touch_nothing() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    world.workspace("live", WorkspaceStatus::Active);
    world.member("live", "owner", "owner");
    assert!(world.ask("live", "owner").await.is_ok());
    assert!(world.ask("bad\u{7}id", "owner").await.is_err());
    assert!(world.ask("live", " ").await.is_err());
    let none = AcceptedRoles::Roles(Vec::new());
    let request = WorkspaceAccessRequest {
        workspace_id: "live",
        accepted: &none,
        allow_pending: false,
    };
    let answer = world
        .engine
        .authorize_workspace("t1", "owner", request)
        .await;
    assert!(matches!(answer, Err(AuthError::Forbidden)));
    settle().await;
    assert!(world.reports.all().is_empty());
    assert!(world.cache.denial_digests().is_empty());
}

#[tokio::test]
async fn a_counter_store_that_fails_emits_nothing_and_leaves_the_answer_alone() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    world.cache.set_unavailable(true);
    let answer = world.ask("w1", "u1").await;
    assert!(
        matches!(answer, Err(AuthError::WorkspaceNotFound)),
        "{answer:?}"
    );
    // A second refusal inside the window is answered the same and reports nothing either.
    assert!(world.ask("w1", "u1").await.is_err());
    assert!(world.reports.all().is_empty());
}

#[tokio::test]
async fn a_host_hook_that_fails_leaves_the_answer_alone() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    world.reports.failing.store(true, Ordering::SeqCst);
    let answer = world.ask("w1", "u1").await;
    assert!(
        matches!(answer, Err(AuthError::WorkspaceNotFound)),
        "{answer:?}"
    );
    assert_eq!(world.reports.all().len(), 1);
}

#[tokio::test]
async fn the_accounts_are_keyed_by_the_subjects_the_contract_pins() {
    let vectors = contract()["workspaceRealtime"]["accessDeniedVectors"].clone();
    let vectors = vectors.as_array().cloned().unwrap_or_default();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let text = |name: &str| vector[name].as_str().unwrap_or_default().to_owned();
        let (tenant, user) = (text("tenantId"), text("userId"));
        let digest = user_subject_hash(&hmac_key(), MfaContext::Dashboard, Some(&tenant), &user);
        assert_eq!(digest, text("digestHex"));
        assert_eq!(text("windowKey"), format!("wad:{digest}"));
        assert_eq!(text("suppressedKey"), format!("wads:{digest}"));
    }
}

#[tokio::test]
async fn the_counters_are_keyed_by_the_callers_tenant_scoped_subject() {
    let Some(world) = world(budget(10)) else { unreachable!() };
    assert!(world.ask("w1", "u1").await.is_err());
    let runtime = world.engine.workspace_runtime();
    let digest = runtime.ok().map(|runtime| {
        let key = &runtime.identifier_key;
        user_subject_hash(key, MfaContext::Dashboard, Some("t1"), "u1")
    });
    assert_eq!(Some(only_digest(&world)), digest);
}

/// The rule's text states the numbers and startup messages this crate hard-codes.
#[test]
fn the_defaults_bounds_and_messages_are_the_ones_the_rule_states() {
    let rule = contract()["workspaceRealtime"]["rules"]["accessDeniedEvents"].clone();
    let rule = rule.as_str().unwrap_or_default();
    let default = AccessDeniedEventsConfig::default();
    let stated = [
        format!(
            "defaults `max` {} and `windowSeconds` {}",
            default.max, default.window_seconds
        ),
        format!("whose expiry is {SUPPRESSED_COUNT_TTL_SECONDS} seconds"),
        refusal("max", 10_000),
        refusal("windowSeconds", 3_600),
    ];
    for text in stated {
        assert!(rule.contains(&text), "{text}");
    }
}

#[test]
fn the_surfaces_are_the_names_the_rule_states() {
    let rule = contract()["workspaceRealtime"]["rules"]["accessDeniedEvents"].clone();
    let rule = rule.as_str().unwrap_or_default();
    let [http, verifier, ws] = [
        AccessSurface::Http,
        AccessSurface::Verifier,
        AccessSurface::Ws,
    ]
    .map(AccessSurface::as_str);
    let stated = format!("`surface` is `{http}`, `{verifier}` or `{ws}`");
    assert!(rule.contains(&stated), "{stated}");
}

/// The startup message for `option` bounded by `max`.
fn refusal(option: &'static str, max: u32) -> String {
    ConfigError::WorkspaceAccessDeniedEventsOption { option, max }.to_string()
}

#[test]
fn a_stored_count_that_is_not_an_integer_reads_as_zero() {
    assert_eq!(suppressed_from("17"), 17);
    for stored in ["", "-1", "1.5", "many"] {
        assert_eq!(suppressed_from(stored), 0, "{stored:?}");
    }
}

#[test]
fn the_unavailable_warning_is_due_once_per_window() {
    let last = Mutex::new(None);
    let start = Instant::now();
    let window = Duration::from_secs(60);
    assert!(warning_due(&last, start, window));
    assert!(!warning_due(&last, start + Duration::from_secs(59), window));
    assert!(warning_due(&last, start + window, window));
    assert!(!warning_due(&last, start + window, window));
}
