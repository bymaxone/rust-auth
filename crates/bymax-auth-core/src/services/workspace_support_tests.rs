//! A fixture for the workspace service tests: an engine with the workspace layer on over the
//! in-memory repositories and membership cache, and builders for the rows they hold (layer:
//! service, test support).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};

use crate::config::{AuthConfig, Environment};
use crate::engine::AuthEngine;
use crate::services::auth::test_support::{base_config, hash_password};
use crate::services::workspace::WorkspaceAccessRequest;
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use crate::traits::{
    AuthHooks, BeforeWorkspaceCreateResult, HookContext, HookError, UserRepository,
};
use crate::workspace::access::{AcceptedRoles, WorkspaceMember};
use crate::workspace::audit::WorkspaceAuditEvent;
use crate::workspace::domain::{Membership, MembershipStatus, Workspace, WorkspaceStatus};
use bymax_auth_types::{AuthError, CreateUserData, SafeAuthUser};

/// The engine and the doubles behind it.
pub(super) struct Fixture {
    pub(super) engine: AuthEngine,
    pub(super) repo: Arc<InMemoryWorkspaces>,
    pub(super) cache: Arc<InMemoryMembershipCache>,
    pub(super) users: Arc<InMemoryUserRepository>,
    pub(super) hooks: Arc<RecordingHooks>,
}

/// Hooks that record every workspace event and answer `before_workspace_create` as told.
#[derive(Default)]
pub(super) struct RecordingHooks {
    events: Mutex<Vec<WorkspaceAuditEvent>>,
    contexts: Mutex<Vec<HookContext>>,
    decision: Mutex<Option<Result<BeforeWorkspaceCreateResult, &'static str>>>,
    asked: Mutex<Vec<String>>,
    failing_events: AtomicBool,
}

impl RecordingHooks {
    /// Makes `before_workspace_create` answer `decision` (`Err` with a text is a
    /// `HookError::Rejected`, `Err("internal")` a `HookError::Internal`).
    pub(super) fn decide(&self, decision: Result<BeforeWorkspaceCreateResult, &'static str>) {
        if let Ok(mut slot) = self.decision.lock() {
            *slot = Some(decision);
        }
    }

    /// Makes `on_workspace_event` fail after recording the event.
    pub(super) fn fail_events(&self) {
        self.failing_events.store(true, Ordering::SeqCst);
    }

    /// The names `before_workspace_create` was asked about, in order.
    pub(super) fn asked(&self) -> Vec<String> {
        self.asked.lock().map(|a| a.clone()).unwrap_or_default()
    }

    /// The events reported so far, waiting for `count` of them, since delivery is detached.
    pub(super) async fn events(&self, count: usize) -> Vec<WorkspaceAuditEvent> {
        for _ in 0..500 {
            let seen = self.events.lock().map(|e| e.clone()).unwrap_or_default();
            if seen.len() >= count {
                return seen;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// The hook contexts the events were reported with.
    pub(super) fn contexts(&self) -> Vec<HookContext> {
        self.contexts.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl AuthHooks for RecordingHooks {
    async fn before_workspace_create(
        &self,
        _user: &SafeAuthUser,
        name: &str,
        _ctx: &HookContext,
    ) -> Result<BeforeWorkspaceCreateResult, HookError> {
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(name.to_owned());
        }
        let decision = self.decision.lock().ok().and_then(|d| d.clone());
        match decision {
            None => Ok(BeforeWorkspaceCreateResult::Allow),
            Some(Ok(result)) => Ok(result),
            Some(Err("internal")) => Err(HookError::Internal("hook down".into())),
            Some(Err(text)) => Err(HookError::Rejected(text.to_owned())),
        }
    }

    async fn on_workspace_event(
        &self,
        event: &WorkspaceAuditEvent,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        if let (Ok(mut events), Ok(mut contexts)) = (self.events.lock(), self.contexts.lock()) {
            events.push(event.clone());
            contexts.push(ctx.clone());
        }
        if self.failing_events.load(Ordering::SeqCst) {
            return Err(HookError::Rejected("carries a@e.com".to_owned()));
        }
        Ok(())
    }
}

/// The password every seeded account has.
pub(super) const PASSWORD: &str = "glidingwalnut42";

/// Seeds an active, verified account of `tenant` with [`PASSWORD`] (or none) and returns its id.
pub(super) async fn seed_account(f: &Fixture, tenant: &str, email: &str, password: bool) -> String {
    let created = f
        .users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "Member".to_owned(),
            password_hash: password.then(|| hash_password(PASSWORD)),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: tenant.to_owned(),
            email_verified: Some(true),
        })
        .await;
    created.map(|user| user.id).unwrap_or_default()
}

/// The member the guard would hand a route: `user` holding `role` in `tenant`/`workspace`.
pub(super) fn acting_member(
    tenant: &str,
    workspace: &str,
    user: &str,
    role: &str,
) -> WorkspaceMember {
    WorkspaceMember {
        tenant_id: tenant.to_owned(),
        workspace_id: workspace.to_owned(),
        user_id: user.to_owned(),
        role: role.to_owned(),
    }
}

/// The contract, parsed; `Null` when unreadable, which fails every comparison made on it.
pub(super) fn contract() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)
}

/// A configuration with the workspace layer on: owner over admin over member.
pub(super) fn config() -> AuthConfig {
    let mut config = base_config();
    config.workspaces.enabled = true;
    config.workspaces.roles.hierarchy = BTreeMap::from([
        (
            "owner".to_owned(),
            vec!["admin".to_owned(), "member".to_owned()],
        ),
        ("admin".to_owned(), vec!["member".to_owned()]),
        ("member".to_owned(), Vec::new()),
    ]);
    config.workspaces.roles.owner_role = "owner".to_owned();
    config
}

/// An engine over `config` with every workspace collaborator wired.
pub(super) fn build(config: AuthConfig) -> Option<Fixture> {
    let repo = Arc::new(InMemoryWorkspaces::new());
    let cache = Arc::new(InMemoryMembershipCache::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let hooks = Arc::new(RecordingHooks::default());
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(cache.clone())
        .hooks(hooks.clone())
        .build()
        .ok()?;
    Some(Fixture {
        engine,
        repo,
        cache,
        users,
        hooks,
    })
}

/// The instant `tick` seconds after the epoch, so rows sort by the order they were made.
pub(super) fn instant(tick: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::seconds(tick)
}

/// A workspace of `tenant` created at `tick`.
pub(super) fn workspace(tenant: &str, id: &str, status: WorkspaceStatus, tick: i64) -> Workspace {
    Workspace {
        id: id.to_owned(),
        tenant_id: tenant.to_owned(),
        name: format!("Workspace {id}"),
        status,
        created_at: instant(tick),
        deletion_scheduled_at: None,
    }
}

/// The key and state of one seeded membership.
pub(super) struct Seat<'a> {
    pub(super) tenant: &'a str,
    pub(super) workspace: &'a str,
    pub(super) user: &'a str,
    pub(super) role: &'a str,
    pub(super) status: MembershipStatus,
}

/// A membership in the state `seat` describes, created at `tick`.
pub(super) fn membership(seat: &Seat<'_>, tick: i64) -> Membership {
    Membership {
        tenant_id: seat.tenant.to_owned(),
        workspace_id: seat.workspace.to_owned(),
        user_id: seat.user.to_owned(),
        role: seat.role.to_owned(),
        status: seat.status,
        invited_by_user_id: None,
        created_at: instant(tick),
        updated_at: instant(tick),
    }
}

/// An active membership of `user` holding `role` in `tenant`/`workspace`.
pub(super) fn active<'a>(
    tenant: &'a str,
    workspace: &'a str,
    user: &'a str,
    role: &'a str,
) -> Seat<'a> {
    Seat {
        tenant,
        workspace,
        user,
        role,
        status: MembershipStatus::Active,
    }
}

/// Asks the guard of a surface accepting `accepted` to admit `user` of `tenant` to `workspace`.
pub(super) async fn authorize(
    f: &Fixture,
    (tenant, user, workspace): (&str, &str, &str),
    accepted: &AcceptedRoles,
    allow_pending: bool,
) -> Result<WorkspaceMember, AuthError> {
    let request = WorkspaceAccessRequest {
        workspace_id: workspace,
        accepted,
        allow_pending,
    };
    f.engine.authorize_workspace(tenant, user, request).await
}
