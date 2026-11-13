//! A fixture for the workspace service tests: an engine with the workspace layer on over the
//! in-memory repositories and membership cache, and builders for the rows they hold (layer:
//! service, test support).

use std::collections::BTreeMap;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use crate::config::{AuthConfig, Environment};
use crate::engine::AuthEngine;
use crate::services::auth::test_support::base_config;
use crate::services::workspace::WorkspaceAccessRequest;
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use crate::workspace::access::{AcceptedRoles, WorkspaceMember};
use crate::workspace::domain::{Membership, MembershipStatus, Workspace, WorkspaceStatus};
use bymax_auth_types::AuthError;

/// The engine and the doubles behind it.
pub(super) struct Fixture {
    pub(super) engine: AuthEngine,
    pub(super) repo: Arc<InMemoryWorkspaces>,
    pub(super) cache: Arc<InMemoryMembershipCache>,
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
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(cache.clone())
        .build()
        .ok()?;
    Some(Fixture {
        engine,
        repo,
        cache,
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
