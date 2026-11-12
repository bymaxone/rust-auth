//! [`RequireWorkspace`] on host-shaped routes: a policy that names roles, one that admits pending
//! workspaces, one that declares nothing, a member route whose second parameter is read after the
//! guard, and the routes that misuse the guard (layer: HTTP adapter, tests).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bymax_auth_core::config::{SameSite, TokenDelivery};
use bymax_auth_core::services::workspace::invalid_path_identifier;
use bymax_auth_core::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use bymax_auth_core::workspace::access::AcceptedRoles;
use bymax_auth_core::workspace::bounds::check_identifier;
use bymax_auth_core::workspace::domain::{
    Membership, MembershipStatus, Workspace, WorkspaceStatus,
};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use garde::Validate;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt;

use super::workspace::{AnyWorkspaceMember, RequireWorkspace, ViewMembers, WorkspacePolicy};
use crate::dto::MemberRouteParamsDto;
use crate::response::error_response;
use crate::state::AuthState;
use crate::test_support::{SECRET, resolved_config_with, seed};

struct Admins;
impl WorkspacePolicy for Admins {
    fn accepted(_: &AuthEngine) -> AcceptedRoles {
        AcceptedRoles::roles(["admin"])
    }
}

struct Restorers;
impl WorkspacePolicy for Restorers {
    const ALLOW_PENDING: bool = true;
    fn accepted(_: &AuthEngine) -> AcceptedRoles {
        AcceptedRoles::AnyMember
    }
}

struct Nobody;
impl WorkspacePolicy for Nobody {
    fn accepted(_: &AuthEngine) -> AcceptedRoles {
        AcceptedRoles::Roles(Vec::new())
    }
}

async fn role<P: WorkspacePolicy>(RequireWorkspace(member, _): RequireWorkspace<P>) -> String {
    member.role
}

/// A member route: the guard, then the second parameter, as a route acting on a member reads it.
async fn member_route(
    RequireWorkspace(member, _): RequireWorkspace<AnyWorkspaceMember>,
    Path(params): Path<MemberRouteParamsDto>,
) -> Response {
    let checked = params
        .validate()
        .ok()
        .and_then(|()| check_identifier("userId", &params.user_id).ok());
    match checked {
        Some(()) => format!("{}:{}", member.workspace_id, params.user_id).into_response(),
        None => error_response(&invalid_path_identifier("userId")),
    }
}

/// A workspace-enabled configuration, bearer delivery, with `view_members` as the members
/// permission: owner over admin over member.
fn config(view_members: AcceptedRoles) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(SECRET.to_owned());
    config.token_delivery = TokenDelivery::Bearer;
    config.roles.hierarchy = std::collections::HashMap::from([("USER".to_owned(), Vec::new())]);
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
    config.workspaces.permissions.view_members = view_members;
    config
}

/// The router the tests drive, the state behind it, and the caller's access token.
async fn app_with(view_members: AcceptedRoles) -> Option<(Router, AuthState, String)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let repo = Arc::new(InMemoryWorkspaces::new());
    let engine = AuthEngine::builder()
        .config(config(view_members))
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(Arc::new(InMemoryMembershipCache::new()))
        .build()
        .ok()?;
    let state = AuthState::new(
        Arc::new(engine),
        Arc::new(resolved_config_with(TokenDelivery::Bearer, SameSite::Lax)),
    );
    let user = seed(&users, "ws@e.com", "USER").await;
    let token = state
        .engine()
        .issue_tokens_for_user_id("t1", &user, "203.0.113.4", "agent")
        .await
        .map(|issued| issued.access_token)
        .unwrap_or_default();
    seed_rows(&repo, &user);
    let router = Router::new()
        .route("/admins/{workspaceId}", get(role::<Admins>))
        .route("/restore/{workspaceId}", get(role::<Restorers>))
        .route("/nobody/{workspaceId}", get(role::<Nobody>))
        .route("/w/{workspaceId}/m/{userId}", get(member_route))
        .route("/plain", get(role::<AnyWorkspaceMember>))
        .route("/other/{id}", get(role::<AnyWorkspaceMember>))
        .route("/members/{workspaceId}", get(role::<ViewMembers>))
        .with_state(state.clone());
    Some((router, state, token))
}

/// The caller is an active member of `w-member`, an active admin of `w-admin` and the owner of
/// `w-pending`.
fn seed_rows(repo: &InMemoryWorkspaces, user: &str) {
    let at = OffsetDateTime::UNIX_EPOCH;
    for (id, status, role) in [
        ("w-member", WorkspaceStatus::Active, "member"),
        ("w-admin", WorkspaceStatus::Active, "admin"),
        ("w-pending", WorkspaceStatus::PendingDeletion, "owner"),
    ] {
        repo.seed_workspace(Workspace {
            id: id.to_owned(),
            tenant_id: "t1".to_owned(),
            name: id.to_owned(),
            status,
            created_at: at,
            deletion_scheduled_at: None,
        });
        repo.seed_membership(Membership {
            tenant_id: "t1".to_owned(),
            workspace_id: id.to_owned(),
            user_id: user.to_owned(),
            role: role.to_owned(),
            status: MembershipStatus::Active,
            invited_by_user_id: None,
            created_at: at,
            updated_at: at,
        });
    }
}

/// The router of [`app_with`] under the default members permission, every active member.
async fn app() -> Option<(Router, AuthState, String)> {
    app_with(AcceptedRoles::AnyMember).await
}

/// Sends `GET path` with the caller's token: the status, the error code and the body text.
async fn get_as(app: &Router, path: &str, token: &str) -> (StatusCode, Value, String) {
    let request = Request::builder()
        .uri(path)
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap_or_default();
    let Ok(response) = app.clone().oneshot(request).await;
    let status = response.status();
    let bytes = response.into_body().collect().await.map(|c| c.to_bytes());
    let text = bytes
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json, text)
}

fn fields(body: &Value) -> Vec<String> {
    body["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail["field"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn a_policy_naming_roles_judges_them_through_the_hierarchy() {
    let Some((app, _, token)) = app().await else { return };
    let (status, _, text) = get_as(&app, "/admins/w-admin", &token).await;
    assert_eq!((status, text.as_str()), (StatusCode::OK, "admin"));
    let (status, body, _) = get_as(&app, "/admins/w-member", &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "auth.insufficient_workspace_role");
    // No credential is refused before anything about the workspace is read.
    let (status, body, _) = get_as(&app, "/admins/w-admin", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn only_a_policy_admitting_pending_workspaces_admits_their_owner() {
    let Some((app, _, token)) = app().await else { return };
    let (status, _, text) = get_as(&app, "/restore/w-pending", &token).await;
    assert_eq!((status, text.as_str()), (StatusCode::OK, "owner"));
    let (status, body, _) = get_as(&app, "/admins/w-pending", &token).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "auth.workspace_pending_deletion");
}

#[tokio::test]
async fn a_policy_declaring_nothing_is_refused_before_the_workspace_id_is_read() {
    let Some((app, _, token)) = app().await else { return };
    for path in ["/nobody/w-member", "/nobody/%20"] {
        let (status, body, _) = get_as(&app, path, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(body["error"]["code"], "auth.forbidden", "{path}");
    }
}

#[tokio::test]
async fn the_workspace_id_is_reported_before_any_other_parameter() {
    let Some((app, _, token)) = app().await else { return };
    // Both malformed: only the workspace id, which the guard reads first, is named.
    let (status, body, _) = get_as(&app, "/w/%20/m/%20", &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(fields(&body), ["workspaceId"]);
    // A good workspace id lets the route read the member, which is then named.
    let (status, body, _) = get_as(&app, "/w/w-member/m/%20", &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(fields(&body), ["userId"]);
    let (status, _, text) = get_as(&app, "/w/w-member/m/u9", &token).await;
    assert_eq!((status, text.as_str()), (StatusCode::OK, "w-member:u9"));
}

#[tokio::test]
async fn a_route_that_cannot_name_a_workspace_is_refused_as_requiring_one() {
    let Some((app, _, token)) = app().await else { return };
    for path in ["/plain", "/other/w-member"] {
        let (status, body, _) = get_as(&app, path, &token).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body["error"]["code"], "auth.workspace_required", "{path}");
    }
    // A capture that is not UTF-8 once decoded is a malformed request, not a lookup.
    let (status, body, _) = get_as(&app, "/admins/%FF", &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["message"], "Malformed request");
    assert_ne!(body["error"]["code"], "auth.workspace_required");
}

#[tokio::test]
async fn a_capture_the_router_never_recorded_is_a_route_requiring_a_workspace() {
    // Parts that no router matched carry no captures at all, which axum reports as its own fault
    // (a 500, not a client error), unlike a capture that is not UTF-8 (a 400).
    let Some((_, state, token)) = app().await else { return };
    let (mut parts, ()) = Request::builder()
        .uri("/w/w-member")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap_or_default()
        .into_parts();
    let refused =
        RequireWorkspace::<AnyWorkspaceMember>::from_request_parts(&mut parts, &state).await;
    let response = refused.map(|_| ()).map_err(IntoResponse::into_response);
    let Err(response) = response else { return };
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(body["error"]["code"], "auth.workspace_required");
}

#[tokio::test]
async fn the_members_permission_is_the_configured_roles_and_every_member_by_default() {
    let Some((app, _, token)) = app().await else { return };
    let (status, _, text) = get_as(&app, "/members/w-member", &token).await;
    assert_eq!((status, text.as_str()), (StatusCode::OK, "member"));
    let Some((app, _, token)) = app_with(AcceptedRoles::roles(["admin"])).await else { return };
    let (status, _, text) = get_as(&app, "/members/w-admin", &token).await;
    assert_eq!((status, text.as_str()), (StatusCode::OK, "admin"));
    let (status, body, _) = get_as(&app, "/members/w-member", &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "auth.insufficient_workspace_role");
}
