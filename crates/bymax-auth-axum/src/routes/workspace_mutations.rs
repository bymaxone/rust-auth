//! The writes of the `workspaces` route group: creating a workspace, renaming it, scheduling and
//! undoing its deletion, changing a member's role, removing a member, leaving, and handing
//! ownership over (layer: HTTP adapter, routes).
//!
//! Every route needs a verified dashboard access token and an account in good standing. Creation
//! has no workspace to guard yet; every other route is behind the workspace guard with the
//! permission its action needs, so the workspace a request acts in is the path segment and the
//! caller's role is the one the guard resolved. The guard runs before a body is read, so a caller
//! the guard refuses learns nothing about the body's shape, and the re-proof of the two
//! destructive routes runs only after the guard and the checks the request alone decides. The
//! order of each operation's checks, the audit event, the cache bump and the host notification
//! are the engine's.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, patch, post};
use bymax_auth_core::services::workspace_members::OwnershipHandOver;
use http::StatusCode;

use super::workspaces::{answer, member_body, workspace_body};
use crate::dto::{
    ChangeMemberRoleDto, CreateWorkspaceDto, RenameWorkspaceDto, ScheduleWorkspaceDeletionDto,
    TransferOwnershipDto,
};
use crate::extractors::UserStatus;
use crate::extractors::workspace::{
    AnyWorkspaceMember, DeleteWorkspace, ManageMembers, ManageWorkspace, RequireMemberRoute,
    RequireWorkspace, RestoreWorkspace,
};
use crate::router::throttled;
use crate::routes::RequestMeta;
use crate::shared_limit::Throttle;
use crate::state::{AuthState, AxumAuthConfig};
use crate::validation::ValidatedJson;

/// Assemble the write routes of the `workspaces` group with their per-route limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: &Throttle) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/workspaces",
            throttled(post(create), limits.workspace_create, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}",
            throttled(patch(rename), limits.workspace_rename, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/schedule-deletion",
            throttled(
                post(schedule_deletion),
                limits.workspace_schedule_deletion,
                ip_source,
            ),
        )
        .route(
            "/workspaces/{workspaceId}/restore",
            throttled(post(restore), limits.workspace_restore, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/members/{userId}",
            throttled(patch(change_role), limits.workspace_change_role, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/members/{userId}",
            throttled(
                delete(remove_member),
                limits.workspace_remove_member,
                ip_source,
            ),
        )
        .route(
            "/workspaces/{workspaceId}/leave",
            throttled(post(leave), limits.workspace_leave, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/transfer-ownership",
            throttled(
                post(transfer_ownership),
                limits.workspace_transfer_ownership,
                ip_source,
            ),
        )
}

/// `POST /auth/workspaces` (201): creates a workspace owned by the caller and answers it. Whether
/// the caller may create one (`workspaces.allow_create`), how many it may own and what the host's
/// `before_workspace_create` decides are the engine's checks.
async fn create(
    State(state): State<AuthState>,
    status: UserStatus,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<CreateWorkspaceDto>,
) -> Response {
    let claims = status.0;
    let created = state
        .engine()
        .create_workspace(&claims.tenant_id, &claims.sub, &dto.name, &ctx)
        .await;
    answer(created, |workspace| {
        (StatusCode::CREATED, Json(workspace_body(&workspace))).into_response()
    })
}

/// `PATCH /auth/workspaces/{workspaceId}` (200): renames the workspace and answers it as it now
/// reads, for a caller holding a role `workspaces.permissions.manage_workspace` accepts.
async fn rename(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ManageWorkspace>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<RenameWorkspaceDto>,
) -> Response {
    let renamed = state
        .engine()
        .rename_workspace(&member, &dto.name, &ctx)
        .await;
    answer(renamed, |workspace| {
        (StatusCode::OK, Json(workspace_body(&workspace))).into_response()
    })
}

/// `POST /auth/workspaces/{workspaceId}/schedule-deletion` (204): re-proves the caller, then
/// schedules the workspace's deletion, for a caller holding a role
/// `workspaces.permissions.delete_workspace` accepts.
async fn schedule_deletion(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<DeleteWorkspace>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ScheduleWorkspaceDeletionDto>,
) -> Response {
    let scheduled = state
        .engine()
        .schedule_workspace_deletion(&member, dto.password.as_deref(), &ctx)
        .await;
    answer(scheduled, |_| StatusCode::NO_CONTENT.into_response())
}

/// `POST /auth/workspaces/{workspaceId}/restore` (204): undoes a scheduled deletion within its
/// grace period. The only route that admits the owner of a workspace pending deletion; no body is
/// read.
async fn restore(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<RestoreWorkspace>,
    RequestMeta(ctx): RequestMeta,
) -> Response {
    let restored = state.engine().restore_workspace(&member, &ctx).await;
    answer(restored, |()| StatusCode::NO_CONTENT.into_response())
}

/// `PATCH /auth/workspaces/{workspaceId}/members/{userId}` (200): gives the member the role and
/// answers the membership as it now stands, for a caller holding a role
/// `workspaces.permissions.manage_members` accepts.
async fn change_role(
    State(state): State<AuthState>,
    RequireMemberRoute(member, target, _): RequireMemberRoute<ManageMembers>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ChangeMemberRoleDto>,
) -> Response {
    let changed = state
        .engine()
        .change_member_role(&member, &target, &dto.role, &ctx)
        .await;
    answer(changed, |membership| {
        (StatusCode::OK, Json(member_body(&membership))).into_response()
    })
}

/// `DELETE /auth/workspaces/{workspaceId}/members/{userId}` (204): removes the member, for a
/// caller holding a role `workspaces.permissions.manage_members` accepts. Nothing but the path is
/// read.
async fn remove_member(
    State(state): State<AuthState>,
    RequireMemberRoute(member, target, _): RequireMemberRoute<ManageMembers>,
    RequestMeta(ctx): RequestMeta,
) -> Response {
    let removed = state
        .engine()
        .remove_workspace_member(&member, &target, &ctx)
        .await;
    answer(removed, |()| StatusCode::NO_CONTENT.into_response())
}

/// `POST /auth/workspaces/{workspaceId}/leave` (204): the caller leaves the workspace; no body is
/// read.
async fn leave(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<AnyWorkspaceMember>,
    RequestMeta(ctx): RequestMeta,
) -> Response {
    let left = state.engine().leave_workspace(&member, &ctx).await;
    answer(left, |()| StatusCode::NO_CONTENT.into_response())
}

/// `POST /auth/workspaces/{workspaceId}/transfer-ownership` (204): hands ownership to another
/// active member. The guard admits any member; that only an owner may hand it over is the engine's
/// first check, ahead of the receiver's standing and the password.
async fn transfer_ownership(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<AnyWorkspaceMember>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<TransferOwnershipDto>,
) -> Response {
    let hand_over = OwnershipHandOver {
        to_user_id: &dto.user_id,
        demote_self_to: dto.demote_self_to.as_deref(),
        password: dto.password.as_deref(),
    };
    let transferred = state
        .engine()
        .transfer_workspace_ownership(&member, hand_over, &ctx)
        .await;
    answer(transferred, |()| StatusCode::NO_CONTENT.into_response())
}
