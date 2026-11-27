//! The invitation routes of the `workspaces` group: invite an address, list the pending
//! invitations, resend one, revoke one, and tell a token holder what a token is for (layer: HTTP
//! adapter, routes).
//!
//! The four management routes pass the guard under `manage_members`. Invite, resend and revoke
//! answer 204 with no body, and an account that is not a member changes nothing about that
//! answer. The preview needs no credential, and every token the body accepts but that cannot be
//! previewed is answered with the same error.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bymax_auth_core::services::workspace_invitations::{
    InvitationPreview, WorkspaceInvitationView,
};
use bymax_auth_core::workspace::domain::Page;
use http::StatusCode;
use serde_json::{Value, json};

use crate::dto::{
    InviteToWorkspaceDto, PreviewWorkspaceInvitationDto, WorkspaceInvitationEmailDto,
    WorkspacePageQueryDto,
};
use crate::extractors::workspace::{ManageMembers, RequireWorkspace};
use crate::routes::RequestMeta;
use crate::routes::workspaces::{answer, page_of};
use crate::shared_limit::Throttle;
use crate::state::{AuthState, AxumAuthConfig};
use crate::validation::{ValidatedJson, ValidatedQuery};

/// The invitation routes with their per-route limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: &Throttle) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/workspaces/{workspaceId}/invitations",
            crate::router::throttled(post(invite), limits.workspace_invite, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/invitations",
            crate::router::throttled(get(list), limits.workspace_invitations, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/invitations/resend",
            crate::router::throttled(post(resend), limits.workspace_invitation_resend, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/invitations/revoke",
            crate::router::throttled(post(revoke), limits.workspace_invitation_revoke, ip_source),
        )
        .route(
            "/workspaces/invitations/preview",
            crate::router::throttled(
                post(preview),
                limits.workspace_invitation_preview,
                ip_source,
            ),
        )
}

/// `POST /auth/workspaces/{workspaceId}/invitations` (204): invites the address, or sends again
/// to one already invited.
async fn invite(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ManageMembers>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(body): ValidatedJson<InviteToWorkspaceDto>,
) -> Response {
    let invited = state
        .engine()
        .invite_workspace_member(&member, &body.email, &body.role, &ctx)
        .await;
    answer(invited, |()| StatusCode::NO_CONTENT.into_response())
}

/// `GET /auth/workspaces/{workspaceId}/invitations` (200): one page of the pending member
/// invitations, oldest first. No token is part of it.
async fn list(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ManageMembers>,
    ValidatedQuery(query): ValidatedQuery<WorkspacePageQueryDto>,
) -> Response {
    let listed = state
        .engine()
        .list_workspace_invitations(&member, page_of(&query))
        .await;
    answer(listed, |page| {
        (StatusCode::OK, Json(invitations_body(&page))).into_response()
    })
}

/// `POST /auth/workspaces/{workspaceId}/invitations/resend` (204): sends a pending invitation
/// again under a new token.
async fn resend(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ManageMembers>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(body): ValidatedJson<WorkspaceInvitationEmailDto>,
) -> Response {
    let sent = state
        .engine()
        .resend_workspace_invitation(&member, &body.email, &ctx)
        .await;
    answer(sent, |()| StatusCode::NO_CONTENT.into_response())
}

/// `POST /auth/workspaces/{workspaceId}/invitations/revoke` (204): withdraws a pending
/// invitation.
async fn revoke(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ManageMembers>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(body): ValidatedJson<WorkspaceInvitationEmailDto>,
) -> Response {
    let revoked = state
        .engine()
        .revoke_workspace_invitation(&member, &body.email, &ctx)
        .await;
    answer(revoked, |()| StatusCode::NO_CONTENT.into_response())
}

/// `POST /auth/workspaces/invitations/preview` (200): what the token is for. No credential is
/// read: the token is the whole of what the caller holds.
async fn preview(
    State(state): State<AuthState>,
    ValidatedJson(body): ValidatedJson<PreviewWorkspaceInvitationDto>,
) -> Response {
    let previewed = state
        .engine()
        .preview_workspace_invitation(&body.token)
        .await;
    answer(previewed, |preview| {
        (StatusCode::OK, Json(preview_body(&preview))).into_response()
    })
}

/// One page of pending invitations.
fn invitations_body(page: &Page<WorkspaceInvitationView>) -> Value {
    let items: Vec<Value> = page
        .items
        .iter()
        .map(|item| {
            json!({
                "email": item.email,
                "role": item.role,
                "inviterUserId": item.inviter_user_id,
                "createdAt": item.created_at,
                "expiresAt": item.expires_at,
                "resendCount": item.resend_count,
            })
        })
        .collect();
    json!({ "items": items, "nextCursor": page.next_cursor })
}

/// What a token is for. A bootstrap invitation has no inviter to name.
fn preview_body(preview: &InvitationPreview) -> Value {
    match preview {
        InvitationPreview::Member {
            workspace_name,
            inviter_name,
            role,
            masked_email,
            account_exists,
        } => json!({
            "kind": "member",
            "workspaceName": workspace_name,
            "inviterName": inviter_name,
            "role": role,
            "maskedEmail": masked_email,
            "accountExists": account_exists,
        }),
        InvitationPreview::Bootstrap {
            workspace_name,
            role,
            masked_email,
            account_exists,
        } => json!({
            "kind": "bootstrap",
            "workspaceName": workspace_name,
            "role": role,
            "maskedEmail": masked_email,
            "accountExists": account_exists,
        }),
    }
}
