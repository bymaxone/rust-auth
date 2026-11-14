//! [`RequireWorkspace<P>`]: the workspace guard, admitting a request only to the workspace its
//! route names, for an active member holding a role the route accepts (layer: HTTP adapter,
//! guard).
//!
//! The workspace comes from the route's `{workspaceId}` capture and nowhere else: never a body, a
//! query, a header or a remembered default. In order the guard verifies the dashboard access token
//! and the account's standing (as [`super::UserStatus`] does), refuses a policy that declares no
//! role (`403 auth.forbidden`), refuses a malformed `workspaceId` (`400 auth.validation` naming
//! it, ahead of any lookup), and then lets the engine judge the membership: the identical `404
//! auth.workspace_not_found` for a stranger, a missing workspace, an inactive one and a non-owner
//! of one pending deletion; `409 auth.workspace_pending_deletion` for its owner unless the policy
//! admits pending workspaces; `403 auth.insufficient_workspace_role` below the accepted roles.
//!
//! Because the guard runs before the handler reads any other path parameter, a request whose
//! `workspaceId` and another parameter are both malformed is answered for `workspaceId` alone. A
//! member route reads its `{userId}` capture through [`RequireMemberRoute`], which refuses a
//! malformed one (`400 auth.validation` naming `userId`) after `workspaceId` and still ahead of
//! the membership lookup: the shared schema of the two parameters accepts a blank `userId`, so the
//! rule is applied here and not left to the DTO.

use std::collections::HashMap;
use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts, Path};
use bymax_auth_core::AuthEngine;
use bymax_auth_core::config::WorkspacePermission;
use bymax_auth_core::services::workspace::{WorkspaceAccessRequest, invalid_path_identifier};
use bymax_auth_core::workspace::access::{AcceptedRoles, WorkspaceMember};
use bymax_auth_core::workspace::bounds::check_identifier;
use bymax_auth_types::AuthError;
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::state::AuthState;
use crate::transport::{BodyRejection, Transport};

/// The route capture the guard reads the workspace from.
const WORKSPACE_CAPTURE: &str = "workspaceId";

/// The route capture a member route reads the member from.
const MEMBER_CAPTURE: &str = "userId";

/// What a route admits: the workspace roles it accepts and whether the owner of a workspace
/// pending deletion is admitted. Implement it on a marker type and name that type in
/// [`RequireWorkspace`].
pub trait WorkspacePolicy: Send + Sync + 'static {
    /// Whether the owner of a workspace pending deletion is admitted. Every other caller is
    /// refused with the same `404` as a stranger whatever this says. Default: `false`, so the
    /// owner is answered `409 auth.workspace_pending_deletion`, which lets a client offer to
    /// restore the workspace; a route admitting it can act on data that is about to go.
    const ALLOW_PENDING: bool = false;

    /// The roles the route accepts, read when the request arrives. An empty list declares
    /// nothing, and the route is then refused for every caller.
    fn accepted(engine: &AuthEngine) -> AcceptedRoles;
}

/// A policy admitting every active member of an active workspace.
#[derive(Debug, Clone, Copy)]
pub struct AnyWorkspaceMember;

impl WorkspacePolicy for AnyWorkspaceMember {
    fn accepted(_: &AuthEngine) -> AcceptedRoles {
        AcceptedRoles::AnyMember
    }
}

/// The policy of the members list: the roles `workspaces.permissions.view_members` names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ViewMembers;

impl WorkspacePolicy for ViewMembers {
    fn accepted(engine: &AuthEngine) -> AcceptedRoles {
        permitted(engine, WorkspacePermission::ViewMembers)
    }
}

/// The roles `workspaces.permissions` names for `permission`, or none when the layer is off.
fn permitted(engine: &AuthEngine, permission: WorkspacePermission) -> AcceptedRoles {
    engine
        .workspace_permission_roles(permission)
        .cloned()
        .unwrap_or(AcceptedRoles::Roles(Vec::new()))
}

/// The policy of the rename route: the roles `workspaces.permissions.manage_workspace` names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ManageWorkspace;

impl WorkspacePolicy for ManageWorkspace {
    fn accepted(engine: &AuthEngine) -> AcceptedRoles {
        permitted(engine, WorkspacePermission::ManageWorkspace)
    }
}

/// The policy of the schedule-deletion route: the roles
/// `workspaces.permissions.delete_workspace` names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeleteWorkspace;

impl WorkspacePolicy for DeleteWorkspace {
    fn accepted(engine: &AuthEngine) -> AcceptedRoles {
        permitted(engine, WorkspacePermission::DeleteWorkspace)
    }
}

/// The policy of the restore route: the roles that may delete a workspace, and the only route
/// that admits the owner of one pending deletion. Every other caller of such a workspace is
/// answered as a stranger is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RestoreWorkspace;

impl WorkspacePolicy for RestoreWorkspace {
    const ALLOW_PENDING: bool = true;

    fn accepted(engine: &AuthEngine) -> AcceptedRoles {
        permitted(engine, WorkspacePermission::DeleteWorkspace)
    }
}

/// The policy of the member routes (role change, removal): the roles
/// `workspaces.permissions.manage_members` names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ManageMembers;

impl WorkspacePolicy for ManageMembers {
    fn accepted(engine: &AuthEngine) -> AcceptedRoles {
        permitted(engine, WorkspacePermission::ManageMembers)
    }
}

/// The workspace guard. Carries the [`WorkspaceMember`] the engine admitted: a handler takes the
/// workspace it acts in from here and never from the request, since this is the only place that
/// checked the caller may act in it.
///
/// Rejects with the codes listed in the module documentation, and with the transport envelope's
/// "Malformed request" for a capture that is not valid UTF-8. A route without a `{workspaceId}`
/// capture is refused with `400 auth.workspace_required`.
#[derive(Debug, Clone)]
pub struct RequireWorkspace<P: WorkspacePolicy>(pub WorkspaceMember, pub PhantomData<P>);

impl<P, S> FromRequestParts<S> for RequireWorkspace<P>
where
    P: WorkspacePolicy,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (member, _) = admit::<P, S>(parts, state, false).await?;
        Ok(Self(member, PhantomData))
    }
}

/// The guard of a member route, `/workspaces/{workspaceId}/members/{userId}`: the workspace guard,
/// with the `{userId}` capture checked after `workspaceId` and before the membership is looked up.
/// Carries the admitted [`WorkspaceMember`] and the member the route names.
#[derive(Debug, Clone)]
pub(crate) struct RequireMemberRoute<P: WorkspacePolicy>(
    pub(crate) WorkspaceMember,
    pub(crate) String,
    pub(crate) PhantomData<P>,
);

impl<P, S> FromRequestParts<S> for RequireMemberRoute<P>
where
    P: WorkspacePolicy,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let (member, target) = admit::<P, S>(parts, state, true).await?;
        Ok(Self(member, target.unwrap_or_default(), PhantomData))
    }
}

/// The guard's steps, in order: the credential and the account's standing, the `workspaceId`
/// capture, the `userId` capture when the route has one, then the access decision.
async fn admit<P, S>(
    parts: &mut Parts,
    state: &S,
    member_route: bool,
) -> Result<(WorkspaceMember, Option<String>), BodyRejection>
where
    P: WorkspacePolicy,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    let auth_state = AuthState::from_ref(state);
    let engine = auth_state.engine();
    let claims = verified_dashboard_claims(parts, &auth_state).await?;
    engine
        .assert_user_active_and_verified(&claims.sub, &claims.tenant_id)
        .await?;
    let mut captures = route_captures(parts, state).await?;
    let workspace_id = captures
        .remove(WORKSPACE_CAPTURE)
        .ok_or_else(|| BodyRejection::from(AuthError::WorkspaceRequired))?;
    let target = if member_route {
        checked_identifier(&workspace_id, WORKSPACE_CAPTURE)?;
        let target = captures.remove(MEMBER_CAPTURE).unwrap_or_default();
        checked_identifier(&target, MEMBER_CAPTURE)?;
        Some(target)
    } else {
        None
    };
    let accepted = P::accepted(engine);
    let request = WorkspaceAccessRequest {
        workspace_id: &workspace_id,
        accepted: &accepted,
        allow_pending: P::ALLOW_PENDING,
    };
    let member = engine
        .authorize_workspace(&claims.tenant_id, &claims.sub, request)
        .await?;
    Ok((member, target))
}

/// `value` as a path identifier, or `400 auth.validation` naming `field`.
fn checked_identifier(value: &str, field: &'static str) -> Result<(), BodyRejection> {
    check_identifier(field, value)
        .map_err(|refused| BodyRejection::from(invalid_path_identifier(refused.field)))
}

/// The route's captures, percent-decoded.
async fn route_captures<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
) -> Result<HashMap<String, String>, BodyRejection> {
    let captures = Path::<HashMap<String, String>>::from_request_parts(parts, state)
        .await
        .map_err(|rejection| match rejection.status() {
            status if status.is_client_error() => BodyRejection::from(Transport::Malformed(status)),
            _ => BodyRejection::from(AuthError::WorkspaceRequired),
        })?;
    let Path(captures) = captures;
    Ok(captures)
}
