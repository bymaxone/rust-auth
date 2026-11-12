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
//! `workspaceId` and another parameter are both malformed is answered for `workspaceId` alone.

use std::collections::HashMap;
use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts, Path};
use bymax_auth_core::AuthEngine;
use bymax_auth_core::services::workspace::WorkspaceAccessRequest;
use bymax_auth_core::workspace::access::{AcceptedRoles, WorkspaceMember};
use bymax_auth_types::AuthError;
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::state::AuthState;
use crate::transport::{BodyRejection, Transport};

/// The route capture the guard reads the workspace from.
const WORKSPACE_CAPTURE: &str = "workspaceId";

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
        engine
            .workspace_view_members_roles()
            .cloned()
            .unwrap_or(AcceptedRoles::Roles(Vec::new()))
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
        let auth_state = AuthState::from_ref(state);
        let engine = auth_state.engine();
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        engine
            .assert_user_active_and_verified(&claims.sub, &claims.tenant_id)
            .await?;
        let workspace_id = workspace_capture(parts, state).await?;
        let accepted = P::accepted(engine);
        let request = WorkspaceAccessRequest {
            workspace_id: &workspace_id,
            accepted: &accepted,
            allow_pending: P::ALLOW_PENDING,
        };
        let member = engine
            .authorize_workspace(&claims.tenant_id, &claims.sub, request)
            .await?;
        Ok(Self(member, PhantomData))
    }
}

/// The `{workspaceId}` capture of the route, percent-decoded.
async fn workspace_capture<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
) -> Result<String, BodyRejection> {
    let captures = Path::<HashMap<String, String>>::from_request_parts(parts, state)
        .await
        .map_err(|rejection| match rejection.status() {
            status if status.is_client_error() => BodyRejection::from(Transport::Malformed(status)),
            _ => BodyRejection::from(AuthError::WorkspaceRequired),
        })?;
    let Path(mut captures) = captures;
    captures
        .remove(WORKSPACE_CAPTURE)
        .ok_or_else(|| BodyRejection::from(AuthError::WorkspaceRequired))
}
