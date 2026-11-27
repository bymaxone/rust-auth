//! The answer of a signup that accepted a workspace invitation: the sign-in answer of the
//! configured delivery mode, with the workspace joined and the role held (layer: HTTP adapter,
//! delivery).

use axum::Json;
use axum::response::{IntoResponse, Response};
use bymax_auth_core::config::TokenDelivery as DeliveryMode;
use bymax_auth_core::services::workspace_invitations::AcceptedWorkspaceInvitation;
use bymax_auth_types::AuthResult;
use http::StatusCode;
use serde_json::json;
use tower_cookies::Cookies;

use super::{TokenDelivery, bearer_body, with_extra_cookies};

impl TokenDelivery<'_> {
    /// Answer 201 for a signup that joined a workspace. The cookies and the tokens in the body
    /// follow the configured mode as a sign-in does; `workspaceId` and `role` are added to the
    /// body in every mode.
    pub(crate) fn deliver_joined(
        &self,
        cookies: &Cookies,
        result: &AuthResult,
        accepted: &AcceptedWorkspaceInvitation,
    ) -> Response {
        let plant = || self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
        let (mut body, extras) = match self.config.delivery {
            DeliveryMode::Cookie => (json!({ "user": result.user }), plant()),
            DeliveryMode::Bearer => (json!(bearer_body(result)), Vec::new()),
            DeliveryMode::Both => (json!(bearer_body(result)), plant()),
        };
        body["workspaceId"] = json!(accepted.workspace_id);
        body["role"] = json!(accepted.role);
        with_extra_cookies((StatusCode::CREATED, Json(body)).into_response(), extras)
    }
}
