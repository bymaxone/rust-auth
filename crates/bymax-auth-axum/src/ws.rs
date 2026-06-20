//! The WebSocket authentication surface (§8.7 / §7.3.6), gated behind the `websocket`
//! feature: the `POST /auth/ws-ticket` mint endpoint and the `WsAuthUser` /
//! `WsAuthUserFromHeader` upgrade extractors.
//!
//! The browser `WebSocket` API cannot set handshake headers, so the upgrade is authenticated
//! by a **single-use, ~30 s opaque ticket** — never an access JWT in the URL (§24 invariant
//! 4). The ticket is minted only from a fully-authorized, MFA-satisfied session (the mint
//! endpoint composes `AuthUser` + `UserStatus` + `MfaSatisfied`) and redeemed exactly once
//! (`GETDEL`) at the upgrade. Non-browser clients that can set headers use
//! `WsAuthUserFromHeader`, which validates the access JWT in the handshake `Authorization`
//! header — still never from the URL.

use axum::Json;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::response::{IntoResponse, Response};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::StatusCode;
use http::request::Parts;
use serde_json::json;

use crate::extractors::{AuthUser, MfaSatisfied, UserStatus};
use crate::response::{AuthRejection, error_response};
use crate::state::AuthState;

/// `POST /auth/ws-ticket` (200). Composes [`AuthUser`] + [`UserStatus`] + [`MfaSatisfied`],
/// so a ticket is minted only from a fully-authorized, MFA-satisfied session. The access
/// token travels in the cookie / `Authorization` header as usual — **never** echoed into a
/// URL. Returns `{ ticket }`.
pub(crate) async fn ws_ticket(
    State(state): State<AuthState>,
    user: AuthUser,
    _status: UserStatus,
    _mfa: MfaSatisfied,
) -> Response {
    match state.engine().issue_ws_ticket(&user.0).await {
        Ok(ticket) => (StatusCode::OK, Json(json!({ "ticket": ticket }))).into_response(),
        Err(error) => error_response(&error),
    }
}

/// Read the single-use `ticket` query parameter from the upgrade URL. This is the **sole**
/// place the adapter reads a credential from the query string (§24 invariant 4) — and it is
/// a one-shot, ~30 s opaque ticket, not a JWT, redeemable only here.
fn ticket_from_query(parts: &Parts) -> Option<String> {
    let query = parts.uri.query()?;
    serde_urlencoded::from_str::<TicketQuery>(query)
        .ok()
        .map(|q| q.ticket)
        .filter(|ticket| !ticket.is_empty())
}

/// The `?ticket=` query shape for the WebSocket upgrade.
#[derive(serde::Deserialize)]
struct TicketQuery {
    /// The single-use opaque upgrade ticket.
    ticket: String,
}

/// WebSocket-upgrade auth via a single-use ticket: reads the `ticket` query parameter and
/// atomically `GETDEL`s `wst:{sha256(ticket)}`, reconstructing the dashboard claims snapshot.
/// The first redemption wins; a missing / expired / already-redeemed ticket refuses the
/// handshake with 401. The access JWT is **never** read from the URL.
#[derive(Debug, Clone)]
pub struct WsAuthUser(pub DashboardClaims);

impl<S> FromRequestParts<S> for WsAuthUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let ticket = ticket_from_query(parts).ok_or(AuthError::TokenInvalid)?;
        let claims = auth_state.engine().redeem_ws_ticket(&ticket).await?;
        Ok(Self(claims))
    }
}

/// WebSocket-upgrade auth for non-browser clients: validates the access JWT in the handshake
/// `Authorization: Bearer` header (HS256-pinned, `type = dashboard`, `rv:{jti}` revocation) —
/// the same checks as `AuthUser`, and still **never** from the URL. Refuses with 401 on an
/// absent or invalid header.
#[derive(Debug, Clone)]
pub struct WsAuthUserFromHeader(pub DashboardClaims);

impl<S> FromRequestParts<S> for WsAuthUserFromHeader
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let token = bearer_from_header(parts).ok_or(AuthError::TokenInvalid)?;
        let claims = auth_state.engine().verify_access_token(&token).await?;
        Ok(Self(claims))
    }
}

/// Read the bearer token from the handshake `Authorization` header. Mirrors the dashboard
/// guard's header parsing; never reads a query string.
fn bearer_from_header(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;
    use http::Request;

    /// Build `Parts` whose URI carries a `?ticket=` query (the sole URL-borne credential).
    fn parts_with_ticket(ticket: &str) -> Parts {
        Request::builder()
            .uri(format!("/ws?ticket={ticket}"))
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0
    }

    /// Build `Parts` with a bearer `Authorization` header (the non-browser WS variant).
    fn parts_with_bearer(token: &str) -> Parts {
        Request::builder()
            .uri("/ws")
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn ws_auth_user_redeems_a_ticket_once_and_refuses_replay() {
        // A minted ticket redeems once via the extractor; a replay (and a bogus ticket) refuse
        // the handshake with token_invalid. The access JWT never appears in the URL.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "ws@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        // Verify the token to get the claims the engine mints a ticket from; both calls succeed
        // for this seeded user, so they are asserted and bound (never an early return).
        let claims = s.state.engine().verify_access_token(&token).await;
        assert!(claims.is_ok());
        let Ok(claims) = claims else { return };
        let ticket = s.state.engine().issue_ws_ticket(&claims).await;
        assert!(ticket.is_ok());
        let Ok(ticket) = ticket else { return };

        let mut parts = parts_with_ticket(&ticket);
        let ok = WsAuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(WsAuthUser(c)) if c.sub == id));

        // A replay of the same ticket is refused (GETDEL consumed it).
        let mut replay = parts_with_ticket(&ticket);
        let denied = WsAuthUser::from_request_parts(&mut replay, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::TokenInvalid))
        ));

        // No `?ticket=` at all → refused.
        let mut none = Request::builder()
            .uri("/ws")
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0;
        let none_denied = WsAuthUser::from_request_parts(&mut none, &s.state).await;
        assert!(matches!(
            none_denied,
            Err(AuthRejection(AuthError::TokenInvalid))
        ));
    }

    #[tokio::test]
    async fn ws_auth_user_from_header_validates_the_access_jwt() {
        // The non-browser variant validates the access JWT in the handshake header; a missing
        // or invalid header refuses the handshake.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "wsh@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        let mut parts = parts_with_bearer(&token);
        let ok = WsAuthUserFromHeader::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(WsAuthUserFromHeader(c)) if c.sub == id));

        // The scheme token is case-insensitive: `authorization: bearer <token>` is accepted
        // the same as `Bearer <token>` (the lowercase fallback branch of `bearer_from_header`).
        let mut lower = Request::builder()
            .uri("/ws")
            .header(http::header::AUTHORIZATION, format!("bearer {token}"))
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0;
        let lower_ok = WsAuthUserFromHeader::from_request_parts(&mut lower, &s.state).await;
        assert!(matches!(lower_ok, Ok(WsAuthUserFromHeader(c)) if c.sub == id));

        // A garbage bearer token is refused.
        let mut bad = parts_with_bearer("not-a-jwt");
        let denied = WsAuthUserFromHeader::from_request_parts(&mut bad, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::TokenInvalid))
        ));

        // No header at all is refused.
        let mut none = Request::builder()
            .uri("/ws")
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0;
        let none_denied = WsAuthUserFromHeader::from_request_parts(&mut none, &s.state).await;
        assert!(matches!(
            none_denied,
            Err(AuthRejection(AuthError::TokenInvalid))
        ));

        // An empty bearer value (`Authorization: Bearer `) is treated as no token (the
        // empty-token branch of `bearer_from_header`).
        let mut empty = Request::builder()
            .uri("/ws")
            .header(http::header::AUTHORIZATION, "Bearer ")
            .body(())
            .unwrap_or_default()
            .into_parts()
            .0;
        let empty_denied = WsAuthUserFromHeader::from_request_parts(&mut empty, &s.state).await;
        assert!(matches!(
            empty_denied,
            Err(AuthRejection(AuthError::TokenInvalid))
        ));
    }
}
