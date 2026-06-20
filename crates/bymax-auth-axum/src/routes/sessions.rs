//! The `sessions` route group (§8.2.4), gated behind the `sessions` feature: list / revoke-all
//! / revoke-by-id. All three require [`AuthUser`] + [`UserStatus`]. Axum 0.8 uses brace path
//! syntax (`/{id}`); the static `all` segment wins over the `{id}` capture (static beats
//! capture in axum 0.8, regardless of declaration order).

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use bymax_auth_core::services::session::SessionInfo;
use http::StatusCode;
use serde_json::{Value, json};
use tower_cookies::Cookies;

use crate::extractors::{AuthUser, UserStatus};
use crate::response::error_response;
use crate::routes::source_refresh_token;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};

/// Assemble the `sessions` group with per-route rate limits. The paths are declared directly
/// (not nested under a `/sessions` prefix) so the list route matches `GET /sessions` exactly
/// rather than `GET /sessions/` — axum 0.8's `nest` would otherwise require the trailing slash.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/sessions",
            crate::router::throttled(get(list), limits.list_sessions, ip_source),
        )
        .route(
            "/sessions/all",
            crate::router::throttled(delete(revoke_all), limits.revoke_all_sessions, ip_source),
        )
        .route(
            "/sessions/{id}",
            crate::router::throttled(delete(revoke_one), limits.revoke_session, ip_source),
        )
}

/// `GET /auth/sessions` (200). Requires [`AuthUser`] + [`UserStatus`]. The caller's own
/// session is flagged when the request carries the matching refresh cookie.
async fn list(
    State(state): State<AuthState>,
    _status: UserStatus,
    user: AuthUser,
    cookies: Cookies,
) -> Response {
    let refresh = source_refresh_token(&cookies, &state.config().cookies.refresh_name, None);
    let raw = (!refresh.is_empty()).then_some(refresh.as_str());
    match state.engine().list_user_sessions(&user.0.sub, raw).await {
        Ok(sessions) => {
            let body: Vec<Value> = sessions.iter().map(session_to_json).collect();
            (StatusCode::OK, Json(json!({ "sessions": body }))).into_response()
        }
        Err(error) => error_response(&error),
    }
}

/// `DELETE /auth/sessions/all` (204). Requires [`AuthUser`] + [`UserStatus`]. Revokes every
/// session except the caller's current one.
async fn revoke_all(
    State(state): State<AuthState>,
    _status: UserStatus,
    user: AuthUser,
    cookies: Cookies,
) -> Response {
    let refresh = source_refresh_token(&cookies, &state.config().cookies.refresh_name, None);
    let raw = (!refresh.is_empty()).then_some(refresh.as_str());
    match state
        .engine()
        .revoke_other_user_sessions(&user.0.sub, raw)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `DELETE /auth/sessions/{id}` (204). Requires [`AuthUser`] + [`UserStatus`]. Ownership-checked.
async fn revoke_one(
    State(state): State<AuthState>,
    _status: UserStatus,
    user: AuthUser,
    Path(id): Path<String>,
) -> Response {
    match state.engine().revoke_user_session(&user.0.sub, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// Project a [`SessionInfo`] into the display-safe JSON body (§7.4): the short id, the full
/// hash, device/IP, the current flag, and the timestamps as Unix-millisecond numbers.
fn session_to_json(info: &SessionInfo) -> Value {
    json!({
        "id": info.id,
        "sessionHash": info.session_hash,
        "device": info.device,
        "ip": info.ip,
        "isCurrent": info.is_current,
        "createdAt": to_millis(info.created_at),
        "lastActivityAt": to_millis(info.last_activity_at),
    })
}

/// Convert an `OffsetDateTime` to Unix milliseconds, clamped into `i64`.
fn to_millis(value: time::OffsetDateTime) -> i64 {
    let nanos = value.unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}
