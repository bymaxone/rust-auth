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

/// Convert an `OffsetDateTime` to Unix milliseconds, clamped into the `i64` range (see
/// [`clamp_millis`]). A pre-epoch (negative) instant stays negative rather than being silently
/// flipped to `i64::MAX`.
fn to_millis(value: time::OffsetDateTime) -> i64 {
    clamp_millis(value.unix_timestamp_nanos() / 1_000_000)
}

/// Saturate an `i128` millisecond count into the `i64` range: a value past `i64::MAX` clamps to
/// `i64::MAX`, one below `i64::MIN` clamps to `i64::MIN`, and any in-range value is returned
/// exactly. This preserves the sign — corrupting a negative timestamp into `i64::MAX` (the old
/// `try_from(..).unwrap_or(i64::MAX)` behavior) is the bug this avoids.
fn clamp_millis(millis: i128) -> i64 {
    millis.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[cfg(test)]
mod tests {
    use super::{clamp_millis, to_millis};
    use time::OffsetDateTime;

    #[test]
    fn clamp_millis_returns_in_range_values_unchanged() {
        // A normal, in-range millisecond count passes through exactly.
        assert_eq!(clamp_millis(1_700_000_000_000), 1_700_000_000_000);
        // The boundary values are returned as themselves, not clamped.
        assert_eq!(clamp_millis(i64::MAX as i128), i64::MAX);
        assert_eq!(clamp_millis(i64::MIN as i128), i64::MIN);
    }

    #[test]
    fn clamp_millis_preserves_a_negative_pre_epoch_value() {
        // A pre-epoch (negative) timestamp stays negative — it must NOT become i64::MAX.
        let pre_epoch = -1_700_000_000_000_i128;
        assert_eq!(clamp_millis(pre_epoch), -1_700_000_000_000);
        assert_ne!(clamp_millis(pre_epoch), i64::MAX);
    }

    #[test]
    fn clamp_millis_saturates_above_and_below_the_i64_range() {
        // Above i64::MAX saturates to i64::MAX; below i64::MIN saturates to i64::MIN.
        assert_eq!(clamp_millis(i64::MAX as i128 + 1), i64::MAX);
        assert_eq!(clamp_millis(i64::MIN as i128 - 1), i64::MIN);
    }

    #[test]
    fn to_millis_converts_normal_and_pre_epoch_instants() {
        // A normal post-epoch instant converts to its positive millisecond count.
        let normal = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(to_millis(normal), 1_700_000_000_000);
        // A pre-epoch instant converts to a NEGATIVE millisecond count (the regression guard:
        // the old `try_from(..).unwrap_or(i64::MAX)` would have corrupted this to i64::MAX).
        let pre_epoch =
            OffsetDateTime::from_unix_timestamp(-1_000).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(to_millis(pre_epoch), -1_000_000);
        assert_ne!(to_millis(pre_epoch), i64::MAX);
    }
}
