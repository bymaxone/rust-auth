//! The `workspaces` route group: the workspaces a signed-in identity belongs to, its role in one,
//! the members of one it may see, and the record of the one it last switched to (layer: HTTP
//! adapter, routes).
//!
//! Every route needs a verified dashboard access token and an account in good standing. A route
//! under `{workspaceId}` is also behind [`RequireWorkspace`], so the workspace a request acts in is
//! always the path segment. The two lists answer only the caller's own data: its memberships, or
//! the members of a workspace the guard admitted it to, so neither enumerates.
//!
//! A literal route under the same prefix, such as `workspaces/invitations/preview`, coexists with
//! `workspaces/{workspaceId}/...` because a static segment wins over a capture, so a workspace whose
//! id is `invitations` is unreachable there. The shared contract makes a workspace id a
//! library-generated UUID, so only a workspace a host gave that id itself is affected.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bymax_auth_core::services::workspace::{MyWorkspaces, PageQuery, WorkspaceAccessView};
use bymax_auth_core::workspace::domain::{Membership, Page, Workspace};
use bymax_auth_types::AuthError;
use http::StatusCode;
use serde_json::{Value, json};
use time::{OffsetDateTime, UtcOffset};

use crate::dto::WorkspacePageQueryDto;
use crate::extractors::UserStatus;
use crate::extractors::workspace::{AnyWorkspaceMember, RequireWorkspace, ViewMembers};
use crate::response::error_response;
use crate::shared_limit::Throttle;
use crate::state::{AuthState, AxumAuthConfig};
use crate::validation::ValidatedQuery;

/// Assemble the `workspaces` group with its per-route limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: &Throttle) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/workspaces",
            crate::router::throttled(get(list), limits.workspace_list, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/access",
            crate::router::throttled(get(access), limits.workspace_access, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/members",
            crate::router::throttled(get(members), limits.workspace_members, ip_source),
        )
        .route(
            "/workspaces/{workspaceId}/switch",
            crate::router::throttled(post(switch), limits.workspace_switch, ip_source),
        )
}

/// The page a validated query asks for.
fn page_of(query: &WorkspacePageQueryDto) -> PageQuery<'_> {
    PageQuery {
        cursor: query.cursor.as_deref(),
        limit: query.limit.as_deref(),
    }
}

/// `GET /auth/workspaces` (200): one page of the caller's own memberships and the workspace it
/// last switched to. The tenant and the member come from the token; the query carries only the
/// cursor and the page size.
async fn list(
    State(state): State<AuthState>,
    status: UserStatus,
    ValidatedQuery(query): ValidatedQuery<WorkspacePageQueryDto>,
) -> Response {
    let claims = status.0;
    let listed = state
        .engine()
        .list_my_workspaces(&claims.tenant_id, &claims.sub, page_of(&query))
        .await;
    answer(listed, |page| {
        (StatusCode::OK, Json(my_workspaces_body(&page))).into_response()
    })
}

/// `GET /auth/workspaces/{workspaceId}/access` (200): the workspace and the caller's role in it.
async fn access(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<AnyWorkspaceMember>,
) -> Response {
    let view = state.engine().workspace_access(&member).await;
    answer(view, |view| {
        (StatusCode::OK, Json(access_body(&view))).into_response()
    })
}

/// `GET /auth/workspaces/{workspaceId}/members` (200): one page of the workspace's members in
/// every membership status, for a caller holding a role `workspaces.permissions.view_members`
/// accepts. The guard runs before the query is read, so a malformed `workspaceId` is reported
/// ahead of a malformed `limit`.
async fn members(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<ViewMembers>,
    ValidatedQuery(query): ValidatedQuery<WorkspacePageQueryDto>,
) -> Response {
    let listed = state
        .engine()
        .list_workspace_members(&member, page_of(&query))
        .await;
    answer(listed, |page| {
        (StatusCode::OK, Json(members_body(&page))).into_response()
    })
}

/// `POST /auth/workspaces/{workspaceId}/switch` (204): records the workspace as the caller's last
/// active one. The session does not change, since the token carries no workspace, and no body is
/// read.
async fn switch(
    State(state): State<AuthState>,
    RequireWorkspace(member, _): RequireWorkspace<AnyWorkspaceMember>,
) -> Response {
    let switched = state.engine().switch_workspace(&member).await;
    answer(switched, |()| StatusCode::NO_CONTENT.into_response())
}

/// The response for an engine result: `ok` builds the success, and every error renders its own
/// envelope the same way on every route of the group.
fn answer<T>(result: Result<T, AuthError>, ok: impl FnOnce(T) -> Response) -> Response {
    result.map_or_else(|error| error_response(&error), ok)
}

/// An instant as `Date.prototype.toISOString` writes it: UTC, milliseconds, `Z`, and a six-digit
/// signed year outside 0 to 9999.
pub(crate) fn iso_instant(at: OffsetDateTime) -> String {
    let utc = at.checked_to_offset(UtcOffset::UTC).unwrap_or(at);
    let year = utc.year();
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+07}")
    };
    format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    )
}

/// A workspace as a route answers it. The tenant is the caller's own and is not repeated.
fn workspace_body(workspace: &Workspace) -> Value {
    json!({
        "id": workspace.id,
        "name": workspace.name,
        "status": workspace.status.as_str(),
        "createdAt": iso_instant(workspace.created_at),
        "deletionScheduledAt": workspace.deletion_scheduled_at.map(iso_instant),
    })
}

/// The workspace a caller reached and its role.
fn access_body(view: &WorkspaceAccessView) -> Value {
    json!({ "workspace": workspace_body(&view.workspace), "role": view.role })
}

/// One page of the caller's own memberships.
fn my_workspaces_body(page: &MyWorkspaces) -> Value {
    let items: Vec<Value> = page
        .items
        .iter()
        .map(|item| {
            json!({ "workspace": workspace_body(&item.workspace), "role": item.membership.role })
        })
        .collect();
    json!({
        "items": items,
        "nextCursor": page.next_cursor,
        "lastActiveWorkspaceId": page.last_active_workspace_id,
    })
}

/// One member of a workspace.
fn member_body(member: &Membership) -> Value {
    json!({
        "userId": member.user_id,
        "role": member.role,
        "status": member.status.as_str(),
        "invitedByUserId": member.invited_by_user_id,
        "createdAt": iso_instant(member.created_at),
    })
}

/// One page of a workspace's members.
fn members_body(page: &Page<Membership>) -> Value {
    let items: Vec<Value> = page.items.iter().map(member_body).collect();
    json!({ "items": items, "nextCursor": page.next_cursor })
}

#[cfg(test)]
mod tests {
    use super::iso_instant;
    use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

    fn at(year: i32, offset_hours: i8) -> OffsetDateTime {
        let date = Date::from_calendar_date(year, Month::March, 4).unwrap_or(Date::MIN);
        let time = Time::from_hms_milli(5, 6, 7, 89).unwrap_or(Time::MIDNIGHT);
        let offset = UtcOffset::from_hms(offset_hours, 0, 0).unwrap_or(UtcOffset::UTC);
        PrimitiveDateTime::new(date, time).assume_offset(offset)
    }

    #[test]
    fn an_instant_is_written_the_way_to_iso_string_writes_it() {
        assert_eq!(iso_instant(at(2026, 0)), "2026-03-04T05:06:07.089Z");
        // Another offset is converted to UTC first.
        assert_eq!(iso_instant(at(2026, 2)), "2026-03-04T03:06:07.089Z");
        // The year keeps four digits down to 0 and takes a sign and six digits outside 0 to 9999.
        assert_eq!(iso_instant(at(7, 0)), "0007-03-04T05:06:07.089Z");
        assert_eq!(iso_instant(at(9999, 0)), "9999-03-04T05:06:07.089Z");
        assert_eq!(iso_instant(at(-1, 0)), "-000001-03-04T05:06:07.089Z");
    }
}
