//! The request DTOs of the workspace routes: the page query of the two lists and the path
//! parameters of a member route (layer: HTTP adapter, DTO).
//!
//! Each rule is the core's bound from `bymax_auth_core::workspace::bounds`, so the DTO and the
//! service that receives the value refuse the same inputs.

use bymax_auth_core::workspace::bounds::{IDENTIFIER_MAX_CHARS, check_cursor, parse_page_limit};
use garde::Validate;
use serde::Deserialize;

/// `garde` rule: the `cursor` bound, 1 to 512 characters with no control character.
fn cursor_rule(value: &str, _: &()) -> garde::Result {
    check_cursor(value)
        .map_err(|_| garde::Error::new("must be 1 to 512 characters with no control characters"))
}

/// `garde` rule: `limit` is a whole number from 1 to 100 written without a leading zero.
fn limit_rule(value: &str, _: &()) -> garde::Result {
    parse_page_limit(Some(value))
        .map(drop)
        .map_err(|_| garde::Error::new("must be a whole number from 1 to 100"))
}

/// `garde` rule: a path identifier is 1 to 128 characters with no control character.
///
/// Blank is not refused here, because the shared schema does not refuse it: the workspace guard
/// refuses a blank `workspaceId` before this DTO is read, and a route reading another identifier
/// applies the full rule to it before it is used.
fn identifier_rule(value: &str, _: &()) -> garde::Result {
    let count = value.chars().count();
    if (1..=IDENTIFIER_MAX_CHARS).contains(&count) && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(garde::Error::new(
            "must be 1 to 128 characters with no control characters",
        ))
    }
}

/// The query of the two paginated workspace lists, `GET /auth/workspaces` and
/// `GET /auth/workspaces/{workspaceId}/members`.
///
/// The cursor is positional only: the tenant and the workspace of a list always come from the
/// verified credential and the guarded route, so the query has no field that could name them, and
/// a query that tries is refused for the property it should not have.
#[derive(Debug, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspacePageQueryDto {
    /// The `nextCursor` of the previous page; absent for the first page.
    #[garde(inner(custom(cursor_rule)))]
    pub cursor: Option<String>,
    /// The page size as text, a whole number from 1 to 100. Default 50. Received as a string and
    /// checked against its pattern, so `05` and `+5` are refused rather than parsed.
    #[garde(inner(custom(limit_rule)))]
    pub limit: Option<String>,
}

/// The two path parameters of a member route, `/auth/workspaces/{workspaceId}/members/{userId}`.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberRouteParamsDto {
    /// The workspace, 1 to 128 characters with no control character.
    #[garde(custom(identifier_rule))]
    pub workspace_id: String,
    /// The member, 1 to 128 characters with no control character.
    #[garde(custom(identifier_rule))]
    pub user_id: String,
}
