//! The request DTOs of the workspace routes: the page query of the two lists, the path parameters
//! of a member route, and the bodies of the create, rename, schedule-deletion, role-change,
//! ownership hand-over, invitation and invitation acceptance routes (layer: HTTP adapter, DTO).
//!
//! Each rule is the core's bound from `bymax_auth_core::workspace::bounds` or the shared
//! contract's `requestFieldBounds`, so the DTO and the service that receives the value refuse the
//! same inputs. Only shapes are checked here: whether a role is one of the hierarchy, whether a
//! name is blank once trimmed and whether a receiver is an active member are the service's
//! decisions, under the same field names.

use bymax_auth_core::workspace::bounds::{IDENTIFIER_MAX_CHARS, check_cursor, parse_page_limit};
use garde::Validate;
use serde::Deserialize;

use super::no_control_characters;

/// `garde` rule: the `cursor` bound, 1 to 4096 characters with no control character.
fn cursor_rule(value: &str, _: &()) -> garde::Result {
    check_cursor(value)
        .map_err(|_| garde::Error::new("must be 1 to 4096 characters with no control characters"))
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

/// `POST /auth/workspaces` body: the name of the workspace to create.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWorkspaceDto {
    /// The display name, 1 to 120 characters as submitted, with no control character. The
    /// service trims it and refuses one that is blank after trimming, under the same field.
    #[garde(length(chars, min = 1, max = 120), custom(no_control_characters))]
    pub name: String,
}

/// `PATCH /auth/workspaces/{workspaceId}` body: the workspace's new name, under the rules of the
/// name it was created with.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenameWorkspaceDto {
    /// The display name, 1 to 120 characters as submitted, with no control character. The
    /// service trims it and refuses one that is blank after trimming, under the same field.
    #[garde(length(chars, min = 1, max = 120), custom(no_control_characters))]
    pub name: String,
}

/// `POST /auth/workspaces/{workspaceId}/schedule-deletion` body: the caller's proof of who they
/// are, in a POST body because a DELETE body has no defined meaning an intermediary must keep.
#[derive(Debug, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScheduleWorkspaceDeletionDto {
    /// The account's current password, 1 to 128 characters. Absent for an account with no
    /// password, which proves a recent sign-in instead; for one that has a password an absent
    /// value is refused as a wrong one.
    #[garde(inner(length(chars, min = 1, max = 128)))]
    pub password: Option<String>,
}

/// `PATCH /auth/workspaces/{workspaceId}/members/{userId}` body: the role the member should hold.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeMemberRoleDto {
    /// The role, 1 to 64 characters with no control character.
    #[garde(length(chars, min = 1, max = 64), custom(no_control_characters))]
    pub role: String,
}

/// `POST /auth/workspaces/{workspaceId}/transfer-ownership` body: who receives ownership, the role
/// the giver keeps, and the giver's proof.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferOwnershipDto {
    /// The member who becomes an owner, 1 to 128 characters with no control character.
    #[garde(length(chars, min = 1, max = 128), custom(no_control_characters))]
    pub user_id: String,
    /// The role the giver keeps, 1 to 64 characters with no control character; absent keeps both
    /// as owners.
    #[garde(
        inner(length(chars, min = 1, max = 64)),
        inner(custom(no_control_characters))
    )]
    pub demote_self_to: Option<String>,
    /// The giver's current password, 1 to 128 characters; absent for an account with no password.
    #[garde(inner(length(chars, min = 1, max = 128)))]
    pub password: Option<String>,
}

/// `POST /auth/workspaces/{workspaceId}/invitations` body: the address to invite and the role the
/// invitation grants.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteToWorkspaceDto {
    /// The invitee, trimmed and lowercased before the checks, so it matches the address the
    /// invitation is indexed under. At most 255 characters.
    #[garde(email, length(chars, max = 255))]
    #[serde(deserialize_with = "super::text_rules::normalized_email")]
    pub email: String,
    /// The workspace role, 1 to 64 characters with no control character.
    #[garde(length(chars, min = 1, max = 64), custom(no_control_characters))]
    pub role: String,
}

/// The body of the resend and revoke routes under
/// `/auth/workspaces/{workspaceId}/invitations`: the invitee whose pending invitation is meant.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceInvitationEmailDto {
    /// The invitee, under the rules of the address it was invited at.
    #[garde(email, length(chars, max = 255))]
    #[serde(deserialize_with = "super::text_rules::normalized_email")]
    pub email: String,
}

/// `POST /auth/workspaces/invitations/preview` body: the token of the invitation message.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewWorkspaceInvitationDto {
    /// The raw token, exactly 64 characters.
    #[garde(length(chars, min = 64, max = 64))]
    pub token: String,
}

/// `POST /auth/workspaces/invitations/accept` body: the token of the invitation message.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptWorkspaceInvitationDto {
    /// The raw token, exactly 64 characters.
    #[garde(length(chars, min = 64, max = 64))]
    pub token: String,
}

/// `POST /auth/workspaces/invitations/accept-signup` body (public).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptWorkspaceInvitationSignupDto {
    /// The raw token, exactly 64 characters.
    #[garde(length(chars, min = 64, max = 64))]
    pub token: String,
    /// The new account's display name, 2 to 100 characters.
    #[garde(length(chars, min = 2, max = 100))]
    pub name: String,
    /// The new account's password, 8 to 128 characters.
    #[garde(length(chars, min = 8, max = 128))]
    pub password: String,
}
