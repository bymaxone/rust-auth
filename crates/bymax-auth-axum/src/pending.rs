//! What the shared OpenAPI artefacts describe that this crate has not built yet (layer: HTTP
//! adapter, test support).
//!
//! The artefacts are compared with this crate's tables in both directions, so a schema, an
//! operation or a property the artefact adds fails the build until it is built. Each list here
//! is exactly that difference, with the slice that removes it. The comparing tests leave the
//! listed entries out of the artefact's side, and the tests below require each entry to be
//! present in the artefact and absent from the crate: the slice that builds one has to delete its
//! entry, and a gap that is not listed fails the build.

/// Request schemas the artefact carries that no `dto::DECLARED` row maps to yet. None of them has
/// a DTO at all.
pub(crate) const PENDING_SCHEMAS: [&str; 10] = [
    "AcceptWorkspaceInvitationDto",
    "AcceptWorkspaceInvitationSignupDto",
    "ChangeMemberRoleDto",
    "CreateWorkspaceDto",
    "InviteToWorkspaceDto",
    "PreviewWorkspaceInvitationDto",
    "RenameWorkspaceDto",
    "ScheduleWorkspaceDeletionDto",
    "TransferOwnershipDto",
    "WorkspaceInvitationEmailDto",
];

/// Operations the artefact carries that have no row in the operation table yet, as the
/// artefact's `METHOD /path` keys.
pub(crate) const PENDING_OPERATIONS: [&str; 15] = [
    "DELETE /workspaces/:workspaceId/members/:userId",
    "GET /workspaces/:workspaceId/invitations",
    "PATCH /workspaces/:workspaceId",
    "PATCH /workspaces/:workspaceId/members/:userId",
    "POST /workspaces",
    "POST /workspaces/:workspaceId/invitations",
    "POST /workspaces/:workspaceId/invitations/resend",
    "POST /workspaces/:workspaceId/invitations/revoke",
    "POST /workspaces/:workspaceId/leave",
    "POST /workspaces/:workspaceId/restore",
    "POST /workspaces/:workspaceId/schedule-deletion",
    "POST /workspaces/:workspaceId/transfer-ownership",
    "POST /workspaces/invitations/accept",
    "POST /workspaces/invitations/accept-signup",
    "POST /workspaces/invitations/preview",
];

/// Properties of a schema that exists here, which the artefact gives and the DTO lacks, as
/// `(schema, property)`.
pub(crate) const PENDING_PROPERTIES: [(&str, &str); 1] =
    [("OAuthInitiateQueryDto", "workspaceInvitation")];

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn schemas() -> Value {
        serde_json::from_str::<Value>(crate::request_schemas::JSON)
            .map_or(Value::Null, |root| root["schemas"].clone())
    }

    #[test]
    fn every_pending_schema_is_in_the_artefact_and_has_no_dto() {
        let schemas = schemas();
        for name in PENDING_SCHEMAS {
            assert!(
                schemas.get(name).is_some(),
                "{name} is pending but the artefact does not carry it"
            );
            assert!(
                crate::dto::DECLARED
                    .iter()
                    .all(|(_, schema, _)| *schema != name),
                "{name} has a DTO; remove it from PENDING_SCHEMAS"
            );
        }
    }

    #[test]
    fn every_pending_property_is_in_the_artefact_and_missing_from_its_dto() {
        let schemas = schemas();
        for (schema, property) in PENDING_PROPERTIES {
            assert!(
                schemas[schema]["properties"].get(property).is_some(),
                "{schema}.{property} is pending but the artefact does not carry it"
            );
        }
    }
}
