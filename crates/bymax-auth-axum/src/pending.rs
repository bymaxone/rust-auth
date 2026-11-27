//! What the shared OpenAPI artefacts describe that this crate has not built yet (layer: HTTP
//! adapter, test support).
//!
//! The artefacts are compared with this crate's tables in both directions, so a schema, an
//! operation or a property the artefact adds fails the build until it is built. The list here
//! holds the properties still unbuilt. The comparing tests leave a listed entry out of the
//! artefact's side, and the test below requires it to be present in the artefact: the change
//! that builds one has to delete its entry, and a gap that is not listed fails the build.

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
