//! The request-body schemas the adapter validates against (layer: HTTP adapter).
//!
//! The text is `nest-auth`'s generated `conformance/openapi-request-schemas.json`, held
//! byte-identical in `openapi/openapi-request-schemas.json`. The adapter reads it to name the
//! properties a request fails (`required` and `properties`), so a failure names the property the
//! client sent and never a container. With the `openapi` feature the same text is served to a
//! host as data.

use std::sync::OnceLock;

use serde_json::Value;

/// The artefact as shipped.
pub(crate) const JSON: &str = include_str!("../openapi/openapi-request-schemas.json");

/// The schema named `name`: an object with `properties` and, where some are mandatory, `required`.
pub(crate) fn schema(name: &str) -> Option<&'static Value> {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| serde_json::from_str(JSON).unwrap_or(Value::Null))["schemas"].get(name)
}
