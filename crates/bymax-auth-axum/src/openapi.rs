//! The OpenAPI 3.0 request-body schemas of the auth routes (layer: HTTP adapter, feature
//! `openapi`).
//!
//! The schemas are `nest-auth`'s, generated there from its own validators and held here
//! byte-identical in `openapi/openapi-request-schemas.json`, so a client generated from either
//! backend sees the same names and the same bounds. They are plain `serde_json` values: this
//! module builds no document and serves no route. A host places the schemas it wants under
//! `components.schemas` of whatever document it builds.
//!
//! Lengths are counts of characters, the way JSON Schema defines `minLength` and `maxLength`;
//! the DTOs this crate validates with count the same way.
//!
//! The schemas are OpenAPI 3.0 on purpose: a 3.1 fragment merged into a 3.0 document validates
//! as neither. [`openapi_version`] names the version the schemas are written for.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

/// The artefact as shipped: a JSON object with the `openapi` version it is written for and a
/// `schemas` map from DTO name to schema.
pub const REQUEST_SCHEMAS_JSON: &str = include_str!("../openapi/openapi-request-schemas.json");

/// The artefact, parsed once.
fn document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| serde_json::from_str(REQUEST_SCHEMAS_JSON).unwrap_or(Value::Null))
}

/// The OpenAPI version the schemas are written for (`"3.0"`).
#[must_use]
pub fn openapi_version() -> &'static str {
    document()["openapi"].as_str().unwrap_or_default()
}

/// The names of the schemas, in sorted order: the DTO names `nest-auth` uses (`LoginDto`, …).
#[must_use]
pub fn request_schema_names() -> Vec<&'static str> {
    document()["schemas"]
        .as_object()
        .map(|schemas| schemas.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The schema named `name`, or `None` when there is no such schema.
#[must_use]
pub fn request_schema(name: &str) -> Option<Value> {
    document()["schemas"].get(name).cloned()
}

/// Every schema, keyed by name.
#[must_use]
pub fn request_schemas() -> BTreeMap<String, Value> {
    request_schema_names()
        .into_iter()
        .filter_map(|name| request_schema(name).map(|schema| (name.to_owned(), schema)))
        .collect()
}
