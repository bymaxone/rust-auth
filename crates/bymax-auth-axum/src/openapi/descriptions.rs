//! What the server does to a request value that a schema cannot say (layer: HTTP adapter,
//! feature `openapi`).
//!
//! The descriptions are `nest-auth`'s, held byte-identical in
//! `openapi/openapi-request-descriptions.json`. Today they state the normalisation applied to a
//! property before it is validated: a validator decorator cannot express a transform, so a
//! generated schema is silent about it. A host puts a description beside the property it
//! concerns in its own document.
//!
//! Each entry carries a probe, an `input` and the `expected` value the server reads from it. The
//! probe is the sentence's operational meaning, and this crate's tests run it through the real
//! deserialisation of the DTO it names.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

/// The artefact as shipped: a JSON object whose `descriptions` map goes from DTO name to a map
/// from property name to `{ description, probe: { input, expected } }`.
pub const REQUEST_DESCRIPTIONS_JSON: &str =
    include_str!("../../openapi/openapi-request-descriptions.json");

/// The artefact, parsed once.
fn document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| serde_json::from_str(REQUEST_DESCRIPTIONS_JSON).unwrap_or(Value::Null))
}

/// The descriptions, keyed by DTO name and then by property name (the wire name). Each value is
/// `{ "description": <text>, "probe": { "input": <value sent>, "expected": <value read> } }`.
#[must_use]
pub fn request_descriptions() -> BTreeMap<String, BTreeMap<String, Value>> {
    document()["descriptions"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(dto, properties)| {
            let properties = properties
                .as_object()
                .into_iter()
                .flatten()
                .map(|(property, entry)| (property.clone(), entry.clone()))
                .collect();
            (dto.clone(), properties)
        })
        .collect()
}

/// The description text of `property` of the DTO `dto`, or `None` when the artefact has none.
#[must_use]
pub fn request_description(dto: &str, property: &str) -> Option<&'static str> {
    document()["descriptions"][dto][property]["description"].as_str()
}
