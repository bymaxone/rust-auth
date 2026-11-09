//! The contracts of the auth routes that a generated schema cannot state (layer: HTTP adapter,
//! feature `openapi`).
//!
//! The text is `nest-auth`'s, held byte-identical in `openapi/openapi-declared-structures.json`.
//! It has two halves. A **request structure** is a constraint across the properties of a body
//! (`required`, `oneOf` and `anyOf` only, with presence meaning present and not `null`), such as
//! the exactly-one-of proof set of a password reset. An **operation semantic** is a property of
//! a route that no schema holds: a refusal made by a handler rather than by validation, a policy
//! floor that is configuration, or a pair of responses that must be indistinguishable.
//!
//! Every entry carries probes, and this crate's tests run them against the real router. A host
//! places a structure beside the schema it concerns and an operation semantic in the description
//! of the operation.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

/// The artefact as shipped: a JSON object with the `openapi` version it is written for, the
/// `requestStructures` keyed by DTO name and the `operationSemantics` keyed by handler.
pub const DECLARED_STRUCTURES_JSON: &str =
    include_str!("../../openapi/openapi-declared-structures.json");

/// The artefact, parsed once.
fn document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| serde_json::from_str(DECLARED_STRUCTURES_JSON).unwrap_or(Value::Null))
}

/// The entries of one top-level map of the artefact, by key.
fn entries(section: &str) -> BTreeMap<String, Value> {
    document()[section]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect()
}

/// The request structures, keyed by DTO name. Each entry holds the `structure` (OpenAPI 3.0
/// keywords), a `description`, the `probes` that evaluate it and how it is `enforcement`.
#[must_use]
pub fn declared_request_structures() -> BTreeMap<String, Value> {
    entries("requestStructures")
}

/// The operation semantics, keyed by `Controller.handler` (with a `#name` suffix where one
/// handler carries several). Each entry has a `kind` and the probes or bodies that show it.
#[must_use]
pub fn declared_operation_semantics() -> BTreeMap<String, Value> {
    entries("operationSemantics")
}
