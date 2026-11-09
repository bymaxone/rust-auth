//! The OpenAPI schema accessors, against the copy of the artefact held under `conformance/`.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::openapi::{
    REQUEST_SCHEMAS_JSON, openapi_version, request_schema, request_schema_names, request_schemas,
};

/// The shared copy, as it sits in the repository.
const CONFORMANCE_COPY: &str = include_str!("../../../conformance/openapi-request-schemas.json");

fn conformance_schemas() -> Value {
    serde_json::from_str::<Value>(CONFORMANCE_COPY)
        .map_or(Value::Null, |root| root["schemas"].clone())
}

#[test]
fn the_copy_that_ships_with_the_crate_is_the_shared_artefact_byte_for_byte() {
    // The crate cannot `include_str!` a file outside its own directory and still package, so it
    // carries a copy; this is what keeps the copy from becoming a second source.
    assert_eq!(REQUEST_SCHEMAS_JSON, CONFORMANCE_COPY);
}

#[test]
fn every_schema_of_the_artefact_is_served_and_nothing_else() {
    let shared = conformance_schemas();
    let expected: BTreeSet<String> = shared
        .as_object()
        .map(|schemas| schemas.keys().cloned().collect())
        .unwrap_or_default();
    let served: BTreeSet<String> = request_schemas().keys().cloned().collect();
    assert_eq!(served, expected);
    assert!(!expected.is_empty());
    let names: BTreeSet<String> = request_schema_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(names, expected);
}

#[test]
fn a_served_schema_is_the_artefacts_schema() {
    let shared = conformance_schemas();
    for (name, schema) in request_schemas() {
        assert_eq!(schema, shared[name.as_str()], "{name}");
    }
    assert_eq!(
        request_schema("LoginDto").as_ref(),
        Some(&shared["LoginDto"])
    );
}

#[test]
fn an_unknown_schema_name_is_none() {
    assert_eq!(request_schema("NoSuchDto"), None);
    assert_eq!(request_schema(""), None);
}

#[test]
fn the_names_come_back_sorted_and_the_version_is_openapi_3_0() {
    let names = request_schema_names();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    assert_eq!(openapi_version(), "3.0");
}
