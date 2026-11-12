//! The description accessors, against the copy of the artefact held under `conformance/`.

use std::collections::BTreeSet;

use bymax_auth_crypto::mac::sha256;
use serde_json::Value;

use crate::openapi::{REQUEST_DESCRIPTIONS_JSON, request_description, request_descriptions};

/// The shared copy, as it sits in the repository.
const CONFORMANCE_COPY: &str =
    include_str!("../../../conformance/openapi-request-descriptions.json");
/// The digest of the artefact the parity tests were written against. A new release of the
/// artefact fails them until they and this digest move together.
const ARTEFACT_SHA256: &str = "81b6e5aaced9e463dbd61b928dca1b59dbe1b669d4402b3fc9b27e237f476c07";

fn shared() -> Value {
    serde_json::from_str::<Value>(CONFORMANCE_COPY)
        .map_or(Value::Null, |root| root["descriptions"].clone())
}

#[test]
fn the_copy_that_ships_with_the_crate_is_the_shared_artefact_byte_for_byte() {
    assert_eq!(REQUEST_DESCRIPTIONS_JSON, CONFORMANCE_COPY);
}

#[test]
fn the_artefact_is_the_release_the_parity_tests_were_written_against() {
    let hex: String = sha256(CONFORMANCE_COPY.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, ARTEFACT_SHA256);
}

#[test]
fn the_accessor_serves_every_dto_and_property_of_the_artefact_and_nothing_else() {
    let shared = shared();
    let served = request_descriptions();
    let expected: BTreeSet<&str> = shared
        .as_object()
        .map(|dtos| dtos.keys().map(String::as_str).collect())
        .unwrap_or_default();
    assert!(!expected.is_empty());
    assert_eq!(
        served.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected
    );
    for (dto, properties) in &served {
        let wanted: BTreeSet<&str> = shared[dto.as_str()]
            .as_object()
            .map(|props| props.keys().map(String::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            wanted,
            "{dto}"
        );
        for (property, entry) in properties {
            assert_eq!(
                *entry,
                shared[dto.as_str()][property.as_str()],
                "{dto}.{property}"
            );
        }
    }
}

#[test]
fn a_description_is_the_artefacts_text_and_an_unknown_one_is_none() {
    let shared = shared();
    assert_eq!(
        request_description("LoginDto", "email"),
        shared["LoginDto"]["email"]["description"].as_str()
    );
    assert!(
        request_description("LoginDto", "email").is_some_and(|text| text.contains("lowercased"))
    );
    assert_eq!(request_description("LoginDto", "password"), None);
    assert_eq!(request_description("NoSuchDto", "email"), None);
}
