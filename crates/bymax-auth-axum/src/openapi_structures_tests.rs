//! The declared-structure accessors, against the copy of the artefact held under `conformance/`.

use std::collections::BTreeSet;

use bymax_auth_crypto::mac::sha256;
use serde_json::Value;

use crate::openapi::{
    DECLARED_STRUCTURES_JSON, declared_operation_semantics, declared_request_structures,
};

/// The shared copy, as it sits in the repository.
const CONFORMANCE_COPY: &str =
    include_str!("../../../conformance/openapi-declared-structures.json");
/// The digest of the artefact the parity tests were written against (nest-auth `48a5409`). A new
/// release of the artefact fails them until they and this digest move together.
const ARTEFACT_SHA256: &str = "78218849b5d1aea392e54fc0b8722e76444d86db9600cb3d77848f0aa3296fd5";

fn shared(section: &str) -> Value {
    serde_json::from_str::<Value>(CONFORMANCE_COPY)
        .map_or(Value::Null, |root| root[section].clone())
}

#[test]
fn the_copy_that_ships_with_the_crate_is_the_shared_artefact_byte_for_byte() {
    assert_eq!(DECLARED_STRUCTURES_JSON, CONFORMANCE_COPY);
}

#[test]
fn the_artefact_is_the_release_the_parity_tests_were_written_against() {
    let hex: String = sha256(CONFORMANCE_COPY.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, ARTEFACT_SHA256);
}

fn keys_of(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, _)| key.clone())
        .collect()
}

#[test]
fn each_accessor_serves_every_entry_of_its_section_and_nothing_else() {
    let structures = declared_request_structures();
    let semantics = declared_operation_semantics();
    let (want_structures, want_semantics) =
        (shared("requestStructures"), shared("operationSemantics"));
    assert!(!want_structures.is_null() && !want_semantics.is_null());
    assert_eq!(
        structures.keys().cloned().collect::<BTreeSet<_>>(),
        keys_of(&want_structures)
    );
    assert_eq!(
        semantics.keys().cloned().collect::<BTreeSet<_>>(),
        keys_of(&want_semantics)
    );
    for (key, entry) in &structures {
        assert_eq!(*entry, want_structures[key.as_str()], "{key}");
    }
    for (key, entry) in &semantics {
        assert_eq!(*entry, want_semantics[key.as_str()], "{key}");
    }
    assert!(!structures.is_empty() && !semantics.is_empty());
}
