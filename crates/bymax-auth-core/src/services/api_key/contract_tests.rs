//! The service-key behaviour the shared wire contract pins, read from the contract and compared in
//! both directions, so a section or a refusal the contract adds fails here until it is implemented
//! and one it drops fails until the removal is understood. The grammar, the digest vector and the
//! audit names are pinned next to the code that owns them; this file pins what is left.

use std::collections::BTreeSet;

use bymax_auth_types::AuthError;
use serde_json::Value;

use crate::config::ApiKeysConfig;

const CONTRACT: &str = include_str!("../../../../../conformance/wire-contract.json");

fn contract() -> Value {
    serde_json::from_str(CONTRACT).unwrap_or(Value::Null)
}

fn keys_of(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[test]
fn every_section_of_the_api_keys_contract_is_accounted_for() {
    // A section added to or dropped from the contract fails here until someone decides which
    // test or behaviour owns it.
    assert_eq!(
        keys_of(&contract()["apiKeys"]),
        set(&[
            "$comment",
            "auditEvent",
            "digest",
            "header",
            "keyGrammar",
            "lastUsed",
            "refusals",
            "scopes",
            "validity",
            "vector",
            "verificationSteps",
        ])
    );
}

#[test]
fn the_refusals_are_exactly_the_codes_the_decision_answers_with_and_their_statuses() {
    let root = contract();
    let refusals = keys_of(&root["apiKeys"]["refusals"]);
    assert_eq!(
        refusals,
        set(&["api_key_invalid", "api_key_scope_insufficient", "forbidden"])
    );

    let ours = [
        ("api_key_invalid", AuthError::ApiKeyInvalid),
        (
            "api_key_scope_insufficient",
            AuthError::ApiKeyScopeInsufficient,
        ),
        ("forbidden", AuthError::Forbidden),
    ];
    for (name, error) in ours {
        let wire = format!("auth.{name}");
        assert_eq!(
            serde_json::to_value(error.code()).ok(),
            Some(Value::from(wire.clone()))
        );
        assert_eq!(
            root["errorCatalog"]["statuses"][wire.as_str()],
            Value::from(error.http_status()),
            "{name}"
        );
    }
}

#[test]
fn the_default_header_is_the_one_the_contract_names() {
    let header = contract()["apiKeys"]["header"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    assert!(
        header.starts_with(&ApiKeysConfig::default().header),
        "{header}"
    );
    assert!(header.contains("never the query string"));
    assert!(header.contains("repeated header is malformed"));
}

#[test]
fn the_verification_has_the_six_steps_the_verifier_is_built_around() {
    // The verifier's order is exercised by its tests (one row read for every refusal); a seventh
    // or a dropped step in the contract fails here until the verifier is revisited.
    let steps = contract()["apiKeys"]["verificationSteps"]
        .as_array()
        .map(Vec::len);

    assert_eq!(steps, Some(6));
}
