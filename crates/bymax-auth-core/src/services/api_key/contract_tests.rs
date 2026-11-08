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

/// The behaviour the contract states in prose, field by field, as the code was built against it.
/// Each is the contract's text, so a rule the contract changes fails here until the code that
/// implements it (named beside each) is revisited together with this table.
const PROSE_RULES: [(&str, &str); 5] = [
    // `crypto::api_key::digest`, pinned by the crypto tests, including the digest-over-string case.
    (
        "digest",
        "lowercase hex hmac-sha256 with key = pepper and message = secret, utf-8; labels and scopes are never part of the input",
    ),
    // `ApiKeysConfig::default().header`, the axum module's header read, and the repeated-header test.
    (
        "header",
        "x-api-key by default; read from that header only, never the query string; a repeated header is malformed",
    ),
    // `ApiKeyRuntime::verify`: `expiry <= now` is expired, and `revoked_at.is_some()` is revoked.
    (
        "validity",
        "a key is valid strictly before expiresAt, and not at all once revokedAt is set, on every instance and whatever instant revokedAt holds; a date that does not parse counts as lapsed",
    ),
    // `Guarded::admit` (every declared scope) and `undeclared_route` (an empty list is refused).
    (
        "scopes",
        "a key must hold ALL scopes the route declares; no wildcard and no hierarchy; the most specific declaration wins (handler over class); an empty declaration is undeclared and the route is refused",
    ),
    // `LastUsed` (coalesced) and `ApiKeyRepository::touch_last_used` (monotonic).
    (
        "lastUsed",
        "advisory, coalesced per process and flushed in batches; the store write must be monotonic",
    ),
];

#[test]
fn the_prose_rules_are_the_ones_the_code_was_built_against() {
    let section = contract()["apiKeys"].clone();

    for (field, expected) in PROSE_RULES {
        assert_eq!(section[field].as_str(), Some(expected), "{field}");
    }
    // The default the configuration ships is the name the contract's header text starts with.
    let header = section["header"].as_str().unwrap_or_default();
    assert!(
        header.starts_with(&ApiKeysConfig::default().header),
        "{header}"
    );
}

/// The verification steps as the verifier implements them, in order. Each is the contract's text,
/// so a step the contract replaces, reorders, adds or drops fails the test below until the
/// verifier (`ApiKeyRuntime::verify`) and this table are revisited together.
const VERIFICATION_STEPS: [&str; 6] = [
    // Read by the transport adapter and handed to `verify` as `Option<&str>`.
    "read the header",
    // `api_key::parse(..)` with `DUMMY_KEY_ID` and `DUMMY_SECRET` when it yields `None`.
    "parse, substituting a fixed dummy keyId and dummy secret when absent or malformed",
    // One `find_by_id`, whatever the parse produced.
    "look the keyId up in the store, always",
    // `api_key::digest(secret, pepper)`, always.
    "compute the digest of the secret under the pepper",
    // `api_key::digests_match(computed, stored)` with `DUMMY_DIGEST` when there is no row.
    "compare two 32-byte buffers in constant time, against a fixed dummy digest when there is no row",
    // The `match` on (parsed, row) at the end of `verify`, after everything above has run.
    "only then decide: parsed AND found AND equal AND not revoked AND not expired",
];

#[test]
fn the_verification_steps_are_the_ordered_ones_the_verifier_implements() {
    let steps: Vec<String> = contract()["apiKeys"]["verificationSteps"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|step| step.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    assert_eq!(steps, VERIFICATION_STEPS);
}
