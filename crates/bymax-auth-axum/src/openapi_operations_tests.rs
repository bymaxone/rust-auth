//! The operation-security table against the shared artefact, and the requirement each kind becomes
//! under each delivery mode.

use std::collections::{BTreeMap, BTreeSet};

use bymax_auth_core::config::TokenDelivery;
use bymax_auth_crypto::mac::sha256;
use serde_json::Value;

use crate::openapi::{
    ACCESS_BEARER_SCHEME, ACCESS_COOKIE_SCHEME, OperationKind, PLATFORM_BEARER_SCHEME,
    REFRESH_COOKIE_SCHEME, describe_operation, operation_security,
};
use crate::pending::PENDING_OPERATIONS;

/// The shared copy, as it sits in the repository.
const CONFORMANCE_COPY: &str = include_str!("../../../conformance/openapi-operation-security.json");
/// The copy that ships with the crate, which cannot reach outside its own directory.
const CRATE_COPY: &str = include_str!("../openapi/openapi-operation-security.json");
/// The digest of the artefact this table was written against. A new release of the artefact
/// fails the table until the table and this digest are moved together.
const ARTEFACT_SHA256: &str = "41aa87e8ff48c9f417ce2839cdcf86da2cc5f025d3d18aba987437489e004d3a";

fn artefact() -> Value {
    serde_json::from_str(CONFORMANCE_COPY).unwrap_or(Value::Null)
}

/// The artefact key of a table row: `METHOD /path` with `:name` where the table has `{name}`.
fn artefact_key(method: &str, path: &str) -> String {
    let path: Vec<String> = path
        .split('/')
        .map(
            |segment| match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => format!(":{name}"),
                None => segment.to_owned(),
            },
        )
        .collect();
    format!("{method} {}", path.join("/"))
}

#[test]
fn the_copy_that_ships_with_the_crate_is_the_shared_artefact_byte_for_byte() {
    assert_eq!(CRATE_COPY, CONFORMANCE_COPY);
}

#[test]
fn the_artefact_is_the_release_the_table_was_written_against() {
    let hex: String = sha256(CONFORMANCE_COPY.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, ARTEFACT_SHA256);
}

#[test]
fn the_table_and_the_artefact_hold_the_same_operations_with_the_same_kinds() {
    let shared = artefact();
    let expected: BTreeMap<String, String> = shared["operations"]
        .as_object()
        .map(|ops| {
            ops.iter()
                .map(|(key, kind)| (key.clone(), kind.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let table: BTreeMap<String, String> = operation_security()
        .iter()
        .map(|row| {
            (
                artefact_key(row.method, row.path),
                row.kind.name().to_owned(),
            )
        })
        .collect();
    assert_eq!(operation_security().len(), table.len(), "a duplicated row");
    assert!(!expected.is_empty());
    let built: BTreeMap<String, String> = expected
        .iter()
        .filter(|(key, _)| !PENDING_OPERATIONS.contains(&key.as_str()))
        .map(|(key, kind)| (key.clone(), kind.clone()))
        .collect();
    assert_eq!(table, built);
}

#[test]
fn every_pending_operation_is_in_the_artefact_and_has_no_row() {
    let shared = artefact();
    for key in PENDING_OPERATIONS {
        assert!(
            shared["operations"].get(key).is_some(),
            "{key} is pending but the artefact does not carry it"
        );
        assert!(
            operation_security()
                .iter()
                .all(|row| artefact_key(row.method, row.path) != key),
            "{key} has a row; remove it from PENDING_OPERATIONS"
        );
    }
}

#[test]
fn the_kinds_are_the_artefacts_kinds() {
    let names: BTreeSet<&str> = OperationKind::ALL.iter().map(|kind| kind.name()).collect();
    let shared = artefact();
    let expected: BTreeSet<&str> = shared["kinds"]
        .as_object()
        .map(|kinds| kinds.keys().map(String::as_str).collect())
        .unwrap_or_default();
    assert_eq!(names, expected);
    assert_eq!(names.len(), OperationKind::ALL.len());
}

/// An entry as its scheme names, sorted; the empty entry is an empty list.
fn names(entry: &Value) -> Vec<String> {
    let mut schemes: Vec<String> = entry
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    schemes.sort_unstable();
    schemes
}

/// A body as `Some((body required, refreshToken required))`.
type Body = Option<(bool, bool)>;

/// The description of `kind` under `delivery`: the entries, then the body.
fn shape(kind: OperationKind, delivery: TokenDelivery) -> (Vec<Vec<String>>, Body) {
    let described = describe_operation(kind, delivery);
    let entries = described.security.iter().map(names).collect();
    let body = described.request_body.map(|body| {
        let schema = &body["content"]["application/json"]["schema"];
        (
            body["required"].as_bool().unwrap_or(false),
            schema["required"] == serde_json::json!(["refreshToken"]),
        )
    });
    (entries, body)
}

const C: &str = ACCESS_COOKIE_SCHEME;
const B: &str = ACCESS_BEARER_SCHEME;
const R: &str = REFRESH_COOKIE_SCHEME;
const P: &str = PLATFORM_BEARER_SCHEME;
const COOKIE: TokenDelivery = TokenDelivery::Cookie;
const BEARER: TokenDelivery = TokenDelivery::Bearer;
const BOTH: TokenDelivery = TokenDelivery::Both;

/// Asserts the entries (each a list of schemes that must all hold) and the body.
fn check(kind: OperationKind, delivery: TokenDelivery, entries: &[&[&str]], body: Body) {
    let want: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            let mut schemes: Vec<String> = entry.iter().map(|s| (*s).to_owned()).collect();
            schemes.sort_unstable();
            schemes
        })
        .collect();
    assert_eq!(
        shape(kind, delivery),
        (want, body),
        "{kind:?} under {delivery:?}"
    );
}

#[test]
fn an_operation_that_needs_no_credential_declares_an_empty_requirement_everywhere() {
    for delivery in [COOKIE, BEARER, BOTH] {
        check(OperationKind::None, delivery, &[], None);
    }
}

#[test]
fn the_access_token_is_named_by_the_transport_the_deployment_delivers_it_by() {
    check(OperationKind::Access, COOKIE, &[&[C]], None);
    check(OperationKind::Access, BEARER, &[&[B]], None);
    check(OperationKind::Access, BOTH, &[&[C], &[B]], None);
}

#[test]
fn a_required_refresh_credential_is_the_cookie_or_a_body_the_mode_reads() {
    let kind = OperationKind::RefreshRequired;
    check(kind, COOKIE, &[&[R]], None);
    check(kind, BEARER, &[], Some((true, true)));
    check(kind, BOTH, &[&[R], &[]], Some((false, false)));
}

#[test]
fn both_credentials_required_pairs_each_access_form_with_the_refresh_cookie() {
    let kind = OperationKind::AccessAndRefreshRequired;
    check(kind, COOKIE, &[&[C, R]], None);
    check(kind, BEARER, &[&[B]], Some((true, true)));
    check(
        kind,
        BOTH,
        &[&[C, R], &[B, R], &[C], &[B]],
        Some((false, false)),
    );
}

#[test]
fn an_optional_refresh_credential_adds_the_access_form_alone() {
    let kind = OperationKind::AccessWithOptionalRefresh;
    check(kind, COOKIE, &[&[C, R], &[C]], None);
    check(kind, BEARER, &[&[B]], Some((false, false)));
    check(
        kind,
        BOTH,
        &[&[C, R], &[B, R], &[C], &[B]],
        Some((false, false)),
    );
}

#[test]
fn a_method_without_a_body_never_declares_one() {
    let kind = OperationKind::AccessWithOptionalRefreshCookie;
    check(kind, COOKIE, &[&[C, R], &[C]], None);
    check(kind, BEARER, &[&[B]], None);
    check(kind, BOTH, &[&[C, R], &[B, R], &[C], &[B]], None);
}

#[test]
fn logout_requires_nothing_and_names_every_form_it_acts_on() {
    let kind = OperationKind::OptionalAccessAndRefresh;
    check(kind, COOKIE, &[&[C, R], &[C], &[R], &[]], None);
    check(kind, BEARER, &[&[B], &[]], Some((false, false)));
    check(
        kind,
        BOTH,
        &[&[C, R], &[B, R], &[C], &[B], &[R], &[]],
        Some((false, false)),
    );
}

#[test]
fn the_platform_kinds_are_bearer_in_every_delivery_mode() {
    for delivery in [COOKIE, BEARER, BOTH] {
        check(OperationKind::Platform, delivery, &[&[P]], None);
        check(
            OperationKind::PlatformLogout,
            delivery,
            &[&[P], &[]],
            Some((false, true)),
        );
        check(
            OperationKind::PlatformRefresh,
            delivery,
            &[],
            Some((true, true)),
        );
    }
}

#[test]
#[should_panic(expected = "Access under Cookie")]
fn the_expectation_helper_refuses_a_description_that_differs() {
    check(OperationKind::Access, COOKIE, &[&[B]], None);
}
