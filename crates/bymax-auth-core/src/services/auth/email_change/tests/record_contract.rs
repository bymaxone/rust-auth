//! The pending address change against `recordEncodings.emailChangeContext` of the shared contract
//! (layer: core services, test support).
//!
//! The record carries exactly the fields the contract names, a requested change stores the
//! address already normalized and the fingerprint the contract defines, and a record without the
//! fingerprint reads as unbound and still confirms. The key the contract gives the record is the
//! Redis store's, and is asserted against a real Redis in that crate's suite.

use std::collections::BTreeSet;

use bymax_auth_crypto::mac::sha256;
use serde_json::Value;

use super::*;
use crate::services::auth::password_reset::password_fingerprint;

/// The `emailChangeContext` row of the shared contract.
fn contract_row() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    root["recordEncodings"]["emailChangeContext"].clone()
}

/// The field names the row declares. Empty when the contract did not load, which the callers
/// assert against, so a missing file fails rather than comparing nothing.
fn contract_fields() -> BTreeSet<String> {
    contract_row()["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn context(user_id: &str, new_email: &str) -> EmailChangeContext {
    EmailChangeContext {
        user_id: user_id.to_owned(),
        new_email: new_email.to_owned(),
        tenant_id: "t1".to_owned(),
        password_fingerprint: "f".repeat(64),
    }
}

#[test]
fn the_record_carries_exactly_the_fields_the_contract_names() {
    // Both directions: a field the contract adds fails until it is written, and a field written
    // here that the contract does not name is one the sibling backend does not read.
    let fields = contract_fields();
    assert!(!fields.is_empty(), "the contract row did not load");
    let written: BTreeSet<String> = serde_json::to_value(context("u1", "new@example.com"))
        .ok()
        .and_then(|record| record.as_object().map(|map| map.keys().cloned().collect()))
        .unwrap_or_default();
    assert_eq!(written, fields);
}

#[tokio::test]
async fn a_requested_change_stores_the_normalized_address_and_the_password_fingerprint() {
    let Some(h) = setup() else { return };
    let id = h.seed(SeedUser::active("old@example.com", "right")).await;
    let requested = h
        .engine
        .request_email_change("t1", &id, "  New@Example.COM ", "right")
        .await;
    assert!(requested.is_ok());
    let token = h.emails.email_change_token().unwrap_or_default();
    let stored = h.stores.consume_email_change(&token).await.ok().flatten();
    let phc = h
        .users
        .find_by_id(&id, None)
        .await
        .ok()
        .flatten()
        .and_then(|user| user.password_hash)
        .unwrap_or_default();
    assert!(!phc.is_empty(), "the seeded account has no password hash");
    // `passwordFingerprint` is the sha256 of the account's password hash when the token was minted.
    let rule = contract_row()["passwordFingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        rule.starts_with("sha256 of the account's password hash"),
        "{rule}"
    );
    assert!(matches!(
        stored,
        Some(ref c) if c.new_email == "new@example.com"
            && c.user_id == id
            && c.tenant_id == "t1"
            && c.password_fingerprint == hex(&sha256(phc.as_bytes()))
    ));
}

#[tokio::test]
async fn an_account_without_a_password_fingerprints_as_the_empty_string() {
    let rule = contract_row()["passwordFingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        rule.ends_with("or the empty string when the account had none."),
        "{rule}"
    );
    let Some(h) = setup() else { return };
    let created = h
        .users
        .create(bymax_auth_types::CreateUserData {
            email: "oauth@example.com".to_owned(),
            name: "N".to_owned(),
            password_hash: None,
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    assert!(matches!(created, Ok(ref user) if password_fingerprint(user).is_empty()));
}

#[tokio::test]
async fn a_record_without_the_fingerprint_reads_as_unbound_and_confirms() {
    // The contract: an ABSENT `passwordFingerprint` is read as no binding and accepted, so a
    // record written by a build that does not bind still confirms.
    assert!(contract_fields().contains("passwordFingerprint"));
    let Some(h) = setup() else { return };
    let id = h.seed(SeedUser::active("old@example.com", "right")).await;
    let mut record = serde_json::to_value(context(&id, "moved@example.com")).unwrap_or_default();
    if let Some(map) = record.as_object_mut() {
        map.remove("passwordFingerprint");
    }
    let parsed = serde_json::from_value::<EmailChangeContext>(record).ok();
    assert!(matches!(parsed, Some(ref c) if c.password_fingerprint.is_empty()));
    let token = "a".repeat(64);
    let Some(parsed) = parsed else { return };
    let stored = h.stores.put_email_change(&token, &parsed, 600).await;
    assert!(stored.is_ok());
    assert!(h.engine.confirm_email_change(&token).await.is_ok());
    assert_eq!(
        stored_email(&h, &id).await.as_deref(),
        Some("moved@example.com")
    );
}
