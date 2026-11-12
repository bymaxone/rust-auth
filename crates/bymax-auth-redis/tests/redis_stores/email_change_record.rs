//! The pending address change against `recordEncodings.emailChangeContext` of the shared
//! contract, at a real Redis: written under the key the contract gives it with exactly the fields
//! it names, read back from the form a build that does not bind writes, and consumed once. A
//! child module of the combined store suite, so it reuses that suite's container harness and
//! fixtures.

use std::collections::BTreeSet;

use super::*;

/// The `emailChangeContext` row of the shared contract.
fn contract_row() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["recordEncodings"]["emailChangeContext"].clone()
}

/// The full key the contract gives the record of `token`, under the suite's `auth` namespace. The
/// template's one placeholder is filled in; a template that names anything else is left as it
/// is, and no key the store writes matches it.
fn contract_key(token: &str) -> String {
    let template = contract_row()["key"]
        .as_str()
        .unwrap_or_default()
        .replace("{sha256(token)}", &token_hash(token));
    format!("auth:{template}")
}

fn contract_fields() -> BTreeSet<String> {
    contract_row()["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn the_record_is_written_under_the_contract_key_with_the_contract_fields() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let context = EmailChangeContext {
        user_id: "user-42".to_owned(),
        new_email: "new@example.com".to_owned(),
        tenant_id: "t1".to_owned(),
        password_fingerprint: "a".repeat(64),
    };
    let put = stores.put_email_change("ec-secret", &context, 600).await;
    assert!(put.is_ok());

    let key = contract_key("ec-secret");
    assert!((1..=600).contains(&redis.ttl(&key).await), "{key}");
    let stored = redis.get(&key).await.unwrap_or_default();
    let written: BTreeSet<String> = serde_json::from_str::<serde_json::Value>(&stored)
        .ok()
        .and_then(|record| record.as_object().map(|map| map.keys().cloned().collect()))
        .unwrap_or_default();
    let fields = contract_fields();
    assert!(!fields.is_empty(), "the contract row did not load");
    assert_eq!(written, fields);
    // No raw token is resident as a key.
    assert!(
        redis
            .all_keys()
            .await
            .iter()
            .all(|k| !k.contains("ec-secret"))
    );
}

#[tokio::test]
async fn a_record_without_the_fingerprint_is_read_as_unbound_and_consumed_once() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    // The record as the contract names it, less the field it says may be absent.
    let record: serde_json::Map<String, serde_json::Value> = contract_fields()
        .into_iter()
        .filter(|field| field != "passwordFingerprint")
        .map(|field| {
            let value = format!("{field}-value");
            (field, serde_json::Value::String(value))
        })
        .collect();
    assert_eq!(record.len() + 1, contract_fields().len(), "{record:?}");
    let planted = serde_json::Value::Object(record).to_string();
    assert!(redis.set_raw(&contract_key("ec-planted"), &planted).await);

    assert!(matches!(
        stores.consume_email_change("ec-planted").await,
        Ok(Some(c)) if c.user_id == "userId-value"
            && c.new_email == "newEmail-value"
            && c.tenant_id == "tenantId-value"
            && c.password_fingerprint.is_empty()
    ));
    assert!(matches!(
        stores.consume_email_change("ec-planted").await,
        Ok(None)
    ));
}
