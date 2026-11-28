//! The entry's lifetime and which session ids reach the store.

use super::*;
use crate::testing::InMemoryStores;

const KIND: SessionKind = SessionKind::Dashboard;
const SID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

#[test]
fn the_entry_lives_the_access_lifetime_rounded_up_plus_sixty_seconds() {
    let ttl = |millis: u64| entry_ttl_secs(Duration::from_millis(millis));
    assert_eq!(ttl(0), 60);
    assert_eq!(ttl(1), 61);
    assert_eq!(ttl(900_000), 960);
    assert_eq!(ttl(900_500), 961);
}

#[tokio::test]
async fn a_family_id_outside_the_claims_form_is_not_written() {
    let store = InMemoryStores::new();
    for family in ["", "a:b", "legacy-family", &SID.to_uppercase()] {
        let ended = end_session_access(&store, KIND, family, Duration::from_secs(900)).await;
        assert!(ended.is_ok());
    }
    assert_eq!(store.ended_session_count(), 0);
}

#[tokio::test]
async fn a_sid_outside_the_claims_form_is_not_looked_up() {
    let store = InMemoryStores::new();
    store.fail_session_access_reads(true);
    for sid in [None, Some(""), Some("a:b")] {
        assert_eq!(is_session_ended(&store, KIND, sid).await.ok(), Some(false));
    }
    assert!(is_session_ended(&store, KIND, Some(SID)).await.is_err());
}

#[tokio::test]
async fn an_entry_ends_its_own_plane_only() {
    let store = InMemoryStores::new();
    let ended = end_session_access(&store, KIND, SID, Duration::from_secs(900)).await;
    assert!(ended.is_ok());
    assert_eq!(
        is_session_ended(&store, KIND, Some(SID)).await.ok(),
        Some(true)
    );
    let platform = is_session_ended(&store, SessionKind::Platform, Some(SID)).await;
    assert_eq!(platform.ok(), Some(false));
}

/// The `sessionRevocation` row of the shared contract.
fn contract_row() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["recordEncodings"]["sessionRevocation"].clone()
}

#[test]
fn the_entry_lives_as_long_as_the_contracts_rule_says() {
    let ttl = contract_row()["ttl"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        ttl.contains("rounded up") && ttl.contains("plus 60"),
        "{ttl}"
    );
    assert_eq!(CLOCK_MARGIN_SECS, 60);
}
