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
async fn a_family_id_outside_the_claims_form_ends_no_sign_in() {
    let store = InMemoryStores::new();
    store.fail_next_family_removals(1);
    let mut removed = Vec::new();
    let ttl = Duration::from_secs(900);
    let ended = end_sign_in(&store, KIND, "a:b", "subject", ttl, &mut removed).await;
    assert!(ended.is_ok());
    assert!(removed.is_empty());
    assert_eq!(store.ended_session_count(), 0);
    let reached = end_sign_in(&store, KIND, SID, "subject", ttl, &mut removed).await;
    assert!(
        reached.is_err(),
        "the armed family removal was already spent"
    );
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
fn the_contract_row_holds_exactly_these_fields() {
    let row = contract_row();
    let mut fields: Vec<&str> = row
        .as_object()
        .map_or(vec![], |row| row.keys().map(String::as_str).collect());
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["$comment", "key", "reader", "ttl", "value", "writer"]
    );
}

/// Assert that the contract's `field` states every one of `clauses`.
fn states(field: &str, clauses: &[&str]) {
    let rule = contract_row()[field]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for clause in clauses {
        assert!(rule.contains(clause), "{field}: {clause}: {rule}");
    }
}

#[test]
fn the_entry_lives_as_long_as_the_contracts_rule_says() {
    states("ttl", &["access-token lifetime", "rounded up, plus 60"]);
    assert_eq!(CLOCK_MARGIN_SECS, 60);
}

#[test]
fn the_contract_states_the_writer_and_reader_rules_this_module_implements() {
    states(
        "writer",
        &[
            "a logout, an eviction past the session limit",
            "the revocation of one session through the session service and a replayed refresh token",
            "Every refresh session of the family is removed first",
            "the entry is written only after that succeeded",
            "a record without a conforming one ends that session alone and writes nothing",
        ],
    );
    states(
        "reader",
        &[
            "an existing entry refuses, a failed read refuses",
            "a token without a conforming sid is not checked",
        ],
    );
}
