//! The entry that ends one session's access tokens, against a real Redis: its key per plane, its
//! value and its TTL. A child module of the combined store suite, so it reuses that suite's
//! container harness.

use super::*;

const SID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

/// The `sessionRevocation` row of the shared contract.
fn contract_row() -> serde_json::Value {
    let raw = include_str!("../../../../conformance/wire-contract.json");
    let root: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    root["recordEncodings"]["sessionRevocation"].clone()
}

/// The key the contract gives `kind`'s entry for [`SID`], under the suite's namespace.
fn contract_key(row: &serde_json::Value, kind: SessionKind) -> String {
    let plane = match kind {
        SessionKind::Dashboard => " on the dashboard plane",
        SessionKind::Platform => " on the platform plane",
    };
    let template = row["key"]
        .as_str()
        .and_then(|rule| rule.split(", ").find_map(|part| part.strip_suffix(plane)))
        .unwrap_or_default();
    format!("auth:{}", template.replace("{sid}", SID))
}

#[tokio::test]
async fn the_entry_is_written_under_the_contract_s_key_with_its_value_and_the_ttl() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { unreachable!() };

    let row = contract_row();
    let value = row["value"].as_str().unwrap_or_default();
    for (kind, other) in [
        (SessionKind::Dashboard, SessionKind::Platform),
        (SessionKind::Platform, SessionKind::Dashboard),
    ] {
        let key = contract_key(&row, kind);
        let before = stores.is_session_access_revoked(kind, SID).await;
        assert_eq!(before.ok(), Some(false));
        assert!(stores.revoke_session_access(kind, SID, 960).await.is_ok());

        assert_eq!(redis.get(&key).await.as_deref(), Some(value));
        let ttl = redis.ttl(&key).await;
        assert!((900..=960).contains(&ttl), "ttl {ttl}");
        let after = stores.is_session_access_revoked(kind, SID).await;
        assert_eq!(after.ok(), Some(true));
        // The other plane's entry is another key.
        if kind == SessionKind::Dashboard {
            let elsewhere = stores.is_session_access_revoked(other, SID).await;
            assert_eq!(elsewhere.ok(), Some(false));
        }
    }
}
