//! The recent-authentication mark against the shared contract (layer: service, tests).
//!
//! Every vector is read from `recentAuthMarkerVectors` of `conformance/wire-contract.json` and
//! derived here; none is typed into this file. Each vector's fields are taken out of a copy of the
//! object one by one and the copy must end up empty, so a field a later contract adds fails until
//! it is derived. The key is the HMAC of the userSubject under the TEXT of the contract's derived
//! key, then `:` and the sid as it is.

use serde_json::{Map, Value};

use super::{session_id, user_subject, user_subject_hash};
use crate::traits::{SessionKind, SessionRecord, SessionStore};
use bymax_auth_types::MfaContext;
use time::OffsetDateTime;

/// The contract, parsed; `Null` when it cannot be read, which fails every assertion below
/// instead of passing them over nothing.
fn contract() -> Value {
    let path = format!(
        "{}/../../conformance/wire-contract.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

/// The vectors of the section, each as an object; a failure when there are none.
fn vectors(root: &Value) -> Vec<Map<String, Value>> {
    let list: Vec<Map<String, Value>> = root["recentAuthMarkerVectors"]["vectors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_object().cloned())
        .collect();
    assert!(!list.is_empty(), "the pinned vectors did not load");
    list
}

/// Removes `field` from `vector` and returns it as text.
fn take(vector: &mut Map<String, Value>, field: &str) -> String {
    let value = vector.remove(field);
    assert!(value.is_some(), "the vector has no field {field}");
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The identifier key the vectors use: the hex text of `hmacKeyDerivation`'s derived key.
fn identifier_key(root: &Value) -> [u8; 64] {
    let source = root["recentAuthMarkerVectors"]["hmacKeySource"].as_str();
    assert_eq!(
        source,
        Some("hmacKeyDerivation.vectors[0].derivedKeyHex, as text")
    );
    let hex = root["hmacKeyDerivation"]["vectors"][0]["derivedKeyHex"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(hex.len(), 64, "the pinned derived key did not load");
    let mut key = [0_u8; 64];
    key.copy_from_slice(hex.as_bytes());
    key
}

#[test]
fn every_pinned_marker_key_is_derived_from_its_subject_and_sid() {
    let root = contract();
    let key = identifier_key(&root);
    for mut vector in vectors(&root) {
        let tenant = take(&mut vector, "tenantId");
        let user = take(&mut vector, "userId");
        let subject = take(&mut vector, "userSubject");
        let sid = take(&mut vector, "sid");
        let identifier = take(&mut vector, "identifierHex");
        let expected = take(&mut vector, "key");
        assert!(
            vector.is_empty(),
            "a vector field is not derived: {vector:?}"
        );

        assert_eq!(
            user_subject(MfaContext::Dashboard, Some(&tenant), &user),
            subject
        );
        let derived = user_subject_hash(&key, MfaContext::Dashboard, Some(&tenant), &user);
        assert_eq!(derived, identifier);
        assert_eq!(format!("ra:{derived}:{sid}"), expected);
        assert!(
            session_id(&sid).is_some(),
            "a pinned sid must be a conforming one"
        );
    }
}

#[tokio::test]
async fn a_pinned_marker_is_found_by_its_subject_and_its_own_sid_only() {
    let root = contract();
    let all = vectors(&root);
    let store = crate::testing::InMemoryStores::new();
    let Some(first) = all.first() else { return };
    let identifier = first["identifierHex"].as_str().unwrap_or_default();
    let sid = first["sid"].as_str().unwrap_or_default();
    let record = SessionRecord {
        user_id: "u1".to_owned(),
        tenant_id: Some("acme".to_owned()),
        role: "USER".to_owned(),
        device: String::new(),
        ip: String::new(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        mfa_enabled: false,
        mfa_verified: false,
        family_id: sid.to_owned(),
        family_created_at: None,
    };
    let planted = store
        .create_session_with_recent_auth(SessionKind::Dashboard, identifier, "th", &record, 60, 300)
        .await;
    assert!(planted.is_ok());
    assert!(matches!(
        store.has_recent_auth(identifier, sid).await,
        Ok(true)
    ));
    let other_sid = "22222222-2222-4333-8444-555555555555";
    assert!(matches!(
        store.has_recent_auth(identifier, other_sid).await,
        Ok(false)
    ));
    for other in all.iter().skip(1) {
        let other_identifier = other["identifierHex"].as_str().unwrap_or_default();
        assert!(matches!(
            store.has_recent_auth(other_identifier, sid).await,
            Ok(false)
        ));
    }
}

#[test]
fn a_session_id_is_only_the_form_the_contract_defines() {
    // `sessionClaim.format`: 36 characters, lowercase hexadecimal and hyphens in 8-4-4-4-12.
    let format = contract()["accessTokenClaims"]["sessionClaim"]["format"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_default();
    assert!(
        format.contains("8-4-4-4-12"),
        "the pinned format did not load"
    );
    let valid = "11111111-2222-4333-8444-555555555555";
    assert_eq!(session_id(valid), Some(valid));
    for refused in [
        "",
        "11111111-2222-4333-8444-55555555555",
        "11111111-2222-4333-8444-5555555555555",
        "11111111-2222-4333-8444-55555555555G",
        "11111111-2222-4333-8444-55555555555A",
        "11111111-2222-4333-8444-555555555555-",
        "11111111222243338444555555555555",
        "1111111-12222-4333-8444-555555555555",
        "11111111-2222-4333-8444-555555555555:x",
    ] {
        assert_eq!(session_id(refused), None, "{refused:?} must read as absent");
    }
}
