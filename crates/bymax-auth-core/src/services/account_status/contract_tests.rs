//! The account-status cache against the shared wire contract (`userStatusCache`). Every vector is
//! read from the contract file and every one is checked, so a vector added there fails here until
//! the derivation agrees, and one removed fails until the removal is understood. Layer: unit
//! tests over the real subject and HMAC functions.

use bymax_auth_types::MfaContext;

use crate::config::AuthConfig;
use crate::services::{user_subject, user_subject_hash};

/// A section of the contract as it sits in the working tree.
fn contract(section: &str) -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    let found = root
        .get(section)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert!(!found.is_null(), "the contract has no `{section}` section");
    found
}

fn text(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The identifier-HMAC key the contract's vectors use: the 64 hex characters of `derivedKeyHex`
/// taken as TEXT, not decoded.
fn contract_hmac_key() -> [u8; 64] {
    let derivation = contract("hmacKeyDerivation");
    let hex = derivation
        .get("vectors")
        .and_then(|v| v.get(0))
        .map(|v| text(v, "derivedKeyHex"))
        .unwrap_or_default();
    assert_eq!(hex.len(), 64, "the contract's derivedKeyHex did not load");
    let mut key = [0u8; 64];
    key.copy_from_slice(hex.as_bytes());
    key
}

#[test]
fn every_vector_in_the_contract_derives_its_subject_and_digest() {
    let cache = contract("userStatusCache");
    let vectors = cache
        .get("vectors")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!vectors.is_empty(), "the contract carries no vectors");
    let key = contract_hmac_key();
    for vector in &vectors {
        let (tenant, user) = (text(vector, "tenantId"), text(vector, "userId"));
        assert_eq!(
            user_subject(MfaContext::Dashboard, Some(&tenant), &user),
            text(vector, "userSubject"),
            "subject for {tenant:?}/{user:?}"
        );
        assert_eq!(
            user_subject_hash(&key, MfaContext::Dashboard, Some(&tenant), &user),
            text(vector, "digestHex"),
            "digest for {tenant:?}/{user:?}"
        );
    }
    // The case a char-counting implementation gets wrong must stay in the contract: a tenant
    // whose byte length differs from its character count.
    assert!(
        vectors.iter().any(|v| {
            let tenant = text(v, "tenantId");
            tenant.len() != tenant.chars().count()
        }),
        "the contract no longer carries a multi-byte tenant vector"
    );
}

#[test]
fn the_contract_states_the_key_the_value_forms_the_ttl_and_the_invalidation_order() {
    let cache = contract("userStatusCache");
    assert_eq!(
        text(&cache, "key"),
        "{namespace}:{userStatus|userEmailVerified}:{hmac_sha256(hmacKey, userSubject)}"
    );
    let verified = cache.get("emailVerifiedValue").cloned().unwrap_or_default();
    assert_eq!(text(&verified, "verified"), "1");
    assert_eq!(text(&verified, "unverified"), "0");
    // The default TTL both libraries use is the one the contract names.
    let ttl = cache
        .get("ttl")
        .and_then(|t| t.get("default"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(
        ttl,
        Some(AuthConfig::default().user_status_cache_ttl.as_secs())
    );
    let order: Vec<String> = cache
        .get("invalidateOrder")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(order, ["userEmailVerified", "userStatus"]);
}
