//! The password re-proof failure counters of `change-password` and `email-change`: their bytes
//! against `reproofCounterVectors` in the shared wire contract, and their tenant scope through
//! the real service API.
//!
//! Test layer: the engine's auth services over the in-memory repositories and stores.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bymax_auth_types::{AuthError, CreateUserData, MfaContext};
use serde_json::Value;

use super::test_support::{base_config, harness, hash_password};
use crate::config::Environment;
use crate::engine::AuthEngine;
use crate::services::user_subject;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::UserRepository;

/// The two flows this crate derives a re-proof counter for.
const FLOWS: [&str; 2] = ["change-password", "email-change"];

/// The shared wire contract, parsed.
fn contract() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

/// The vectors of the section, as read from the contract.
fn vectors() -> Vec<Value> {
    contract()["reproofCounterVectors"]["vectors"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The keys of a JSON object, as a set.
fn key_set(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

/// The text of `field` on a JSON object.
fn text<'a>(object: &'a Value, field: &str) -> &'a str {
    object[field].as_str().unwrap_or_default()
}

/// `names` as an owned set.
fn set_of(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_section_and_its_vectors_carry_exactly_the_declared_keys() {
    assert_eq!(
        key_set(&contract()["reproofCounterVectors"]),
        set_of(&["$comment", "hmacKeySource", "vectors"])
    );
    let vectors = vectors();
    assert!(!vectors.is_empty(), "the contract did not load its vectors");
    let shape = set_of(&[
        "flow",
        "tenantId",
        "userId",
        "userSubject",
        "identifierHex",
        "key",
    ]);
    for vector in &vectors {
        assert_eq!(key_set(vector), shape, "unexpected vector keys: {vector}");
    }
    let flows: BTreeSet<String> = vectors
        .iter()
        .map(|vector| text(vector, "flow").to_owned())
        .collect();
    assert_eq!(
        flows,
        set_of(&FLOWS),
        "vector flows and the code's flows differ"
    );
}

/// The `userSubjectDerivedKeys` entries that count a failed password re-proof: the MFA flow's own
/// and one per flow of this crate.
const REPROOF_TEMPLATES: [&str; 3] = [
    "reauthFailureCounter",
    "changePasswordFailureCounter",
    "emailChangeFailureCounter",
];

#[test]
fn the_derived_key_templates_name_the_flows_the_code_uses() {
    let contract = contract();
    let derived = contract["userSubjectDerivedKeys"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    // Every entry of the section whose template derives a re-proof counter, found by reading the
    // whole section, so a counter added to the contract without a flow here fails this test.
    let found: BTreeMap<String, String> = derived
        .iter()
        .filter_map(|(name, template)| {
            let template = template.as_str()?;
            template
                .contains("'reauth:")
                .then(|| (name.clone(), template.to_owned()))
        })
        .collect();
    assert_eq!(
        found.keys().cloned().collect::<BTreeSet<_>>(),
        set_of(&REPROOF_TEMPLATES),
        "the contract's re-proof counter templates and the ones this crate derives differ"
    );
    for (name, flow) in [
        ("changePasswordFailureCounter", FLOWS[0]),
        ("emailChangeFailureCounter", FLOWS[1]),
    ] {
        let template = found.get(name).map(String::as_str).unwrap_or_default();
        assert!(
            template.contains(&format!("'reauth:{flow}:{{userSubject}}'")),
            "`userSubjectDerivedKeys.{name}` does not derive the `{flow}` counter: {template}"
        );
    }
}

#[test]
fn every_vector_is_reproduced_byte_for_byte() {
    // The secret behind the vectors' key is read from the contract rather than assumed.
    let contract = contract();
    let key_vector = &contract["hmacKeyDerivation"]["vectors"][0];
    let mut cfg = base_config();
    cfg.jwt.secret = secrecy::SecretString::from(text(key_vector, "secret").to_owned());
    let Some(h) = harness(cfg, None) else { return };
    assert_eq!(
        h.engine.config().hmac_key().as_slice(),
        text(key_vector, "derivedKeyHex").as_bytes(),
        "the engine's identifier key is not the one the vectors name"
    );

    let vectors = vectors();
    assert!(!vectors.is_empty());
    for vector in &vectors {
        let (tenant, user) = (text(vector, "tenantId"), text(vector, "userId"));
        assert_eq!(
            user_subject(MfaContext::Dashboard, Some(tenant), user),
            text(vector, "userSubject")
        );
        let id = h
            .engine
            .reproof_identifier(text(vector, "flow"), tenant, user);
        assert_eq!(
            id,
            text(vector, "identifierHex"),
            "identifier drifted: {vector}"
        );
        assert_eq!(format!("lf:{id}"), text(vector, "key"));
    }
}

/// An engine with its own user repository over a SHARED store, so two of them model two
/// tenants whose repositories both number their first user `user-1`.
fn engine_over(stores: &Arc<InMemoryStores>) -> Option<(AuthEngine, Arc<InMemoryUserRepository>)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let engine = AuthEngine::builder()
        .config(base_config())
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .build()
        .ok()?;
    Some((engine, users))
}

/// Seed an active user whose password is `right`, returning its id.
async fn seed(users: &InMemoryUserRepository, tenant: &str, email: &str) -> String {
    let created = users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "Seed User".to_owned(),
            password_hash: Some(hash_password("right")),
            role: None,
            status: Some("ACTIVE".to_owned()),
            tenant_id: tenant.to_owned(),
            email_verified: Some(true),
        })
        .await;
    created.map(|user| user.id).unwrap_or_default()
}

#[tokio::test]
async fn failures_in_one_tenant_do_not_lock_the_same_id_in_another() {
    let stores = Arc::new(InMemoryStores::new());
    let (Some((a, users_a)), Some((b, users_b))) = (engine_over(&stores), engine_over(&stores))
    else {
        return;
    };
    let id_a = seed(&users_a, "tenant-a", "a@example.com").await;
    let id_b = seed(&users_b, "tenant-b", "b@example.com").await;
    assert!(!id_a.is_empty());
    assert_eq!(id_a, id_b, "the tenants must share a user id for this test");

    for _ in 0..base_config().brute_force.max_attempts {
        let _ = a
            .change_password("tenant-a", &id_a, "wrong", "glidingwalnut42", None)
            .await;
        let _ = a
            .request_email_change("tenant-a", &id_a, "n@example.com", "wrong")
            .await;
    }
    let locked_password = a
        .change_password("tenant-a", &id_a, "right", "glidingwalnut42", None)
        .await;
    assert!(matches!(
        locked_password,
        Err(AuthError::AccountLocked { .. })
    ));
    let locked_email = a
        .request_email_change("tenant-a", &id_a, "n@example.com", "right")
        .await;
    assert!(matches!(locked_email, Err(AuthError::AccountLocked { .. })));

    let spared_email = b
        .request_email_change("tenant-b", &id_b, "n2@example.com", "right")
        .await;
    assert!(
        spared_email.is_ok(),
        "tenant B was locked: {spared_email:?}"
    );
    // The password changes last: the email change must still see the original password.
    let spared_password = b
        .change_password("tenant-b", &id_b, "right", "glidingwalnut42", None)
        .await;
    assert!(
        spared_password.is_ok(),
        "tenant B was locked: {spared_password:?}"
    );
}
