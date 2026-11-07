//! The success of `forgot-password` and `resend-otp` is the one the shared wire contract pins
//! under `responseBodies.passwordResetRequest`: the listed routes answer the listed status with
//! the listed body, byte for byte the same whether or not the account exists. Shares the fixtures
//! of the parent test file.

use super::*;

/// The `responseBodies.passwordResetRequest` entry of the shared wire contract.
fn contract_entry() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["responseBodies"]["passwordResetRequest"].clone()
}

/// The route paths the contract entry names, as mounted under `/auth/`.
fn contract_routes(entry: &serde_json::Value) -> Vec<String> {
    entry["routes"]
        .as_array()
        .map(|routes| {
            routes
                .iter()
                .filter_map(|route| route.as_str().map(|r| format!("/auth/{r}")))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn the_listed_routes_answer_the_contract_body_for_a_known_and_an_unknown_account() {
    let entry = contract_entry();
    let routes = contract_routes(&entry);
    assert_eq!(
        routes.len(),
        2,
        "the contract entry was not read or lists another route set"
    );
    let status = entry["status"].as_u64().unwrap_or(0);

    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "known@e.com", "glidingwalnut42", "USER").await;

    for route in routes {
        let mut raw_bodies = Vec::new();
        for email in ["known@e.com", "ghost@e.com"] {
            let resp = Req::post(&route)
                .json(serde_json::json!({ "email": email, "tenantId": TENANT }))
                .send(&app)
                .await;
            assert_eq!(u64::from(resp.status.as_u16()), status, "{route} {email}");
            assert_eq!(resp.json(), entry["body"], "{route} {email}");
            raw_bodies.push(resp.body);
        }
        assert_eq!(
            raw_bodies[0], raw_bodies[1],
            "{route}: the raw bodies differ"
        );
    }
}

/// The keys of the contract's `failures` object: the rules this crate implements and tests.
const FAILURE_RULES: [&str; 5] = ["after", "before", "cooldown", "floor", "floorMs"];

#[test]
fn the_contract_failure_rules_are_exactly_the_ones_this_crate_implements() {
    let entry = contract_entry();
    let named: std::collections::BTreeSet<String> = entry["failures"]
        .as_object()
        .map(|rules| rules.keys().cloned().collect())
        .unwrap_or_default();
    let implemented: std::collections::BTreeSet<String> = FAILURE_RULES
        .iter()
        .map(|rule| (*rule).to_owned())
        .collect();
    assert_eq!(
        named, implemented,
        "a rule added to the contract must fail here until it is implemented and tested"
    );
    assert_eq!(entry["failures"]["floorMs"].as_u64(), Some(300));
}

#[tokio::test]
async fn every_exit_of_both_routes_waits_the_contract_floor_a_cooldown_hit_included() {
    let entry = contract_entry();
    let floor =
        std::time::Duration::from_millis(entry["failures"]["floorMs"].as_u64().unwrap_or(0));
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "known@e.com", "glidingwalnut42", "USER").await;

    for route in contract_routes(&entry) {
        // The second call of each pair is the cooldown hit.
        for attempt in 0..2 {
            let started = std::time::Instant::now();
            let resp = Req::post(&route)
                .json(serde_json::json!({ "email": "known@e.com", "tenantId": TENANT }))
                .send(&app)
                .await;
            assert_eq!(resp.status.as_u16(), 200, "{route} attempt {attempt}");
            assert!(started.elapsed() >= floor, "{route} attempt {attempt}");
        }
    }
}
