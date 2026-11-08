//! The audit vocabulary is the shared contract's, in both directions: a name the contract adds
//! must fail the build until it is mapped, and one it drops must fail until the removal is
//! understood.

use std::collections::BTreeSet;

use std::collections::BTreeMap;

use super::{ApiKeyAccessEvent, ApiKeyDenyReason, ApiKeyOutcome, HookPlane};
use crate::traits::{AuthHooks, HookContext, NoOpAuthHooks};

const CONTRACT: &str = include_str!("../../../../conformance/wire-contract.json");

/// The strings the contract lists under `apiKeys.auditEvent.{key}`.
fn contract_names(key: &str) -> BTreeSet<String> {
    let parsed: serde_json::Value = serde_json::from_str(CONTRACT).unwrap_or_default();
    parsed["apiKeys"]["auditEvent"][key]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_outcomes_are_exactly_the_contracts() {
    let ours: BTreeSet<String> = [ApiKeyOutcome::Allowed, ApiKeyOutcome::Denied]
        .iter()
        .map(|o| o.as_str().to_owned())
        .collect();

    assert!(
        !contract_names("outcome").is_empty(),
        "the contract section did not load"
    );
    assert_eq!(ours, contract_names("outcome"));
}

#[test]
fn the_deny_reasons_are_exactly_the_contracts() {
    let ours: BTreeSet<String> = [
        ApiKeyDenyReason::Missing,
        ApiKeyDenyReason::Malformed,
        ApiKeyDenyReason::Unknown,
        ApiKeyDenyReason::WrongSecret,
        ApiKeyDenyReason::Revoked,
        ApiKeyDenyReason::Expired,
        ApiKeyDenyReason::ScopeInsufficient,
        ApiKeyDenyReason::RouteUndeclared,
        ApiKeyDenyReason::StoreError,
    ]
    .iter()
    .map(|r| r.as_str().to_owned())
    .collect();

    assert!(
        !contract_names("reason").is_empty(),
        "the contract section did not load"
    );
    assert_eq!(ours, contract_names("reason"));
}

#[test]
fn every_reason_is_named_in_an_exhaustive_match() {
    // Compile-time anchor, like the one over the error codes: adding a reason stops the build
    // here until it is also added to the list in the test above.
    let named = |reason: ApiKeyDenyReason| match reason {
        ApiKeyDenyReason::Missing
        | ApiKeyDenyReason::Malformed
        | ApiKeyDenyReason::Unknown
        | ApiKeyDenyReason::WrongSecret
        | ApiKeyDenyReason::Revoked
        | ApiKeyDenyReason::Expired
        | ApiKeyDenyReason::ScopeInsufficient
        | ApiKeyDenyReason::RouteUndeclared
        | ApiKeyDenyReason::StoreError => true,
    };
    assert!(named(ApiKeyDenyReason::Missing));
}

#[test]
fn the_machine_plane_has_its_own_spelling() {
    assert_eq!(HookPlane::ApiKey.as_str(), "api_key");
}

#[tokio::test]
async fn the_default_hook_accepts_every_event() {
    let event = ApiKeyAccessEvent {
        outcome: ApiKeyOutcome::Denied,
        reason: Some(ApiKeyDenyReason::Missing),
        key_id: None,
        label: None,
        method: "GET".to_owned(),
        route: "/reports".to_owned(),
        required_scopes: vec!["admin".to_owned()],
        ip: "203.0.113.9".to_owned(),
    };
    let ctx = HookContext {
        plane: HookPlane::ApiKey,
        user_id: None,
        email: None,
        tenant_id: None,
        ip: "203.0.113.9".to_owned(),
        user_agent: String::new(),
        sanitized_headers: BTreeMap::new(),
    };

    assert!(NoOpAuthHooks.on_api_key_request(&event, &ctx).await.is_ok());
}
