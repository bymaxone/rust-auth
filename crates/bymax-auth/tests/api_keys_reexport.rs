//! A consumer of the facade with both `axum` and `api-keys` gets the API-key adapter: enabling the
//! facade feature must reach the adapter crate, or its layer, extractor and flush task do not exist.

#![cfg(all(feature = "axum", feature = "api-keys"))]

#[test]
fn the_facade_exposes_the_api_key_adapter_when_both_features_are_on() {
    // Naming the items is the assertion: without the forwarding this does not compile.
    let items = (
        bymax_auth::axum::require_api_key_scopes,
        bymax_auth::axum::spawn_api_key_flush,
    );
    let extractor: Option<bymax_auth::axum::CurrentApiKey> = None;

    std::hint::black_box(items);
    assert!(extractor.is_none());
}
