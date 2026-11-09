//! A validation error names a field the way the wire does. The DTOs are Rust structs, so
//! `garde` reports Rust field paths (`tenant_id`), and a client keys its form errors by the
//! property it sent (`tenantId`). The body routes are covered by the route probe in
//! `openapi_routes.rs`; the OAuth queries are not body routes, so they are covered here,
//! including the two provider-named fields that are already their own wire names.

use super::*;

/// The `field` of every detail in a validation response.
fn error_fields(response: &Captured) -> Vec<String> {
    response.json()["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail["field"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn an_oauth_query_names_its_fields_as_the_wire_does() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let long_tenant = "t".repeat(129);
    let initiate = Req::get(&format!("/auth/oauth/google?tenantId={long_tenant}"))
        .send(&app)
        .await;
    assert_eq!(initiate.status, StatusCode::BAD_REQUEST);
    assert_eq!(error_fields(&initiate), ["tenantId"]);

    // The provider's own names: the DTO reads them as sent, so the error names them as sent.
    let long_text = "d".repeat(513);
    for field in ["error_description", "error_uri"] {
        let callback = Req::get(&format!(
            "/auth/oauth/google/callback?state=deadbeef&error=access_denied&{field}={long_text}"
        ))
        .send(&app)
        .await;
        assert_eq!(callback.status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(error_fields(&callback), [field], "{field}");
    }
}
