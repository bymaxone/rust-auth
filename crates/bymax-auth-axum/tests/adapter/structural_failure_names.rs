//! A request that does not fit its DTO names each failing property by its wire name.
//!
//! What both libraries share for an `auth.validation` answer is the status, the code, the
//! top-level message and the set of distinct `details[].field` values for a given input; the
//! message of each entry is this crate's own, and no message repeats the client's value. The
//! inputs are the ones `nest-auth` measured. Shares the fixtures of the parent test file.

use std::collections::BTreeSet;

use super::*;

/// The distinct fields a validation answer names, after checking its normative parts.
fn named(response: &Captured) -> BTreeSet<String> {
    let body = response.json();
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "auth.validation", "{body}");
    assert_eq!(body["error"]["message"], "Validation failed", "{body}");
    body["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail["field"].as_str().map(str::to_owned))
        .collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

async fn login_with(app: &axum::Router, body: &str) -> Captured {
    Req::post("/auth/login")
        .raw_body(body.as_bytes().to_vec(), "application/json")
        .send(app)
        .await
}

#[tokio::test]
async fn an_empty_body_names_every_required_property() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    assert_eq!(
        named(&login_with(&app, "{}").await),
        set(&["email", "password"])
    );
    // A required property that is `null` is as missing as an absent one.
    let nulls = login_with(&app, r#"{"email":null,"password":null}"#).await;
    assert_eq!(named(&nulls), set(&["email", "password"]));
}

#[tokio::test]
async fn a_value_of_the_wrong_type_names_its_property() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let response = login_with(&app, r#"{"email":5,"password":"x"}"#).await;
    assert_eq!(named(&response), set(&["email"]));
}

#[tokio::test]
async fn a_request_that_fails_by_shape_and_by_bound_names_both() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let response = login_with(&app, r#"{"email":"not-an-email","password":5}"#).await;
    assert_eq!(named(&response), set(&["email", "password"]));
}

#[tokio::test]
async fn an_unknown_property_is_named_and_its_value_is_not_echoed() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let body = r#"{"email":"a@e.com","password":"p","extra":"VALUE-NEVER-ECHOED"}"#;
    let response = login_with(&app, body).await;
    assert_eq!(named(&response), set(&["extra"]));
    let text = String::from_utf8_lossy(&response.body).into_owned();
    assert!(!text.contains("VALUE-NEVER-ECHOED"), "{text}");
}

#[tokio::test]
async fn a_query_that_does_not_fit_names_its_property() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let callback = Req::get("/auth/oauth/google/callback?code=abc")
        .send(&app)
        .await;
    assert_eq!(named(&callback), set(&["state"]));
    let initiate = Req::get("/auth/oauth/google?unexpected=1").send(&app).await;
    assert_eq!(named(&initiate), set(&["unexpected"]));
}
