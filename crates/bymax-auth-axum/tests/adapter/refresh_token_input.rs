//! `refreshTokenInput` of the shared contract against the routes that read a refresh token (layer:
//! HTTP adapter, test).
//!
//! The section states one rule per channel, as clauses separated by `; `. Each clause is claimed
//! by exactly one scenario below and each scenario by exactly one clause, so a clause the contract
//! adds, drops or splits fails until a scenario drives it. Every scenario takes its bound from
//! `requestFieldBounds.opaqueToken`, the bound the section names as its own. Shares the fixtures
//! of the parent test file.

use std::collections::BTreeSet;

use bymax_auth_core::config::TokenDelivery;
use common::Harness;
use serde_json::Value;

use super::*;

const SOURCE: &str = include_str!("refresh_token_input.rs");

/// Each clause of the section, by channel: the words it opens with and the scenario that drives
/// it.
const CLAUSES: [(&str, &str, &str); 6] = [
    (
        "body",
        "a string of",
        "a_body_string_within_the_bound_is_the_token",
    ),
    (
        "body",
        "a missing field or a JSON null",
        "a_missing_or_null_body_token_is_no_token",
    ),
    (
        "body",
        "anything else present",
        "any_other_present_body_value_is_refused_naming_the_field",
    ),
    (
        "cookie",
        "a value over",
        "an_oversize_cookie_is_refused_except_on_logout",
    ),
    ("cookie", "an empty cookie", "an_empty_cookie_is_no_token"),
    (
        "cookie",
        "under tokenDelivery both",
        "under_both_an_oversize_logout_cookie_leaves_the_body_token",
    ),
];

fn contract() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

fn section() -> Value {
    contract()["refreshTokenInput"].clone()
}

/// `(min, max)` of `requestFieldBounds.opaqueToken`; zero for a bound the contract does not give,
/// which [`the_section_states_the_bound_it_names`] refuses.
fn bound() -> (usize, usize) {
    let field = &contract()["requestFieldBounds"]["opaqueToken"];
    let read = |key: &str| {
        field[key]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0)
    };
    (read("min"), read("max"))
}

#[test]
fn every_clause_of_the_section_is_driven_by_exactly_one_scenario() {
    let section = section();
    let channels: BTreeSet<&str> = section
        .as_object()
        .map(|map| {
            map.keys()
                .map(String::as_str)
                .filter(|key| !key.starts_with('$'))
                .collect()
        })
        .unwrap_or_default();
    let claimed: BTreeSet<&str> = CLAUSES.iter().map(|(channel, ..)| *channel).collect();
    assert_eq!(channels, claimed);
    for channel in channels {
        let rule = section[channel].as_str().unwrap_or_default();
        let clauses: Vec<&str> = rule.split("; ").collect();
        for clause in &clauses {
            let owners = CLAUSES
                .iter()
                .filter(|(c, words, _)| *c == channel && clause.starts_with(words))
                .count();
            assert_eq!(owners, 1, "{channel}: {clause}");
        }
        let scenarios = CLAUSES.iter().filter(|(c, ..)| *c == channel).count();
        assert_eq!(clauses.len(), scenarios, "{channel}: {rule}");
    }
    for (_, _, scenario) in CLAUSES {
        let declared = format!("async fn {scenario}()");
        assert!(
            SOURCE.contains(&declared),
            "{scenario} is not a scenario here"
        );
    }
}

#[test]
fn the_section_states_the_bound_it_names() {
    let (min, max) = bound();
    assert!(min >= 1 && max > min, "opaqueToken is {min}..{max}");
    let section = section();
    let comment: String = section["$comment"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(comment.contains("`opaqueToken`"), "{comment}");
    let body = section["body"].as_str().unwrap_or_default();
    assert!(body.contains(&format!("a string of {min} to {max} characters")));
    let cookie = section["cookie"].as_str().unwrap_or_default();
    assert!(cookie.contains(&format!("a value over {max} characters")));
}

/// An engine in `mode` with a seeded user and the sessions group, the router over it, and the
/// login's access and refresh tokens (from the body, or from the cookies in cookie mode).
async fn signed_in(mode: TokenDelivery) -> Option<(Harness, axum::Router, String, String)> {
    let h = build(EngineSpec {
        delivery: mode,
        sessions: true,
        ..EngineSpec::default()
    })?;
    seed_user(&h, "input@e.com", "glidingwalnut42", "USER").await;
    let app = router(&h);
    let login = login(&app, "input@e.com", "glidingwalnut42").await;
    let body = login.json();
    let token = |key: &str, cookie: &str| {
        body[key]
            .as_str()
            .map(str::to_owned)
            .or_else(|| login.cookie_value(cookie))
            .unwrap_or_default()
    };
    let access = token("accessToken", "access_token");
    let refresh = token("refreshToken", "refresh_token");
    Some((h, app, access, refresh))
}

/// The answer to a refresh whose body is `body`.
async fn refresh_with(app: &axum::Router, body: Value) -> Captured {
    Req::post("/auth/refresh").json(body).send(app).await
}

/// Whether a response is the `auth.validation` refusal naming `refreshToken`.
fn names_refresh_token(response: &Captured) -> bool {
    let body = response.json();
    response.status == StatusCode::BAD_REQUEST
        && body["error"]["code"] == "auth.validation"
        && body["error"]["details"][0]["field"] == "refreshToken"
}

/// Whether a response is the invalid-refresh answer: the value was taken as a token, or as no
/// token, and was never refused as malformed.
fn reached_the_lookup(response: &Captured) -> bool {
    response.status == StatusCode::UNAUTHORIZED
        && response.json()["error"]["code"] == "auth.refresh_token_invalid"
}

#[tokio::test]
async fn a_body_string_within_the_bound_is_the_token() {
    let Some((_h, app, _, refresh)) = signed_in(TokenDelivery::Bearer).await else { return };
    let (min, max) = bound();
    for len in [min, max] {
        let answer =
            refresh_with(&app, serde_json::json!({ "refreshToken": "x".repeat(len) })).await;
        assert!(reached_the_lookup(&answer), "{len}: {}", answer.json());
    }
    let rotated = refresh_with(&app, serde_json::json!({ "refreshToken": refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK);
}

#[tokio::test]
async fn a_missing_or_null_body_token_is_no_token() {
    let Some((_h, app, ..)) = signed_in(TokenDelivery::Bearer).await else { return };
    for body in [
        serde_json::json!({}),
        serde_json::json!({ "refreshToken": null }),
    ] {
        let answer = refresh_with(&app, body.clone()).await;
        assert!(reached_the_lookup(&answer), "{body}: {}", answer.json());
    }
}

#[tokio::test]
async fn any_other_present_body_value_is_refused_naming_the_field() {
    let Some((_h, app, _, refresh)) = signed_in(TokenDelivery::Bearer).await else { return };
    let (_, max) = bound();
    for value in [
        Value::String(String::new()),
        Value::String("x".repeat(max + 1)),
        serde_json::json!(5),
        serde_json::json!(true),
        serde_json::json!({ "a": 1 }),
        serde_json::json!(["a"]),
    ] {
        let answer = refresh_with(&app, serde_json::json!({ "refreshToken": value })).await;
        assert!(names_refresh_token(&answer), "{value}: {}", answer.json());
    }
    // Refused before any lookup: the session the caller holds was not touched.
    let rotated = refresh_with(&app, serde_json::json!({ "refreshToken": refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK);
}

#[tokio::test]
async fn an_oversize_cookie_is_refused_except_on_logout() {
    let Some((_h, app, access, refresh)) = signed_in(TokenDelivery::Cookie).await else { return };
    let (_, max) = bound();
    let oversize = "x".repeat(max + 1);
    let refused = Req::post("/auth/refresh")
        .cookie("refresh_token", &oversize)
        .send(&app)
        .await;
    assert!(names_refresh_token(&refused), "{}", refused.json());
    let at_bound = Req::post("/auth/refresh")
        .cookie("refresh_token", &"x".repeat(max))
        .send(&app)
        .await;
    assert!(reached_the_lookup(&at_bound), "{}", at_bound.json());
    // Logout reads it as no token: 204, the auth cookies cleared, the access token blacklisted,
    // and no refresh session touched.
    let logout = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .cookie("refresh_token", &oversize)
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    assert!(!logout.has_cookie_value("access_token") && !logout.set_cookies.is_empty());
    let me = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
}

#[tokio::test]
async fn an_empty_cookie_is_no_token() {
    let Some((_h, app, ..)) = signed_in(TokenDelivery::Cookie).await else { return };
    let answer = Req::post("/auth/refresh")
        .cookie("refresh_token", "")
        .send(&app)
        .await;
    assert!(reached_the_lookup(&answer), "{}", answer.json());
}

#[tokio::test]
async fn under_both_an_oversize_logout_cookie_leaves_the_body_token() {
    let Some((_h, app, access, refresh)) = signed_in(TokenDelivery::Both).await else { return };
    let (_, max) = bound();
    let logout = Req::post("/auth/logout")
        .bearer(&access)
        .cookie("refresh_token", &"x".repeat(max + 1))
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    // The body's token was the one that applied: its session is revoked.
    let revoked = refresh_with(&app, serde_json::json!({ "refreshToken": refresh })).await;
    assert!(reached_the_lookup(&revoked), "{}", revoked.json());
}
