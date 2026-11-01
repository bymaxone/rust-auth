//! The bodies that carry only a refresh token ignore keys they do not read, as nest-auth's do
//! (they have no DTO), while every other body stays strict about unknown keys. Shares the
//! fixtures of the parent test file.

use bymax_auth_core::config::TokenDelivery;

use super::*;

/// A bearer-mode engine with a seeded user and the refresh token a fresh login hands out.
async fn bearer_session(email: &str) -> Option<(common::Harness, axum::Router, String)> {
    let h = build(EngineSpec {
        delivery: TokenDelivery::Bearer,
        sessions: true,
        ..EngineSpec::default()
    })?;
    seed_user(&h, email, "glidingwalnut42", "USER").await;
    let app = router(&h);
    let token = login(&app, email, "glidingwalnut42").await.json()["refreshToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Some((h, app, token))
}

#[tokio::test]
async fn a_refresh_body_with_an_extra_key_still_refreshes() {
    let Some((_h, app, token)) = bearer_session("extra-r@e.com").await else { return };
    assert!(!token.is_empty());
    let refreshed = Req::post("/auth/refresh")
        .json(serde_json::json!({ "refreshToken": token, "client": "web", "retry": 1 }))
        .send(&app)
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert!(refreshed.json()["refreshToken"].is_string());
}

#[tokio::test]
async fn a_logout_body_with_an_extra_key_still_ends_the_session() {
    let Some((_h, app, token)) = bearer_session("extra-l@e.com").await else { return };
    let access = login(&app, "extra-l@e.com", "glidingwalnut42").await.json()["accessToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let logout = Req::post("/auth/logout")
        .bearer(&access)
        .json(serde_json::json!({ "refreshToken": token, "reason": "user" }))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    // The refresh session named in the body was revoked, so it no longer rotates.
    let after = Req::post("/auth/refresh")
        .json(serde_json::json!({ "refreshToken": token }))
        .send(&app)
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn another_body_still_refuses_an_unknown_key() {
    // The loosening stops at the refresh-token bodies: a login body with a key it does not read
    // is a validation error, so the strictness cannot spread by accident.
    let Some((_h, app, _token)) = bearer_session("strict@e.com").await else { return };
    let refused = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "strict@e.com", "password": "glidingwalnut42", "tenantId": TENANT,
            "remember": true
        }))
        .send(&app)
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}
