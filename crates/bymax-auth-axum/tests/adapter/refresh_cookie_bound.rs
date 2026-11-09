//! The refresh cookie is held to the bound the body value is held to: 1 to 2048 characters.
//!
//! An empty cookie is no token; a cookie of exactly 2048 characters is a token; a longer one is
//! refused as `auth.validation` naming `refreshToken` before anything is looked up. Logout alone
//! treats an oversize cookie as no token, because a cookie planted by a sibling subdomain must
//! not stop the user from signing out: it answers 204, clears the auth cookies and still revokes
//! the access token, but touches no refresh session. Shares the fixtures of the parent test
//! file.

use bymax_auth_core::config::TokenDelivery;
use common::Harness;

use super::*;

const LIMIT: usize = 2048;

/// An engine in `mode` with a seeded user and the sessions group, and the router over it.
async fn app_in(mode: TokenDelivery) -> Option<(Harness, axum::Router)> {
    let h = build(EngineSpec {
        delivery: mode,
        sessions: true,
        ..EngineSpec::default()
    })?;
    seed_user(&h, "u@e.com", "glidingwalnut42", "USER").await;
    let app = router(&h);
    Some((h, app))
}

/// The two cookies a cookie-mode login set.
async fn cookie_login(app: &axum::Router) -> (String, String) {
    let login = login(app, "u@e.com", "glidingwalnut42").await;
    (
        login.cookie_value("access_token").unwrap_or_default(),
        login.cookie_value("refresh_token").unwrap_or_default(),
    )
}

/// Whether a response is the `auth.validation` refusal naming `refreshToken`.
fn names_refresh_token(response: &Captured) -> bool {
    let body = response.json();
    response.status == StatusCode::BAD_REQUEST
        && body["error"]["code"] == "auth.validation"
        && body["error"]["details"][0]["field"] == "refreshToken"
}

#[tokio::test]
async fn an_oversize_refresh_cookie_is_refused_where_the_token_would_be_used() {
    let Some((_h, app)) = app_in(TokenDelivery::Cookie).await else { return };
    let (access, refresh) = cookie_login(&app).await;
    let oversize = "x".repeat(LIMIT + 1);
    let refused = [
        Req::post("/auth/refresh").cookie("refresh_token", &oversize),
        Req::get("/auth/sessions")
            .cookie("access_token", &access)
            .cookie("refresh_token", &oversize),
        Req::post("/auth/sessions/revoke-all")
            .cookie("access_token", &access)
            .cookie("refresh_token", &oversize),
        Req::post("/auth/password/change")
            .cookie("access_token", &access)
            .cookie("refresh_token", &oversize)
            .json(serde_json::json!({
                "currentPassword": "glidingwalnut42",
                "newPassword": "aquietmorningwalk77"
            })),
    ];
    for request in refused {
        let response = request.send(&app).await;
        assert!(names_refresh_token(&response), "{}", response.json());
    }
    // Nothing was looked up or touched: the real session still rotates.
    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
}

#[tokio::test]
async fn the_bound_is_inclusive_and_an_empty_cookie_is_no_token() {
    let Some((_h, app)) = app_in(TokenDelivery::Cookie).await else { return };
    for value in ["x".repeat(LIMIT), String::new()] {
        let response = Req::post("/auth/refresh")
            .cookie("refresh_token", &value)
            .send(&app)
            .await;
        // A token that names no session, or no token: refused as an invalid refresh, never as a
        // validation error.
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{}", value.len());
    }
}

#[tokio::test]
async fn logout_treats_an_oversize_refresh_cookie_as_no_token() {
    let Some((_h, app)) = app_in(TokenDelivery::Cookie).await else { return };
    let (access, refresh) = cookie_login(&app).await;
    let logout = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .cookie("refresh_token", &"x".repeat(LIMIT + 1))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    assert!(!logout.has_cookie_value("access_token"));
    assert!(
        !logout.set_cookies.is_empty(),
        "the auth cookies are cleared"
    );
    // The access token was revoked exactly as a logout without a refresh token revokes it.
    let me = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    // No refresh session was touched.
    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
}

#[tokio::test]
async fn logout_still_refuses_a_body_value_past_the_bound() {
    let Some((_h, app)) = app_in(TokenDelivery::Bearer).await else { return };
    let login = login(&app, "u@e.com", "glidingwalnut42").await;
    let access = login.json()["accessToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let response = Req::post("/auth/logout")
        .bearer(&access)
        .json(serde_json::json!({ "refreshToken": "x".repeat(LIMIT + 1) }))
        .send(&app)
        .await;
    assert!(names_refresh_token(&response), "{}", response.json());
}

#[tokio::test]
async fn under_both_an_oversize_cookie_on_logout_leaves_the_body_token_in_charge() {
    let Some((_h, app)) = app_in(TokenDelivery::Both).await else { return };
    let login = login(&app, "u@e.com", "glidingwalnut42").await;
    let body = login.json();
    let access = body["accessToken"].as_str().unwrap_or_default().to_owned();
    let refresh = body["refreshToken"].as_str().unwrap_or_default().to_owned();
    let logout = Req::post("/auth/logout")
        .bearer(&access)
        .cookie("refresh_token", &"x".repeat(LIMIT + 1))
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let revoked = Req::post("/auth/refresh")
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    let refused = Req::post("/auth/refresh")
        .cookie("refresh_token", &"x".repeat(LIMIT + 1))
        .json(serde_json::json!({ "refreshToken": "valid-looking" }))
        .send(&app)
        .await;
    assert!(names_refresh_token(&refused), "{}", refused.json());
}
