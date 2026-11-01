//! A delivery mode reads the refresh token from its own channel only: the cookie in `cookie`
//! mode, the body in `bearer` mode, the cookie and then the body in `both`. Shares the fixtures
//! of the parent test file.

use bymax_auth_core::config::TokenDelivery;
use common::Harness;

use super::*;

/// The refresh token a fresh login hands out, from whichever channel the mode delivers it on.
async fn issued_refresh(app: &axum::Router, email: &str, from_body: bool) -> String {
    let login = login(app, email, "glidingwalnut42").await;
    if from_body {
        login.json()["refreshToken"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    } else {
        login.cookie_value("refresh_token").unwrap_or_default()
    }
}

/// Refresh with the token in the cookie, the body, or both, and return the status.
async fn refresh_status(
    app: &axum::Router,
    cookie: Option<&str>,
    body: Option<&str>,
) -> StatusCode {
    let mut request = Req::post("/auth/refresh");
    if let Some(value) = cookie {
        request = request.cookie("refresh_token", value);
    }
    if let Some(value) = body {
        request = request.json(serde_json::json!({ "refreshToken": value }));
    }
    request.send(app).await.status
}

/// An engine in `mode` with a seeded user, and the router over it.
async fn app_in(mode: TokenDelivery, email: &str) -> Option<(Harness, axum::Router)> {
    let h = build(EngineSpec {
        delivery: mode,
        ..EngineSpec::default()
    })?;
    seed_user(&h, email, "glidingwalnut42", "USER").await;
    let app = router(&h);
    Some((h, app))
}

#[tokio::test]
async fn cookie_mode_takes_the_cookie_and_refuses_a_token_in_the_body() {
    let Some((_h, app)) = app_in(TokenDelivery::Cookie, "c@e.com").await else { return };
    let token = issued_refresh(&app, "c@e.com", false).await;
    assert!(!token.is_empty());
    // The body is not this mode's channel: a token only there is no refresh at all.
    assert_eq!(
        refresh_status(&app, None, Some(&token)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_status(&app, Some(&token), None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn bearer_mode_takes_the_body_and_refuses_a_stray_cookie() {
    let Some((_h, app)) = app_in(TokenDelivery::Bearer, "b@e.com").await else { return };
    let token = issued_refresh(&app, "b@e.com", true).await;
    assert!(!token.is_empty());
    assert_eq!(
        refresh_status(&app, Some(&token), None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_status(&app, None, Some(&token)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn both_mode_takes_either_channel_and_the_cookie_first() {
    let Some((_h, app)) = app_in(TokenDelivery::Both, "o@e.com").await else { return };
    let token = issued_refresh(&app, "o@e.com", false).await;
    assert!(!token.is_empty());
    assert_eq!(
        refresh_status(&app, Some(&token), None).await,
        StatusCode::OK
    );
    // The first request rotated the token, so the next two prove precedence on a fresh one.
    let fresh = issued_refresh(&app, "o@e.com", false).await;
    assert_eq!(
        refresh_status(&app, None, Some(&fresh)).await,
        StatusCode::OK
    );
    let third = issued_refresh(&app, "o@e.com", false).await;
    assert_eq!(
        refresh_status(&app, Some(&third), Some("not-a-token")).await,
        StatusCode::OK,
        "a valid cookie wins over a body value"
    );
}

#[tokio::test]
async fn a_logout_revokes_only_what_its_mode_reads() {
    let Some((_h, app)) = app_in(TokenDelivery::Cookie, "l@e.com").await else { return };
    let token = issued_refresh(&app, "l@e.com", false).await;
    // A cookie-mode logout that is handed the token only in the body does not read it, so the
    // refresh session stays redeemable; the cookie channel is what ends it.
    let _ = Req::post("/auth/logout")
        .json(serde_json::json!({ "refreshToken": token }))
        .send(&app)
        .await;
    assert_eq!(
        refresh_status(&app, Some(&token), None).await,
        StatusCode::OK
    );
}
