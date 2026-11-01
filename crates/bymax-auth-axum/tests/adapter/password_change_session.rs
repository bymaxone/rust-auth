//! Changing a password keeps the caller's own session and revokes every other one, whichever
//! channel carries the caller's refresh token: the body in bearer mode and the refresh cookie in
//! cookie mode. Shares the fixtures of the parent test file.

use super::*;

/// A fresh login for `email`, returned as (access cookie, refresh cookie).
async fn session_for(app: &axum::Router, email: &str) -> (String, String) {
    let login = login(app, email, "oldsecret777777").await;
    (
        login.cookie_value("access_token").unwrap_or_default(),
        login.cookie_value("refresh_token").unwrap_or_default(),
    )
}

/// Whether `refresh` still rotates.
async fn refreshes(app: &axum::Router, refresh: &str) -> bool {
    Req::post("/auth/refresh")
        .cookie("refresh_token", refresh)
        .send(app)
        .await
        .status
        == StatusCode::OK
}

#[tokio::test]
async fn the_refresh_cookie_of_the_caller_keeps_their_session_through_a_password_change() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let _ = seed_user(&h, "keeper@e.com", "oldsecret777777", "USER").await;
    let (access, mine) = session_for(&app, "keeper@e.com").await;
    let (_, other_device) = session_for(&app, "keeper@e.com").await;
    assert!(!mine.is_empty() && !other_device.is_empty());

    let changed = Req::post("/auth/password/change")
        .cookie("access_token", &access)
        .cookie("refresh_token", &mine)
        .json(serde_json::json!({
            "currentPassword": "oldsecret777777", "newPassword": "glidingwalnut42"
        }))
        .send(&app)
        .await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT);

    // The other device is signed out; the caller, who sent their cookie, stays signed in.
    assert!(!refreshes(&app, &other_device).await);
    assert!(refreshes(&app, &mine).await);
}
