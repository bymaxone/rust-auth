//! The concurrent-session cap lists the user's sessions after the new one is stored. When that
//! read fails, the login still succeeds: the session is live, so refusing the tokens would leave
//! one the client can never use. Shares the fixtures of the parent test file.

use super::*;

/// The sessions listed for the holder of `access`.
async fn listed_sessions(app: &axum::Router, access: &str) -> serde_json::Value {
    Req::get("/auth/sessions")
        .cookie("access_token", access)
        .send(app)
        .await
        .json()
}

#[tokio::test]
async fn a_password_login_survives_a_failed_session_cap_listing() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "capfail@e.com", "glidingwalnut42", "USER").await;

    h.stores.fail_next_session_listings(1);
    let session = login(&app, "capfail@e.com", "glidingwalnut42").await;
    assert_eq!(session.status, StatusCode::OK, "{:?}", session.json());
    let access = session.cookie_value("access_token").unwrap_or_default();
    assert!(!access.is_empty(), "the client must receive its tokens");

    // The session that was stored is the one the client holds.
    let me = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);
    let listed = listed_sessions(&app, &access).await;
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "{listed}");
}

#[tokio::test]
async fn an_oauth_login_survives_a_failed_session_cap_listing() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let initiate = Req::get("/auth/oauth/google?tenantId=t1").send(&app).await;
    assert_eq!(initiate.status, StatusCode::FOUND);
    let location = initiate
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let state = location
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or("")
        .to_owned();

    h.stores.fail_next_session_listings(1);
    let callback = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .cookie("oauth_state", &state)
    .send(&app)
    .await;
    assert_eq!(callback.status, StatusCode::OK, "{:?}", callback.json());
    assert!(callback.json()["user"].is_object());
    assert!(callback.has_cookie_value("access_token"));
}
