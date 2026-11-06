//! A logout whose revocation writes fail is answered as an error and keeps the auth cookies, so
//! the client can retry; a `204` for one that left the access token alive would tell a user who
//! signed out that it worked. Shares the fixtures of the parent test file.

use super::*;

/// The code of the error envelope in `response`.
fn error_code(response: &Captured) -> String {
    response.json()["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// A logout request that carries the session in the cookies a browser would send.
fn cookie_logout(access: &str, refresh: &str) -> Req {
    Req::post("/auth/logout")
        .cookie("access_token", access)
        .cookie("refresh_token", refresh)
        .cookie("has_session", "1")
}

#[tokio::test]
async fn a_failed_dashboard_logout_is_an_error_that_keeps_the_cookies_and_a_retry_finishes_it() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "out@e.com", "glidingwalnut42", "USER").await;
    let session = login(&app, "out@e.com", "glidingwalnut42").await;
    let access = session.cookie_value("access_token").unwrap_or_default();
    let refresh = session.cookie_value("refresh_token").unwrap_or_default();

    h.stores.fail_next_blacklist_writes(1);
    let failed = cookie_logout(&access, &refresh).send(&app).await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&failed), "auth.internal");
    assert!(failed.set_cookies.is_empty(), "{:?}", failed.set_cookies);

    // The access token still authenticates, which is the reason the failure has to be loud.
    let me = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);

    let retried = cookie_logout(&access, &refresh).send(&app).await;
    assert_eq!(retried.status, StatusCode::NO_CONTENT);
    assert!(!retried.set_cookies.is_empty());
    let after = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_failed_platform_logout_is_an_error_and_a_retry_finishes_it() {
    let Some(h) = build(EngineSpec {
        platform: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "pl-out@e.com", "SUPER_ADMIN").await;
    let session = platform_login(&app, "pl-out@e.com").await;
    let (access, refresh) = (platform_access(&session), platform_refresh(&session));
    let body = serde_json::json!({ "refreshToken": refresh });

    h.stores.fail_next_blacklist_writes(1);
    let failed = Req::post("/auth/platform/logout")
        .bearer(&access)
        .json(body.clone())
        .send(&app)
        .await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&failed), "auth.internal");
    let me = Req::get("/auth/platform/me")
        .bearer(&access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);

    let retried = Req::post("/auth/platform/logout")
        .bearer(&access)
        .json(body)
        .send(&app)
        .await;
    assert_eq!(retried.status, StatusCode::NO_CONTENT);
    let after = Req::get("/auth/platform/me")
        .bearer(&access)
        .send(&app)
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}
