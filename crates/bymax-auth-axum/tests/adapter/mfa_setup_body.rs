//! `POST /auth/mfa/setup` and `POST /auth/platform/mfa/setup` take an optional body: a request
//! that carries none is the same request as one carrying `{}`. The two must never differ in
//! outcome, and neither may reach a server error. Shares the fixtures of the parent test file.

use super::*;

/// What a setup request answered: the status and the error code (empty on success).
fn outcome(response: &Captured) -> (StatusCode, String) {
    let code = response.json()["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    (response.status, code)
}

/// Post `path` once with no body and once with `{}`, authenticated by `authed`, and return both
/// answers in that order.
async fn bodyless_and_empty_object(
    app: &axum::Router,
    path: &str,
    authed: impl Fn(Req) -> Req,
) -> (Captured, Captured) {
    let bodyless = authed(Req::post(path)).send(app).await;
    let empty = authed(Req::post(path))
        .json(serde_json::json!({}))
        .send(app)
        .await;
    (bodyless, empty)
}

#[tokio::test]
async fn a_dashboard_setup_without_a_body_answers_like_an_empty_object() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "nobody@e.com", "password": "glidingwalnut42", "name": "Nob", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();

    // The account has a password, so a request that supplies none is refused. Refused the same
    // way with or without a body, and as a client error: an absent body is not a server fault.
    let (bodyless, empty) = bodyless_and_empty_object(&app, "/auth/mfa/setup", |req| {
        req.cookie("access_token", &access)
    })
    .await;
    assert!(bodyless.status.is_client_error(), "{:?}", bodyless.status);
    assert_eq!(outcome(&bodyless), outcome(&empty));
}

#[tokio::test]
async fn an_oauth_only_account_can_enrol_with_or_without_a_body() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let initiate = Req::get("/auth/oauth/google?tenantId=t1").send(&app).await;
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
    let callback = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .cookie("oauth_state", &state)
    .send(&app)
    .await;
    assert_eq!(callback.status, StatusCode::OK);
    let access = callback.cookie_value("access_token").unwrap_or_default();

    // An account provisioned through OAuth has no password to supply; its proof is the sign-in it
    // just completed, so a request with no body enrols, exactly as one with `{}` does.
    let (bodyless, empty) = bodyless_and_empty_object(&app, "/auth/mfa/setup", |req| {
        req.cookie("access_token", &access)
    })
    .await;
    assert_eq!(bodyless.status, StatusCode::CREATED);
    assert_eq!(outcome(&bodyless), outcome(&empty));
    assert!(bodyless.json()["secret"].is_string());
}

#[tokio::test]
async fn a_platform_setup_without_a_body_answers_like_an_empty_object() {
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "padmin@e.com", "SUPER_ADMIN").await;
    let access = platform_access(&platform_login(&app, "padmin@e.com").await);

    // A platform admin always has a password, so both forms are refused, identically.
    let (bodyless, empty) =
        bodyless_and_empty_object(&app, "/auth/platform/mfa/setup", |req| req.bearer(&access))
            .await;
    assert!(bodyless.status.is_client_error(), "{:?}", bodyless.status);
    assert_eq!(outcome(&bodyless), outcome(&empty));
}
