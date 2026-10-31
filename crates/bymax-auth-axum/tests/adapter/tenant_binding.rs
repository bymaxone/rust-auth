//! With `enforce_tenant_binding` on, an access token minted for one tenant is refused when it is
//! presented under another tenant's host, on every route that authenticates the caller. Shares
//! the fixtures of the parent test file.

use super::*;

/// Log `email` in under `host` (the resolver names the tenant after it) and return the access
/// cookie.
async fn access_under(app: &axum::Router, host: &str, email: &str) -> String {
    let login = Req::post("/auth/login")
        .header(header::HOST, host)
        .json(serde_json::json!({ "email": email, "password": "glidingwalnut42" }))
        .send(app)
        .await;
    assert_eq!(login.status, StatusCode::OK, "login under {host}");
    login.cookie_value("access_token").unwrap_or_default()
}

#[tokio::test]
async fn a_token_minted_for_one_tenant_is_refused_under_another_tenants_host() {
    let Some(h) = build(EngineSpec {
        enforce_tenant_binding: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // `seed_user` creates the account in tenant `t1`, which is also the host that names it.
    let _ = seed_user(&h, "bound@e.com", "glidingwalnut42", "USER").await;
    let access = access_under(&app, TENANT, "bound@e.com").await;

    let own_host = Req::get("/auth/me")
        .header(header::HOST, TENANT)
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(own_host.status, StatusCode::OK);

    let other_host = Req::get("/auth/me")
        .header(header::HOST, "t2")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(
        other_host.status,
        StatusCode::UNAUTHORIZED,
        "a token minted for {TENANT} was accepted under another tenant's host"
    );
    assert_eq!(other_host.json()["error"]["code"], "auth.token_invalid");
}

#[tokio::test]
async fn without_the_flag_a_token_is_not_compared_with_the_host() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let _ = seed_user(&h, "free@e.com", "glidingwalnut42", "USER").await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "free@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    let elsewhere = Req::get("/auth/me")
        .header(header::HOST, "t2")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK);
}
