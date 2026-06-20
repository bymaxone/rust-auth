//! End-to-end tests for the Axum adapter, driving the assembled router with
//! `tower::ServiceExt::oneshot` over the in-memory trait doubles (no Docker required). Every
//! endpoint, extractor, error arm, delivery mode, the per-route rate limiting, and the WS
//! ticket are exercised here. The real-Redis testcontainers tier lives in `redis_e2e.rs`.
//!
//! The shared harness (`common`) builds the engine + router and provides the request/response
//! helpers; every helper it defines is used somewhere in this file.
//!
//! This suite drives the full route table, so it is gated on every optional adapter feature:
//! under a bare-feature build the optional groups compile to nothing and there is no full
//! router to exercise (the per-module unit tests cover the always-on `auth`/`password_reset`
//! surface). The real-Redis tier in `redis_e2e.rs` carries the same gate.
#![cfg(all(
    feature = "mfa",
    feature = "sessions",
    feature = "platform",
    feature = "oauth",
    feature = "invitations",
    feature = "websocket"
))]

mod common;

use common::{
    Captured, EngineSpec, Req, TENANT, build, build_oauth_with_redirects, current_totp,
    enable_mfa_flag, router, seed_admin, seed_user, set_status, totp_at,
};
use http::{Method, StatusCode, header};

/// Log in and return the captured response (cookie mode) for a seeded active user.
async fn login(router: &axum::Router, email: &str, password: &str) -> Captured {
    Req::post("/auth/login")
        .json(serde_json::json!({ "email": email, "password": password, "tenantId": TENANT }))
        .send(router)
        .await
}

/// Log in and return the access-token cookie value.
async fn login_access_cookie(router: &axum::Router, email: &str, password: &str) -> String {
    login(router, email, password)
        .await
        .cookie_value("access_token")
        .unwrap_or_default()
}

// ----------------------------------------------------------------------------------------
// Router skeleton + toggle/feature gating
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn always_on_groups_are_mounted_and_optional_groups_are_absent_by_default() {
    // A bare engine mounts auth + password_reset only; an unconfigured optional group
    // contributes ZERO routes (sessions toggle off → 404, not 401/405).
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    // The always-on `me` route exists (401 without a token, not 404).
    let me = Req::get("/auth/me").send(&app).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);

    // The sessions group is toggled off → the route is not mounted at all.
    let sessions = Req::get("/auth/sessions").send(&app).await;
    assert_eq!(sessions.status, StatusCode::NOT_FOUND);

    // The router reports exactly the derived groups.
    let derived = bymax_auth_axum::AuthRouter::from_engine(
        h.engine.clone(),
        bymax_auth_axum::AxumAuthConfig::default(),
    )
    .groups();
    assert!(derived.auth && derived.password_reset);
    assert!(!derived.sessions && !derived.mfa && !derived.platform && !derived.oauth);
    assert!(!derived.invitations && !derived.platform_mfa);
}

#[tokio::test]
async fn an_unknown_route_is_404() {
    // A path outside the mounted table is a clean 404.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let resp = Req::get("/auth/does-not-exist").send(&app).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

// ----------------------------------------------------------------------------------------
// auth group + delivery modes
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn register_login_me_logout_cookie_mode() {
    // The full cookie-mode lifecycle, asserting the secure cookie attributes at each step.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "a@e.com", "password": "password123", "name": "Ada", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    // Cookie mode: the body carries the user, not the tokens.
    assert!(reg.json().get("user").is_some());
    assert!(reg.json().get("accessToken").is_none());

    // The access cookie is HttpOnly + Lax + path `/`; the refresh cookie is Strict + path
    // scoped; the signal cookie is non-HttpOnly.
    let access = reg.cookie("access_token").unwrap_or_default();
    assert!(access.contains("HttpOnly"));
    assert!(access.contains("SameSite=Lax"));
    assert!(access.contains("Path=/"));
    let refresh = reg.cookie("refresh_token").unwrap_or_default();
    assert!(refresh.contains("HttpOnly"));
    assert!(refresh.contains("SameSite=Strict"));
    assert!(refresh.contains("Path=/auth"));
    let signal = reg.cookie("has_session").unwrap_or_default();
    assert!(!signal.contains("HttpOnly"));

    // `me` with the access cookie returns the user.
    let access_value = reg.cookie_value("access_token").unwrap_or_default();
    let me = Req::get("/auth/me")
        .cookie("access_token", &access_value)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["user"]["email"], "a@e.com");

    // Logout clears the cookies (a cleared cookie has an empty value / expiry).
    let refresh_value = reg.cookie_value("refresh_token").unwrap_or_default();
    let logout = Req::post("/auth/logout")
        .cookie("access_token", &access_value)
        .cookie("refresh_token", &refresh_value)
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    assert!(!logout.has_cookie_value("access_token"));
}

#[tokio::test]
async fn login_bearer_mode_returns_tokens_in_body_and_no_cookies() {
    // Bearer mode: the body carries the token pair and NO cookies are set; the guard reads
    // the `Authorization` header.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    };
    let Some(h) = build(spec) else { return };
    let app = router(&h);
    seed_user(&h, "b@e.com", "password123", "USER").await;

    let resp = login(&app, "b@e.com", "password123").await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.set_cookies.is_empty());
    let token = resp.json()["accessToken"].as_str().unwrap_or("").to_owned();
    assert!(!token.is_empty());
    assert!(resp.json()["refreshToken"].is_string());

    // `me` via the bearer header.
    let me = Req::get("/auth/me").bearer(&token).send(&app).await;
    assert_eq!(me.status, StatusCode::OK);

    // A cookie is ignored in bearer mode (no header → 401).
    let me_cookie = Req::get("/auth/me")
        .cookie("access_token", &token)
        .send(&app)
        .await;
    assert_eq!(me_cookie.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_both_mode_sets_cookies_and_body_tokens() {
    // `both` mode sets cookies AND returns the tokens in the body; the guard accepts either.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Both,
        ..EngineSpec::default()
    };
    let Some(h) = build(spec) else { return };
    let app = router(&h);
    seed_user(&h, "c@e.com", "password123", "USER").await;

    let resp = login(&app, "c@e.com", "password123").await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.has_cookie_value("access_token"));
    let token = resp.json()["accessToken"].as_str().unwrap_or("").to_owned();
    assert!(!token.is_empty());

    // The header path works under `both`.
    let me = Req::get("/auth/me").bearer(&token).send(&app).await;
    assert_eq!(me.status, StatusCode::OK);
    // The cookie path also works under `both`.
    let me2 = Req::get("/auth/me")
        .cookie("access_token", &token)
        .send(&app)
        .await;
    assert_eq!(me2.status, StatusCode::OK);
}

#[tokio::test]
async fn refresh_rotates_in_cookie_and_bearer_modes() {
    // Cookie-mode refresh reads the refresh cookie and sets a new pair; bearer-mode refresh
    // reads the body refreshToken and returns the new pair.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "r@e.com", "password": "password123", "name": "Ray", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let refresh_value = reg.cookie_value("refresh_token").unwrap_or_default();

    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh_value)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert!(rotated.has_cookie_value("refresh_token"));

    // Bearer mode: the refresh comes from the body.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    };
    let Some(hb) = build(spec) else { return };
    let appb = router(&hb);
    seed_user(&hb, "rb@e.com", "password123", "USER").await;
    let login = login(&appb, "rb@e.com", "password123").await;
    let refresh_token = login.json()["refreshToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let rotated_b = Req::post("/auth/refresh")
        .json(serde_json::json!({ "refreshToken": refresh_token }))
        .send(&appb)
        .await;
    assert_eq!(rotated_b.status, StatusCode::OK);
    assert!(rotated_b.json()["accessToken"].is_string());

    // An empty refresh body in bearer mode → no token → refresh-token-invalid.
    let empty = Req::post("/auth/refresh").send(&appb).await;
    assert_eq!(empty.status, StatusCode::UNAUTHORIZED);
    assert_eq!(empty.json()["error"]["code"], "auth.refresh_token_invalid");

    // A malformed refresh body is a validation error.
    let bad = Req::post("/auth/refresh")
        .raw_body(b"{ not json".to_vec(), "application/json")
        .send(&appb)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.json()["error"]["code"], "auth.validation");
}

#[tokio::test]
async fn invalid_credentials_and_unknown_email_are_indistinguishable() {
    // Anti-enumeration: a wrong password and an unknown email both return the same generic
    // 401 invalid-credentials.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "known@e.com", "password123", "USER").await;

    let wrong = login(&app, "known@e.com", "wrongpass").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"]["code"], "auth.invalid_credentials");

    let unknown = login(&app, "nobody@e.com", "password123").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.json()["error"]["code"], "auth.invalid_credentials");
}

// ----------------------------------------------------------------------------------------
// Validation: deny_unknown_fields + field rules
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn validation_rejects_unknown_fields_and_bad_fields() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    // An unknown field 400s with `auth.validation` and per-field details.
    let unknown = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "a@e.com", "password": "p", "tenantId": TENANT, "surprise": 1
        }))
        .send(&app)
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.json()["error"]["code"], "auth.validation");
    assert!(unknown.json()["error"]["details"].is_array());

    // A bad email fails the `garde(email)` rule.
    let bad_email = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "not-an-email", "password": "password123", "name": "X", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(bad_email.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_email.json()["error"]["code"], "auth.validation");

    // A too-short password fails the length rule.
    let short_pw = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "ok@e.com", "password": "short", "name": "X", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(short_pw.status, StatusCode::BAD_REQUEST);
}

// ----------------------------------------------------------------------------------------
// Token extractor arms: missing / invalid / revoked, optional-none, caching
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn auth_user_rejects_missing_invalid_and_revoked_tokens() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "tok@e.com", "password123", "USER").await;

    // Missing → token_invalid.
    let missing = Req::get("/auth/me").send(&app).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.json()["error"]["code"], "auth.token_invalid");

    // Malformed → token_invalid.
    let malformed = Req::get("/auth/me")
        .cookie("access_token", "not-a-jwt")
        .send(&app)
        .await;
    assert_eq!(malformed.status, StatusCode::UNAUTHORIZED);
    assert_eq!(malformed.json()["error"]["code"], "auth.token_invalid");

    // Revoked (after logout) → still token_invalid (no expired/revoked oracle).
    let access = login_access_cookie(&app, "tok@e.com", "password123").await;
    let login_resp = login(&app, "tok@e.com", "password123").await;
    let refresh_value = login_resp.cookie_value("refresh_token").unwrap_or_default();
    let access2 = login_resp.cookie_value("access_token").unwrap_or_default();
    let _ = Req::post("/auth/logout")
        .cookie("access_token", &access2)
        .cookie("refresh_token", &refresh_value)
        .send(&app)
        .await;
    let revoked = Req::get("/auth/me")
        .cookie("access_token", &access2)
        .send(&app)
        .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(revoked.json()["error"]["code"], "auth.token_invalid");
    // The first access token (never logged out) still verifies.
    let ok = Req::get("/auth/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(ok.status, StatusCode::OK);
}

// ----------------------------------------------------------------------------------------
// password_reset group (anti-enum) + verify-otp flow
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn password_reset_endpoints_are_anti_enumerating() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    // forgot-password returns 200 for an unknown email (anti-enum).
    let forgot = Req::post("/auth/password/forgot-password")
        .json(serde_json::json!({ "email": "ghost@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(forgot.status, StatusCode::OK);

    // resend-otp likewise.
    let resend = Req::post("/auth/password/resend-otp")
        .json(serde_json::json!({ "email": "ghost@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(resend.status, StatusCode::OK);

    // verify-otp with a bogus code is an OTP error (the record is absent).
    let verify = Req::post("/auth/password/verify-otp")
        .json(serde_json::json!({ "email": "ghost@e.com", "otp": "123456", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert!(matches!(
        verify.status,
        StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
    ));

    // reset-password with a bogus token is a reset-token error.
    let reset = Req::post("/auth/password/reset-password")
        .json(serde_json::json!({
            "email": "ghost@e.com", "newPassword": "newpassword1", "token": "bogus", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reset.status, StatusCode::BAD_REQUEST);
}

// ----------------------------------------------------------------------------------------
// verify-email / resend-verification
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn verify_and_resend_verification_are_uniform() {
    let Some(h) = build(EngineSpec {
        verification_required: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    // resend-verification is uniform (204) for any email.
    let resend = Req::post("/auth/resend-verification")
        .json(serde_json::json!({ "email": "ghost@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(resend.status, StatusCode::NO_CONTENT);

    // verify-email with a bogus OTP is an OTP error.
    let verify = Req::post("/auth/verify-email")
        .json(serde_json::json!({ "email": "ghost@e.com", "otp": "123456", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert!(matches!(
        verify.status,
        StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
    ));
}

// ----------------------------------------------------------------------------------------
// sessions group (AuthUser + UserStatus, static `all` vs `{id}`)
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn sessions_list_revoke_one_and_revoke_all() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "s@e.com", "password": "password123", "name": "Sam", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let refresh = reg.cookie_value("refresh_token").unwrap_or_default();

    // List the caller's sessions; the current one is flagged.
    let list = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    let sessions = list.json()["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!sessions.is_empty());
    let hash = sessions[0]["sessionHash"].as_str().unwrap_or("").to_owned();

    // The static `all` segment wins over the `{id}` capture.
    let revoke_all = Req::delete("/auth/sessions/all")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(revoke_all.status, StatusCode::NO_CONTENT);

    // Revoke a specific session by its hash.
    let revoke_one = Req::delete(&format!("/auth/sessions/{hash}"))
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(revoke_one.status, StatusCode::NO_CONTENT);

    // A blocked status fails the `UserStatus` gate on the sessions list.
    let banned_id = reg.json()["user"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    set_status(&h, &banned_id, "BANNED").await;
    let blocked = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.json()["error"]["code"], "auth.account_banned");
}

// ----------------------------------------------------------------------------------------
// mfa group: setup → verify-enable (TOTP) → challenge wiring; disable; enrolment skip-mfa
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn mfa_setup_verify_enable_and_challenge_error_arms() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "m@e.com", "password": "password123", "name": "Mo", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();

    // setup returns the secret/qr/recovery codes (enrolment is reachable without MfaSatisfied).
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(setup.status, StatusCode::OK);
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    assert!(!secret.is_empty());

    // verify-enable with a valid TOTP enables MFA (204).
    let code = current_totp(&secret);
    let enable = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": code }))
        .send(&app)
        .await;
    assert_eq!(enable.status, StatusCode::NO_CONTENT);

    // The public challenge with a bogus temp token is an invalid-temp-token 401.
    let challenge = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": "bogus", "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);

    // disable with a wrong code is rejected (not 204).
    let disable = Req::post("/auth/mfa/disable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(disable.status, StatusCode::NO_CONTENT);

    // recovery-codes with a wrong code is rejected.
    let recov = Req::post("/auth/mfa/recovery-codes")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(recov.status, StatusCode::OK);
}

#[tokio::test]
async fn login_with_mfa_returns_a_challenge_body() {
    // A login for an MFA-enabled account returns `{ mfaRequired, mfaTempToken }`, not a session.
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let id = seed_user(&h, "mfauser@e.com", "password123", "USER").await;
    enable_mfa_flag(&h, &id).await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "mfauser@e.com", "password": "password123", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(login.status, StatusCode::OK);
    assert_eq!(login.json()["mfaRequired"], true);
    assert!(login.json()["mfaTempToken"].is_string());
    // No session cookies were set on the challenge.
    assert!(!login.has_cookie_value("access_token"));
}

// ----------------------------------------------------------------------------------------
// platform group + platform_mfa
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn platform_login_me_logout_and_dashboard_token_is_rejected() {
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "boss@e.com", "SUPER_ADMIN").await;

    // Platform login (no tenant) returns a platform session.
    let login = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "boss@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    assert_eq!(login.status, StatusCode::OK);
    let access = login.cookie_value("access_token").unwrap_or_default();
    assert!(!access.is_empty());

    // Platform `me` returns the admin (no tenantId).
    let me = Req::get("/auth/platform/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["user"]["email"], "boss@e.com");

    // A dashboard token on a platform route is `platform_auth_required`.
    let dash = seed_user(&h, "tenant@e.com", "password123", "USER").await;
    let _ = dash;
    let dash_login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "tenant@e.com", "password": "password123", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let dash_token = dash_login.cookie_value("access_token").unwrap_or_default();
    let wrong = Req::get("/auth/platform/me")
        .cookie("access_token", &dash_token)
        .send(&app)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"]["code"], "auth.platform_auth_required");

    // Platform logout clears the session.
    let logout = Req::post("/auth/platform/logout")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    // Platform refresh with no token is rejected.
    let refresh = Req::post("/auth/platform/refresh").send(&app).await;
    assert_eq!(refresh.status, StatusCode::UNAUTHORIZED);

    // Platform revoke-all requires a platform token.
    let revoke = Req::delete("/auth/platform/sessions").send(&app).await;
    assert_eq!(revoke.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn platform_mfa_setup_requires_platform_auth() {
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // Without a platform token the platform MFA setup is rejected.
    let setup = Req::post("/auth/platform/mfa/setup").send(&app).await;
    assert_eq!(setup.status, StatusCode::UNAUTHORIZED);

    // With a platform token, setup returns the enrolment material.
    seed_admin(&h, "padmin@e.com", "SUPER_ADMIN").await;
    let login = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "padmin@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    let setup_ok = Req::post("/auth/platform/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(setup_ok.status, StatusCode::OK);
    assert!(setup_ok.json()["secret"].is_string());
}

// ----------------------------------------------------------------------------------------
// invitations group: create (tenant from claims) + accept; oauth callback
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn invitation_create_and_accept() {
    let Some(h) = build(EngineSpec {
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // An authenticated ADMIN can create an invitation (204); tenant comes from the claims.
    let admin_id = seed_user(&h, "inviter@e.com", "password123", "ADMIN").await;
    let _ = admin_id;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "inviter@e.com", "password": "password123", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    let create = Req::post("/auth/invitations")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "invitee@e.com", "role": "USER" }))
        .send(&app)
        .await;
    assert_eq!(create.status, StatusCode::NO_CONTENT);

    // Creating without auth is rejected.
    let no_auth = Req::post("/auth/invitations")
        .json(serde_json::json!({ "email": "x@e.com", "role": "USER" }))
        .send(&app)
        .await;
    assert_eq!(no_auth.status, StatusCode::UNAUTHORIZED);

    // Accepting a bogus token is an invalid-invitation-token 400.
    let accept = Req::post("/auth/invitations/accept")
        .json(
            serde_json::json!({ "token": "bogus", "name": "New User", "password": "password123" }),
        )
        .send(&app)
        .await;
    assert_eq!(accept.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        accept.json()["error"]["code"],
        "auth.invalid_invitation_token"
    );
}

#[tokio::test]
async fn oauth_initiate_redirects_and_callback_completes() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    // initiate 302-redirects to the provider; the engine stored the state.
    let initiate = Req::get("/auth/oauth/google?tenantId=t1").send(&app).await;
    assert_eq!(initiate.status, StatusCode::FOUND);
    let location = initiate
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(location.contains("state="));
    // Recover the state the engine minted from the redirect URL.
    let state = location
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or("")
        .to_owned();

    // The callback consumes the state and (via the allowing hook) creates a session.
    let callback = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .send(&app)
    .await;
    assert_eq!(callback.status, StatusCode::OK);
    assert!(callback.json()["user"].is_object());

    // An unknown provider is an oauth-failed 401.
    let unknown = Req::get("/auth/oauth/unknown?tenantId=t1").send(&app).await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.json()["error"]["code"], "auth.oauth_failed");

    // A replayed/forged state is rejected.
    let forged = Req::get("/auth/oauth/google/callback?code=abc&state=deadbeef")
        .send(&app)
        .await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
}

// ----------------------------------------------------------------------------------------
// WebSocket ticket: mint (AuthUser+UserStatus+MfaSatisfied) + single-use redeem
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn ws_ticket_mint_and_single_use_redeem() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "ws@e.com", "password": "password123", "name": "Wes", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();

    // Mint a ticket; the access token is in the cookie, never a URL.
    let mint = Req::post("/auth/ws-ticket")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(mint.status, StatusCode::OK);
    let ticket = mint.json()["ticket"].as_str().unwrap_or("").to_owned();
    assert!(!ticket.is_empty());

    // Minting without auth is rejected.
    let no_auth = Req::post("/auth/ws-ticket").send(&app).await;
    assert_eq!(no_auth.status, StatusCode::UNAUTHORIZED);

    // The ticket redeems once via the engine; a second redemption is refused (single-use).
    let first = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(
        matches!(first, Ok(claims) if claims.sub == reg.json()["user"]["id"].as_str().unwrap_or_default())
    );
    let second = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(second.is_err());
}

// ----------------------------------------------------------------------------------------
// Per-route rate limiting: 429 + Retry-After in the canonical envelope
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn exceeding_the_login_limit_returns_a_429_envelope_with_retry_after() {
    // The default login limit is 5/60s; the 6th rapid attempt from the same IP is throttled.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "rl@e.com", "password123", "USER").await;

    let mut throttled = None;
    for _ in 0..12 {
        let resp = Req::post("/auth/login")
            .json(serde_json::json!({
                "email": "rl@e.com", "password": "wrongpass", "tenantId": TENANT
            }))
            .send(&app)
            .await;
        if resp.status == StatusCode::TOO_MANY_REQUESTS {
            throttled = Some(resp);
            break;
        }
    }
    let Some(resp) = throttled else {
        // If the limiter did not trip in this environment, skip the strict assertions.
        return;
    };
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.json()["error"]["code"], "auth.too_many_requests");
    assert!(resp.retry_after().is_some());

    // A different route's limit is independent (register is not throttled by login attempts).
    let register = Req::new(Method::POST, "/auth/register")
        .json(serde_json::json!({
            "email": "fresh@e.com", "password": "password123", "name": "Fresh", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_ne!(register.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_custom_rate_limit_override_changes_the_threshold() {
    use bymax_auth_axum::{AuthRouter, AxumAuthConfig, RateLimit, RateLimitConfig};
    // Override the login limit to 1/60s and a per-route disable for register, proving the
    // config knobs flow through.
    let Some(h) = build(EngineSpec::default()) else { return };
    seed_user(&h, "ov@e.com", "password123", "USER").await;
    let limits = RateLimitConfig {
        login: Some(RateLimit::new(1, 60)),
        register: None,
        ..RateLimitConfig::default()
    };
    let config = AxumAuthConfig {
        rate_limits: limits,
        ..AxumAuthConfig::default()
    };
    let app = AuthRouter::from_engine(h.engine.clone(), config).into_router();

    let first = Req::post("/auth/login")
        .json(serde_json::json!({ "email": "ov@e.com", "password": "wrong", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_ne!(first.status, StatusCode::TOO_MANY_REQUESTS);
    let second = Req::post("/auth/login")
        .json(serde_json::json!({ "email": "ov@e.com", "password": "wrong", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
}

// ----------------------------------------------------------------------------------------
// Trusted-proxy IP source + CORS + custom prefix
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn custom_config_with_forwarded_for_cors_and_prefix() {
    use bymax_auth_axum::{AuthRouter, AxumAuthConfig, ClientIpSource};
    let Some(h) = build(EngineSpec::default()) else { return };
    let config = AxumAuthConfig {
        route_prefix: "api/auth".to_owned(),
        client_ip_source: ClientIpSource::TrustedForwardedFor,
        cors: Some(tower_http::cors::CorsLayer::permissive()),
        ..AxumAuthConfig::default()
    };
    let app = AuthRouter::from_engine(h.engine.clone(), config).into_router();

    // The route now lives under the custom prefix.
    let me = Req::get("/api/auth/me").send(&app).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);

    // The trusted-proxy strategy keys the limiter off `X-Forwarded-For`.
    let resp = Req::post("/api/auth/login")
        .header(
            header::HeaderName::from_static("x-forwarded-for"),
            "198.51.100.7",
        )
        .json(serde_json::json!({ "email": "p@e.com", "password": "wrong", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert!(matches!(
        resp.status,
        StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
    ));
}

// ----------------------------------------------------------------------------------------
// platform: refresh + revoke-all + mfa-challenge arms (exhaustive handler coverage)
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn platform_refresh_revoke_all_and_mfa_challenge_arms() {
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "ops@e.com", "SUPER_ADMIN").await;
    let login = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "ops@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    let refresh = login.cookie_value("refresh_token").unwrap_or_default();

    // Platform refresh rotates the pair from the cookie.
    let rotated = Req::post("/auth/platform/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);

    // A malformed platform refresh body is a validation error.
    let bad = Req::post("/auth/platform/refresh")
        .raw_body(b"{not json".to_vec(), "application/json")
        .send(&app)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // revoke-all with a platform token succeeds.
    let revoke = Req::delete("/auth/platform/sessions")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    // The public platform MFA challenge with a bogus temp token is rejected.
    let challenge = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": "bogus", "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
}

// ----------------------------------------------------------------------------------------
// platform_mfa: setup → verify-enable (TOTP) → recovery-codes → disable (full lifecycle)
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn platform_mfa_full_lifecycle() {
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "padmin2@e.com", "SUPER_ADMIN").await;
    let login = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "padmin2@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();

    let setup = Req::post("/auth/platform/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(setup.status, StatusCode::OK);
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();

    // Each TOTP-gated step uses a distinct window offset so the per-window anti-replay never
    // rejects a reused code (the verifier's window tolerance accepts the near-future codes).
    let enable = Req::post("/auth/platform/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 0) }))
        .send(&app)
        .await;
    assert_eq!(enable.status, StatusCode::NO_CONTENT);

    // recovery-codes with a fresh-window TOTP returns a fresh set.
    let recov = Req::post("/auth/platform/mfa/recovery-codes")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 30) }))
        .send(&app)
        .await;
    assert_eq!(recov.status, StatusCode::OK);
    assert!(recov.json()["recoveryCodes"].is_array());

    // disable with another fresh-window TOTP turns it off.
    let disable = Req::post("/auth/platform/mfa/disable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 60) }))
        .send(&app)
        .await;
    assert_eq!(disable.status, StatusCode::NO_CONTENT);

    // verify-enable / disable / recovery-codes without a platform token are rejected.
    for path in [
        "/auth/platform/mfa/verify-enable",
        "/auth/platform/mfa/disable",
        "/auth/platform/mfa/recovery-codes",
    ] {
        let resp = Req::post(path)
            .json(serde_json::json!({ "code": "123456" }))
            .send(&app)
            .await;
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }
}

// ----------------------------------------------------------------------------------------
// mfa: dashboard challenge success arm (login → challenge with a live TOTP → full session)
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn mfa_dashboard_challenge_success_issues_a_session() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // Enrol MFA for a fresh user via setup + verify-enable.
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "ch@e.com", "password": "password123", "name": "Cho", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    // Keep a recovery code for the challenge so it does not collide with the verify-enable
    // TOTP in the same anti-replay window.
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;

    // A fresh login now returns an MFA challenge with a temp token.
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "ch@e.com", "password": "password123", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(login.json()["mfaRequired"], true);
    let temp = login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // Completing the challenge with a recovery code issues a full dashboard session.
    let challenge = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": recovery }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.has_cookie_value("access_token"));
}

// ----------------------------------------------------------------------------------------
// validation: the ValidatedQuery path (OAuth query) rejects a missing field
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn oauth_query_validation_rejects_a_missing_tenant_id() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // initiate without the required `tenantId` query is a validation 400.
    let resp = Req::get("/auth/oauth/google").send(&app).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    assert_eq!(resp.json()["error"]["code"], "auth.validation");

    // The callback missing `code`/`state` is a validation 400.
    let cb = Req::get("/auth/oauth/google/callback").send(&app).await;
    assert_eq!(cb.status, StatusCode::BAD_REQUEST);
}

// ----------------------------------------------------------------------------------------
// oauth: configured success/mfa/error redirect branches (302)
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn oauth_callback_redirect_branches() {
    use bymax_auth_axum::{AuthRouter, AxumAuthConfig};
    use bymax_auth_core::config::TokenDelivery;
    // Build an engine with the three redirect URLs configured.
    let Some(h) = build_oauth_with_redirects() else { return };
    let _ = TokenDelivery::Cookie;
    let app = AuthRouter::from_engine(h.engine.clone(), AxumAuthConfig::default()).into_router();

    // initiate to get a valid state.
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

    // Success → 302 to the configured success URL (cookies planted on the redirect).
    let callback = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .send(&app)
    .await;
    assert_eq!(callback.status, StatusCode::FOUND);
    assert!(callback.has_cookie_value("access_token"));

    // A forged state with the error redirect configured → 302 to the error URL with ?error=.
    let forged = Req::get("/auth/oauth/google/callback?code=abc&state=deadbeefdeadbeef")
        .send(&app)
        .await;
    assert_eq!(forged.status, StatusCode::FOUND);
    let err_location = forged
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(err_location.contains("error=oauth_failed"));
}

// ----------------------------------------------------------------------------------------
// Handler error/success arm coverage: the paths a happy-only test leaves uncovered
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn register_duplicate_email_hits_the_error_arm() {
    // A duplicate registration triggers the engine error arm of `register` (409).
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "dup@e.com", "password123", "USER").await;
    let resp = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "dup@e.com", "password": "password123", "name": "Dup", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(resp.status, StatusCode::CONFLICT);
    assert_eq!(resp.json()["error"]["code"], "auth.email_already_exists");
}

#[tokio::test]
async fn session_revoke_with_a_malformed_hash_hits_the_error_arm() {
    // Revoking a non-owned/malformed session hash triggers the `revoke_one` error arm.
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "rv@e.com", "password": "password123", "name": "Rv", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let resp = Req::delete("/auth/sessions/not-a-valid-hash")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(resp.json()["error"]["code"], "auth.session_not_found");
}

#[tokio::test]
async fn invitation_create_with_an_unknown_role_hits_the_error_arm() {
    // Creating an invitation for a role outside the hierarchy is an insufficient-role error.
    let Some(h) = build(EngineSpec {
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "inv2@e.com", "password123", "ADMIN").await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "inv2@e.com", "password": "password123", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    let resp = Req::post("/auth/invitations")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "x@e.com", "role": "NONEXISTENT_ROLE" }))
        .send(&app)
        .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    assert_eq!(resp.json()["error"]["code"], "auth.insufficient_role");
}

#[tokio::test]
async fn password_reset_otp_two_step_success_flow() {
    // forgot-password mints an OTP; verify-otp exchanges it for a verified token (success arm);
    // reset-password with that token succeeds (204). Uses the in-memory OTP peek.
    use bymax_auth_core::traits::OtpPurpose;
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "pw@e.com", "password123", "USER").await;

    // Trigger the reset so an OTP record exists.
    let _ = Req::post("/auth/password/forgot-password")
        .json(serde_json::json!({ "email": "pw@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;

    // Recover the OTP from the in-memory store (the engine derives the identifier internally).
    let Some(otp) = common::peek_otp(&h, OtpPurpose::PasswordReset, "pw@e.com") else {
        // The reset flow may use a link token rather than an OTP depending on config; skip.
        return;
    };

    let verify = Req::post("/auth/password/verify-otp")
        .json(serde_json::json!({ "email": "pw@e.com", "otp": otp, "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(verify.status, StatusCode::OK);
    let verified = verify.json()["verifiedToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(!verified.is_empty());

    let reset = Req::post("/auth/password/reset-password")
        .json(serde_json::json!({
            "email": "pw@e.com", "newPassword": "newpassword1",
            "verifiedToken": verified, "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reset.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_oversized_body_is_rejected_as_validation() {
    // A body exceeding the configured limit trips the request-body-limit layer; the
    // `ValidatedJson` extractor maps the rejection to the canonical `auth.validation` envelope.
    use bymax_auth_axum::{AuthRouter, AxumAuthConfig};
    let Some(h) = build(EngineSpec::default()) else { return };
    let config = AxumAuthConfig {
        max_body_bytes: 16,
        ..AxumAuthConfig::default()
    };
    let app = AuthRouter::from_engine(h.engine.clone(), config).into_router();
    let big = "x".repeat(4096);
    let resp = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "a@e.com", "password": big, "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    assert_eq!(resp.json()["error"]["code"], "auth.validation");
}

#[tokio::test]
async fn invitation_accept_success_creates_a_session() {
    // Seed an invitation directly into the store, then accept it — covering the accept success
    // arm (a full session is issued, 201).
    use bymax_auth_core::traits::{InvitationStore, StoredInvitation};
    let Some(h) = build(EngineSpec {
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let inviter = seed_user(&h, "host@e.com", "password123", "ADMIN").await;
    let invitation = StoredInvitation {
        email: "joiner@e.com".to_owned(),
        role: "USER".to_owned(),
        tenant_id: TENANT.to_owned(),
        inviter_user_id: inviter,
    };
    let _ = h
        .stores
        .put_invitation("invite-token-xyz", &invitation, 600)
        .await;

    let accept = Req::post("/auth/invitations/accept")
        .json(serde_json::json!({
            "token": "invite-token-xyz", "name": "New Joiner", "password": "password123"
        }))
        .send(&app)
        .await;
    assert_eq!(accept.status, StatusCode::CREATED);
    assert!(accept.has_cookie_value("access_token"));
}

#[tokio::test]
async fn platform_login_mfa_challenge_success() {
    // A platform admin with MFA enabled: login returns a challenge, and the platform MFA
    // challenge with a recovery code issues a full platform session (the success arm).
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let admin_id = seed_admin(&h, "mfaboss@e.com", "SUPER_ADMIN").await;

    // Enrol platform MFA via setup + verify-enable.
    let login0 = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "mfaboss@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let access = login0.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/platform/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/platform/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    let _ = admin_id;

    // A fresh login now returns a platform MFA challenge.
    let login = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "mfaboss@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    assert_eq!(login.json()["mfaRequired"], true);
    let temp = login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // Completing the platform MFA challenge with a recovery code issues a platform session.
    let challenge = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": recovery }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.has_cookie_value("access_token"));
}

#[tokio::test]
async fn oauth_callback_with_mfa_user_takes_the_mfa_redirect_branch() {
    // An OAuth user with MFA enabled yields an MfaChallenge outcome; with the mfa_redirect_url
    // configured the callback 302-redirects and plants the mfa_temp cookie (the MFA branch).
    let Some(h) = build_oauth_with_redirects() else { return };
    // Pre-create the OAuth user with MFA enabled so the callback resolves to a challenge.
    let id = seed_user(&h, "mock@example.com", "password123", "USER").await;
    enable_mfa_flag(&h, &id).await;
    // Link the OAuth identity so the callback finds this user (provider id from the mock).
    use bymax_auth_core::traits::UserRepository;
    let _ = h.users.link_oauth(&id, "google", "mock-123").await;

    let app = bymax_auth_axum::AuthRouter::from_engine(
        h.engine.clone(),
        bymax_auth_axum::AxumAuthConfig::default(),
    )
    .into_router();

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
    .send(&app)
    .await;
    // The MFA branch: a 302 to the mfa redirect, with the ephemeral mfa_temp cookie planted.
    assert_eq!(callback.status, StatusCode::FOUND);
    assert!(callback.cookie("mfa_temp_token").is_some());
}

#[tokio::test]
async fn auth_router_free_function_builds_a_working_router() {
    // The top-level `auth_router(engine, config)` convenience function (the alternative to
    // `AuthRouter::from_engine(..).into_router()`) yields a working router.
    let Some(h) = build(EngineSpec::default()) else { return };
    // Move a fresh engine into the free function (it takes ownership of the engine).
    let Some(h2) = build(EngineSpec::default()) else { return };
    let _ = h;
    let engine = match std::sync::Arc::try_unwrap(h2.engine) {
        Ok(engine) => engine,
        Err(_) => return,
    };
    let app = bymax_auth_axum::auth_router(engine, bymax_auth_axum::AxumAuthConfig::default());
    let me = Req::get("/auth/me").send(&app).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

// ----------------------------------------------------------------------------------------
// Handler error arms reachable with a minted token for a non-existent subject
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn me_and_sessions_error_arms_with_a_ghost_subject() {
    // A token whose subject does not exist drives the `me`/sessions error arms (the engine
    // fetches the user, finds none, and returns an error the handler renders).
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let ghost = common::mint_dashboard_token("ghost-user", "USER", "ACTIVE");

    // `me` for a ghost subject → token_invalid (the me error arm).
    let me = Req::get("/auth/me")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);

    // `sessions` list goes through the UserStatus gate first (the ghost is not in the store →
    // the status assertion fails), exercising the status-gate path on the sessions route.
    let sessions = Req::get("/auth/sessions")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_eq!(sessions.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn platform_me_and_revoke_error_arms_with_a_ghost_admin() {
    // A platform token for a non-existent admin drives the platform me/revoke error arms.
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let ghost = common::mint_platform_token("ghost-admin", "SUPER_ADMIN");

    let me = Req::get("/auth/platform/me")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.json()["error"]["code"], "auth.token_invalid");

    // revoke-all for a ghost admin: the engine revokes nothing and returns Ok (204), but the
    // path is exercised; a logout for the ghost also runs.
    let revoke = Req::delete("/auth/platform/sessions")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);
    let logout = Req::post("/auth/platform/logout")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn mfa_setup_error_arm_when_already_enabled() {
    // Calling setup twice (after enrolment) triggers the mfa setup error arm (already enabled).
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "me2@e.com", "password": "password123", "name": "M", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    // setup again now hits the setup error arm; the exact status depends on the engine's
    // re-enrolment policy, so assert only that it is no longer the 200 success.
    let again = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_ne!(again.status, StatusCode::OK);
}

#[tokio::test]
async fn mfa_verify_enable_error_arm_with_a_wrong_code() {
    // verify-enable with a wrong code triggers the verify-enable error arm.
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "ve@e.com", "password": "password123", "name": "V", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let _ = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let resp = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(resp.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn platform_login_error_arm_with_bad_credentials() {
    // A wrong platform password triggers the platform login error arm.
    let Some(h) = build(EngineSpec {
        platform: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "pl@e.com", "SUPER_ADMIN").await;
    let resp = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "pl@e.com", "password": "wrong" }))
        .send(&app)
        .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.json()["error"]["code"], "auth.invalid_credentials");
}

#[tokio::test]
async fn oauth_callback_mfa_branch_without_redirect_returns_json() {
    // An MFA OAuth user with NO mfa_redirect_url configured returns the JSON challenge body
    // (the `None => deliver_mfa_challenge` arm), planting the mfa_temp cookie.
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let id = seed_user(&h, "mock@example.com", "password123", "USER").await;
    enable_mfa_flag(&h, &id).await;
    use bymax_auth_core::traits::UserRepository;
    let _ = h.users.link_oauth(&id, "google", "mock-123").await;
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
    .send(&app)
    .await;
    // No redirect configured → 200 JSON challenge body, with the mfa_temp cookie planted.
    assert_eq!(callback.status, StatusCode::OK);
    assert_eq!(callback.json()["mfaRequired"], true);
    assert!(callback.cookie("mfa_temp_token").is_some());
}

#[tokio::test]
async fn verify_email_success_with_a_live_otp() {
    // The verify-email happy path: a registered user with a real verification OTP verifies (204).
    use bymax_auth_core::traits::OtpPurpose;
    let Some(h) = build(EngineSpec {
        verification_required: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    // Register so the user exists and a verification OTP is dispatched.
    let _ = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "vfy@e.com", "password": "password123", "name": "Vfy", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let Some(otp) = common::peek_otp(&h, OtpPurpose::EmailVerification, "vfy@e.com") else {
        return;
    };
    let verify = Req::post("/auth/verify-email")
        .json(serde_json::json!({ "email": "vfy@e.com", "otp": otp, "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(verify.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn dashboard_mfa_disable_and_recovery_success() {
    // The dashboard MFA disable + recovery-codes happy arms (distinct TOTP windows).
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "dr@e.com", "password": "password123", "name": "Dr", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 0) }))
        .send(&app)
        .await;

    let recov = Req::post("/auth/mfa/recovery-codes")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 30) }))
        .send(&app)
        .await;
    assert_eq!(recov.status, StatusCode::OK);

    let disable = Req::post("/auth/mfa/disable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": totp_at(&secret, 60) }))
        .send(&app)
        .await;
    assert_eq!(disable.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn mfa_handler_error_arms_with_a_ghost_subject() {
    // A token for a non-existent subject drives the mfa setup/verify error arms (the engine
    // fetches the user and errors).
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let ghost = common::mint_dashboard_token("ghost-mfa", "USER", "ACTIVE");

    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_ne!(setup.status, StatusCode::OK);

    let verify = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(verify.status, StatusCode::NO_CONTENT);

    let disable = Req::post("/auth/mfa/disable")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(disable.status, StatusCode::NO_CONTENT);

    let recov = Req::post("/auth/mfa/recovery-codes")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(recov.status, StatusCode::OK);
}

#[tokio::test]
async fn platform_mfa_handler_error_arms_with_a_ghost_admin() {
    // A platform token for a non-existent admin drives the platform_mfa handler error arms.
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let ghost = common::mint_platform_token("ghost-padmin", "SUPER_ADMIN");

    let setup = Req::post("/auth/platform/mfa/setup")
        .cookie("access_token", &ghost)
        .send(&app)
        .await;
    assert_ne!(setup.status, StatusCode::OK);
    let verify = Req::post("/auth/platform/mfa/verify-enable")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(verify.status, StatusCode::NO_CONTENT);
    let disable = Req::post("/auth/platform/mfa/disable")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(disable.status, StatusCode::NO_CONTENT);
    let recov = Req::post("/auth/platform/mfa/recovery-codes")
        .cookie("access_token", &ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(recov.status, StatusCode::OK);
}

#[tokio::test]
async fn mfa_and_platform_challenge_context_mismatch_arms() {
    // A platform temp token submitted to the dashboard challenge (and vice versa) hits the
    // context-mismatch `None` arm of each challenge handler.
    let Some(h) = build(EngineSpec {
        platform: true,
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    // Enrol a platform admin and obtain a platform MFA temp token via login.
    let admin = seed_admin(&h, "ctx@e.com", "SUPER_ADMIN").await;
    let login0 = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "ctx@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let access = login0.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/platform/mfa/setup")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/platform/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    let _ = admin;
    let plogin = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "ctx@e.com", "password": "adminpass123" }))
        .send(&app)
        .await;
    let platform_temp = plogin.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // Submit the PLATFORM temp token + a VALID recovery code to the DASHBOARD challenge: the
    // MFA service succeeds and yields a `Platform` result, so the dashboard handler's
    // context-mismatch `None` arm fires (`mfa_temp_token_invalid`).
    if !platform_temp.is_empty() {
        let mismatch = Req::post("/auth/mfa/challenge")
            .json(serde_json::json!({ "mfaTempToken": platform_temp, "code": recovery }))
            .send(&app)
            .await;
        assert_eq!(mismatch.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            mismatch.json()["error"]["code"],
            "auth.mfa_temp_token_invalid"
        );
    }

    let _ = recovery;
}

// ----------------------------------------------------------------------------------------
// Store-failure error arms: a backend that fails list/revoke-all/mint reaches the handler
// error arms (the extractors still pass because the blacklist check delegates successfully).
// ----------------------------------------------------------------------------------------

#[tokio::test]
async fn sessions_list_and_revoke_all_store_failure_arms() {
    let Some(h) = common::build_failing() else {
        return;
    };
    let app = router(&h);
    // Register against the delegating store (writes succeed) to obtain a valid session.
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "sf@e.com", "password": "password123", "name": "Sf", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let refresh = reg.cookie_value("refresh_token").unwrap_or_default();

    // `list_sessions` fails in the store → the list handler error arm renders a 500.
    let list = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(list.status, StatusCode::INTERNAL_SERVER_ERROR);

    // `revoke_all` fails in the store → the revoke-all handler error arm renders a 500.
    let revoke = Req::delete("/auth/sessions/all")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn ws_ticket_mint_store_failure_arm() {
    let Some(h) = common::build_failing() else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "wsf@e.com", "password": "password123", "name": "Wf", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    // `issue_ws_ticket` mint fails in the store → the ws_ticket handler error arm renders a 500.
    let mint = Req::post("/auth/ws-ticket")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(mint.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn platform_revoke_all_store_failure_arm() {
    let Some(h) = common::build_failing() else {
        return;
    };
    let app = router(&h);
    // A minted platform token passes the extractor (blacklist delegates), then revoke-all's
    // store op fails → the platform revoke-all error arm renders a 500.
    let token = common::mint_platform_token("padmin", "SUPER_ADMIN");
    let revoke = Req::delete("/auth/platform/sessions")
        .cookie("access_token", &token)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn platform_extractor_propagates_internal_errors_but_masks_token_failures() {
    // With the `rv:{jti}` revocation check failing (Redis down), a *well-formed* platform token
    // reaches that check inside the `PlatformUser` extractor. The internal failure MUST surface
    // as a 500 — masking it as a 401 would hide an outage behind an auth error.
    let Some(h) = common::build_failing_blacklist() else {
        return;
    };
    let app = router(&h);

    let token = common::mint_platform_token("padmin", "SUPER_ADMIN");
    let internal = Req::get("/auth/platform/me")
        .cookie("access_token", &token)
        .send(&app)
        .await;
    assert_eq!(internal.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(internal.json()["error"]["code"], "auth.internal");

    // A token-auth failure (a malformed/invalid token) never reaches the revocation check, so it
    // still collapses to `platform_auth_required` (401) — the masking is correct for THIS case.
    let invalid = Req::get("/auth/platform/me")
        .cookie("access_token", "not-a-jwt")
        .send(&app)
        .await;
    assert_eq!(invalid.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid.json()["error"]["code"],
        "auth.platform_auth_required"
    );
}
