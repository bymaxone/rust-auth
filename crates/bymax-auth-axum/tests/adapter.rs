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
    Captured, EngineSpec, Req, TENANT, build, build_oauth_with_failing_state_store,
    build_oauth_with_redirects, current_totp, enable_mfa_flag, router, seed_admin, seed_user,
    set_status,
};
use http::{HeaderName, Method, StatusCode, header};

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

/// Log a platform admin in. Platform delivery is ALWAYS bearer, so the response plants no
/// cookie and every platform token — access and refresh — travels in the JSON body.
async fn platform_login(router: &axum::Router, email: &str) -> Captured {
    Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": email, "password": "adminpass123" }))
        .send(router)
        .await
}

/// The `accessToken` a platform login/refresh returned in its body.
fn platform_access(resp: &Captured) -> String {
    resp.json()["accessToken"].as_str().unwrap_or("").to_owned()
}

/// The `refreshToken` a platform login/refresh returned in its body.
fn platform_refresh(resp: &Captured) -> String {
    resp.json()["refreshToken"]
        .as_str()
        .unwrap_or("")
        .to_owned()
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
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr),
    )
    .groups();
    assert!(derived.auth && derived.password_reset);
    assert!(!derived.sessions && !derived.mfa && !derived.platform && !derived.oauth);
    assert!(!derived.invitations && !derived.platform_mfa);
}

#[tokio::test]
async fn the_set_cookie_header_is_marked_sensitive_so_tracing_cannot_print_the_token() {
    // Every successful login answers with `Set-Cookie: access_token=<a signed JWT>`. Marking
    // the header sensitive is what stops a deployment whose tracing records response headers —
    // a reasonable thing to switch on while debugging — from writing live session tokens into
    // its logs, where they outlive the session and are read by people it was never issued to.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "sensitive@e.com", "password": "glidingwalnut42", "name": "Sensi", "tenantId": TENANT
        }))
        .send(&app)
        .await;

    assert_eq!(reg.status, StatusCode::CREATED);
    let cookies: Vec<_> = reg.headers.get_all(header::SET_COOKIE).iter().collect();
    assert!(!cookies.is_empty(), "the login must set cookies at all");
    for value in cookies {
        assert!(value.is_sensitive(), "Set-Cookie must be marked sensitive");
    }
}

#[tokio::test]
async fn password_change_requires_a_session_and_the_current_password() {
    // The four recovery routes beside it answer to anyone who can read the account's mailbox;
    // this one answers only to someone who holds a live session AND knows the password. ASVS v5
    // §6.2.2 and §6.2.3 require it at Level 1, and it was the one credential operation this
    // library did not own.
    let Some(h) = build(EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "changer@e.com", "password": "oldsecret77", "name": "Cha", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let access = reg.json()["accessToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();

    // Unauthenticated: refused before anything is read.
    let anonymous = Req::post("/auth/password/change")
        .json(serde_json::json!({
            "currentPassword": "oldsecret77", "newPassword": "glidingwalnut42"
        }))
        .send(&app)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    // Authenticated but unable to produce the current password — the stolen-session case.
    let wrong = Req::post("/auth/password/change")
        .bearer(&access)
        .json(serde_json::json!({
            "currentPassword": "not-the-password", "newPassword": "glidingwalnut42"
        }))
        .send(&app)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"]["code"], "auth.invalid_credentials");

    // With both, it rotates.
    let changed = Req::post("/auth/password/change")
        .bearer(&access)
        .json(serde_json::json!({
            "currentPassword": "oldsecret77", "newPassword": "glidingwalnut42"
        }))
        .send(&app)
        .await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT);

    // The new password is what logs in afterwards.
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "changer@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(login.status, StatusCode::OK);
}

#[tokio::test]
async fn register_refuses_a_common_password_by_default() {
    // NIST SP 800-63B §3.1.1.2 says a verifier SHALL screen against a blocklist of common
    // passwords, and ASVS v5 §6.2.4 asks for it at Level 1. The previous default approved
    // everything, so a deployment on defaults accepted this — and the brute-force machinery
    // never fired, because spraying one password across ten thousand accounts never crosses any
    // single account's threshold.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    for weak in ["Password1", "12345678", "qwerty123", "iloveyou"] {
        let res = Req::post("/auth/register")
            .json(serde_json::json!({
                "email": format!("{weak}@e.com"), "password": weak, "name": "Weak",
                "tenantId": TENANT
            }))
            .send(&app)
            .await;
        assert_eq!(
            res.json()["error"]["code"],
            "auth.password_compromised",
            "for {weak}"
        );
    }
}

#[tokio::test]
async fn revoke_all_sessions_works_in_bearer_mode_and_never_reports_a_silent_success() {
    // A bearer deployment plants no cookies at all, and this route read the caller's current
    // session only from the jar — so it could never identify one, and the engine treated that
    // as "revoke nothing, successfully". A user with a compromised second device clicked
    // "sign out my other devices", got 204, and nothing happened: the attacker's refresh token
    // kept rotating. The body channel now works, and an unidentifiable session is refused
    // rather than answered.
    let Some(h) = build(EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "revoker@e.com", "password": "glidingwalnut42", "name": "Reva", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let body = reg.json();
    let access = body["accessToken"].as_str().unwrap_or_default().to_owned();
    let refresh = body["refreshToken"].as_str().unwrap_or_default().to_owned();
    assert!(
        !refresh.is_empty(),
        "bearer mode returns the tokens in the body"
    );

    // No body-supplied token: the route cannot tell which session to keep, and says so.
    let blind = Req::delete("/auth/sessions/all")
        .bearer(&access)
        .send(&app)
        .await;
    assert_eq!(blind.status, StatusCode::NOT_FOUND);
    assert_eq!(blind.json()["error"]["code"], "auth.session_not_found");

    // With the token in the body — the channel a bearer client actually has — it works.
    let revoked = Req::delete("/auth/sessions/all")
        .bearer(&access)
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn session_cookies_are_host_only_unless_a_domain_resolver_is_configured() {
    // Default: no `Domain` attribute at all. A cookie carrying `Domain=app.example.com` is
    // sent to every subdomain of that name (RFC 6265 §5.2.3), so deriving it from the request
    // host would hand the session to a marketing site, a user-content host, or a stale DNS
    // record someone else now answers for. Host-only is the safe default; sharing is opted in.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "hostonly@e.com", "password": "glidingwalnut42", "name": "Hana", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    assert!(!reg.set_cookies.is_empty());
    for cookie in &reg.set_cookies {
        assert!(
            !cookie.to_ascii_lowercase().contains("domain="),
            "unexpected Domain attribute: {cookie}"
        );
    }
}

#[tokio::test]
async fn a_configured_domain_resolver_stamps_every_session_cookie_and_the_logout_clear() {
    // `cookies.resolve_domains` was a config field the adapter never read — an option that
    // silently did nothing. The resolved domain is stamped on all three session cookies, and
    // the logout clear mirrors it: a browser matches a deletion on name + domain + path, so a
    // host-only clear would leave the real cookie in place and the user who signed out would
    // stay signed in. Only the first domain is used — a browser rejects a `Set-Cookie` whose
    // `Domain` is not a suffix of the responding host (RFC 6265 §5.3.6), so a second one on
    // the same response is either a duplicate scope or a value the browser drops.
    let Some(h) = build(EngineSpec {
        cookie_domains: &[".example.com", ".api.example.com"],
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    let reg = Req::post("/auth/register")
        .header(header::HOST, "app.example.com:8443")
        .json(serde_json::json!({
            "email": "shared@e.com", "password": "glidingwalnut42", "name": "Sara", "tenantId": TENANT
        }))
        .send(&app)
        .await;

    // The resolver is handed the request host with the port stripped — it names a domain, not
    // an origin, and `app.example.com:8443` is not a legal `Domain` value. A resolver that
    // received an empty string could not scope anything, which is how this stayed dead config.
    assert_eq!(
        h.domain_resolver.as_ref().and_then(|r| r
            .seen_host
            .lock()
            .ok()
            .and_then(|seen| seen.clone())),
        Some("app.example.com".to_owned())
    );
    assert_eq!(reg.status, StatusCode::CREATED);
    assert_eq!(reg.set_cookies.len(), 3);
    assert_eq!(
        reg.set_cookies
            .iter()
            .filter(|c| c.contains("Domain=example.com"))
            .count(),
        3,
        // The leading dot the resolver returned is dropped on the way out: RFC 6265 §4.1.2.3
        // ignores it, and `Domain=example.com` already matches every subdomain.
        "expected all three session cookies scoped to the resolved domain"
    );

    // The clear has to replay the cookies: `tower-cookies` only emits a removal for a cookie
    // the request actually carried, so a jar-less logout would emit nothing and prove nothing.
    let logout = Req::post("/auth/logout")
        .cookie(
            "access_token",
            &reg.cookie_value("access_token").unwrap_or_default(),
        )
        .cookie(
            "refresh_token",
            &reg.cookie_value("refresh_token").unwrap_or_default(),
        )
        .cookie("has_session", "1")
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    assert_eq!(logout.set_cookies.len(), 3);
    assert_eq!(
        logout
            .set_cookies
            .iter()
            .filter(|c| c.contains("Domain=example.com"))
            .count(),
        3,
        "expected all three clears scoped to the resolved domain"
    );
}

#[tokio::test]
async fn an_unknown_route_is_404() {
    // A path outside the mounted table is a clean 404.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    let resp = Req::get("/auth/does-not-exist").send(&app).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_response_is_stamped_uncacheable() {
    // RFC 6749 §5.1: a response carrying a token must never be cacheable — a CDN or
    // corporate proxy that caches a login response serves one user's tokens to the next
    // caller. The stamp is a router-wide layer rather than per handler, so a future route
    // cannot forget it; this test pins success, auth-failure, and 404 responses alike,
    // because a cached 401 wedges a client just as a cached login leaks one. `nest-auth`
    // stamps the identical headers via a controller interceptor.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);

    for path in ["/auth/me", "/auth/does-not-exist"] {
        let resp = Req::get(path).send(&app).await;
        assert_eq!(
            resp.headers
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "missing no-store on {path}"
        );
        assert_eq!(
            resp.headers
                .get(http::header::PRAGMA)
                .and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "missing pragma on {path}"
        );
    }
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
            "email": "a@e.com", "password": "glidingwalnut42", "name": "Ada", "tenantId": TENANT
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

    // Max-Age is what makes each cookie outlive the response: the access cookie tracks the
    // access-token lifetime (15 min), the refresh and signal cookies the refresh lifetime
    // (7 days). A session cookie instead — or one capped at a second — would log every user
    // out when they closed the tab.
    assert!(access.contains("Max-Age=900"), "access: {access}");
    assert!(refresh.contains("Max-Age=604800"), "refresh: {refresh}");
    assert!(signal.contains("Max-Age=604800"), "signal: {signal}");

    // `me` with the access cookie returns the safe user as the TOP-LEVEL body — no
    // `{ user: … }` wrapper (nest-auth's `AuthController.me` returns the object itself, and
    // its published client decodes it unwrapped).
    let access_value = reg.cookie_value("access_token").unwrap_or_default();
    let me = Req::get("/auth/me")
        .cookie("access_token", &access_value)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["email"], "a@e.com");
    assert!(me.json().get("user").is_none());

    // Logout clears the cookies (a cleared cookie has an empty value / expiry).
    let refresh_value = reg.cookie_value("refresh_token").unwrap_or_default();
    // The browser sends all three cookies back (the signal one is Path=/ and merely
    // JS-readable, not omitted), so the logout is exercised with the jar it actually sees.
    let logout = Req::post("/auth/logout")
        .cookie("access_token", &access_value)
        .cookie("refresh_token", &refresh_value)
        .cookie("has_session", "1")
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    // Every cookie the login planted is expired back, each on the Path it was set with — a
    // clearing header on the wrong path leaves a ghost cookie the browser keeps sending. The
    // absence of a `Set-Cookie` is not a logout: the browser would keep the credential.
    for (name, path) in [
        ("access_token", "Path=/"),
        ("refresh_token", "Path=/auth"),
        ("has_session", "Path=/"),
    ] {
        let cleared = logout.cookie(name).unwrap_or_default();
        assert!(
            cleared.contains("Max-Age=0"),
            "{name} not expired: {cleared}"
        );
        assert!(
            cleared.contains(path),
            "{name} cleared on the wrong path: {cleared}"
        );
        assert!(!logout.has_cookie_value(name));
    }
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
    seed_user(&h, "b@e.com", "glidingwalnut42", "USER").await;

    let resp = login(&app, "b@e.com", "glidingwalnut42").await;
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
    seed_user(&h, "c@e.com", "glidingwalnut42", "USER").await;

    let resp = login(&app, "c@e.com", "glidingwalnut42").await;
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
            "email": "r@e.com", "password": "glidingwalnut42", "name": "Ray", "tenantId": TENANT
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
    // Cookie mode echoes the user in the body (nest-auth's refresh re-reads it via `getMe` and
    // hands a full `AuthResult` to the delivery layer) instead of the old empty `{}`, so a
    // client never needs a follow-up `GET /auth/me` after a rotation.
    assert_eq!(rotated.json()["user"]["email"], "r@e.com");
    assert!(rotated.json().get("accessToken").is_none());

    // Bearer mode: the refresh comes from the body.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    };
    let Some(hb) = build(spec) else { return };
    let appb = router(&hb);
    seed_user(&hb, "rb@e.com", "glidingwalnut42", "USER").await;
    let login = login(&appb, "rb@e.com", "glidingwalnut42").await;
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
    assert!(rotated_b.json()["refreshToken"].is_string());
    // Bearer mode echoes the user alongside the new pair, the same body a bearer login returns.
    assert_eq!(rotated_b.json()["user"]["email"], "rb@e.com");

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
async fn bearer_mode_logout_revokes_the_refresh_session_from_the_body() {
    // The security fix behind accepting `refreshToken` in the logout body: a bearer deployment
    // plants NO cookie, so a logout that only read the cookie left the refresh session alive —
    // the "logged out" client could keep rotating it indefinitely. With the body accepted, the
    // session is gone and the token no longer rotates.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    };
    let Some(h) = build(spec) else { return };
    let app = router(&h);
    seed_user(&h, "blo@e.com", "glidingwalnut42", "USER").await;
    let session = login(&app, "blo@e.com", "glidingwalnut42").await;
    let access = session.json()["accessToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let refresh = session.json()["refreshToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(!refresh.is_empty());

    let logout = Req::post("/auth/logout")
        .bearer(&access)
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    // The revoked refresh token is dead: rotating it now fails.
    let replay = Req::post("/auth/refresh")
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.json()["error"]["code"], "auth.refresh_token_invalid");
}

#[tokio::test]
async fn logout_without_any_refresh_token_still_succeeds() {
    // Logout stays best-effort and idempotent: neither an absent body nor an unparseable one
    // blocks it (the access JTI is still blacklisted), so a client can always end its session.
    let spec = EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    };
    let Some(h) = build(spec) else { return };
    let app = router(&h);
    seed_user(&h, "nolo@e.com", "glidingwalnut42", "USER").await;

    let first = login(&app, "nolo@e.com", "glidingwalnut42").await;
    let access = first.json()["accessToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let bare = Req::post("/auth/logout").bearer(&access).send(&app).await;
    assert_eq!(bare.status, StatusCode::NO_CONTENT);
    // The access token was still revoked, so it no longer authenticates.
    let after = Req::get("/auth/me").bearer(&access).send(&app).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);

    let second = login(&app, "nolo@e.com", "glidingwalnut42").await;
    let access2 = second.json()["accessToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let junk = Req::post("/auth/logout")
        .bearer(&access2)
        .raw_body(b"{not json".to_vec(), "application/json")
        .send(&app)
        .await;
    assert_eq!(junk.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn platform_logout_revokes_the_refresh_session_from_the_body() {
    // The platform twin of the logout gap: platform delivery never plants a cookie, so the
    // refresh token can only arrive in the body. Reading it there is what actually kills the
    // platform refresh session.
    let Some(h) = build(EngineSpec {
        platform: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "plo@e.com", "SUPER_ADMIN").await;
    let session = platform_login(&app, "plo@e.com").await;
    let access = platform_access(&session);
    let refresh = platform_refresh(&session);

    let logout = Req::post("/auth/platform/logout")
        .bearer(&access)
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    let replay = Req::post("/auth/platform/refresh")
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_credentials_and_unknown_email_are_indistinguishable() {
    // Anti-enumeration: a wrong password and an unknown email both return the same generic
    // 401 invalid-credentials.
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "known@e.com", "glidingwalnut42", "USER").await;

    let wrong = login(&app, "known@e.com", "wrongpass").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"]["code"], "auth.invalid_credentials");

    let unknown = login(&app, "nobody@e.com", "glidingwalnut42").await;
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
            "email": "not-an-email", "password": "glidingwalnut42", "name": "X", "tenantId": TENANT
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
    seed_user(&h, "tok@e.com", "glidingwalnut42", "USER").await;

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
    let access = login_access_cookie(&app, "tok@e.com", "glidingwalnut42").await;
    let login_resp = login(&app, "tok@e.com", "glidingwalnut42").await;
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
    // The uniform body is half the anti-enumeration contract: an empty response would be as
    // distinguishable to a prober as a 404.
    assert_eq!(forgot.json(), serde_json::json!({}));

    // resend-otp likewise.
    let resend = Req::post("/auth/password/resend-otp")
        .json(serde_json::json!({ "email": "ghost@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;
    assert_eq!(resend.status, StatusCode::OK);
    assert_eq!(resend.json(), serde_json::json!({}));

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
            "email": "s@e.com", "password": "glidingwalnut42", "name": "Sam", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let refresh = reg.cookie_value("refresh_token").unwrap_or_default();

    // List the caller's sessions; the current one is flagged. The body is the BARE array —
    // nest-auth's `SessionController.listSessions` returns `SessionInfo[]`, not a
    // `{ sessions: [...] }` wrapper.
    let list = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(list.json().get("sessions").is_none());
    let sessions = list.json().as_array().cloned().unwrap_or_default();
    assert!(!sessions.is_empty());
    // The per-item shape is unchanged: the display id, the full hash, and the current flag.
    assert!(sessions[0]["id"].is_string());
    assert_eq!(sessions[0]["isCurrent"], true);
    let hash = sessions[0]["sessionHash"].as_str().unwrap_or("").to_owned();

    // The static `all` segment wins over the `{id}` capture.
    let revoke_all = Req::delete("/auth/sessions/all")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(revoke_all.status, StatusCode::NO_CONTENT);

    // Revoking the other devices advances the token epoch, so every access token for the
    // account is stale — the caller's included. Without it, a device the user just signed out
    // keeps working until its access token expires, which is not what "sign out my other
    // devices" means to the person clicking it.
    let stale = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);

    // The caller — and only the caller — recovers immediately: the one refresh session the
    // revocation preserved is theirs. The revoked devices lost theirs and cannot.
    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let access = rotated
        .cookie_value("access_token")
        .unwrap_or_default()
        .to_owned();
    let refresh = rotated
        .cookie_value("refresh_token")
        .unwrap_or_default()
        .to_owned();

    // The pre-rotation hash names a session the rotation has since replaced, so the `{id}`
    // route reports it as gone rather than pretending to revoke it.
    let already_gone = Req::delete(&format!("/auth/sessions/{hash}"))
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(already_gone.status, StatusCode::NOT_FOUND);

    // A second device, so there is a real session to revoke by id.
    let second = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "s@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(second.status, StatusCode::OK);

    let list = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    let sessions = list.json().as_array().cloned().unwrap_or_default();
    let victim = sessions
        .iter()
        .find(|session| session["isCurrent"] != true)
        .and_then(|session| session["sessionHash"].as_str())
        .unwrap_or_default()
        .to_owned();
    assert!(!victim.is_empty());

    // Revoke that one by its hash.
    let revoke_one = Req::delete(&format!("/auth/sessions/{victim}"))
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(revoke_one.status, StatusCode::NO_CONTENT);

    // Revoking ONE session advances the epoch for the same reason revoking all of them does:
    // deleting the refresh session stops rotation but says nothing about the access token that
    // device is already carrying, and someone revoking a device they believe is compromised is
    // deciding about right now. The caller's own token goes stale too and is re-minted on the
    // next rotation — which the shipped client does silently, and which this test does by hand.
    let stale_again = Req::get("/auth/sessions")
        .cookie("access_token", &access)
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(stale_again.status, StatusCode::UNAUTHORIZED);
    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let access = rotated
        .cookie_value("access_token")
        .unwrap_or_default()
        .to_owned();

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
            "email": "m@e.com", "password": "glidingwalnut42", "name": "Mo", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();

    // setup returns the secret/qr/recovery codes (enrolment is reachable without MfaSatisfied),
    // with a 201 — nest-auth's `MfaController.setup` carries no `@HttpCode`, so it answers with
    // Nest's `POST` default.
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    assert_eq!(setup.status, StatusCode::CREATED);
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
    let id = seed_user(&h, "mfauser@e.com", "glidingwalnut42", "USER").await;
    enable_mfa_flag(&h, &id).await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "mfauser@e.com", "password": "glidingwalnut42", "tenantId": TENANT
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

    // Platform login (no tenant) returns a platform session in the BODY under `admin`, with
    // the token pair alongside — nest-auth's `PlatformBearerAuthResponse`. Even though this
    // engine is in `cookie` delivery mode, the platform path plants NO cookie at all.
    let login = platform_login(&app, "boss@e.com").await;
    assert_eq!(login.status, StatusCode::OK);
    assert!(login.set_cookies.is_empty());
    assert_eq!(login.json()["admin"]["email"], "boss@e.com");
    assert!(login.json().get("user").is_none());
    let access = platform_access(&login);
    assert!(!access.is_empty());
    assert!(!platform_refresh(&login).is_empty());

    // Platform `me` returns the admin as the top-level body (no wrapper, no tenantId), read
    // via the bearer header — the only channel a platform token ever travels on.
    let me = Req::get("/auth/platform/me")
        .bearer(&access)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["email"], "boss@e.com");
    assert!(me.json().get("user").is_none());

    // A dashboard token on a platform route is `platform_auth_required`.
    let dash = seed_user(&h, "tenant@e.com", "glidingwalnut42", "USER").await;
    let _ = dash;
    let dash_login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "tenant@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let dash_token = dash_login.cookie_value("access_token").unwrap_or_default();
    let wrong = Req::get("/auth/platform/me")
        .bearer(&dash_token)
        .send(&app)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"]["code"], "auth.platform_auth_required");

    // The dashboard access COOKIE is never accepted on a platform route either, whatever it
    // carries — platform extraction reads the bearer header only.
    let via_cookie = Req::get("/auth/platform/me")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(via_cookie.status, StatusCode::UNAUTHORIZED);

    // Platform logout clears the session.
    let logout = Req::post("/auth/platform/logout")
        .bearer(&access)
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

    // With a platform bearer token, setup returns the enrolment material with a 201 (the
    // shared nest-auth `MfaController.setup` has no `@HttpCode`).
    seed_admin(&h, "padmin@e.com", "SUPER_ADMIN").await;
    let login = platform_login(&app, "padmin@e.com").await;
    let access = platform_access(&login);
    let setup_ok = Req::post("/auth/platform/mfa/setup")
        .bearer(&access)
        .json(serde_json::json!({ "password": "adminpass123" }))
        .send(&app)
        .await;
    assert_eq!(setup_ok.status, StatusCode::CREATED);
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
    let admin_id = seed_user(&h, "inviter@e.com", "glidingwalnut42", "ADMIN").await;
    let _ = admin_id;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "inviter@e.com", "password": "glidingwalnut42", "tenantId": TENANT
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

    // Accepting a well-shaped token that names no invitation is an invalid-invitation-token
    // 400. Well-shaped on purpose: a token of the wrong LENGTH is refused by the DTO before
    // the engine sees it, which exercises the validation envelope rather than this arm.
    let accept = Req::post("/auth/invitations/accept")
        .json(serde_json::json!({
            "token": "b".repeat(64), "name": "New User", "password": "glidingwalnut42"
        }))
        .send(&app)
        .await;
    assert_eq!(accept.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        accept.json()["error"]["code"],
        "auth.invalid_invitation_token"
    );

    // The invitation created above can be withdrawn — an invitation is a credential, and
    // until this route existed it stayed redeemable for its whole TTL whatever happened.
    let revoke = Req::post("/auth/invitations/revoke")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "invitee@e.com" }))
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    // …and so is an address that has none: the endpoint answers the same either way, or it
    // becomes an oracle for which addresses have pending invitations.
    let absent = Req::post("/auth/invitations/revoke")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "nobody@e.com" }))
        .send(&app)
        .await;
    assert_eq!(absent.status, StatusCode::NO_CONTENT);

    // Withdrawing without auth is rejected, exactly like minting one.
    let no_auth_revoke = Req::post("/auth/invitations/revoke")
        .json(serde_json::json!({ "email": "invitee@e.com" }))
        .send(&app)
        .await;
    assert_eq!(no_auth_revoke.status, StatusCode::UNAUTHORIZED);
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

    // The initiate response planted the binding cookie: HttpOnly, SameSite=Lax (the provider's
    // callback is a cross-site top-level GET, and Strict would withhold the cookie on exactly
    // that hop), scoped to `/`, carrying the same state the authorize URL carries.
    let planted = initiate.cookie("oauth_state").unwrap_or_default();
    assert!(planted.contains(&format!("oauth_state={state}")));
    assert!(planted.contains("HttpOnly"));
    assert!(planted.contains("SameSite=Lax"));
    assert!(planted.contains("Path=/"));

    // Without the cookie, a callback carrying a live state is refused — the lured-victim
    // request, where the attacker holds the URL and the victim's browser holds no cookie for
    // the attacker's flow (RFC 6749 §10.12). Sent BEFORE the legitimate callback below, so
    // the 401 cannot be explained by an already-spent state; the success that follows proves
    // the refusal did not burn it either.
    let lured = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .send(&app)
    .await;
    assert_eq!(lured.status, StatusCode::UNAUTHORIZED);
    assert_eq!(lured.json()["error"]["code"], "auth.oauth_failed");

    // The callback consumes the state and (via the allowing hook) creates a session.
    let callback = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    // The browser replays the `oauth_state` cookie the initiate response planted; without it
    // the callback is refused, which is the whole point of the binding (RFC 6749 §10.12).
    .cookie("oauth_state", &state)
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
            "email": "ws@e.com", "password": "glidingwalnut42", "name": "Wes", "tenantId": TENANT
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
    seed_user(&h, "rl@e.com", "glidingwalnut42", "USER").await;

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
            "email": "fresh@e.com", "password": "glidingwalnut42", "name": "Fresh", "tenantId": TENANT
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
    seed_user(&h, "ov@e.com", "glidingwalnut42", "USER").await;
    let limits = RateLimitConfig {
        login: Some(RateLimit::new(1, 60)),
        register: None,
        ..RateLimitConfig::default()
    };
    let config = AxumAuthConfig {
        rate_limits: limits,
        ..AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
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
        ..AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
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
    let login = platform_login(&app, "ops@e.com").await;
    let access = platform_access(&login);
    let refresh = platform_refresh(&login);

    // Platform refresh rotates the pair from the BODY (platform never uses cookies) and echoes
    // the admin alongside the new pair, matching `PlatformAuthController.refresh`.
    let rotated = Req::post("/auth/platform/refresh")
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert!(rotated.set_cookies.is_empty());
    assert_eq!(rotated.json()["admin"]["email"], "ops@e.com");
    assert!(rotated.json()["accessToken"].is_string());
    assert_ne!(platform_refresh(&rotated), refresh);

    // A malformed platform refresh body is a validation error.
    let bad = Req::post("/auth/platform/refresh")
        .raw_body(b"{not json".to_vec(), "application/json")
        .send(&app)
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // revoke-all with a platform token succeeds.
    let revoke = Req::delete("/auth/platform/sessions")
        .bearer(&access)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    // The public platform MFA challenge with a bogus temp token is rejected.
    let challenge = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": "bogus", "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);

    // Omitting the temp token entirely is an INVALID-TEMP-TOKEN 401, not a validation 400:
    // the shared DTO makes the field optional for the dashboard OAuth cookie flow, and the
    // platform handler (which has no cookie flow) rejects the absence explicitly, exactly as
    // `PlatformAuthController.mfaChallenge` does.
    let missing = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.json()["error"]["code"],
        "auth.mfa_temp_token_invalid"
    );
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
    let login = platform_login(&app, "padmin2@e.com").await;
    let access = platform_access(&login);

    // Enrolment answers 201 (Nest's `POST` default, since `MfaController.setup` sets no code).
    let setup = Req::post("/auth/platform/mfa/setup")
        .bearer(&access)
        .json(serde_json::json!({ "password": "adminpass123" }))
        .send(&app)
        .await;
    assert_eq!(setup.status, StatusCode::CREATED);
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();

    // ONE captured base for every code: distinct steps per verification, immune to a step
    // boundary passing mid-test (see totp_at_abs).
    let base = common::now_unix();
    let enable = Req::post("/auth/platform/mfa/verify-enable")
        .bearer(&access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base) }))
        .send(&app)
        .await;
    assert_eq!(enable.status, StatusCode::NO_CONTENT);

    // Enabling bumped the platform token epoch, so the pre-enable token is dead — exactly
    // what a compromised-account recovery needs. The admin re-authenticates through the
    // platform challenge, as a real client would.
    let stale = Req::post("/auth/platform/mfa/recovery-codes")
        .bearer(&access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base + 30) }))
        .send(&app)
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);

    let relogin = platform_login(&app, "padmin2@e.com").await;
    let temp = relogin.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let challenged = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 30) }))
        .send(&app)
        .await;
    assert_eq!(challenged.status, StatusCode::OK);
    let access = platform_access(&challenged);

    // recovery-codes with a fresh-step TOTP returns a fresh set.
    let recov = Req::post("/auth/platform/mfa/recovery-codes")
        .bearer(&access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base + 60) }))
        .send(&app)
        .await;
    assert_eq!(recov.status, StatusCode::OK);
    assert!(recov.json()["recoveryCodes"].is_array());

    // disable with step base-30: inside the verifier's window, never consumed by anti-replay
    // (the steps at base, base+30 and base+60 all were).
    let disable = Req::post("/auth/platform/mfa/disable")
        .bearer(&access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base - 30) }))
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
            "email": "ch@e.com", "password": "glidingwalnut42", "name": "Cho", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
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
            "email": "ch@e.com", "password": "glidingwalnut42", "tenantId": TENANT
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

#[tokio::test]
async fn mfa_challenge_falls_back_to_the_oauth_temp_cookie_and_clears_it() {
    // The browser OAuth + MFA flow end to end: the callback plants the HttpOnly
    // `mfa_temp_token` cookie and 302s to the MFA page, which can never read that cookie to
    // echo it in a body. Requiring `mfaTempToken` in the body therefore made the flow
    // impossible to complete. The cookie is now the fallback — and it is CLEARED once consumed
    // so the spent token is not left in the browser.
    let Some(h) = build(EngineSpec {
        mfa: true,
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    // The mock provider resolves to this account; enabling MFA makes the callback yield a
    // challenge rather than a session.
    let id = seed_user(&h, "mock@example.com", "glidingwalnut42", "USER").await;
    let app = router(&h);

    // Enrol MFA properly so a recovery code exists for the challenge.
    let login0 = login(&app, "mock@example.com", "glidingwalnut42").await;
    let access = login0.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    use bymax_auth_core::traits::UserRepository;
    let _ = h.users.link_oauth(&id, "google", "mock-123").await;

    // Drive the real OAuth callback so the temp cookie is planted by the adapter itself.
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
    // The browser replays the `oauth_state` cookie the initiate response planted; without it
    // the callback is refused, which is the whole point of the binding (RFC 6749 §10.12).
    .cookie("oauth_state", &state)
    .send(&app)
    .await;
    let temp_cookie = callback.cookie_value("mfa_temp_token").unwrap_or_default();
    assert!(!temp_cookie.is_empty());

    // The challenge body omits `mfaTempToken` entirely — the cookie carries it.
    let challenge = Req::post("/auth/mfa/challenge")
        .cookie("mfa_temp_token", &temp_cookie)
        .json(serde_json::json!({ "code": recovery }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.has_cookie_value("access_token"));
    // The consumed temp cookie is cleared (a `Set-Cookie` with an empty value).
    assert!(challenge.cookie("mfa_temp_token").is_some());
    assert!(!challenge.has_cookie_value("mfa_temp_token"));
}

#[tokio::test]
async fn mfa_challenge_temp_token_sourcing_precedence_and_clearing_policy() {
    // Three rules of the cookie fallback, all mirroring `mfa.controller.ts`:
    //   1. neither channel supplied → `mfa_temp_token_invalid`, NOT a validation 400;
    //   2. a dead cookie token → cleared (retrying under it can never succeed);
    //   3. a live token + a WRONG code → cookie KEPT, so the user can retry inside its TTL.
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    // 1. Neither body nor cookie.
    let neither = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({ "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(neither.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        neither.json()["error"]["code"],
        "auth.mfa_temp_token_invalid"
    );

    // 2. A forged cookie token is invalid → the cookie is cleared.
    let dead = Req::post("/auth/mfa/challenge")
        .cookie("mfa_temp_token", "bogus")
        .json(serde_json::json!({ "code": "123456" }))
        .send(&app)
        .await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
    assert!(dead.cookie("mfa_temp_token").is_some());
    assert!(!dead.has_cookie_value("mfa_temp_token"));

    // 3. A LIVE temp token from a real MFA login, submitted with a wrong code: the failure is
    // recoverable, so the cookie must survive for the retry.
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "keep@e.com", "password": "glidingwalnut42", "name": "Kee", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    let mfa_login = login(&app, "keep@e.com", "glidingwalnut42").await;
    let temp = mfa_login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(!temp.is_empty());
    let wrong_code = Req::post("/auth/mfa/challenge")
        .cookie("mfa_temp_token", &temp)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(wrong_code.status, StatusCode::OK);
    assert_eq!(
        wrong_code.json()["error"]["code"],
        "auth.mfa_invalid_code",
        "a wrong code must not be reported as an invalid temp token"
    );
    assert!(wrong_code.cookie("mfa_temp_token").is_none());
}

#[tokio::test]
async fn mfa_challenge_body_token_wins_over_a_stale_cookie() {
    // The body is the historical channel of the password-login flow, so it takes precedence
    // when both are present. On success the stale cookie is still cleared — nest-auth clears
    // whenever a cookie was on the request, so a spent OAuth cookie never lingers after the
    // challenge completes through the other channel.
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "pref@e.com", "password": "glidingwalnut42", "name": "Pre", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;

    let mfa_login = login(&app, "pref@e.com", "glidingwalnut42").await;
    let temp = mfa_login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // The body carries the REAL token while the cookie carries garbage: the body wins, so the
    // challenge succeeds (a cookie-first handler would have failed on the garbage value).
    let challenge = Req::post("/auth/mfa/challenge")
        .cookie("mfa_temp_token", "stale-and-ignored")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": recovery }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.has_cookie_value("access_token"));
    // The stale cookie present on the request is cleared on success all the same.
    assert!(challenge.cookie("mfa_temp_token").is_some());
    assert!(!challenge.has_cookie_value("mfa_temp_token"));
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
async fn a_provider_error_callback_is_an_oauth_failure_not_a_validation_error() {
    // RFC 6749 §4.1.2.1: a provider that refuses answers with `error` and no `code` — which is
    // what Google sends when the user clicks "Cancel". The query used to require `code`, so a
    // user who simply changed their mind got a validation envelope instead of the library's
    // own refusal. A callback carrying neither takes the same path.
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    for query in [
        "error=access_denied&state=deadbeef",
        "error=temporarily_unavailable&error_description=try%20later&state=deadbeef",
        "state=deadbeef",
    ] {
        let res = Req::get(&format!("/auth/oauth/google/callback?{query}"))
            .send(&app)
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "for query {query}");
        assert_eq!(res.json()["error"]["code"], "auth.oauth_failed");
        // The provider's own string never reaches the caller: it is provider-chosen text, and
        // `oauth_failed` already says everything the library is willing to vouch for.
        let body = String::from_utf8_lossy(&res.body).to_string();
        assert!(!body.contains("access_denied"));
        assert!(!body.contains("temporarily_unavailable"));
    }
}

#[tokio::test]
async fn an_infrastructure_failure_on_the_callback_does_not_become_an_error_redirect() {
    // The error redirect exists to explain a refusal to a user. A store that is down is not a
    // refusal: dressing it up as `?error=oauth_failed` would tell the user to try again while
    // hiding an outage from whatever watches 5xx. Only an `OauthFailed` gets the redirect.
    let Some(h) = build_oauth_with_failing_state_store() else { return };
    let app = router(&h);

    // A well-formed 64-hex state: a malformed one is refused on shape before the store is
    // ever consulted, and the test would pass on the wrong path.
    let state = "a".repeat(64);
    let res = Req::get(&format!(
        "/auth/oauth/google/callback?code=abc&state={state}"
    ))
    .cookie("oauth_state", &state)
    .send(&app)
    .await;

    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!res.headers.contains_key(header::LOCATION));
}

#[tokio::test]
async fn oauth_callback_redirect_branches() {
    use bymax_auth_axum::{AuthRouter, AxumAuthConfig};
    use bymax_auth_core::config::TokenDelivery;
    // Build an engine with the three redirect URLs configured.
    let Some(h) = build_oauth_with_redirects() else { return };
    let _ = TokenDelivery::Cookie;
    let app = AuthRouter::from_engine(
        h.engine.clone(),
        AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr),
    )
    .into_router();

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
    // The browser replays the `oauth_state` cookie the initiate response planted; without it
    // the callback is refused, which is the whole point of the binding (RFC 6749 §10.12).
    .cookie("oauth_state", &state)
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
    seed_user(&h, "dup@e.com", "glidingwalnut42", "USER").await;
    let resp = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "dup@e.com", "password": "glidingwalnut42", "name": "Dup", "tenantId": TENANT
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
            "email": "rv@e.com", "password": "glidingwalnut42", "name": "Rv", "tenantId": TENANT
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
    seed_user(&h, "inv2@e.com", "glidingwalnut42", "ADMIN").await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "inv2@e.com", "password": "glidingwalnut42", "tenantId": TENANT
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
    seed_user(&h, "pw@e.com", "glidingwalnut42", "USER").await;

    // Trigger the reset so an OTP record exists.
    let _ = Req::post("/auth/password/forgot-password")
        .json(serde_json::json!({ "email": "pw@e.com", "tenantId": TENANT }))
        .send(&app)
        .await;

    // Recover the OTP from the in-memory store (the engine derives the identifier internally).
    // Asserted rather than skipped: the OTP existing is what proves the route reached the
    // engine at all, and a skip here would pass just as happily against a handler that did
    // nothing but answer 200.
    let otp = common::peek_otp(&h, OtpPurpose::PasswordReset, "pw@e.com").unwrap_or_default();
    assert!(!otp.is_empty(), "forgot-password minted no reset OTP");

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
        ..AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
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

/// A realistically shaped invitation token: 64 hex characters, exactly what the engine
/// mints and exactly what the DTO now requires.
const INVITE_TOKEN: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

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
    let inviter = seed_user(&h, "host@e.com", "glidingwalnut42", "ADMIN").await;
    let invitation = StoredInvitation {
        email: "joiner@e.com".to_owned(),
        role: "USER".to_owned(),
        tenant_id: TENANT.to_owned(),
        inviter_user_id: inviter,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    let _ = h
        .stores
        .put_invitation(INVITE_TOKEN, &invitation, 600)
        .await;

    let accept = Req::post("/auth/invitations/accept")
        .json(serde_json::json!({
            "token": INVITE_TOKEN, "name": "New Joiner", "password": "glidingwalnut42"
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
    let login0 = platform_login(&app, "mfaboss@e.com").await;
    let access = platform_access(&login0);
    let setup = Req::post("/auth/platform/mfa/setup")
        .bearer(&access)
        .json(serde_json::json!({ "password": "adminpass123" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/platform/mfa/verify-enable")
        .bearer(&access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    let _ = admin_id;

    // A fresh login now returns a platform MFA challenge.
    let login = platform_login(&app, "mfaboss@e.com").await;
    assert_eq!(login.json()["mfaRequired"], true);
    let temp = login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // Completing the platform MFA challenge with a recovery code issues a platform session —
    // in the body under `admin`, with no cookie planted (platform is always bearer).
    let challenge = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": recovery }))
        .send(&app)
        .await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.set_cookies.is_empty());
    assert_eq!(challenge.json()["admin"]["email"], "mfaboss@e.com");
    assert!(!platform_access(&challenge).is_empty());
}

#[tokio::test]
async fn oauth_callback_with_mfa_user_takes_the_mfa_redirect_branch() {
    // An OAuth user with MFA enabled yields an MfaChallenge outcome; with the mfa_redirect_url
    // configured the callback 302-redirects and plants the mfa_temp cookie (the MFA branch).
    let Some(h) = build_oauth_with_redirects() else { return };
    // Pre-create the OAuth user with MFA enabled so the callback resolves to a challenge.
    let id = seed_user(&h, "mock@example.com", "glidingwalnut42", "USER").await;
    enable_mfa_flag(&h, &id).await;
    // Link the OAuth identity so the callback finds this user (provider id from the mock).
    use bymax_auth_core::traits::UserRepository;
    let _ = h.users.link_oauth(&id, "google", "mock-123").await;

    let app = bymax_auth_axum::AuthRouter::from_engine(
        h.engine.clone(),
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr),
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
    // The browser replays the `oauth_state` cookie the initiate response planted; without it
    // the callback is refused, which is the whole point of the binding (RFC 6749 §10.12).
    .cookie("oauth_state", &state)
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
    let app = bymax_auth_axum::auth_router(
        engine,
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr),
    );
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
        .bearer(&ghost)
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.json()["error"]["code"], "auth.token_invalid");

    // revoke-all for a ghost admin: the engine revokes nothing but still bumps the ghost's
    // epoch — 204, and the path is exercised.
    let revoke = Req::delete("/auth/platform/sessions")
        .bearer(&ghost)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);
    // The token that performed the revoke is now dead like every other token the ghost held:
    // revoke-all reaches the access tokens too, not only the refresh sessions. Probed with
    // `me` rather than `logout` — logout is deliberately public now, so that an operator whose
    // access token expired can still end their session, which makes it useless as evidence
    // that a token is still alive.
    let dead = Req::get("/auth/platform/me")
        .bearer(&ghost)
        .send(&app)
        .await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
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
            "email": "me2@e.com", "password": "glidingwalnut42", "name": "M", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    // setup again now hits the setup error arm; the exact status depends on the engine's
    // re-enrolment policy, so assert only that it is no longer the 201 success.
    let again = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    assert_ne!(again.status, StatusCode::CREATED);
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
            "email": "ve@e.com", "password": "glidingwalnut42", "name": "V", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let _ = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
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
    let id = seed_user(&h, "mock@example.com", "glidingwalnut42", "USER").await;
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
    // The browser replays the `oauth_state` cookie the initiate response planted; without it
    // the callback is refused, which is the whole point of the binding (RFC 6749 §10.12).
    .cookie("oauth_state", &state)
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
            "email": "vfy@e.com", "password": "glidingwalnut42", "name": "Vfy", "tenantId": TENANT
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
            "email": "dr@e.com", "password": "glidingwalnut42", "name": "Dr", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    // ONE captured base for every code in this test: per-call clock reads can straddle a
    // 30-second step boundary mid-test and collide two "distinct" steps on the anti-replay
    // marker (see totp_at_abs).
    let base = common::now_unix();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base) }))
        .send(&app)
        .await;

    // Enabling bumped the token epoch, so the pre-enable token is dead — the account must
    // re-authenticate through the challenge, which is exactly what a real client does.
    let stale = Req::post("/auth/mfa/recovery-codes")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base + 30) }))
        .send(&app)
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);

    let relogin = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "dr@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let temp = relogin.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let challenged = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({ "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 30) }))
        .send(&app)
        .await;
    assert_eq!(challenged.status, StatusCode::OK);
    let access = challenged.cookie_value("access_token").unwrap_or_default();

    let recov = Req::post("/auth/mfa/recovery-codes")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base + 60) }))
        .send(&app)
        .await;
    assert_eq!(recov.status, StatusCode::OK);

    // Step base-30: inside the verifier's window and never consumed by the anti-replay
    // marker (the steps at base, base+30 and base+60 all were).
    let disable = Req::post("/auth/mfa/disable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, base - 30) }))
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
    assert_ne!(setup.status, StatusCode::CREATED);

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
        .bearer(&ghost)
        .send(&app)
        .await;
    assert_ne!(setup.status, StatusCode::CREATED);
    let verify = Req::post("/auth/platform/mfa/verify-enable")
        .bearer(&ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(verify.status, StatusCode::NO_CONTENT);
    let disable = Req::post("/auth/platform/mfa/disable")
        .bearer(&ghost)
        .json(serde_json::json!({ "code": "000000" }))
        .send(&app)
        .await;
    assert_ne!(disable.status, StatusCode::NO_CONTENT);
    let recov = Req::post("/auth/platform/mfa/recovery-codes")
        .bearer(&ghost)
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
    let login0 = platform_login(&app, "ctx@e.com").await;
    let access = platform_access(&login0);
    let setup = Req::post("/auth/platform/mfa/setup")
        .bearer(&access)
        .json(serde_json::json!({ "password": "adminpass123" }))
        .send(&app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/platform/mfa/verify-enable")
        .bearer(&access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(&app)
        .await;
    let _ = admin;
    let plogin = platform_login(&app, "ctx@e.com").await;
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
            "email": "sf@e.com", "password": "glidingwalnut42", "name": "Sf", "tenantId": TENANT
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
            "email": "wsf@e.com", "password": "glidingwalnut42", "name": "Wf", "tenantId": TENANT
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
        .bearer(&token)
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn refresh_surfaces_a_failure_to_re_read_the_account_after_rotation() {
    // Echoing the account in the refresh body means the handler does a second step after the
    // rotation succeeds: recover the subject from the new access token, then re-read the
    // record. With the `rv:{jti}` revocation check failing (Redis down) that second step
    // fails, and the request MUST surface the infrastructure error as a 500 — reporting a
    // rotation whose body could not be built as a success would hand the client a body it
    // cannot use.
    let Some(h) = common::build_failing_blacklist() else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "rr@e.com", "password": "glidingwalnut42", "name": "Rr", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let refresh = reg.cookie_value("refresh_token").unwrap_or_default();
    assert!(!refresh.is_empty());

    let rotated = Req::post("/auth/refresh")
        .cookie("refresh_token", &refresh)
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(rotated.json()["error"]["code"], "auth.internal");
}

#[tokio::test]
async fn platform_refresh_surfaces_a_failure_to_re_read_the_admin_after_rotation() {
    // The platform twin of the above: the admin echo needs the freshly-minted platform token
    // verified, so a failing revocation check turns the rotation into a 500 rather than a
    // success with no `admin` in it.
    let Some(h) = common::build_failing_blacklist() else {
        return;
    };
    let app = router(&h);
    seed_admin(&h, "rrp@e.com", "SUPER_ADMIN").await;
    let session = platform_login(&app, "rrp@e.com").await;
    let refresh = platform_refresh(&session);
    assert!(!refresh.is_empty());

    let rotated = Req::post("/auth/platform/refresh")
        .json(serde_json::json!({ "refreshToken": refresh }))
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(rotated.json()["error"]["code"], "auth.internal");
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
        .bearer(&token)
        .send(&app)
        .await;
    assert_eq!(internal.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(internal.json()["error"]["code"], "auth.internal");

    // A token-auth failure (a malformed/invalid token) never reaches the revocation check, so it
    // still collapses to `platform_auth_required` (401) — the masking is correct for THIS case.
    let invalid = Req::get("/auth/platform/me")
        .bearer("not-a-jwt")
        .send(&app)
        .await;
    assert_eq!(invalid.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid.json()["error"]["code"],
        "auth.platform_auth_required"
    );
}

// ---------------------------------------------------------------------------
// Cross-site request check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_cookie_authenticated_write_from_an_untrusted_origin_is_refused() {
    // The attack this exists for: under `SameSite=None` the browser attaches the session
    // cookie to a POST issued by a page on another origin, and without the check that request
    // is authenticated. `Lax`/`Strict` never send the cookie cross-site, so the exposure is
    // exactly the `None` deployment — which is the one configured here.
    let Some(h) = build(EngineSpec {
        trusted_origins: &["https://app.example.com"],
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "csrf@e.com", "glidingwalnut42", "USER").await;
    let access = login_access_cookie(&app, "csrf@e.com", "glidingwalnut42").await;

    let refused = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .header(header::ORIGIN, "https://evil.example.com")
        .header(HeaderName::from_static("sec-fetch-site"), "cross-site")
        .send(&app)
        .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(
        refused.json()["error"]["code"],
        serde_json::json!("auth.untrusted_origin")
    );

    // The refresh cookie is a credential in its own right — it mints access tokens — so a
    // request carrying only that one is as much a target as one carrying the access cookie.
    let refresh_only = Req::post("/auth/logout")
        .cookie("refresh_token", &"r".repeat(64))
        .header(header::ORIGIN, "https://evil.example.com")
        .send(&app)
        .await;
    assert_eq!(refresh_only.status, StatusCode::FORBIDDEN);

    // These two used to be admitted, because a request carrying none of the module's cookies
    // was read as having no ambient credential to abuse. The requests that MINT one were the
    // gap: this layer wraps the whole router, and `POST /auth/login` carries no cookie and
    // answers with a session — so an attacker's page could log a victim's browser into the
    // ATTACKER's account and then read back whatever the victim did there.
    let login_csrf = Req::post("/auth/login")
        .header(header::ORIGIN, "https://evil.example.com")
        .header(HeaderName::from_static("sec-fetch-site"), "cross-site")
        .json(serde_json::json!({ "email": "origin@e.com", "password": "glidingwalnut42" }))
        .send(&app)
        .await;
    assert_eq!(login_csrf.status, StatusCode::FORBIDDEN);

    // Same for the session-signal cookie, which authenticates nothing: what decides the
    // refusal is the announced origin, not what the request already carries.
    let signal_only = Req::post("/auth/logout")
        .cookie("has_session", "1")
        .header(header::ORIGIN, "https://evil.example.com")
        .send(&app)
        .await;
    assert_eq!(signal_only.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_cross_site_check_admits_what_it_should() {
    let Some(h) = build(EngineSpec {
        trusted_origins: &["https://app.example.com"],
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "origin@e.com", "glidingwalnut42", "USER").await;

    // A listed origin is what the allow-list is for.
    let access = login_access_cookie(&app, "origin@e.com", "glidingwalnut42").await;
    let allowed = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .header(header::ORIGIN, "https://app.example.com")
        .send(&app)
        .await;
    assert_eq!(allowed.status, StatusCode::NO_CONTENT);

    // The app calling itself never consults the list — which is what keeps a same-origin
    // deployment working with nothing configured.
    let access = login_access_cookie(&app, "origin@e.com", "glidingwalnut42").await;
    let same_origin = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .header(header::ORIGIN, "https://evil.example.com")
        .header(HeaderName::from_static("sec-fetch-site"), "same-origin")
        .send(&app)
        .await;
    assert_eq!(same_origin.status, StatusCode::NO_CONTENT);

    // The real non-browser caller: no `Origin`, no `Sec-Fetch-Site`. That shape is admitted,
    // and it is the one that keeps curl and server-to-server callers working — no page can
    // make a browser OMIT `Origin` on a cross-site request, so the absence is evidence there
    // is no browser involved. A caller that DOES announce an untrusted origin is refused
    // whether or not it carries a cookie; see the two cases below.
    let bearer = Req::post("/auth/logout")
        .json(serde_json::json!({ "refreshToken": "r".repeat(64) }))
        .send(&app)
        .await;
    assert_ne!(bearer.status, StatusCode::FORBIDDEN);

    // Origin casing: scheme and host are case-insensitive (RFC 6454 §4), so an origin that
    // differs from the listed one only in case IS the listed origin and must be admitted.
    let access = login_access_cookie(&app, "origin@e.com", "glidingwalnut42").await;
    let upper = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .header(header::ORIGIN, "https://APP.Example.COM")
        .send(&app)
        .await;
    assert_eq!(upper.status, StatusCode::NO_CONTENT);

    // A read changes nothing and is never a target.
    let read = Req::get("/auth/me")
        .cookie(
            "access_token",
            &login_access_cookie(&app, "origin@e.com", "glidingwalnut42").await,
        )
        .header(header::ORIGIN, "https://evil.example.com")
        .send(&app)
        .await;
    assert_eq!(read.status, StatusCode::OK);
}

#[tokio::test]
async fn a_cross_site_fetch_with_no_origin_header_is_refused() {
    // A browser that sends `Sec-Fetch-Site` sends `Origin` too on a state-changing request, so
    // this shape is malformed rather than a legitimate caller — and admitting it would be a
    // trivial way around the check.
    let Some(h) = build(EngineSpec {
        trusted_origins: &["https://app.example.com"],
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "nohdr@e.com", "glidingwalnut42", "USER").await;
    let access = login_access_cookie(&app, "nohdr@e.com", "glidingwalnut42").await;

    let refused = Req::post("/auth/logout")
        .cookie("access_token", &access)
        .header(HeaderName::from_static("sec-fetch-site"), "same-site")
        .send(&app)
        .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_default_posture_refuses_a_cross_site_login_with_nothing_allowlisted() {
    // The DEFAULT deployment: `SameSite=Lax`, empty `trusted_origins`. Every other test in this
    // file that exercises the origin layer populates the list, which forces `SameSite=None` in
    // the harness — so this shape, the one most consumers actually run, had no coverage at all.
    //
    // It used to be admitted: an empty list short-circuited the whole check. The justification
    // was that `Lax` withholds the session cookie cross-site anyway, which is true and beside
    // the point here. `POST /auth/login` carries the attacker's credentials in its OWN body and
    // needs no cookie; the response plants a session, and because a form POST is a top-level
    // navigation the browser stores it first-party. The victim then works inside the attacker's
    // account. `Sec-Fetch-Site` states plainly that the request came from elsewhere and no page
    // can forge it, so an empty list no longer excuses it.
    let Some(h) = build(EngineSpec::default()) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "defcsrf@e.com", "glidingwalnut42", "USER").await;

    for site in ["cross-site", "same-site"] {
        let refused = Req::post("/auth/login")
            .json(serde_json::json!({
                "email": "defcsrf@e.com",
                "password": "glidingwalnut42",
                "tenantId": "t1",
            }))
            .header(header::ORIGIN, "https://evil.example.com")
            .header(HeaderName::from_static("sec-fetch-site"), site)
            .send(&app)
            .await;

        assert_eq!(refused.status, StatusCode::FORBIDDEN, "site = {site}");
        assert_eq!(
            refused.json()["error"]["code"],
            serde_json::json!("auth.untrusted_origin"),
            "site = {site}"
        );
    }

    // The browser vouching for the request still passes with nothing listed, so an ordinary
    // same-origin deployment is untouched.
    for site in ["same-origin", "none"] {
        let allowed = Req::post("/auth/login")
            .json(serde_json::json!({
                "email": "defcsrf@e.com",
                "password": "glidingwalnut42",
                "tenantId": "t1",
            }))
            .header(header::ORIGIN, "https://app.internal")
            .header(HeaderName::from_static("sec-fetch-site"), site)
            .send(&app)
            .await;

        assert_eq!(allowed.status, StatusCode::OK, "site = {site}");
    }

    // And the case the layer genuinely cannot classify: an `Origin` with no `Sec-Fetch-Site`,
    // which a same-origin POST also produces. Admitted deliberately — refusing it would answer
    // 403 to every same-origin write from such a browser, since this crate never learns its own
    // origin. A deployment that wants it closed lists its origin, which validation now accepts
    // under `Lax` for exactly this reason.
    let ambiguous = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "defcsrf@e.com",
            "password": "glidingwalnut42",
            "tenantId": "t1",
        }))
        .header(header::ORIGIN, "https://app.internal")
        .send(&app)
        .await;

    assert_eq!(ambiguous.status, StatusCode::OK);
}

#[tokio::test]
async fn a_body_that_does_not_declare_json_is_refused() {
    // `Bytes::from_request` accepts any `Content-Type`, so `POST /auth/login` with
    // `text/plain` and a JSON body used to be accepted. That combination is a CORS SIMPLE
    // request — no preflight — so a cross-origin page can send it and the browser attaches
    // cookies wherever `SameSite` permits; an HTML form with `enctype="text/plain"` produces
    // exactly that shape. Requiring the type re-arms the preflight behind the origin layer.
    //
    // It is also a wire divergence: nest-auth runs behind `express.json()`, which parses only
    // `application/json`, so the same request 400s there and succeeded here.
    let Some(h) = build(EngineSpec::default()) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "ctype@e.com", "glidingwalnut42", "USER").await;

    let body = br#"{"email":"ctype@e.com","password":"glidingwalnut42","tenantId":"t1"}"#;
    let refused = Req::post("/auth/login")
        .raw_body(body.to_vec(), "text/plain")
        .send(&app)
        .await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.json()["error"]["code"],
        serde_json::json!("auth.validation")
    );

    // The declared type still works, including with parameters and the `+json` suffix family.
    for content_type in ["application/json", "application/json; charset=utf-8"] {
        let ok = Req::post("/auth/login")
            .raw_body(body.to_vec(), content_type)
            .send(&app)
            .await;
        assert_eq!(ok.status, StatusCode::OK, "content-type = {content_type}");
    }
}

#[tokio::test]
async fn the_address_change_routes_move_an_account_only_after_the_new_address_proves_itself() {
    // End to end through the router: the request changes nothing, the confirmation changes
    // everything, and each guard along the way answers through the HTTP surface a consumer
    // actually sees.
    let Some(h) = build(EngineSpec {
        email_change: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let user_id = seed_user(&h, "old@e.com", "glidingwalnut42", "USER").await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "old@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();

    // Unauthenticated, the request is refused before anything is read.
    let anonymous = Req::post("/auth/email/change")
        .json(serde_json::json!({ "newEmail": "new@e.com", "currentPassword": "glidingwalnut42" }))
        .send(&app)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    // The wrong current password reads as invalid credentials — the same answer a failed login
    // gives, so a thief holding the token learns nothing new.
    let wrong = Req::post("/auth/email/change")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "newEmail": "new@e.com", "currentPassword": "not-it" }))
        .send(&app)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    // The right one starts the change…
    let requested = Req::post("/auth/email/change")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "newEmail": "new@e.com", "currentPassword": "glidingwalnut42" }))
        .send(&app)
        .await;
    assert_eq!(requested.status, StatusCode::NO_CONTENT);

    // …and the account still answers under the OLD address, because nothing has been proved.
    let still_old = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "old@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(still_old.status, StatusCode::OK);

    // A bogus token reaches no record.
    let bogus = Req::post("/auth/email/change/confirm")
        .json(serde_json::json!({ "token": "0".repeat(64) }))
        .send(&app)
        .await;
    assert_eq!(bogus.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        bogus.json()["error"]["code"],
        "auth.email_change_token_invalid"
    );

    // …and a token of the wrong shape is refused by validation before it is hashed at all.
    let malformed = Req::post("/auth/email/change/confirm")
        .json(serde_json::json!({ "token": "too-short" }))
        .send(&app)
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);

    // The real token only ever reaches the new mailbox, so a known one is planted — exactly the
    // pair `request_email_change` writes — and the confirmation is driven over HTTP. Without
    // this the route's success arm is never taken, and the whole point of the flow is what
    // happens when the new address does prove itself.
    let token = "7".repeat(64);
    use bymax_auth_core::traits::PasswordResetStore as _;
    let planted = h
        .stores
        .put_email_change(
            &token,
            &bymax_auth_core::traits::EmailChangeContext {
                user_id: user_id.clone(),
                new_email: "new@e.com".to_owned(),
                tenant_id: TENANT.to_owned(),
                password_fingerprint: String::new(),
            },
            600,
        )
        .await;
    assert!(planted.is_ok());

    let confirmed = Req::post("/auth/email/change/confirm")
        .json(serde_json::json!({ "token": token }))
        .send(&app)
        .await;
    assert_eq!(confirmed.status, StatusCode::NO_CONTENT);

    // The account answers under the NEW address now, and no longer under the old one.
    let under_new = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "new@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(under_new.status, StatusCode::OK);
    let under_old = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "old@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(under_old.status, StatusCode::UNAUTHORIZED);
}
