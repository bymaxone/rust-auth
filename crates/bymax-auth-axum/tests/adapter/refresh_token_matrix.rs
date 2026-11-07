//! One row per body value and route: what a body carrying a refresh token does on the routes
//! that read one, and what it leaves behind. A missing field or `null` is no token; a string of
//! 1 to 2048 characters is the token; every other value is refused before the route does
//! anything, so a refused logout or revoke-all leaves the session it named alive. Shares the
//! fixtures of the parent test file.

use bymax_auth_core::config::TokenDelivery;

use super::*;

/// A body value the matrix sends, with a label for the failure message.
struct Body {
    label: &'static str,
    bytes: Vec<u8>,
}

fn body(label: &'static str, bytes: impl Into<Vec<u8>>) -> Body {
    Body {
        label,
        bytes: bytes.into(),
    }
}

/// Values that mean "no token" on a route that reads the body.
fn no_token() -> Vec<Body> {
    vec![
        body("no body", ""),
        body("empty object", "{}"),
        body("null token", r#"{"refreshToken":null}"#),
        body("other key only", r#"{"other":1}"#),
    ]
}

/// Values for the token that are present and not a string of 1 to 2048 characters.
fn bad_token() -> Vec<Body> {
    let long = format!(r#"{{"refreshToken":"{}"}}"#, "x".repeat(2049));
    vec![
        body("empty string", r#"{"refreshToken":""}"#),
        body("2049 characters", long),
        body("number", r#"{"refreshToken":5}"#),
        body("boolean", r#"{"refreshToken":true}"#),
        body("object", r#"{"refreshToken":{"a":1}}"#),
        body("array", r#"{"refreshToken":["a"]}"#),
    ]
}

/// Bodies the transport refuses whatever the route: not JSON, or a root that is not an object.
fn not_an_object() -> Vec<Body> {
    vec![
        body("invalid JSON", "{ not json"),
        body("bare string", r#""abc""#),
        body("bare number", "42"),
        body("array root", r#"["abc"]"#),
    ]
}

fn assert_refused(answer: &Captured, what: &str, field: Option<&str>) {
    assert_eq!(
        answer.status,
        StatusCode::BAD_REQUEST,
        "{what}: {}",
        String::from_utf8_lossy(&answer.body)
    );
    let json = answer.json();
    assert_eq!(json["error"]["code"], "auth.validation", "{what}");
    match field {
        Some(field) => assert_eq!(json["error"]["details"][0]["field"], field, "{what}"),
        None => assert_eq!(json["error"]["message"], "Malformed request", "{what}"),
    }
}

/// A router whose per-route allowances are off for the routes the matrix hits many times.
fn unlimited_router(h: &common::Harness) -> axum::Router {
    let config = bymax_auth_axum::AxumAuthConfig {
        rate_limits: bymax_auth_axum::RateLimitConfig {
            refresh: None,
            logout: None,
            revoke_all_sessions: None,
            change_password: None,
            ..bymax_auth_axum::RateLimitConfig::default()
        },
        ..bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
    };
    router_with(h, config)
}

/// A bearer-mode engine with a dashboard account signed in twice, and a platform admin.
struct World {
    app: axum::Router,
    access: String,
    refresh: String,
    other_refresh: String,
    admin_access: String,
    admin_refresh: String,
}

async fn world() -> Option<(common::Harness, World)> {
    let h = build(EngineSpec {
        delivery: TokenDelivery::Bearer,
        sessions: true,
        platform: true,
        ..EngineSpec::default()
    })?;
    seed_user(&h, "matrix@e.com", "glidingwalnut42", "USER").await;
    seed_admin(&h, "matrixadmin@e.com", "SUPER_ADMIN").await;
    let app = unlimited_router(&h);
    let first = login(&app, "matrix@e.com", "glidingwalnut42").await;
    let second = login(&app, "matrix@e.com", "glidingwalnut42").await;
    let admin = platform_login(&app, "matrixadmin@e.com").await;
    let token = |c: &Captured, key: &str| c.json()[key].as_str().unwrap_or_default().to_owned();
    let world = World {
        access: token(&first, "accessToken"),
        refresh: token(&first, "refreshToken"),
        other_refresh: token(&second, "refreshToken"),
        admin_access: platform_access(&admin),
        admin_refresh: platform_refresh(&admin),
        app,
    };
    Some((h, world))
}

impl World {
    async fn post(&self, path: &str, bearer: &str, body: &Body) -> Captured {
        let request = Req::post(path).raw_body(body.bytes.clone(), "application/json");
        let request = if bearer.is_empty() {
            request
        } else {
            request.bearer(bearer)
        };
        request.send(&self.app).await
    }

    /// Whether the dashboard session `refresh` still rotates.
    async fn rotates(&self, refresh: &str) -> bool {
        let body = body("probe", format!(r#"{{"refreshToken":"{refresh}"}}"#));
        self.post("/auth/refresh", "", &body).await.status == StatusCode::OK
    }
}

#[tokio::test]
async fn a_refresh_body_is_the_token_no_token_or_a_refusal() {
    let Some((_h, w)) = world().await else { return };
    for b in no_token() {
        let answer = w.post("/auth/refresh", "", &b).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{}", b.label);
        assert_eq!(
            answer.json()["error"]["code"],
            "auth.refresh_token_invalid",
            "{}",
            b.label
        );
    }
    for b in bad_token() {
        assert_refused(
            &w.post("/auth/refresh", "", &b).await,
            b.label,
            Some("refreshToken"),
        );
    }
    for b in not_an_object() {
        assert_refused(&w.post("/auth/refresh", "", &b).await, b.label, None);
    }
    assert!(w.rotates(&w.refresh).await, "a valid token rotates");
}

#[tokio::test]
async fn a_refused_logout_body_revokes_nothing() {
    let Some((_h, w)) = world().await else { return };
    for b in bad_token().into_iter().chain(not_an_object()) {
        let answer = w.post("/auth/logout", &w.access, &b).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", b.label);
        // Nothing was revoked: the access token still authenticates and the session rotates.
        let me = Req::get("/auth/me").bearer(&w.access).send(&w.app).await;
        assert_eq!(
            me.status,
            StatusCode::OK,
            "{}: the access token was revoked",
            b.label
        );
    }
    assert!(
        w.rotates(&w.refresh).await,
        "the session survived every refused logout"
    );
}

#[tokio::test]
async fn a_logout_with_no_token_still_ends_the_access_token() {
    let Some((_h, w)) = world().await else { return };
    let answer = w
        .post("/auth/logout", &w.access, &body("empty object", "{}"))
        .await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let me = Req::get("/auth/me").bearer(&w.access).send(&w.app).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refused_revoke_all_body_ends_no_session() {
    let Some((_h, w)) = world().await else { return };
    for b in bad_token().into_iter().chain(not_an_object()) {
        let answer = w.post("/auth/sessions/revoke-all", &w.access, &b).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", b.label);
    }
    assert!(
        w.rotates(&w.other_refresh).await,
        "the other device survived every refusal"
    );
    for b in no_token() {
        let answer = w.post("/auth/sessions/revoke-all", &w.access, &b).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", b.label);
        assert_eq!(
            answer.json()["error"]["code"],
            "auth.session_not_found",
            "{}",
            b.label
        );
    }
}

#[tokio::test]
async fn the_platform_routes_hold_the_same_rule() {
    let Some((_h, w)) = world().await else { return };
    for b in bad_token() {
        assert_refused(
            &w.post("/auth/platform/refresh", "", &b).await,
            b.label,
            Some("refreshToken"),
        );
        let logout = w.post("/auth/platform/logout", &w.admin_access, &b).await;
        assert_refused(&logout, b.label, Some("refreshToken"));
    }
    for b in not_an_object() {
        assert_refused(
            &w.post("/auth/platform/refresh", "", &b).await,
            b.label,
            None,
        );
    }
    let valid = body(
        "valid",
        format!(r#"{{"refreshToken":"{}"}}"#, w.admin_refresh),
    );
    let refreshed = w.post("/auth/platform/refresh", "", &valid).await;
    assert_eq!(
        refreshed.status,
        StatusCode::OK,
        "no refused request consumed the session"
    );
}

#[tokio::test]
async fn cookie_delivery_ignores_a_token_value_in_the_body_but_not_a_broken_body() {
    let Some(h) = build(EngineSpec::default()) else { return };
    seed_user(&h, "cookie-matrix@e.com", "glidingwalnut42", "USER").await;
    let app = unlimited_router(&h);
    let first = login(&app, "cookie-matrix@e.com", "glidingwalnut42").await;
    let mut refresh = first.cookie_value("refresh_token").unwrap_or_default();
    for value in [r#"{"refreshToken":5}"#, r#"{"refreshToken":""}"#, "[]"] {
        let answer = Req::post("/auth/refresh")
            .cookie("refresh_token", &refresh)
            .raw_body(value.as_bytes().to_vec(), "application/json")
            .send(&app)
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{value}");
        // Each refresh rotates the cookie; the next request presents the new one.
        refresh = answer.cookie_value("refresh_token").unwrap_or_default();
    }
    let broken = Req::post("/auth/refresh")
        .raw_body(b"{ not json".to_vec(), "application/json")
        .send(&app)
        .await;
    assert_refused(&broken, "invalid JSON in cookie mode", None);
}

/// The JSON body of a password change that names `token` as the caller's refresh token.
fn change_body(token: &str) -> serde_json::Value {
    serde_json::json!({
        "currentPassword": "glidingwalnut42",
        "newPassword": "a-brand-new-passphrase",
        "refreshToken": token,
    })
}

#[tokio::test]
async fn a_password_change_naming_no_live_session_is_refused_and_changes_nothing() {
    let Some((_h, w)) = world().await else { return };
    let answer = Req::post("/auth/password/change")
        .bearer(&w.access)
        .json(change_body(&"f".repeat(64)))
        .send(&w.app)
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.json()["error"]["code"], "auth.session_not_found");
    // The old password still signs in and no session ended.
    let again = login(&w.app, "matrix@e.com", "glidingwalnut42").await;
    assert_eq!(again.status, StatusCode::OK);
    assert!(w.rotates(&w.other_refresh).await);
}

#[tokio::test]
async fn a_token_that_just_rotated_still_stands_for_its_session() {
    let Some((_h, w)) = world().await else { return };
    let refreshed = w
        .post(
            "/auth/refresh",
            "",
            &body("rotate", format!(r#"{{"refreshToken":"{}"}}"#, w.refresh)),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    let successor = refreshed.json()["refreshToken"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // The predecessor is inside its grace window: revoke-all keeps the session that replaced it
    // and ends the other device.
    let revoke = w
        .post(
            "/auth/sessions/revoke-all",
            &w.access,
            &body("old", format!(r#"{{"refreshToken":"{}"}}"#, w.refresh)),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);
    assert!(w.rotates(&successor).await, "the caller's session survived");
    assert!(!w.rotates(&w.other_refresh).await, "the other device ended");
}
