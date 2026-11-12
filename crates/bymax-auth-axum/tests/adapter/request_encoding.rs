//! Which routes refuse a request body that declares a `Content-Encoding` other than `identity`
//! is read from the shared contract's `requestEncoding` section: every route the section lists
//! behaves as its list says, with a signed-in caller so the check is reached rather than an
//! authentication refusal. Shares the fixtures of the parent test file.

use std::collections::BTreeSet;

use super::*;

/// The `requestEncoding` section of the shared wire contract.
fn section() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["requestEncoding"].clone()
}

/// One list of the section as a set of `METHOD path` strings.
fn routes(list: &str) -> BTreeSet<String> {
    section()[list]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The credentials a request to either plane needs, so the encoding check is reached rather than
/// an authentication refusal.
struct Credentials {
    dashboard: String,
    platform: String,
}

/// A router with every optional surface on, so every route the contract names is mounted, and a
/// signed-in account for each plane.
async fn every_surface() -> Option<(axum::Router, Credentials)> {
    let harness = build(EngineSpec {
        mfa: true,
        platform: true,
        invitations: true,
        email_change: true,
        sessions: true,
        ..EngineSpec::default()
    })?;
    let app = router(&harness);
    seed_user(&harness, "enc@example.com", "glidingwalnut42", "USER").await;
    let dashboard = login(&app, "enc@example.com", "glidingwalnut42")
        .await
        .cookie_value("access_token")
        .unwrap_or_default();
    let admin = common::seed_admin(&harness, "encadmin@example.com", "SUPPORT").await;
    let platform = common::mint_platform_token(&admin, "SUPPORT");
    Some((
        app,
        Credentials {
            dashboard,
            platform,
        },
    ))
}

/// A gzip-declared JSON body of `body`, with the `Content-Length` a real client sends (the test
/// harness sets none).
fn with_gzip_body(request: Req, body: &[u8]) -> Req {
    request
        .raw_body(body.to_vec(), "application/json")
        .header(http::header::CONTENT_LENGTH, &body.len().to_string())
        .header(http::header::CONTENT_ENCODING, "gzip")
}

/// A `METHOD path` string as a request under the route prefix, with a gzip-declared body.
fn gzip_request(route: &str, body: &[u8], credentials: &Credentials) -> Req {
    let (method, path) = route.split_once(' ').unwrap_or(("POST", route));
    let method = method.parse().unwrap_or(http::Method::POST);
    let request = with_gzip_body(Req::new(method, &format!("/auth/{path}")), body);
    if path.starts_with("platform/") {
        request.bearer(&credentials.platform)
    } else {
        request.cookie("access_token", &credentials.dashboard)
    }
}

#[tokio::test]
async fn a_strict_route_refuses_a_declared_encoding() {
    let Some((app, credentials)) = every_surface().await else {
        return;
    };
    let strict = routes("strict");
    assert!(!strict.is_empty(), "the contract lists no strict routes");
    for route in &strict {
        let response = gzip_request(route, b"{}", &credentials).send(&app).await;
        assert_eq!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route}"
        );
    }
}

#[tokio::test]
async fn an_unchecked_route_does_not_refuse_a_declared_encoding() {
    let Some((app, credentials)) = every_surface().await else {
        return;
    };
    let unchecked = routes("unchecked");
    assert!(
        !unchecked.is_empty(),
        "the contract lists no unchecked routes"
    );
    for route in &unchecked {
        let response = gzip_request(route, b"{}", &credentials).send(&app).await;
        assert_ne!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route}"
        );
        assert_ne!(
            response.status,
            StatusCode::NOT_FOUND,
            "{route} is not mounted"
        );
    }
}

/// `whenBody` routes the contract lists that this router does not serve yet. Until a slice
/// serves one, a request without a body is still refused by the encoding layer like any other
/// unlisted route, which [`a_pending_when_body_route_is_still_refused_without_a_body`] requires:
/// the slice that serves it has to delete its entry here, and a route the contract adds that is
/// not listed fails [`a_when_body_route_refuses_only_a_request_that_carries_a_body`].
const PENDING_WHEN_BODY: [&str; 3] = [
    "POST workspaces/:workspaceId/leave",
    "POST workspaces/:workspaceId/restore",
    "POST workspaces/:workspaceId/switch",
];

#[tokio::test]
async fn a_pending_when_body_route_is_still_refused_without_a_body() {
    let Some((app, credentials)) = every_surface().await else {
        return;
    };
    let in_contract = routes("whenBody");
    for route in PENDING_WHEN_BODY {
        assert!(
            in_contract.contains(route),
            "{route} is pending but the contract does not list it"
        );
        let empty = gzip_request(route, b"", &credentials).send(&app).await;
        assert_eq!(
            empty.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route} is served; remove it from PENDING_WHEN_BODY"
        );
    }
}

#[tokio::test]
async fn a_when_body_route_refuses_only_a_request_that_carries_a_body() {
    let Some((app, credentials)) = every_surface().await else {
        return;
    };
    let when_body: Vec<String> = routes("whenBody")
        .into_iter()
        .filter(|route| !PENDING_WHEN_BODY.contains(&route.as_str()))
        .collect();
    assert!(
        !when_body.is_empty(),
        "the contract lists no whenBody routes"
    );
    for route in &when_body {
        let with_body = gzip_request(route, b"{}", &credentials).send(&app).await;
        assert_eq!(
            with_body.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route}"
        );
        let empty = gzip_request(route, b"", &credentials).send(&app).await;
        assert_ne!(empty.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{route}");
    }
}

#[tokio::test]
async fn a_method_the_contract_never_checks_is_not_refused() {
    let Some((app, credentials)) = every_surface().await else {
        return;
    };
    let methods = section()["methodsNeverChecked"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!methods.is_empty(), "the contract lists no methods");
    for method in methods.iter().filter_map(|method| method.as_str()) {
        let route = format!("{method} me");
        let response = gzip_request(&route, b"{}", &credentials).send(&app).await;
        assert_ne!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route}"
        );
    }
}

#[tokio::test]
async fn a_refused_encoding_is_answered_before_authentication() {
    let Some((app, _credentials)) = every_surface().await else {
        return;
    };
    // Every route that checks the encoding, with no credentials at all: a route behind
    // authentication must still answer the encoding refusal, not the authentication one.
    let checked: BTreeSet<String> = routes("strict")
        .union(&routes("whenBody"))
        .cloned()
        .collect();
    assert!(!checked.is_empty(), "the contract checks no routes");
    for route in &checked {
        let (method, path) = route.split_once(' ').unwrap_or(("POST", route));
        let request = Req::new(
            method.parse().unwrap_or(http::Method::POST),
            &format!("/auth/{path}"),
        );
        let response = with_gzip_body(request, b"{}").send(&app).await;
        assert_eq!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{route}"
        );
    }
}

#[tokio::test]
async fn a_refused_encoding_spends_no_rate_limit_budget() {
    let Some(h) = build(EngineSpec::default()) else {
        return;
    };
    let config = bymax_auth_axum::AxumAuthConfig {
        rate_limits: common::slow_refill_rate_limits(),
        ..bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
    };
    let app = router_with(&h, config);
    // Many more refused requests than the login allowance of five: none may answer 429.
    for attempt in 0..12 {
        let response = Req::post("/auth/login")
            .raw_body(b"{}".to_vec(), "application/json")
            .header(http::header::CONTENT_ENCODING, "gzip")
            .send(&app)
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "attempt {attempt}"
        );
    }
    // The allowance is intact: a readable request is still answered by the handler (a
    // credential refusal), not by the limiter.
    let readable = Req::post("/auth/login")
        .json(serde_json::json!({"email": "nobody@e.com", "password": "glidingwalnut42", "tenantId": "t1"}))
        .send(&app)
        .await;
    assert_ne!(readable.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_refused_encoding_is_answered_whatever_the_declared_length() {
    let Some(h) = build(EngineSpec::default()) else {
        return;
    };
    let config = bymax_auth_axum::AxumAuthConfig {
        max_body_bytes: 1024,
        ..bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
    };
    let app = router_with(&h, config);
    // A declared length far over the limit: the encoding is still what the request is refused for.
    let request = Req::post("/auth/login")
        .raw_body(b"{}".to_vec(), "application/json")
        .header(http::header::CONTENT_LENGTH, "4096")
        .header(http::header::CONTENT_ENCODING, "gzip");
    let response = request.send(&app).await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn the_policy_follows_a_custom_route_prefix() {
    let Some(h) = build(EngineSpec::default()) else {
        return;
    };
    let config = bymax_auth_axum::AxumAuthConfig {
        route_prefix: "/api/v1/auth/".to_owned(),
        ..bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
    };
    let app = router_with(&h, config);
    let checked = Req::post("/api/v1/auth/login");
    let refused = with_gzip_body(checked, b"{}").send(&app).await;
    assert_eq!(refused.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // An unchecked route stays unchecked under the same prefix.
    let exempt = with_gzip_body(Req::post("/api/v1/auth/logout"), b"{}")
        .send(&app)
        .await;
    assert_ne!(exempt.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_ne!(exempt.status, StatusCode::NOT_FOUND);
}
