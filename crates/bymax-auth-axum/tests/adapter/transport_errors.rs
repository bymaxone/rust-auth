//! Requests the HTTP layer refuses before a handler decides anything — a body that is not JSON,
//! one over the limit, a charset or encoding the adapter cannot read — answer the shared
//! contract's `transportErrors` envelope: `auth.validation`, a fixed message, `details: null`,
//! and no part of the request. A body that is JSON but not the shape the route reads answers the
//! ordinary validation envelope with a fixed message. Shares the fixtures of the parent test file.

use bymax_auth_axum::AxumAuthConfig;

use super::*;

/// A value no response may repeat: it stands in for whatever a client puts in a body, a key or a
/// query string.
const MARKER: &str = "SECRETVALUE-9f3a";

/// An adapter whose login limit is off, so a test may send many bad requests to one route, and
/// whose body limit is small enough to exceed cheaply.
fn small_body_router(h: &common::Harness) -> axum::Router {
    let config = AxumAuthConfig {
        max_body_bytes: 1024,
        rate_limits: bymax_auth_axum::RateLimitConfig {
            login: None,
            ..bymax_auth_axum::RateLimitConfig::default()
        },
        ..AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr)
    };
    router_with(h, config)
}

fn login_request(body: Vec<u8>, content_type: &'static str) -> Req {
    Req::post("/auth/login").raw_body(body, content_type)
}

fn text(response: &Captured) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

/// Assert `response` is the transport envelope: the status, `auth.validation`, the fixed
/// `message`, and `details: null`, with nothing of `forbidden` anywhere in the body.
fn assert_transport(response: &Captured, status: StatusCode, message: &str, forbidden: &[&str]) {
    let body = text(response);
    assert_eq!(response.status, status, "{body}");
    let json = response.json();
    assert_eq!(json["error"]["code"], "auth.validation", "{body}");
    assert_eq!(json["error"]["message"], message, "{body}");
    assert!(json["error"]["details"].is_null(), "{body}");
    for secret in forbidden {
        assert!(!body.contains(secret), "`{secret}` was echoed: {body}");
    }
}

#[tokio::test]
async fn a_body_that_is_not_json_answers_malformed_request_and_echoes_nothing() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    let bodies: Vec<(&str, String)> = vec![
        ("not json", "{not json".to_owned()),
        ("a bare string", format!("\"{MARKER}\"")),
        ("a bare number", "42".to_owned()),
        ("a bare literal", "true".to_owned()),
        ("a bare null", "null".to_owned()),
        ("a truncated object", format!(r#"{{"email":"{MARKER}"#)),
        ("an empty body", String::new()),
    ];
    for (label, body) in bodies {
        let answer = login_request(body.into_bytes(), "application/json")
            .send(&app)
            .await;
        assert_transport(
            &answer,
            StatusCode::BAD_REQUEST,
            "Malformed request",
            &[MARKER, "LoginDto", "expected struct", "line 1", "column"],
        );
        assert!(
            text(&answer).contains("Malformed request"),
            "{label}: {}",
            text(&answer)
        );
    }
}

#[tokio::test]
async fn json_of_the_wrong_shape_names_the_failing_property_and_echoes_no_value() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    // (body, the properties it fails, what must not appear in the answer). The client's own key
    // is the property name for an unknown key and may appear; a value never does. The second
    // body fails `password` by type and `email` by format, and both are named.
    let cases = [
        (
            format!(r#"{{"email":"a@e.com","password":"p","tenantId":"t1","{MARKER}":1}}"#),
            vec![MARKER],
            vec!["LoginDto", "expected one of", "unknown field"],
        ),
        (
            format!(r#"{{"email":"{MARKER}","password":5,"tenantId":"t1"}}"#),
            vec!["email", "password"],
            vec![MARKER, "LoginDto", "invalid type"],
        ),
        (
            format!(r#"{{"email":"{MARKER}@e.com","tenantId":"t1"}}"#),
            vec!["password"],
            vec![MARKER, "LoginDto", "missing field"],
        ),
    ];
    for (body, properties, secrets) in cases {
        let answer = login_request(body.into_bytes(), "application/json")
            .send(&app)
            .await;
        let text = text(&answer);
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{text}");
        let json = answer.json();
        assert_eq!(json["error"]["code"], "auth.validation", "{text}");
        assert_eq!(json["error"]["message"], "Validation failed", "{text}");
        let details = json["error"]["details"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut named: Vec<&str> = details.iter().filter_map(|d| d["field"].as_str()).collect();
        named.sort_unstable();
        named.dedup();
        assert_eq!(named, properties, "{text}");
        for secret in secrets.into_iter().chain(["expected struct", "line 1"]) {
            assert!(!text.contains(secret), "`{secret}` was echoed: {text}");
        }
    }
}

#[tokio::test]
async fn a_rule_message_never_repeats_the_value_that_failed_it() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    // Well-formed JSON of the right shape whose email fails its rule: the detail names the field
    // and the rule, not the address.
    let body = format!(r#"{{"email":"{MARKER}","password":"glidingwalnut42","tenantId":"t1"}}"#);
    let answer = login_request(body.into_bytes(), "application/json")
        .send(&app)
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", text(&answer));
    assert_eq!(answer.json()["error"]["message"], "Validation failed");
    assert!(!text(&answer).contains(MARKER), "{}", text(&answer));
}

#[tokio::test]
async fn a_body_over_the_limit_answers_413_whether_or_not_it_declares_its_length() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    let big = vec![b'a'; 4096];
    // No Content-Length: the limit trips while the body is being read.
    let undeclared = login_request(big.clone(), "application/json")
        .send(&app)
        .await;
    assert_transport(
        &undeclared,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request entity too large",
        &["length limit", "Failed to buffer"],
    );
    // A declared length over the limit is refused before the body is read at all.
    let declared = login_request(b"{}".to_vec(), "application/json")
        .header(header::CONTENT_LENGTH, "4096")
        .send(&app)
        .await;
    assert_transport(
        &declared,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request entity too large",
        &[],
    );
    assert_eq!(
        declared
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
}

#[tokio::test]
async fn a_charset_or_encoding_the_adapter_cannot_read_answers_415() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    let body = br#"{"email":"nobody@e.com","password":"wrongwrong1","tenantId":"t1"}"#.to_vec();
    for content_type in [
        "application/json; charset=nope",
        "application/json; charset=utf-16",
        "application/json; charset=\"UTF-16\"",
        "application/json; charset=latin1",
    ] {
        let answer = login_request(body.clone(), content_type).send(&app).await;
        assert_transport(
            &answer,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type",
            &["nope", "utf-16", "latin1"],
        );
    }
    let encoded = login_request(body, "application/json")
        .header(header::CONTENT_ENCODING, "gzip")
        .send(&app)
        .await;
    assert_transport(
        &encoded,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Unsupported media type",
        &["gzip"],
    );
}

#[tokio::test]
async fn utf8_in_any_spelling_and_the_identity_encoding_are_still_read() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "application/json; charset=UTF-8",
        "application/json; charset=\"utf-8\"",
        "application/problem+json; charset=utf-8",
    ] {
        // A different account each time, so the lockout (also a 429) never answers for the parser.
        let own = format!(
            r#"{{"email":"reader{}@e.com","password":"wrongwrong1","tenantId":"t1"}}"#,
            content_type.len()
        );
        let answer = login_request(own.into_bytes(), content_type)
            .send(&app)
            .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{content_type}");
    }
    let identity = login_request(
        br#"{"email":"identity@e.com","password":"wrongwrong1","tenantId":"t1"}"#.to_vec(),
        "application/json",
    )
    .header(header::CONTENT_ENCODING, "identity")
    .send(&app)
    .await;
    assert_eq!(identity.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_missing_or_wrong_content_type_stays_a_validation_error_naming_the_field() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = small_body_router(&h);
    let body = br#"{"email":"nobody@e.com","password":"wrongwrong1","tenantId":"t1"}"#.to_vec();
    let plain = login_request(body.clone(), "text/plain").send(&app).await;
    let none = Req::post("/auth/login").send(&app).await;
    for answer in [plain, none] {
        let json = answer.json();
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", text(&answer));
        assert_eq!(json["error"]["code"], "auth.validation");
        assert_eq!(json["error"]["message"], "Validation failed");
        assert_eq!(json["error"]["details"][0]["field"], "content-type");
    }
}

#[tokio::test]
async fn the_refresh_body_never_echoes_what_it_could_not_read() {
    // Bearer delivery reads the token from the body; cookie delivery ignores the field.
    let Some(h) = build(EngineSpec {
        delivery: bymax_auth_core::config::TokenDelivery::Bearer,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = small_body_router(&h);
    // Valid JSON whose token is not a string: the shape error, with a fixed message.
    let wrong_type = Req::post("/auth/refresh")
        .raw_body(
            format!(r#"{{"refreshToken":{{"{MARKER}":1}}}}"#).into_bytes(),
            "application/json",
        )
        .send(&app)
        .await;
    assert_eq!(
        wrong_type.status,
        StatusCode::BAD_REQUEST,
        "{}",
        text(&wrong_type)
    );
    assert_eq!(wrong_type.json()["error"]["message"], "Validation failed");
    assert!(!text(&wrong_type).contains(MARKER), "{}", text(&wrong_type));
    // A body that is not JSON at all: the transport envelope.
    let garbage = Req::post("/auth/refresh")
        .raw_body(format!("\"{MARKER}\"").into_bytes(), "application/json")
        .send(&app)
        .await;
    assert_transport(
        &garbage,
        StatusCode::BAD_REQUEST,
        "Malformed request",
        &[MARKER],
    );
    // Over the limit on a route that reads the raw body: the same 413 envelope, not a plain text.
    let over = Req::post("/auth/refresh")
        .raw_body(vec![b'a'; 4096], "application/json")
        .send(&app)
        .await;
    assert_transport(
        &over,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request entity too large",
        &[],
    );
}

#[tokio::test]
async fn a_query_string_that_does_not_fit_names_the_property_and_echoes_no_value() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = small_body_router(&h);
    let answer = Req::get(&format!(
        "/auth/oauth/google?tenantId=t1&unexpected={MARKER}"
    ))
    .send(&app)
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", text(&answer));
    assert_eq!(answer.json()["error"]["code"], "auth.validation");
    assert_eq!(answer.json()["error"]["details"][0]["field"], "unexpected");
    assert!(!text(&answer).contains(MARKER), "{}", text(&answer));
}

#[tokio::test]
async fn an_undecodable_path_parameter_answers_malformed_request() {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = small_body_router(&h);
    // Invalid UTF-8 after percent-decoding: refused as a malformed request, not axum's plain text.
    let answer = Req::get("/auth/oauth/%FF?tenantId=t1").send(&app).await;
    assert_transport(
        &answer,
        StatusCode::BAD_REQUEST,
        "Malformed request",
        &["Invalid URL", "provider", "UTF-8"],
    );
}

/// A router, and the access cookie of an email-verified account, for `POST /auth/mfa/setup`.
async fn mfa_setup_session(h: &common::Harness) -> (axum::Router, String) {
    let app = small_body_router(h);
    seed_user(h, "setup@e.com", "glidingwalnut42", "USER").await;
    let access = login(&app, "setup@e.com", "glidingwalnut42")
        .await
        .cookie_value("access_token")
        .unwrap_or_default();
    (app, access)
}

fn mfa_setup_request(access: &str, body: String, content_type: &'static str) -> Req {
    Req::post("/auth/mfa/setup")
        .cookie("access_token", access)
        .raw_body(body.into_bytes(), content_type)
}

#[tokio::test]
async fn an_mfa_setup_body_that_does_not_parse_never_echoes_what_it_held() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let (app, access) = mfa_setup_session(&h).await;
    // Not JSON: the transport envelope.
    let garbage = mfa_setup_request(&access, format!("\"{MARKER}\""), "application/json")
        .send(&app)
        .await;
    assert_transport(
        &garbage,
        StatusCode::BAD_REQUEST,
        "Malformed request",
        &[MARKER],
    );
    // JSON of the wrong shape: the validation envelope, with a fixed detail.
    let shaped = mfa_setup_request(&access, format!(r#"{{"{MARKER}":1}}"#), "application/json")
        .send(&app)
        .await;
    assert_eq!(shaped.status, StatusCode::BAD_REQUEST, "{}", text(&shaped));
    assert_eq!(shaped.json()["error"]["message"], "Validation failed");
    // The unknown key is the property the answer names; the value is never echoed.
    assert_eq!(shaped.json()["error"]["details"][0]["field"], MARKER);
    assert!(!text(&shaped).contains("\"1\""), "{}", text(&shaped));
    assert!(
        !text(&shaped).contains("unknown field"),
        "{}",
        text(&shaped)
    );
}

#[tokio::test]
async fn an_mfa_setup_body_in_an_unreadable_form_or_too_large_is_refused() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let (app, access) = mfa_setup_session(&h).await;
    // A charset the adapter cannot read.
    let charset = mfa_setup_request(&access, "{}".to_owned(), "application/json; charset=nope")
        .send(&app)
        .await;
    assert_transport(
        &charset,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Unsupported media type",
        &["nope"],
    );
    // Over the limit, with no declared length, on a route that buffers the body itself.
    let over = mfa_setup_request(&access, "a".repeat(4096), "application/json")
        .send(&app)
        .await;
    assert_transport(
        &over,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Request entity too large",
        &[],
    );
}
