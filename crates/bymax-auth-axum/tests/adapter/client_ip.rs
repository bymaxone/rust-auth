//! Which address a request is attributed to: the one the session records, and the one the rate
//! limiter charges. A forwarded address is believed only from a peer the deployment vouches for.
//! Shares the fixtures of the parent test file.

use bymax_auth_axum::{AuthRouter, AxumAuthConfig, ClientIpSource};
use bymax_auth_core::ConfigError;

use super::*;

/// The harness peer's address (see `common::PEER`).
const PROXY: &str = "203.0.113.4";

/// A forwarded-for deployment whose only proxy is the harness peer.
fn behind_the_proxy() -> AxumAuthConfig {
    AxumAuthConfig::new(ClientIpSource::TrustedForwardedFor)
        .is_trusted_proxy(|peer| peer.to_string() == PROXY)
}

/// A forwarded-for deployment that vouches for nobody.
fn trusting_no_peer() -> AxumAuthConfig {
    AxumAuthConfig::new(ClientIpSource::TrustedForwardedFor).is_trusted_proxy(|_| false)
}

/// Log in as `email` with `forwarded` as the `X-Forwarded-For` header and return the address the
/// session list reports for the new session.
async fn recorded_address(app: &axum::Router, email: &str, forwarded: &str) -> String {
    let login = Req::post("/auth/login")
        .header(HeaderName::from_static("x-forwarded-for"), forwarded)
        .json(serde_json::json!({ "email": email, "password": "glidingwalnut42", "tenantId": TENANT }))
        .send(app)
        .await;
    let list = Req::get("/auth/sessions")
        .cookie(
            "access_token",
            &login.cookie_value("access_token").unwrap_or_default(),
        )
        .cookie(
            "refresh_token",
            &login.cookie_value("refresh_token").unwrap_or_default(),
        )
        .send(app)
        .await;
    list.json()
        .as_array()
        .and_then(|sessions| sessions.first())
        .and_then(|session| session["ip"].as_str())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn trusting_the_forwarded_header_without_a_predicate_refuses_to_build() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let refused = AuthRouter::from_engine(
        h.engine.clone(),
        AxumAuthConfig::new(ClientIpSource::TrustedForwardedFor),
    );
    assert!(matches!(
        refused,
        Err(ConfigError::TrustedForwardedForRequiresPredicate)
    ));
    assert_eq!(
        ConfigError::TrustedForwardedForRequiresPredicate.to_string(),
        "TrustedForwardedFor requires is_trusted_proxy"
    );
    // The same deployment is fine once it says which peers are its proxies, and the direct
    // posture needs no predicate.
    assert!(AuthRouter::from_engine(h.engine.clone(), behind_the_proxy()).is_ok());
    assert!(
        AuthRouter::from_engine(
            h.engine.clone(),
            AxumAuthConfig::new(ClientIpSource::PeerAddr)
        )
        .is_ok()
    );
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_session_records_the_forwarded_client() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    seed_user(&h, "fwd@e.com", "glidingwalnut42", "USER").await;
    let app = router_with(&h, behind_the_proxy());
    assert_eq!(
        recorded_address(&app, "fwd@e.com", "6.6.6.6, 198.51.100.7").await,
        "198.51.100.7"
    );
}

#[tokio::test]
async fn a_peer_nobody_vouches_for_cannot_choose_the_address_the_session_records() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    seed_user(&h, "forged@e.com", "glidingwalnut42", "USER").await;
    let app = router_with(&h, trusting_no_peer());
    assert_eq!(
        recorded_address(&app, "forged@e.com", "6.6.6.6").await,
        PROXY
    );
}

#[tokio::test]
async fn the_direct_posture_records_the_peer_whatever_the_header_says() {
    let Some(h) = build(EngineSpec {
        sessions: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    seed_user(&h, "direct@e.com", "glidingwalnut42", "USER").await;
    let app = router(&h);
    assert_eq!(
        recorded_address(&app, "direct@e.com", "6.6.6.6").await,
        PROXY
    );
}

/// The status of one failed login attempt for `email` carrying `forwarded` as `X-Forwarded-For`.
/// Each client uses its own email, because the account lockout is keyed on the email and would
/// otherwise answer 429 for reasons that have nothing to do with the address.
async fn failed_login_status(app: &axum::Router, email: &str, forwarded: &str) -> StatusCode {
    Req::post("/auth/login")
        .header(HeaderName::from_static("x-forwarded-for"), forwarded)
        .json(serde_json::json!({ "email": email, "password": "wrong", "tenantId": TENANT }))
        .send(app)
        .await
        .status
}

#[tokio::test]
async fn rotating_the_header_from_an_untrusted_peer_does_not_buy_a_fresh_limit() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router_with(&h, trusting_no_peer());
    let mut last = StatusCode::OK;
    for attempt in 0..8 {
        last = failed_login_status(
            &app,
            &format!("rot{attempt}@e.com"),
            &format!("9.9.9.{attempt}"),
        )
        .await;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_limit() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router_with(&h, behind_the_proxy());
    let mut last = StatusCode::OK;
    for _ in 0..8 {
        last = failed_login_status(&app, "a@e.com", "198.51.100.7").await;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // A different client behind the same proxy is not charged to it.
    assert_eq!(
        failed_login_status(&app, "b@e.com", "198.51.100.8").await,
        StatusCode::UNAUTHORIZED
    );
}
