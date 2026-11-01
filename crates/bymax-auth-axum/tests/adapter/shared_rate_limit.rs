//! The per-route rate limit counted in the engine's shared store: two routers over one store
//! share one budget, a store failure is reported rather than waved through, a request with no
//! readable address is charged to one shared bucket, and an engine without a shared counter keeps
//! the in-process limiter. Shares the fixtures of the parent test file.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use bymax_auth_axum::{AuthRouter, AxumAuthConfig, ClientIpSource};
use bymax_auth_core::AuthEngine;
use bymax_auth_core::config::{AuthConfig, Environment};
use bymax_auth_core::testing::{InMemoryStores, InMemoryUserRepository};
use bymax_auth_core::traits::RateLimitStore;
use bymax_auth_types::AuthError;
use secrecy::SecretString;
use tower::ServiceExt;

use super::*;

/// The login limit in the contract: 5 requests per 60 seconds.
const LOGIN_LIMIT: usize = 5;

/// A counter that always fails, standing in for an unreachable Redis.
struct DownCounter;

#[async_trait]
impl RateLimitStore for DownCounter {
    async fn hit(&self, _route: &str, _bucket: &str, _window: u64) -> Result<i64, AuthError> {
        Err(AuthError::Internal(Box::new(std::io::Error::other(
            "counter unavailable",
        ))))
    }
}

/// An engine over `stores`, counting limits in `counter` when one is given.
fn engine(
    stores: &Arc<InMemoryStores>,
    counter: Option<Arc<dyn RateLimitStore>>,
) -> Option<Router> {
    engine_with_source(stores, counter, ClientIpSource::PeerAddr)
}

/// As [`engine`], reading the client address by `source`.
fn engine_with_source(
    stores: &Arc<InMemoryStores>,
    counter: Option<Arc<dyn RateLimitStore>>,
    source: ClientIpSource,
) -> Option<Router> {
    engine_with_config(stores, counter, AxumAuthConfig::new(source))
}

/// As [`engine`], under an explicit adapter configuration.
fn engine_with_config(
    stores: &Arc<InMemoryStores>,
    counter: Option<Arc<dyn RateLimitStore>>,
    adapter: AxumAuthConfig,
) -> Option<Router> {
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(common::JWT_SECRET.to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    let mut builder = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .session_store(stores.clone())
        .otp_store(stores.clone())
        .brute_force_store(stores.clone());
    if let Some(counter) = counter {
        builder = builder.rate_limit_store(counter);
    }
    let built = builder.build();
    assert!(
        built.is_ok(),
        "the engine must build: {:?}",
        built.as_ref().err()
    );
    let built = built.ok()?;
    Some(AuthRouter::from_engine(Arc::new(built), adapter).into_router())
}

/// One failed login from the harness's fixed peer address. A different email for every attempt,
/// so the account lockout (also a 429) never stands in for the limiter under test.
async fn login_attempt(app: &Router, attempt: usize) -> Captured {
    Req::post("/auth/login")
        .json(serde_json::json!({
            "email": format!("nobody{attempt}@e.com"), "password": "wrong", "tenantId": TENANT
        }))
        .send(app)
        .await
}

#[tokio::test]
async fn two_routers_over_one_store_share_one_budget() {
    let stores = Arc::new(InMemoryStores::new());
    let counter: Arc<dyn RateLimitStore> = stores.clone();
    let (Some(first), Some(second)) = (
        engine(&stores, Some(counter.clone())),
        engine(&stores, Some(counter)),
    ) else {
        return;
    };

    // The budget is spent across both instances, as a load balancer would spread the requests.
    for attempt in 0..LOGIN_LIMIT {
        let app = if attempt % 2 == 0 { &first } else { &second };
        assert_eq!(
            login_attempt(app, attempt).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login_attempt(&first, LOGIN_LIMIT).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let refused = login_attempt(&second, LOGIN_LIMIT + 1).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    // The full window, not the time left in it.
    assert_eq!(
        refused
            .headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("60")
    );
    assert_eq!(refused.json()["error"]["code"], "auth.too_many_requests");
}

#[tokio::test]
async fn a_failing_counter_is_reported_not_waved_through() {
    let stores = Arc::new(InMemoryStores::new());
    let Some(app) = engine(&stores, Some(Arc::new(DownCounter))) else { return };
    assert_eq!(
        login_attempt(&app, 0).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn requests_with_no_readable_address_share_one_bucket() {
    let stores = Arc::new(InMemoryStores::new());
    let counter: Arc<dyn RateLimitStore> = stores.clone();
    let Some(app) = engine(&stores, Some(counter)) else { return };
    let bare = |attempt: usize| {
        let body =
            format!(r#"{{"email":"nobody{attempt}@e.com","password":"wrong","tenantId":"t1"}}"#);
        http::Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_default()
    };

    // No peer address: an unreadable address is one shared bucket, never an unlimited budget.
    for attempt in 0..LOGIN_LIMIT {
        let answer = app.clone().oneshot(bare(attempt)).await;
        assert!(matches!(answer, Ok(r) if r.status() == StatusCode::UNAUTHORIZED));
    }
    let refused = app.clone().oneshot(bare(LOGIN_LIMIT)).await;
    let Ok(refused) = refused;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(refused.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    assert!(String::from_utf8_lossy(&body).contains("auth.too_many_requests"));
}

#[tokio::test]
async fn without_a_shared_counter_the_in_process_limiter_still_applies() {
    let stores = Arc::new(InMemoryStores::new());
    let Some(app) = engine(&stores, None) else { return };
    for attempt in 0..LOGIN_LIMIT {
        assert_eq!(
            login_attempt(&app, attempt).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let limited = login_attempt(&app, LOGIN_LIMIT).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.json()["error"]["code"], "auth.too_many_requests");
}

#[tokio::test]
async fn the_in_process_fallback_keys_on_the_forwarded_address_when_it_is_trusted() {
    let stores = Arc::new(InMemoryStores::new());
    let Some(app) = engine_with_source(&stores, None, ClientIpSource::TrustedForwardedFor) else {
        return;
    };
    // A different email each time, so the account lockout (also a 429) never answers for the
    // limiter: only the per-address window can produce `auth.too_many_requests` here.
    let from = |address: &'static str, attempt: usize| {
        Req::post("/auth/login")
            .header(HeaderName::from_static("x-forwarded-for"), address)
            .json(serde_json::json!({
                "email": format!("nobody{attempt}@e.com"), "password": "wrong", "tenantId": TENANT
            }))
    };
    for attempt in 0..LOGIN_LIMIT {
        let answer = from("198.51.100.7", attempt).send(&app).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    }
    let limited = from("198.51.100.7", LOGIN_LIMIT).send(&app).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.json()["error"]["code"], "auth.too_many_requests");
    // Another forwarded address is another budget, though the peer socket is the same.
    let other = from("198.51.100.8", LOGIN_LIMIT + 1).send(&app).await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_shared_counter_charges_each_forwarded_address_its_own_budget() {
    let stores = Arc::new(InMemoryStores::new());
    let counter: Arc<dyn RateLimitStore> = stores.clone();
    let Some(app) = engine_with_source(&stores, Some(counter), ClientIpSource::TrustedForwardedFor)
    else {
        return;
    };
    let from = |address: &'static str, attempt: usize| {
        Req::post("/auth/login")
            .header(HeaderName::from_static("x-forwarded-for"), address)
            .json(serde_json::json!({
                "email": format!("nobody{attempt}@e.com"), "password": "wrong", "tenantId": TENANT
            }))
    };
    for attempt in 0..LOGIN_LIMIT {
        let answer = from("198.51.100.7", attempt).send(&app).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    }
    let limited = from("198.51.100.7", LOGIN_LIMIT).send(&app).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    // Another forwarded address is another budget, though the peer socket is the same; if every
    // address collapsed into one bucket this request would be refused too.
    let other = from("198.51.100.8", LOGIN_LIMIT + 1).send(&app).await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_route_whose_limit_is_disabled_is_not_limited_without_a_shared_counter_either() {
    let stores = Arc::new(InMemoryStores::new());
    let adapter = AxumAuthConfig {
        rate_limits: bymax_auth_axum::RateLimitConfig {
            login: None,
            ..bymax_auth_axum::RateLimitConfig::default()
        },
        ..AxumAuthConfig::new(ClientIpSource::PeerAddr)
    };
    let Some(app) = engine_with_config(&stores, None, adapter) else { return };
    // Well past the default window of 5: nothing counts these.
    for attempt in 0..(LOGIN_LIMIT * 2) {
        assert_eq!(
            login_attempt(&app, attempt).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
}
