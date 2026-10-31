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
    Some(
        AuthRouter::from_engine(
            Arc::new(built),
            AxumAuthConfig::new(ClientIpSource::PeerAddr),
        )
        .into_router(),
    )
}

/// One failed login from the harness's fixed peer address.
async fn login_attempt(app: &Router) -> StatusCode {
    Req::post("/auth/login")
        .json(serde_json::json!({ "email": "no@e.com", "password": "wrong", "tenantId": TENANT }))
        .send(app)
        .await
        .status
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
        assert_eq!(login_attempt(app).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(login_attempt(&first).await, StatusCode::TOO_MANY_REQUESTS);
    let refused = Req::post("/auth/login")
        .json(serde_json::json!({ "email": "no@e.com", "password": "wrong", "tenantId": TENANT }))
        .send(&second)
        .await;
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
    assert_eq!(login_attempt(&app).await, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn requests_with_no_readable_address_share_one_bucket() {
    let stores = Arc::new(InMemoryStores::new());
    let counter: Arc<dyn RateLimitStore> = stores.clone();
    let Some(app) = engine(&stores, Some(counter)) else { return };
    let bare = || {
        http::Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"email":"no@e.com","password":"wrong","tenantId":"t1"}"#,
            ))
            .unwrap_or_default()
    };

    // No peer address: an unreadable address is one shared bucket, never an unlimited budget.
    for _ in 0..LOGIN_LIMIT {
        let answer = app.clone().oneshot(bare()).await;
        assert!(matches!(answer, Ok(r) if r.status() == StatusCode::UNAUTHORIZED));
    }
    let refused = app.clone().oneshot(bare()).await;
    assert!(matches!(refused, Ok(r) if r.status() == StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn without_a_shared_counter_the_in_process_limiter_still_applies() {
    let stores = Arc::new(InMemoryStores::new());
    let Some(app) = engine(&stores, None) else { return };
    for _ in 0..LOGIN_LIMIT {
        assert_eq!(login_attempt(&app).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(login_attempt(&app).await, StatusCode::TOO_MANY_REQUESTS);
}
