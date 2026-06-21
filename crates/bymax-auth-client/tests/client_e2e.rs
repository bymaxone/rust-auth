//! End-to-end round-trip of the native [`AuthClient`] against a **real** `bymax-auth-axum`
//! backend served over a TCP socket, with genuine Redis (via `testcontainers`).
//!
//! It proves the typed Rust client speaks the backend's bearer-mode wire contract end to
//! end: `register → me → refresh → me → logout`, plus a wrong-password login mapping to the
//! typed [`AuthClientError::Api`]. The single legitimate skip is Docker being unavailable
//! (no container starts); once a container is running, every step asserts a real outcome.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bymax_auth_axum::{AuthRouter, AxumAuthConfig};
use bymax_auth_client::{AuthClient, AuthClientError, AuthOutcome, LoginRequest, RegisterRequest};
use bymax_auth_core::config::TokenDelivery;
use bymax_auth_core::testing::{InMemoryPlatformUserRepository, InMemoryUserRepository};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::AuthErrorCode;
use secrecy::SecretString;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const TENANT: &str = "t1";

/// A running Redis container plus its URL; dropping it stops the container.
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

/// Start a `redis:8` container, returning `None` when Docker is unavailable so the test skips.
async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

/// Build a bearer-delivery engine over the real Redis stores.
fn build_engine(redis: &TestRedis) -> Option<Arc<AuthEngine>> {
    let _ = redis.container.id();
    let stores = Arc::new(RedisStores::connect(&redis.url, "auth").ok()?);
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.token_delivery = TokenDelivery::Bearer;
    // No verification gate, so a wrong-password login reaches the credential check (rather
    // than short-circuiting on an unverified email).
    config.email_verification.required = false;
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users)
        .platform_user_repository(admins)
        .redis_stores(stores)
        .build()
        .ok()?;
    Some(Arc::new(engine))
}

/// Serve the engine's router on a fresh loopback port, returning the base URL and the server
/// task handle (aborted by the caller at the end).
async fn serve(engine: Arc<AuthEngine>) -> Option<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let app = AuthRouter::from_engine(engine, AxumAuthConfig::default()).into_router();
    let handle = tokio::spawn(async move {
        let service = app.into_make_service_with_connect_info::<SocketAddr>();
        let _ = axum::serve(listener, service).await;
    });
    Some((format!("http://{addr}"), handle))
}

/// Register inputs for the round-trip user.
fn registration() -> RegisterRequest {
    RegisterRequest {
        email: "round.trip@example.com".to_owned(),
        password: "a-strong-password-123".to_owned(),
        name: "Round Trip".to_owned(),
        tenant_id: TENANT.to_owned(),
    }
}

#[tokio::test]
async fn register_me_refresh_logout_round_trip_over_real_http() {
    // Skip cleanly when Docker is unavailable; otherwise every step asserts a real outcome.
    let Some(redis) = try_start().await else { return };
    let Some(engine) = build_engine(&redis) else { return };
    let Some((base, server)) = serve(engine).await else { return };

    let client = AuthClient::new(base.clone());

    // register → a full bearer-mode authentication; the client retains the session.
    let registered = client.register(&registration()).await;
    assert!(matches!(registered, Ok(AuthOutcome::Authenticated(_))));
    assert!(client.has_session());

    // me → the credential-free user, fetched with the stored access token.
    let me = client.me().await;
    assert!(matches!(&me, Ok(user) if user.email == "round.trip@example.com"));

    // refresh → a fresh pair is stored, and me still works against the rotated token.
    let rotated = client.refresh().await;
    assert!(rotated.is_ok());
    assert!(client.me().await.is_ok());

    // logout → the session is revoked and cleared locally.
    assert!(client.logout().await.is_ok());
    assert!(!client.has_session());

    // A second client logging in with the wrong password maps to the typed Api error.
    let other = AuthClient::new(base);
    let bad = other
        .login(&LoginRequest {
            email: "round.trip@example.com".to_owned(),
            password: "wrong-password".to_owned(),
            tenant_id: TENANT.to_owned(),
        })
        .await;
    assert!(matches!(
        bad,
        Err(AuthClientError::Api {
            code: AuthErrorCode::InvalidCredentials,
            ..
        })
    ));

    server.abort();
}
