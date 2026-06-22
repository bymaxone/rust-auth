//! The crate-side dogfood smoke.
//!
//! Boots `bymax-auth-axum`'s router over a real `testcontainers` Redis and drives the
//! full happy path — register -> login -> /me -> refresh -> /me -> logout — through the
//! native `bymax-auth-client`, asserting a real outcome at each step. A wrong-password
//! login is asserted to map to the typed `InvalidCredentials` error. The single
//! legitimate skip is Docker being unavailable.
//!
//! This validates the to-be-shipped backend surface (the facade-equivalent stack
//! assembled from path dependencies) before a release, exactly as the release
//! pre-publish step would run it against a `cargo package`d build.

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

const TENANT: &str = "default";
const EMAIL: &str = "smoke@example.com";
const PASSWORD: &str = "a-strong-smoke-password-123";

/// A running Redis container plus its URL; dropping it stops the container.
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

/// Start a `redis:8` container, returning `None` when Docker is unavailable so the smoke skips.
async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

/// Build a bearer-delivery engine over the real Redis stores — the shape a backend consumer ships.
fn build_engine(redis: &TestRedis) -> Option<Arc<AuthEngine>> {
    let _ = redis.container.id();
    let stores = Arc::new(RedisStores::connect(&redis.url, "smoke").ok()?);
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.token_delivery = TokenDelivery::Bearer;
    // No verification gate, so a wrong-password login reaches the credential check.
    config.email_verification.required = false;
    config.sessions.enabled = true;
    config.controllers.sessions = true;
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

/// Serve the engine's router on a fresh loopback port; the caller aborts the task at the end.
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

#[tokio::test]
async fn happy_path_register_login_me_refresh_logout() {
    // The ONLY legitimate skip is Docker being unavailable. Once the container is up,
    // every subsequent step must assert a real outcome (assert-then-bind) so an engine
    // build or server-bind failure HARD-FAILS the smoke instead of passing silently.
    let Some(redis) = try_start().await else { return };

    let engine = build_engine(&redis);
    assert!(engine.is_some(), "engine build failed after Redis came up");
    let Some(engine) = engine else { return };

    let served = serve(engine).await;
    assert!(
        served.is_some(),
        "router failed to bind after Redis came up"
    );
    let Some((base, server)) = served else { return };

    // register → a full bearer-mode authentication; the client retains the session.
    let client = AuthClient::new(base.clone());
    let registered = client
        .register(&RegisterRequest {
            email: EMAIL.to_owned(),
            password: PASSWORD.to_owned(),
            name: "Smoke".to_owned(),
            tenant_id: TENANT.to_owned(),
        })
        .await;
    assert!(matches!(registered, Ok(AuthOutcome::Authenticated(_))));

    // logout the registration session, then log in fresh to exercise the login path.
    assert!(client.logout().await.is_ok());

    let login = client
        .login(&LoginRequest {
            email: EMAIL.to_owned(),
            password: PASSWORD.to_owned(),
            tenant_id: TENANT.to_owned(),
        })
        .await;
    assert!(matches!(login, Ok(AuthOutcome::Authenticated(_))));
    assert!(client.has_session());

    // me → the credential-free user.
    let me = client.me().await;
    assert!(matches!(&me, Ok(user) if user.email == EMAIL));

    // refresh → a fresh pair is stored, and me still works against the rotated token.
    assert!(client.refresh().await.is_ok());
    assert!(client.me().await.is_ok());

    // logout → the session is revoked and cleared locally.
    assert!(client.logout().await.is_ok());
    assert!(!client.has_session());

    // A wrong-password login maps to the typed InvalidCredentials error.
    let other = AuthClient::new(base);
    let bad = other
        .login(&LoginRequest {
            email: EMAIL.to_owned(),
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
