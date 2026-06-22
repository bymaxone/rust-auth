//! The smallest end-to-end `bymax-auth` service.
//!
//! It mounts the Axum adapter over the in-memory `UserRepository` and store
//! doubles (so it needs no database and no Redis), then serves the always-on
//! `auth` + `password_reset` route groups. Once running, the happy path is:
//!
//! ```text
//! curl -i -c jar -X POST localhost:8080/auth/register \
//!   -H 'content-type: application/json' \
//!   -d '{"email":"a@b.test","password":"correct horse battery","name":"A","tenantId":"default"}'
//! curl -i -c jar -b jar -X POST localhost:8080/auth/login \
//!   -H 'content-type: application/json' \
//!   -d '{"email":"a@b.test","password":"correct horse battery","tenantId":"default"}'
//! curl -i -b jar localhost:8080/auth/me
//! ```
//!
//! In a real service you replace `InMemoryUserRepository` with your own
//! `UserRepository` (sqlx/SeaORM/Diesel) and `InMemoryStores` with the Redis-backed
//! `bymax-auth-redis` stores. Nothing else about the wiring changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bymax_auth_axum::{AxumAuthConfig, auth_router};
use bymax_auth_core::testing::{InMemoryStores, InMemoryUserRepository};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use secrecy::SecretString;

/// The address the example binds; override with `BIND_ADDR`.
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let engine = build_engine()?;
    let router = auth_router(engine, AxumAuthConfig::default());

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "axum-minimal listening — try POST /auth/register then /auth/login");

    // `ConnectInfo<SocketAddr>` is required by the adapter's request-context and
    // per-route rate limiter, so the router is served with peer-address capture.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Build the engine over the in-memory doubles with a development-friendly profile
/// (non-secure cookies so the example works over plain HTTP on localhost).
fn build_engine() -> Result<AuthEngine, Box<dyn std::error::Error>> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    // The signing secret must be at least 32 bytes. NEVER hard-code a real secret —
    // load it from the environment / a secret manager in production.
    config.jwt.secret = SecretString::from(
        std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "an-insecure-example-secret-do-not-ship-0".to_owned()),
    );
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["USER".to_owned()]),
        ("USER".to_owned(), Vec::new()),
    ]);

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Development)
        .user_repository(users)
        .redis_stores(stores)
        .build()?;

    Ok(engine)
}
