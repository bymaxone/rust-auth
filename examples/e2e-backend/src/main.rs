//! The backend the Playwright browser E2E drives.
//!
//! It is the Axum router over the **Redis-backed** stores (so refresh rotation and
//! session tracking are the real, atomic Lua paths), with cookie delivery and the
//! session group enabled. The E2E harness starts a `testcontainers` Redis, exports
//! `REDIS_URL` + `JWT_SECRET`, runs this binary, and serves the Next.js example in
//! front of it — then drives login -> request -> silent refresh -> logout in a real
//! browser, asserting the Next middleware edge-verifies (via WASM) a token this
//! backend signed.
//!
//! The user repository is the in-memory double (the E2E focuses on the auth wiring,
//! not a database); everything else is production-shaped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bymax_auth_axum::{AxumAuthConfig, auth_router};
use bymax_auth_core::config::TokenDelivery;
use bymax_auth_core::testing::InMemoryUserRepository;
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use secrecy::SecretString;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8090";

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
    tracing::info!(%bind, "e2e-backend listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn build_engine() -> Result<AuthEngine, Box<dyn std::error::Error>> {
    let redis_url =
        std::env::var("REDIS_URL").map_err(|_| "REDIS_URL is required for the e2e backend")?;
    let stores = Arc::new(RedisStores::connect(&redis_url, "e2e")?);
    let users = Arc::new(InMemoryUserRepository::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(
        std::env::var("JWT_SECRET").map_err(|_| "JWT_SECRET is required (at least 32 bytes)")?,
    );
    // Cookie delivery so the browser drives the HttpOnly-cookie flow; no email
    // verification gate so the E2E user can log in immediately after registering.
    config.token_delivery = TokenDelivery::Cookie;
    config.email_verification.required = false;
    config.sessions.enabled = true;
    config.controllers.sessions = true;
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Development)
        .user_repository(users)
        .redis_stores(stores)
        .build()?;

    Ok(engine)
}
