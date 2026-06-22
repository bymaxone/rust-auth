//! The TOTP multi-factor lifecycle on top of the minimal service.
//!
//! It enables the `mfa` route group (the Cargo feature compiles it; the
//! `controllers.mfa` toggle mounts it) and serves, in addition to register/login:
//!
//! - `POST /auth/mfa/setup` — returns the TOTP secret + `otpauth://` URI **once**;
//! - `POST /auth/mfa/verify-enable` — confirms a code and turns MFA on;
//! - `POST /auth/mfa/challenge` — exchanges an `mfa_temp_token` + code for tokens;
//! - `POST /auth/mfa/disable` and `POST /auth/mfa/recovery-codes`.
//!
//! After MFA is enabled, `login` returns `{ mfaRequired: true, mfaTempToken }`
//! instead of tokens; the client completes the challenge to finish signing in.
//!
//! The MFA secret-at-rest key is AES-256-GCM (32 bytes, base64). In production load
//! it from a secret manager — never hard-code it as this example does for clarity.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bymax_auth_axum::{AxumAuthConfig, auth_router};
use bymax_auth_core::config::MfaConfig;
use bymax_auth_core::testing::{InMemoryStores, InMemoryUserRepository};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use secrecy::SecretString;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8081";

/// A 32-byte AES-256-GCM key, base64-encoded, for the MFA secret-at-rest. Example
/// material only — generate a fresh random key per deployment.
const EXAMPLE_MFA_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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
    tracing::info!(%bind, "axum-mfa listening — register, login, then POST /auth/mfa/setup");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn build_engine() -> Result<AuthEngine, Box<dyn std::error::Error>> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(
        std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "an-insecure-example-secret-do-not-ship-0".to_owned()),
    );
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);

    // Enable the session group (so the example also lists/revokes sessions) and the
    // MFA group with its encryption key and TOTP parameters.
    config.sessions.enabled = true;
    config.controllers.sessions = true;
    config.controllers.mfa = true;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(EXAMPLE_MFA_KEY_B64.to_owned()),
        issuer: "bymax-auth example".to_owned(),
        recovery_code_count: 8,
        totp_window: 1,
    });

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Development)
        .user_repository(users)
        .redis_stores(stores)
        .build()?;

    Ok(engine)
}
