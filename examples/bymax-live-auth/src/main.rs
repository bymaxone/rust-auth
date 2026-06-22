//! The dogfood integration shape — the production consumer pattern.
//!
//! This is the auth wiring a real application (Bymax Live) assembles: the full
//! backend surface (sessions, MFA, OAuth, platform-admin, invitations) mounted on
//! the **Redis-backed** stores, exactly as a production deployment runs it. It is a
//! runnable reference, not a deployable service — it builds and starts, but a real
//! deployment supplies its own `UserRepository` (backed by a database) in place of
//! the in-memory one used here for brevity.
//!
//! ## Running
//!
//! Point `REDIS_URL` at a Redis instance (the production session/OTP/brute-force
//! backend) and `JWT_SECRET` at a 32-byte secret. With no `REDIS_URL`, startup
//! fails with a clear message — the dogfood deliberately exercises the **real**
//! store wiring rather than an in-memory stand-in.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bymax_auth_axum::{AxumAuthConfig, auth_router};
use bymax_auth_core::config::MfaConfig;
use bymax_auth_core::testing::{InMemoryPlatformUserRepository, InMemoryUserRepository};
use bymax_auth_core::traits::{AuthHooks, HookContext, HookError, OAuthLoginResult, OAuthProfile};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::SafeAuthUser;
use secrecy::SecretString;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8083";
const EXAMPLE_MFA_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The production OAuth decision: link to an existing identity, otherwise create one.
struct LiveOAuthHooks;

#[async_trait]
impl AuthHooks for LiveOAuthHooks {
    async fn on_oauth_login(
        &self,
        _profile: &OAuthProfile,
        existing: Option<&SafeAuthUser>,
        _ctx: &HookContext,
    ) -> Result<OAuthLoginResult, HookError> {
        if existing.is_some() {
            Ok(OAuthLoginResult::Link)
        } else {
            Ok(OAuthLoginResult::Create)
        }
    }
}

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
    tracing::info!(%bind, "bymax-live-auth listening — the full production auth surface");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn build_engine() -> Result<AuthEngine, Box<dyn std::error::Error>> {
    // The Redis-backed stores are the production session/OTP/brute-force/ws-ticket/
    // password-reset/invitation/MFA/OAuth-state backend, wired through one handle.
    let redis_url = std::env::var("REDIS_URL").map_err(
        |_| "REDIS_URL is required: bymax-live-auth exercises the real Redis store wiring",
    )?;
    let stores = Arc::new(RedisStores::connect(&redis_url, "live")?);

    // In a real deployment these are your database-backed repositories; the in-memory
    // doubles keep this reference focused on the auth wiring.
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(
        std::env::var("JWT_SECRET").map_err(|_| "JWT_SECRET is required (at least 32 bytes)")?,
    );
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
        ("MEMBER".to_owned(), Vec::new()),
    ]);
    config.roles.platform_hierarchy = Some(HashMap::from([
        ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
        ("SUPPORT".to_owned(), Vec::new()),
    ]));

    // The full surface a production consumer enables. (OAuth has its own dedicated
    // reference in `examples/axum-oauth-google`, where the provider + state store +
    // sign-in hook are wired; it is omitted here to keep the dogfood self-contained
    // without external provider credentials.)
    config.sessions.enabled = true;
    config.controllers.sessions = true;
    config.controllers.mfa = true;
    config.controllers.invitations = true;
    config.invitations.enabled = true;
    config.platform.enabled = true;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(
            std::env::var("MFA_KEY").unwrap_or_else(|_| EXAMPLE_MFA_KEY_B64.to_owned()),
        ),
        issuer: "Bymax Live".to_owned(),
        recovery_code_count: 8,
        totp_window: 1,
    });

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Production)
        .user_repository(users)
        .platform_user_repository(admins)
        .redis_stores(stores)
        .hooks(Arc::new(LiveOAuthHooks))
        .build()?;

    Ok(engine)
}
