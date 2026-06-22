//! The Google OAuth authorize -> callback flow.
//!
//! It serves:
//!
//! - `GET /auth/oauth/google?tenantId=...` — 302 to Google's consent screen with a
//!   single-use `state` and a PKCE `code_challenge` (S256) minted server-side;
//! - `GET /auth/oauth/google/callback?code=...&state=...` — consumes the `state`
//!   atomically (`GETDEL`), exchanges the code with the stored PKCE verifier, fetches
//!   the verified profile, and applies the `on_oauth_login` decision.
//!
//! The redirect URLs are operator-configured at startup and are **never**
//! request-derived (no open redirect). The example never contacts Google in CI — it
//! builds and starts with placeholder credentials from the environment.
//!
//! ## Production note — TLS
//!
//! The bundled `ReqwestHttpClient` ships with **no TLS backend** (the workspace bans
//! `ring`/OpenSSL), so it speaks plain HTTP only. To actually reach Google over
//! HTTPS, construct it from a TLS-capable `reqwest::Client` via
//! `ReqwestHttpClient::with_client(...)`, or supply your own `HttpClient`
//! implementation. This example wires the plain client so it compiles and starts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bymax_auth_axum::{AxumAuthConfig, auth_router};
use bymax_auth_core::config::GoogleOAuthConfig;
use bymax_auth_core::providers::GoogleOAuthProvider;
use bymax_auth_core::providers::ReqwestHttpClient;
use bymax_auth_core::testing::{InMemoryStores, InMemoryUserRepository};
use bymax_auth_core::traits::{AuthHooks, HookContext, HookError, OAuthLoginResult, OAuthProfile};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_types::SafeAuthUser;
use secrecy::SecretString;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8082";

/// A hook that turns a verified Google profile into an account decision. The default
/// `NoOpAuthHooks` rejects OAuth sign-in (fail-closed), so a real `on_oauth_login`
/// implementation is required to enable the flow. Here: link to an existing user,
/// otherwise create one.
struct OAuthDecisionHooks;

#[async_trait]
impl AuthHooks for OAuthDecisionHooks {
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
    tracing::info!(%bind, "axum-oauth-google listening — open GET /auth/oauth/google?tenantId=default");

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

    // Placeholder credentials from the environment; the example never calls Google in CI.
    let google = GoogleOAuthConfig {
        client_id: std::env::var("GOOGLE_CLIENT_ID")
            .unwrap_or_else(|_| "example-client-id.apps.googleusercontent.com".to_owned()),
        client_secret: SecretString::from(
            std::env::var("GOOGLE_CLIENT_SECRET")
                .unwrap_or_else(|_| "example-client-secret".to_owned()),
        ),
        callback_url: std::env::var("GOOGLE_CALLBACK_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8082/auth/oauth/google/callback".to_owned()),
        scope: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
    };

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(
        std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "an-insecure-example-secret-do-not-ship-0".to_owned()),
    );
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);

    config.controllers.oauth = true;
    config.sessions.enabled = true;
    config.controllers.sessions = true;
    // Operator-configured (never request-derived) post-callback redirect targets.
    config.oauth.success_redirect_url = Some("http://127.0.0.1:3000/dashboard".to_owned());
    config.oauth.error_redirect_url = Some("http://127.0.0.1:3000/login?error".to_owned());
    config.oauth.google = Some(google.clone());

    // The bundled HTTP client (plain HTTP — see the module note about TLS for real Google).
    let http = Arc::new(ReqwestHttpClient::new()?);
    let provider = Arc::new(GoogleOAuthProvider::new(google, http.clone()));

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Development)
        .user_repository(users)
        .redis_stores(stores.clone())
        .http_client(http)
        .oauth_provider(provider)
        .oauth_state_store(stores)
        .hooks(Arc::new(OAuthDecisionHooks))
        .build()?;

    Ok(engine)
}
