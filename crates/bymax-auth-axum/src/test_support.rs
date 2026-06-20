//! Crate-internal test scaffolding: build an [`AuthState`] over the in-memory trait doubles
//! and synthesize request `Parts`, so the extractor unit tests can drive `FromRequestParts`
//! directly. The public extractors that no mounted handler composes — `RequireRole`,
//! `CurrentUser`, `OptionalAuthUser`, `SelfOrAdmin`, `RequirePlatformRole` — are covered here;
//! the route handlers are covered by the integration tier.
//!
//! Tokens are minted through the engine's real issuance paths (a seeded user logged in via
//! `issue_tokens_for_user_id`, an admin via the platform login), so the unit tests exercise
//! genuine HS256-signed tokens rather than hand-rolled ones.

use std::collections::HashMap;
use std::sync::Arc;

use bymax_auth_core::config::{MfaConfig, TokenDelivery};
use bymax_auth_core::testing::{
    InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository,
};
use bymax_auth_core::traits::UserRepository;
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_types::CreateUserData;
use http::Request;
use http::request::Parts;
use secrecy::SecretString;
use tower_cookies::Cookies;

use crate::state::{AuthState, ClientIpSource, ResolvedConfig, ResolvedCookies};

/// The fixed JWT secret for the unit tier.
pub(crate) const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// The concrete collaborators behind a test [`AuthState`], so a test can seed users.
pub(crate) struct Scaffold {
    pub state: AuthState,
    pub users: Arc<InMemoryUserRepository>,
}

/// Build a [`Scaffold`] over in-memory stores with the platform domain + MFA configured, so
/// the platform/MFA/role extractor tests can run. Returns `None` only if the engine fails to
/// build (it does not, for this config) — callers use `let Some(s) = scaffold(..) else { return };`.
pub(crate) fn scaffold(delivery: TokenDelivery) -> Option<Scaffold> {
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(SECRET.to_owned());
    config.token_delivery = delivery;
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["USER".to_owned()]),
        ("USER".to_owned(), Vec::new()),
    ]);
    config.roles.platform_hierarchy = Some(HashMap::from([
        ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
        ("SUPPORT".to_owned(), Vec::new()),
    ]));
    config.platform.enabled = true;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(mfa_key()),
        issuer: "Bymax".to_owned(),
        recovery_code_count: 8,
        totp_window: 2,
    });

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(stores)
        .build()
        .ok()?;

    Some(Scaffold {
        state: AuthState::new(Arc::new(engine), Arc::new(resolved_config(delivery))),
        users,
    })
}

/// The resolved adapter config for a scaffold (Lax access cookie).
fn resolved_config(delivery: TokenDelivery) -> ResolvedConfig {
    resolved_config_with(delivery, bymax_auth_core::config::SameSite::Lax)
}

/// A resolved adapter config with an explicit delivery mode and access-cookie `SameSite`, for
/// the delivery unit tests that exercise each cookie/mode arm directly.
pub(crate) fn resolved_config_with(
    delivery: TokenDelivery,
    same_site: bymax_auth_core::config::SameSite,
) -> ResolvedConfig {
    ResolvedConfig {
        route_prefix: "auth".to_owned(),
        delivery,
        cookies: ResolvedCookies {
            access_name: "access_token".to_owned(),
            refresh_name: "refresh_token".to_owned(),
            signal_name: "has_session".to_owned(),
            refresh_path: "/auth".to_owned(),
            mfa_temp_path: "/auth/mfa".to_owned(),
            secure: true,
            same_site,
            access_max_age_secs: 900,
            refresh_max_age_secs: 604_800,
        },
        client_ip_source: ClientIpSource::PeerAddr,
    }
}

/// A 32-byte AES key, base64-encoded, for the MFA config.
fn mfa_key() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

/// Seed an active dashboard user with the given role; returns its id.
pub(crate) async fn seed(users: &InMemoryUserRepository, email: &str, role: &str) -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    let hash = bymax_auth_crypto::password::hash(b"password123", &params).unwrap_or_default();
    let created = users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "Seed".to_owned(),
            password_hash: Some(hash),
            role: Some(role.to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    // The in-memory create always succeeds for a fresh email; `unwrap_or_default` keeps the
    // helper panic-free without a separate (dead) error arm.
    created.map(|user| user.id).unwrap_or_default()
}

/// Mint a real dashboard access token for a seeded user via the engine's password-less
/// issuance path, returning the access token string. Returns an empty string on any failure
/// (the test assertions then fail rather than panicking).
pub(crate) async fn dashboard_token(scaffold: &Scaffold, user_id: &str) -> String {
    scaffold
        .state
        .engine()
        .issue_tokens_for_user_id(user_id, "203.0.113.4", "agent")
        .await
        .map(|result| result.access_token)
        .unwrap_or_default()
}

/// Sign an arbitrary serializable claims value with the scaffold's HS256 secret. Lets a test
/// mint a token no normal flow would (e.g. an MFA-enabled-but-unverified dashboard token, or a
/// platform token) so every extractor arm is reachable. Returns an empty string on failure.
pub(crate) fn mint_token<C: serde::Serialize>(claims: &C) -> String {
    let key = bymax_auth_jwt::HsKey::from_bytes(SECRET.as_bytes());
    bymax_auth_jwt::sign(claims, &key).unwrap_or_default()
}

/// Build request `Parts` carrying the access-token cookie set to `token`, with the cookie jar
/// installed in the extensions exactly as the cookie-manager layer would.
pub(crate) fn parts_with_cookie(token: &str) -> Parts {
    let request = Request::builder()
        .uri("/auth/me")
        .body(())
        .unwrap_or_default();
    let (mut parts, ()) = request.into_parts();
    let jar = Cookies::default();
    if !token.is_empty() {
        jar.add(tower_cookies::Cookie::new("access_token", token.to_owned()));
    }
    parts.extensions.insert(jar);
    parts
}

/// Build request `Parts` carrying a bearer `Authorization` header.
pub(crate) fn parts_with_bearer(token: &str) -> Parts {
    Request::builder()
        .uri("/auth/me")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap_or_default()
        .into_parts()
        .0
}

/// Build request `Parts` with no credential at all (no cookie jar, no header).
pub(crate) fn parts_empty() -> Parts {
    Request::builder()
        .uri("/auth/me")
        .body(())
        .unwrap_or_default()
        .into_parts()
        .0
}
