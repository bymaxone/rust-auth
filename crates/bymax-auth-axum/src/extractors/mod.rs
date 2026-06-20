//! The request guards (§8.3), expressed as Axum 0.8 `FromRequestParts` extractors.
//!
//! Each extractor sources a token from the cookie or the `Authorization` header — **never**
//! the query string (§24 invariant 4) — and asks the engine to verify it; the adapter owns
//! no auth logic. Security is opt-in per handler: a public route requests no auth extractor,
//! an MFA-exempt-but-authenticated route requests `AuthUser` without `MfaSatisfied`. The
//! first auth extractor to run caches the verified claims on `parts.extensions`, so stacked
//! extractors pay for exactly one HMAC verification per request.

mod auth_user;
mod current_user;
mod mfa;
mod optional;
mod role;
mod self_or_admin;
mod status;

#[cfg(feature = "platform")]
mod platform;

pub use auth_user::AuthUser;
pub use current_user::CurrentUser;
pub use mfa::MfaSatisfied;
pub use optional::OptionalAuthUser;
pub use role::{RequireRole, Role};
pub use self_or_admin::{AdminRole, SelfOrAdmin};
pub use status::UserStatus;

#[cfg(feature = "platform")]
pub use platform::{PlatformRole, PlatformUser, RequirePlatformRole};

use bymax_auth_core::config::TokenDelivery;
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;
use tower_cookies::Cookies;

use crate::state::{AuthState, ResolvedConfig};

/// Read the bearer token from the `Authorization` header, if present and well-formed
/// (`Authorization: Bearer <token>`). Never reads a query string.
fn bearer_from_header(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

/// Read the access-token cookie value, if the cookie jar is present and the cookie is set.
fn access_cookie(parts: &Parts, config: &ResolvedConfig) -> Option<String> {
    let cookies = parts.extensions.get::<Cookies>()?;
    cookies
        .get(&config.cookies.access_name)
        .map(|cookie| cookie.value().to_owned())
        .filter(|value| !value.is_empty())
}

/// Source the dashboard access token per the configured [`TokenDelivery`] mode: cookie only
/// (`Cookie`), `Authorization: Bearer` only (`Bearer`), or cookie-first-else-header (`Both`).
/// Returns `None` when no token is present on the accepted channel(s).
pub(crate) fn source_access_token(parts: &Parts, config: &ResolvedConfig) -> Option<String> {
    match config.delivery {
        TokenDelivery::Cookie => access_cookie(parts, config),
        TokenDelivery::Bearer => bearer_from_header(parts),
        TokenDelivery::Both => access_cookie(parts, config).or_else(|| bearer_from_header(parts)),
    }
}

/// Verify the dashboard access token once per request, caching the claims on
/// `parts.extensions`. A subsequent stacked extractor reads the cached value rather than
/// re-running the HMAC verification + revocation lookup. A missing token is the boundary
/// sentinel [`AuthError::TokenMissing`] (collapsed to `token_invalid` on the wire).
pub(crate) async fn verified_dashboard_claims(
    parts: &mut Parts,
    state: &AuthState,
) -> Result<DashboardClaims, AuthError> {
    if let Some(cached) = parts.extensions.get::<DashboardClaims>() {
        return Ok(cached.clone());
    }
    let token = source_access_token(parts, state.config()).ok_or(AuthError::TokenMissing)?;
    let claims = state.engine().verify_access_token(&token).await?;
    parts.extensions.insert(claims.clone());
    Ok(claims)
}
