//! [`AuthUser`] (§8.3.2): the `JwtAuthGuard` equivalent. Its presence in a handler
//! signature makes the route require a valid dashboard access token.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::DashboardClaims;
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Verified dashboard access-token claims. Sourcing follows the configured token-delivery
/// mode (cookie / `Authorization` header — never a query string); verification (HS256-pinned
/// signature, `type == dashboard`, `rv:{jti}` revocation) is an engine call. A
/// missing/invalid/expired token rejects with `token_invalid` (401); a revoked token also
/// collapses to `token_invalid` at the boundary, so no oracle distinguishes the cases.
#[derive(Debug, Clone)]
pub struct AuthUser(pub DashboardClaims);

impl<S> FromRequestParts<S> for AuthUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        Ok(Self(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        dashboard_token, parts_with_bearer, parts_with_cookie, scaffold, seed,
    };
    use bymax_auth_core::config::TokenDelivery;
    use bymax_auth_types::AuthError;

    #[tokio::test]
    async fn bearer_mode_sources_from_the_authorization_header_and_caches_claims() {
        // In bearer mode the token comes from the `Authorization` header; a cookie is ignored.
        let Some(s) = scaffold(TokenDelivery::Bearer) else { return };
        let id = seed(&s.users, "bear@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        let mut parts = parts_with_bearer(&token);
        let ok = AuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(AuthUser(c)) if c.sub == id));
        // The claims were cached on the extensions, so a second resolution reads through.
        let again = AuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(again, Ok(AuthUser(_))));

        // A cookie is not read in bearer mode → missing.
        let mut cookie_parts = parts_with_cookie(&token);
        let missing = AuthUser::from_request_parts(&mut cookie_parts, &s.state).await;
        assert!(matches!(
            missing,
            Err(AuthRejection(AuthError::TokenMissing))
        ));
    }

    #[tokio::test]
    async fn bearer_mode_accepts_a_lowercase_bearer_scheme() {
        // The scheme token is case-insensitive: `authorization: bearer <token>` resolves the
        // same as `Bearer <token>` (the lowercase fallback branch of `bearer_from_header`).
        let Some(s) = scaffold(TokenDelivery::Bearer) else { return };
        let id = seed(&s.users, "lower@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        let (mut parts, ()) = http::Request::builder()
            .uri("/auth/me")
            .header(http::header::AUTHORIZATION, format!("bearer {token}"))
            .body(())
            .unwrap_or_default()
            .into_parts();
        let ok = AuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(AuthUser(c)) if c.sub == id));
    }

    #[tokio::test]
    async fn bearer_mode_with_an_empty_bearer_value_is_missing() {
        // `Authorization: Bearer ` (empty value) sources no token (the empty-token branch of
        // `bearer_from_header`), so the guard rejects with token_missing.
        let Some(s) = scaffold(TokenDelivery::Bearer) else { return };
        let (mut parts, ()) = http::Request::builder()
            .uri("/auth/me")
            .header(http::header::AUTHORIZATION, "Bearer ")
            .body(())
            .unwrap_or_default()
            .into_parts();
        let missing = AuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            missing,
            Err(AuthRejection(AuthError::TokenMissing))
        ));
    }

    #[tokio::test]
    async fn cookie_mode_with_an_empty_jar_is_missing() {
        // In cookie mode, a present jar with no `access_token` cookie sources no token (the
        // `access_cookie` None branch), so the guard rejects with token_missing.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let mut parts = parts_with_cookie(""); // installs an empty jar, no value set
        let missing = AuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            missing,
            Err(AuthRejection(AuthError::TokenMissing))
        ));
    }

    #[tokio::test]
    async fn both_mode_accepts_cookie_or_header() {
        // In `both` mode either channel works.
        let Some(s) = scaffold(TokenDelivery::Both) else { return };
        let id = seed(&s.users, "both@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        let mut cookie_parts = parts_with_cookie(&token);
        assert!(matches!(
            AuthUser::from_request_parts(&mut cookie_parts, &s.state).await,
            Ok(AuthUser(_))
        ));
        let mut header_parts = parts_with_bearer(&token);
        assert!(matches!(
            AuthUser::from_request_parts(&mut header_parts, &s.state).await,
            Ok(AuthUser(_))
        ));
    }
}
