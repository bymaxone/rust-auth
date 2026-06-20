//! [`CurrentUser`] (§8.3.7): the `@CurrentUser()` parameter decorator. Functionally the
//! same as [`super::AuthUser`] — it requires and exposes the verified claims — but the
//! distinct name reads naturally as a handler parameter. A single claim
//! (`@CurrentUser('sub')`) is obtained by field access on `CurrentUser.0`.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::DashboardClaims;
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// The verified dashboard claims exposed as a handler parameter. Requires authentication
/// (same as [`super::AuthUser`]); rejects an absent/invalid token with `token_invalid` (401).
#[derive(Debug, Clone)]
pub struct CurrentUser(pub DashboardClaims);

impl<S> FromRequestParts<S> for CurrentUser
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
    use crate::response::AuthRejection;
    use crate::test_support::{dashboard_token, parts_empty, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;
    use bymax_auth_types::AuthError;

    #[tokio::test]
    async fn current_user_exposes_claims_and_rejects_when_absent() {
        // A valid token yields the claims as a parameter; an absent token rejects.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "cu@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        let mut parts = parts_with_cookie(&token);
        let ok = CurrentUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(CurrentUser(claims)) if claims.sub == id));

        let mut empty = parts_empty();
        let denied = CurrentUser::from_request_parts(&mut empty, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::TokenMissing))
        ));
    }
}
