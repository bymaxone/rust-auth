//! [`OptionalAuthUser`] (§8.3.3): the `OptionalAuthGuard` equivalent — identical sourcing
//! and verification to [`super::AuthUser`], but it **never** rejects.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::DashboardClaims;
use http::request::Parts;
use std::convert::Infallible;

use crate::extractors::verified_dashboard_claims;
use crate::state::AuthState;

/// The verified claims when a valid dashboard token is present, else `None`. An absent,
/// malformed, expired, or revoked token yields `None` rather than a rejection — used by
/// public endpoints that render extra content for signed-in users.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<DashboardClaims>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        // Any failure (missing / invalid / expired / revoked) degrades to `None`.
        let claims = verified_dashboard_claims(parts, &auth_state).await.ok();
        Ok(Self(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, parts_empty, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;

    #[tokio::test]
    async fn optional_yields_some_for_valid_and_none_otherwise() {
        // A valid token yields `Some`; an absent or invalid token yields `None`, never an error.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "opt@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        let mut parts = parts_with_cookie(&token);
        let some = OptionalAuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(some, Ok(OptionalAuthUser(Some(c))) if c.sub == id));

        let mut empty = parts_empty();
        let none = OptionalAuthUser::from_request_parts(&mut empty, &s.state).await;
        assert!(matches!(none, Ok(OptionalAuthUser(None))));

        let mut bad = parts_with_cookie("garbage");
        let bad_none = OptionalAuthUser::from_request_parts(&mut bad, &s.state).await;
        assert!(matches!(bad_none, Ok(OptionalAuthUser(None))));
    }
}
