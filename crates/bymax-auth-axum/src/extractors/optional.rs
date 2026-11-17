//! [`OptionalAuthUser`] (§8.3.3): the `OptionalAuthGuard` equivalent — identical sourcing
//! and verification to [`super::AuthUser`], but a request that carries no token at all is
//! anonymous. A token that is present is verified like any other: one that does not verify is
//! rejected exactly as [`super::AuthUser`] rejects it, never read as anonymous, and a store that
//! cannot answer is `503 auth.service_unavailable`.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// The verified claims when a valid dashboard token is present, `None` when the request carries no
/// token, and a rejection when a token is present and does not verify (malformed, expired,
/// revoked, of another type) or the store cannot answer. Used by public endpoints that render
/// extra content for signed-in users: a caller who sent a credential is told it failed, not served
/// as anonymous.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<DashboardClaims>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let verified = verified_dashboard_claims(parts, &auth_state).await;
        degrade(verified).map(Self)
    }
}

/// Turns a verification result into the optional claims: a missing token is anonymous, and every
/// failure of a token that was sent stays the rejection.
fn degrade(
    verified: Result<DashboardClaims, AuthError>,
) -> Result<Option<DashboardClaims>, AuthRejection> {
    match verified {
        Ok(claims) => Ok(Some(claims)),
        Err(AuthError::TokenMissing) => Ok(None),
        Err(error) => Err(AuthRejection(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, parts_empty, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;

    #[tokio::test]
    async fn optional_yields_some_for_a_valid_token_and_none_for_no_token() {
        // A valid token yields `Some`; no token at all yields `None`, never an error.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "opt@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        let mut parts = parts_with_cookie(&token);
        let some = OptionalAuthUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(some, Ok(OptionalAuthUser(Some(c))) if c.sub == id));

        let mut empty = parts_empty();
        let none = OptionalAuthUser::from_request_parts(&mut empty, &s.state).await;
        assert!(matches!(none, Ok(OptionalAuthUser(None))));
    }

    #[tokio::test]
    async fn a_token_that_is_present_but_does_not_verify_is_rejected_like_auth_user() {
        // A presented credential is never read as "anonymous": a caller who sent a bad token
        // learns it, exactly as on a route that requires authentication.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let mut bad = parts_with_cookie("garbage");
        let rejected = OptionalAuthUser::from_request_parts(&mut bad, &s.state).await;
        assert!(
            matches!(rejected, Err(AuthRejection(AuthError::TokenInvalid))),
            "got {rejected:?}"
        );
    }

    #[test]
    fn only_a_missing_token_degrades_to_none_and_every_other_failure_is_the_rejection() {
        assert!(matches!(degrade(Err(AuthError::TokenMissing)), Ok(None)));
        for error in [
            AuthError::TokenInvalid,
            AuthError::TokenRevoked,
            AuthError::TokenExpired,
            AuthError::ServiceUnavailable("store unavailable".into()),
            AuthError::Internal("defect".into()),
        ] {
            let rejected = degrade(Err(error));
            assert!(
                matches!(rejected, Err(AuthRejection(_))),
                "got {rejected:?}"
            );
        }
    }
}
