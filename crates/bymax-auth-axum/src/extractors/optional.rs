//! [`OptionalAuthUser`] (§8.3.3): the `OptionalAuthGuard` equivalent — identical sourcing
//! and verification to [`super::AuthUser`], but a token that does not verify degrades to `None`.
//! The one rejection is a store that cannot answer: the revocation, epoch and account-status
//! reads come before any decision, so an outage is `503 auth.service_unavailable`, never an
//! anonymous caller (`serviceUnavailable.appliesTo`).

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// The verified claims when a valid dashboard token is present, else `None`. An absent,
/// malformed, expired, or revoked token yields `None` rather than a rejection — used by
/// public endpoints that render extra content for signed-in users. A store that cannot answer
/// is rejected with `503`, because answering `None` would treat a signed-in caller as anonymous.
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

/// Turns a verification result into the optional claims: a missing, malformed, expired or revoked
/// token degrades to `None`, and an outage stays the rejection.
fn degrade(
    verified: Result<DashboardClaims, AuthError>,
) -> Result<Option<DashboardClaims>, AuthRejection> {
    match verified {
        Ok(claims) => Ok(Some(claims)),
        Err(outage @ AuthError::ServiceUnavailable(_)) => Err(AuthRejection(outage)),
        Err(_) => Ok(None),
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

    #[test]
    fn an_outage_is_rejected_and_every_other_failure_degrades_to_none() {
        let outage = Err(AuthError::ServiceUnavailable("store unavailable".into()));
        assert!(matches!(
            degrade(outage),
            Err(AuthRejection(AuthError::ServiceUnavailable(_)))
        ));
        for error in [
            AuthError::TokenInvalid,
            AuthError::TokenMissing,
            AuthError::TokenRevoked,
            AuthError::Internal("defect".into()),
        ] {
            assert!(matches!(degrade(Err(error)), Ok(None)));
        }
    }
}
