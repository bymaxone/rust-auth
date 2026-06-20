//! [`RequireRole<R>`] (§8.3.4): the `@Roles(...)` + `RolesGuard` equivalent. The required
//! role is a const-generic marker type, so the requirement is part of the handler's type
//! and cannot drift from the guard at runtime.

use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Marker implemented by consumer dashboard-role types; `NAME` matches a key in the
/// configured dashboard role hierarchy.
pub trait Role {
    /// The role name as it appears in `roles.hierarchy`.
    const NAME: &'static str;
}

/// Requires [`super::AuthUser`] **and** that the user's role satisfies `R` under the
/// dashboard hierarchy (`AuthEngine::role_satisfies`). Carries the verified claims, so a
/// handler needing both the gate and the user takes just `RequireRole<R>` and reads `.0`.
/// Rejects with `insufficient_role` (403) on a role failure (and `token_invalid` when the
/// underlying authentication fails).
#[derive(Debug, Clone)]
pub struct RequireRole<R: Role>(pub DashboardClaims, pub PhantomData<R>);

impl<R, S> FromRequestParts<S> for RequireRole<R>
where
    R: Role,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        if auth_state.engine().role_satisfies(&claims.role, R::NAME) {
            Ok(Self(claims, PhantomData))
        } else {
            Err(AuthRejection(AuthError::InsufficientRole))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;

    struct Admin;
    impl Role for Admin {
        const NAME: &'static str = "ADMIN";
    }

    #[tokio::test]
    async fn admin_role_satisfies_and_user_role_is_insufficient() {
        // An ADMIN token satisfies `RequireRole<Admin>`; a USER token is rejected 403.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let admin_id = seed(&s.users, "admin@e.com", "ADMIN").await;
        let admin_token = dashboard_token(&s, &admin_id).await;
        let mut parts = parts_with_cookie(&admin_token);
        let ok = RequireRole::<Admin>::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(RequireRole(claims, _)) if claims.role == "ADMIN"));

        let user_id = seed(&s.users, "user@e.com", "USER").await;
        let user_token = dashboard_token(&s, &user_id).await;
        let mut parts = parts_with_cookie(&user_token);
        let denied = RequireRole::<Admin>::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::InsufficientRole))
        ));
    }

    #[tokio::test]
    async fn require_role_rejects_an_unauthenticated_request() {
        // Without a token the underlying `AuthUser` resolution fails first.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let mut parts = parts_with_cookie("");
        let denied = RequireRole::<Admin>::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::TokenMissing))
        ));
    }
}
