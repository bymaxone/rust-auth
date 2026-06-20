//! [`UserStatus`] (§8.3.7): the `UserStatusGuard` equivalent. Resolves [`super::AuthUser`],
//! then asserts the account is not in a blocked status via the engine.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::DashboardClaims;
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Requires [`super::AuthUser`] and that the user's current status is not in the configured
/// blocked set. The status is resolved by `AuthEngine::assert_user_active(sub)`; a blocked
/// account rejects with the status-specific code (`AccountBanned`/`AccountInactive`/
/// `AccountSuspended`/`PendingApproval`, all 403). Carries the verified claims.
#[derive(Debug, Clone)]
pub struct UserStatus(pub DashboardClaims);

impl<S> FromRequestParts<S> for UserStatus
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        auth_state.engine().assert_user_active(&claims.sub).await?;
        Ok(Self(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::AuthRejection;
    use crate::test_support::{dashboard_token, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;
    use bymax_auth_core::traits::UserRepository;
    use bymax_auth_types::AuthError;

    #[tokio::test]
    async fn active_passes_and_blocked_status_rejects() {
        // An active account passes; flipping the stored status to BANNED makes the extractor
        // reject with the status-specific 403.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "st@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        let mut parts = parts_with_cookie(&token);
        let ok = UserStatus::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(UserStatus(_))));

        let _ = s.users.update_status(&id, "BANNED").await;
        let mut parts = parts_with_cookie(&token);
        let denied = UserStatus::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::AccountBanned))
        ));
    }
}
