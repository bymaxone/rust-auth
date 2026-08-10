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
        // The tenant comes from the verified token, never from the request: a repository id is
        // unique only within a tenant, so an unscoped lookup can resolve someone else's account.
        auth_state
            .engine()
            .assert_user_active(&claims.sub, Some(&claims.tenant_id))
            .await?;
        Ok(Self(claims))
    }
}

/// Requires everything [`UserStatus`] does **and** that the account's address is verified.
///
/// Separate from [`UserStatus`] rather than folded into it, because the two gates protect
/// different things and the routes that want them differ. `UserStatus` guards operations a
/// signed-in account may perform regardless of whether its address is proven — listing its own
/// sessions, changing its password, opening a socket. This one guards the operations that must
/// not be reachable from an address nobody has proven, MFA enrolment above all: enrolling a
/// second factor on an unverified account binds it to a mailbox that was never shown to belong
/// to the person, and the recovery path for that factor runs back through the same address.
///
/// `GET /auth/me` deliberately takes neither: a pending or suspended client still has to be able
/// to read its own profile to render the "verify your email" or "suspended" screen, and
/// `SafeAuthUser` carries `status` and `email_verified` for exactly that.
///
/// The verified half is conditional on `email_verification.required`; see
/// `AuthEngine::assert_user_active_and_verified`.
#[derive(Debug, Clone)]
pub struct VerifiedUser(pub DashboardClaims);

impl<S> FromRequestParts<S> for VerifiedUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        auth_state
            .engine()
            .assert_user_active_and_verified(&claims.sub, Some(&claims.tenant_id))
            .await?;
        Ok(Self(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::AuthRejection;
    use crate::test_support::{dashboard_token, mint_token, parts_with_cookie, scaffold, seed};
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

    #[tokio::test]
    async fn the_status_lookup_is_scoped_to_the_token_tenant() {
        // A repository id is unique only WITHIN a tenant, and the repository contract says to
        // pass `None` only for internal admin flows. This gate used to pass `None`, so a host
        // whose ids are per-tenant serials could have it resolve a different tenant's row and
        // decide on that account's status. The in-memory repository honours the tenant argument,
        // so a token whose tenant does not hold the id must be refused rather than silently
        // answered by whatever row shares the id.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "scoped@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        // The seeded account lives in `t1`, and the token says `t1`: it resolves.
        let mut parts = parts_with_cookie(&token);
        assert!(matches!(
            UserStatus::from_request_parts(&mut parts, &s.state).await,
            Ok(UserStatus(_))
        ));

        // The regression this guards against is the EXTRACTOR passing `None`, so it has to be
        // driven through the extractor. Calling the engine directly with another tenant would
        // only prove the engine scopes — and would keep passing if the extractor stopped
        // sending the tenant at all, which is exactly the bug.
        //
        // A token is minted whose claims name a tenant the account does not belong to. Scoped,
        // the lookup finds nothing and the gate refuses; unscoped, it finds the row by bare id
        // and lets the request through.
        let elsewhere = DashboardClaims {
            iss: None,
            aud: None,
            sub: id.clone(),
            jti: "jti-other-tenant".to_owned(),
            tenant_id: "some-other-tenant".to_owned(),
            role: "USER".to_owned(),
            token_type: bymax_auth_types::DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: 1_700_000_000,
            exp: 4_102_444_800,
            epoch: 0,
        };
        let mut parts = parts_with_cookie(&mint_token(&elsewhere));
        let refused = UserStatus::from_request_parts(&mut parts, &s.state).await;
        assert!(
            matches!(refused, Err(AuthRejection(AuthError::TokenInvalid))),
            "the gate resolved an id outside the token's tenant: {refused:?}"
        );
    }

    #[tokio::test]
    async fn verified_user_refuses_an_unproven_address_and_passes_a_proven_one() {
        // The MFA-management gate. `seed` creates verified accounts, so the pass arm is the
        // seeded one; flipping the flag off is what proves the check is load-bearing rather
        // than a status gate wearing a different name.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "vfy@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;

        let mut parts = parts_with_cookie(&token);
        assert!(matches!(
            VerifiedUser::from_request_parts(&mut parts, &s.state).await,
            Ok(VerifiedUser(_))
        ));

        let _ = s.users.update_email_verified(&id, false).await;
        let mut parts = parts_with_cookie(&token);
        let denied = VerifiedUser::from_request_parts(&mut parts, &s.state).await;
        assert!(
            matches!(denied, Err(AuthRejection(AuthError::EmailNotVerified))),
            "an unverified address reached an MFA-management route: {denied:?}"
        );

        // The status half still applies, so the two gates compose rather than replace.
        let _ = s.users.update_email_verified(&id, true).await;
        let _ = s.users.update_status(&id, "SUSPENDED").await;
        let mut parts = parts_with_cookie(&token);
        assert!(matches!(
            VerifiedUser::from_request_parts(&mut parts, &s.state).await,
            Err(AuthRejection(AuthError::AccountSuspended))
        ));
    }
}
