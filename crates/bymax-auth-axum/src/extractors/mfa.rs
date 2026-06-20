//! [`MfaSatisfied`] (§8.3.7): the `MfaRequiredGuard` equivalent. Its **omission** from a
//! handler is the `@SkipMfa()` semantic — routes reachable during MFA enrolment
//! (`mfa/setup`, `mfa/verify-enable`) deliberately do not compose it.

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Requires [`super::AuthUser`] and that the session has cleared the second factor when the
/// account has MFA enabled (`claims.mfa_enabled` ⇒ `claims.mfa_verified`). An MFA-enabled
/// account whose session has not satisfied MFA rejects with `mfa_required` (403); an account
/// without MFA passes through. Carries the verified claims.
#[derive(Debug, Clone)]
pub struct MfaSatisfied(pub DashboardClaims);

impl<S> FromRequestParts<S> for MfaSatisfied
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;
        if claims.mfa_enabled && !claims.mfa_verified {
            return Err(AuthRejection(AuthError::MfaRequired));
        }
        Ok(Self(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, mint_token, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;
    use bymax_auth_types::{DashboardClaims, DashboardType};

    /// A far-future expiry so the minted token is temporally valid well past any test run.
    fn future_exp() -> i64 {
        4_700_000_000
    }

    #[tokio::test]
    async fn passes_without_mfa_and_rejects_when_mfa_unsatisfied() {
        // A non-MFA account passes; an MFA-enabled account whose session has not satisfied the
        // second factor is rejected `mfa_required`.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "nomfa@e.com", "USER").await;
        let token = dashboard_token(&s, &id).await;
        let mut parts = parts_with_cookie(&token);
        let ok = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(MfaSatisfied(_))));

        // Mint a token with mfa_enabled=true, mfa_verified=false (no normal flow issues one).
        let claims = DashboardClaims {
            sub: id.clone(),
            jti: "jti-unverified".to_owned(),
            tenant_id: "t1".to_owned(),
            role: "USER".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: true,
            mfa_verified: false,
            iat: 1_700_000_000,
            exp: future_exp(),
        };
        let unverified = mint_token(&claims);
        let mut parts = parts_with_cookie(&unverified);
        let denied = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(denied, Err(AuthRejection(AuthError::MfaRequired))));

        // An mfa_enabled + verified token passes.
        let verified_claims = DashboardClaims {
            mfa_verified: true,
            ..claims
        };
        let verified = mint_token(&verified_claims);
        let mut parts = parts_with_cookie(&verified);
        let ok2 = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok2, Ok(MfaSatisfied(_))));
    }
}
