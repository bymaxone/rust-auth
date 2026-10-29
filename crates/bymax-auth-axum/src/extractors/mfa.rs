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
/// account whose session has not satisfied MFA rejects with `mfa_required` (403) once the
/// account itself is usable; an account without MFA passes through. Carries the verified
/// claims.
///
/// The account is judged first when a challenge is pending: a blocked account rejects with its
/// status code, an unverified address with `email_not_verified` (where the deployment requires
/// verification) and an account that no longer exists with `token_invalid`, never with
/// `mfa_required`. That order holds wherever the handler lists this extractor. It is the order of
/// nest-auth's access-token verifier (status gate, then MFA). Language difference: the
/// `mfa_enabled` claim is a typed `bool` here, so there is no malformed-claim refusal to port.
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
            // The account's status (and, where the deployment enforces it, its verified address)
            // is judged BEFORE the second factor is demanded, whatever order the handler lists
            // its extractors in: a blocked, unverified or deleted account must be told that, not
            // asked to complete a challenge it cannot use. nest-auth's token verifier applies the
            // same order through `assertDashboardAccountUsable`. Read only on this branch, so a
            // satisfied request costs no extra lookup.
            auth_state
                .engine()
                .assert_user_active_and_verified(&claims.sub, Some(&claims.tenant_id))
                .await?;
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
    use bymax_auth_core::traits::UserRepository;
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
            iss: None,
            aud: None,
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
            epoch: 0,
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

    /// Claims for `sub` in tenant `t1` whose second factor is enrolled but not yet satisfied.
    fn mfa_pending_claims(sub: &str) -> DashboardClaims {
        DashboardClaims {
            iss: None,
            aud: None,
            sub: sub.to_owned(),
            jti: format!("jti-pending-{sub}"),
            tenant_id: "t1".to_owned(),
            role: "USER".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: true,
            mfa_verified: false,
            iat: 1_700_000_000,
            exp: future_exp(),
            epoch: 0,
        }
    }

    #[tokio::test]
    async fn a_blocked_account_with_mfa_pending_is_told_its_status_not_mfa_required() {
        // Same precedence as nest-auth's HTTP guard chain and its token verifier: status first,
        // then MFA. Without it a banned account whose session has not cleared the second factor
        // was answered `mfa_required`, steering it into a challenge it can never complete.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "blocked-pending@e.com", "USER").await;
        let token = mint_token(&mfa_pending_claims(&id));

        // Active + MFA pending: still the second-factor refusal.
        let mut parts = parts_with_cookie(&token);
        let pending = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            pending,
            Err(AuthRejection(AuthError::MfaRequired))
        ));

        // Banned + MFA pending: the status wins.
        let _ = s.users.update_status(&id, "BANNED").await;
        let mut parts = parts_with_cookie(&token);
        let banned = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(
            matches!(banned, Err(AuthRejection(AuthError::AccountBanned))),
            "a banned account with MFA pending must be refused for its status: {banned:?}"
        );
    }

    #[tokio::test]
    async fn a_deleted_account_with_mfa_pending_is_a_token_invalid_not_mfa_required() {
        // The subject has no account behind it, so the status gate answers `token_invalid`
        // before the second factor is considered.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let token = mint_token(&mfa_pending_claims("no-such-account"));
        let mut parts = parts_with_cookie(&token);
        let gone = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(
            matches!(gone, Err(AuthRejection(AuthError::TokenInvalid))),
            "a deleted account with MFA pending must be refused as token_invalid: {gone:?}"
        );
    }

    #[tokio::test]
    async fn an_unverified_account_with_mfa_pending_is_told_to_verify_not_mfa_required() {
        // nest-auth answers EMAIL_NOT_VERIFIED before MFA_REQUIRED on the dashboard plane: the
        // gate that refuses a blocked account also refuses an unproven address.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let id = seed(&s.users, "unverified-pending@e.com", "USER").await;
        let token = mint_token(&mfa_pending_claims(&id));

        let _ = s.users.update_email_verified(&id, false).await;
        let mut parts = parts_with_cookie(&token);
        let unverified = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(
            matches!(unverified, Err(AuthRejection(AuthError::EmailNotVerified))),
            "an unverified account with MFA pending must be refused as email_not_verified: {unverified:?}"
        );

        let _ = s.users.update_email_verified(&id, true).await;
        let mut parts = parts_with_cookie(&token);
        let verified = MfaSatisfied::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            verified,
            Err(AuthRejection(AuthError::MfaRequired))
        ));
    }
}
