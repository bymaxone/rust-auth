//! The platform-domain extractors (§8.3.5 / §8.3.6), gated behind the `platform` feature:
//! [`PlatformUser`] (the platform twin of `AuthUser`) and [`RequirePlatformRole<R>`].

use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts};
use bymax_auth_types::{AuthError, PlatformClaims};
use http::request::Parts;

use crate::extractors::source_access_token;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Verify the platform access token once per request, caching the claims on
/// `parts.extensions`. The token is sourced from the same cookie/`Authorization`-header
/// channels as the dashboard token (never a query string); a dashboard token presented here
/// fails the `type == platform` assertion and is mapped to `PlatformAuthRequired`.
async fn verified_platform_claims(
    parts: &mut Parts,
    state: &AuthState,
) -> Result<PlatformClaims, AuthError> {
    if let Some(cached) = parts.extensions.get::<PlatformClaims>() {
        return Ok(cached.clone());
    }
    let token =
        source_access_token(parts, state.config()).ok_or(AuthError::PlatformAuthRequired)?;
    let claims = state
        .engine()
        .verify_platform_token(&token)
        .await
        // A dashboard token (or any non-platform token) here is "platform auth required".
        .map_err(|_| AuthError::PlatformAuthRequired)?;
    parts.extensions.insert(claims.clone());
    Ok(claims)
}

/// Verified platform access-token claims (`type == platform`, no `tenantId`). A dashboard
/// token presented here rejects with `platform_auth_required` (401), mirroring
/// `JwtPlatformGuard`; isolation is enforced by the `type` claim, not a separate key.
#[derive(Debug, Clone)]
pub struct PlatformUser(pub PlatformClaims);

impl<S> FromRequestParts<S> for PlatformUser
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_platform_claims(parts, &auth_state).await?;
        Ok(Self(claims))
    }
}

/// Marker implemented by consumer platform-role types; `NAME` matches a key in the
/// configured platform role hierarchy.
pub trait PlatformRole {
    /// The platform-role name as it appears in `roles.platform_hierarchy`.
    const NAME: &'static str;
}

/// Requires [`PlatformUser`] **and** that the role satisfies `R` under the **platform**
/// hierarchy (`AuthEngine::platform_role_satisfies`). Rejects with `insufficient_role` (403)
/// on a role failure.
#[derive(Debug, Clone)]
pub struct RequirePlatformRole<R: PlatformRole>(pub PlatformClaims, pub PhantomData<R>);

impl<R, S> FromRequestParts<S> for RequirePlatformRole<R>
where
    R: PlatformRole,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_platform_claims(parts, &auth_state).await?;
        if auth_state
            .engine()
            .platform_role_satisfies(&claims.role, R::NAME)
        {
            Ok(Self(claims, PhantomData))
        } else {
            Err(AuthRejection(AuthError::InsufficientRole))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dashboard_token, mint_token, parts_with_cookie, scaffold, seed};
    use bymax_auth_core::config::TokenDelivery;
    use bymax_auth_types::{PlatformClaims, PlatformType};

    struct SuperAdmin;
    impl PlatformRole for SuperAdmin {
        const NAME: &'static str = "SUPER_ADMIN";
    }

    fn platform_claims(role: &str) -> PlatformClaims {
        PlatformClaims {
            sub: "admin-1".to_owned(),
            jti: "jti-platform".to_owned(),
            role: role.to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: 1_700_000_000,
            exp: 4_700_000_000,
        }
    }

    #[tokio::test]
    async fn platform_user_accepts_platform_token_and_rejects_dashboard_token() {
        // A platform token resolves; a dashboard token here is `platform_auth_required`.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let token = mint_token(&platform_claims("SUPER_ADMIN"));
        let mut parts = parts_with_cookie(&token);
        let ok = PlatformUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(PlatformUser(c)) if c.role == "SUPER_ADMIN"));
        // A second resolution on the same parts reads the cached claims (the read-through arm).
        let cached = PlatformUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(cached, Ok(PlatformUser(_))));

        let user_id = seed(&s.users, "d@e.com", "USER").await;
        let dash = dashboard_token(&s, &user_id).await;
        let mut parts = parts_with_cookie(&dash);
        let denied = PlatformUser::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::PlatformAuthRequired))
        ));

        // An absent token is also `platform_auth_required`.
        let mut empty = parts_with_cookie("");
        let none = PlatformUser::from_request_parts(&mut empty, &s.state).await;
        assert!(matches!(
            none,
            Err(AuthRejection(AuthError::PlatformAuthRequired))
        ));
    }

    #[tokio::test]
    async fn require_platform_role_checks_the_platform_hierarchy() {
        // SUPER_ADMIN satisfies SUPER_ADMIN; SUPPORT does not.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let super_token = mint_token(&platform_claims("SUPER_ADMIN"));
        let mut parts = parts_with_cookie(&super_token);
        let ok = RequirePlatformRole::<SuperAdmin>::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(ok, Ok(RequirePlatformRole(_, _))));

        let support_token = mint_token(&platform_claims("SUPPORT"));
        let mut parts = parts_with_cookie(&support_token);
        let denied =
            RequirePlatformRole::<SuperAdmin>::from_request_parts(&mut parts, &s.state).await;
        assert!(matches!(
            denied,
            Err(AuthRejection(AuthError::InsufficientRole))
        ));
    }
}
