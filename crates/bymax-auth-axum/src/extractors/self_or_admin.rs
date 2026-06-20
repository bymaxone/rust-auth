//! [`SelfOrAdmin<A>`] (§8.3.7): the `SelfOrAdminGuard` equivalent — a path-parameter-aware
//! extractor that admits the request when the `{user_id}` path segment equals the caller's
//! `sub`, or the caller's role satisfies the configured admin role.

use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts, Path};
use bymax_auth_types::{AuthError, DashboardClaims};
use http::request::Parts;

use crate::extractors::verified_dashboard_claims;
use crate::response::AuthRejection;
use crate::state::AuthState;

/// Marker for the admin dashboard role that bypasses the self-only check; `NAME` matches a
/// key in the configured dashboard role hierarchy.
pub trait AdminRole {
    /// The admin role name as it appears in `roles.hierarchy`.
    const NAME: &'static str;
}

/// Admits the request when the `{user_id}` path segment equals the caller's `sub`
/// (the primary IDOR defense) **or** the caller's role satisfies `A` (the admin override).
/// Carries the verified claims. Rejects with `forbidden` (403) when neither holds, and with
/// `token_invalid` when the path segment is absent (a route misuse — `SelfOrAdmin` must be
/// mounted on a `/{user_id}` path).
#[derive(Debug, Clone)]
pub struct SelfOrAdmin<A: AdminRole>(pub DashboardClaims, pub PhantomData<A>);

impl<A, S> FromRequestParts<S> for SelfOrAdmin<A>
where
    A: AdminRole,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let claims = verified_dashboard_claims(parts, &auth_state).await?;

        // The `{user_id}` capture must be present; its absence is a routing error, mapped to
        // `token_invalid` so it never silently admits.
        let Path(user_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| AuthRejection(AuthError::TokenInvalid))?;

        let is_self = user_id == claims.sub;
        let is_admin = auth_state.engine().role_satisfies(&claims.role, A::NAME);
        if is_self || is_admin {
            Ok(Self(claims, PhantomData))
        } else {
            Err(AuthRejection(AuthError::Forbidden))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AuthState;
    use crate::test_support::{dashboard_token, scaffold, seed};
    use axum::Router;
    use axum::routing::get;
    use bymax_auth_core::config::TokenDelivery;
    use http::{Request, StatusCode};
    use tower::ServiceExt;
    use tower_cookies::CookieManagerLayer;

    struct Admin;
    impl AdminRole for Admin {
        const NAME: &'static str = "ADMIN";
    }

    /// A handler that only succeeds if `SelfOrAdmin<Admin>` admitted the request.
    async fn guarded(_guard: SelfOrAdmin<Admin>) -> StatusCode {
        StatusCode::OK
    }

    /// Drive a `/users/{user_id}` request carrying the access cookie through a mini-router.
    async fn call(state: &AuthState, user_id: &str, token: &str) -> StatusCode {
        let app: Router = Router::new()
            .route("/users/{user_id}", get(guarded))
            .layer(CookieManagerLayer::new())
            .with_state(state.clone());
        // The request inputs are always valid and a `Router`'s `oneshot` error is `Infallible`,
        // so building from parts and mapping the result degrades without a dead error arm.
        let mut request = Request::new(axum::body::Body::empty());
        *request.uri_mut() = format!("/users/{user_id}").parse().unwrap_or_default();
        if let Ok(value) = http::HeaderValue::from_str(&format!("access_token={token}")) {
            request.headers_mut().insert(http::header::COOKIE, value);
        }
        app.oneshot(request)
            .await
            .map(|response| response.status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    #[tokio::test]
    async fn admits_self_or_admin_and_forbids_others() {
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        // A USER hitting their own id is admitted (self).
        let user_id = seed(&s.users, "self@e.com", "USER").await;
        let user_token = dashboard_token(&s, &user_id).await;
        assert_eq!(call(&s.state, &user_id, &user_token).await, StatusCode::OK);

        // The same USER hitting someone else's id is forbidden.
        assert_eq!(
            call(&s.state, "other-id", &user_token).await,
            StatusCode::FORBIDDEN
        );

        // An ADMIN hitting any id is admitted (role override).
        let admin_id = seed(&s.users, "adm@e.com", "ADMIN").await;
        let admin_token = dashboard_token(&s, &admin_id).await;
        assert_eq!(call(&s.state, "anyone", &admin_token).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_user_id_path_segment_is_a_routing_error() {
        // Mounted on a route without a `{user_id}` capture, the `Path<String>` extraction fails
        // and the guard maps it to `token_invalid` (401) rather than silently admitting — the
        // absent-path-segment arm.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        let user_id = seed(&s.users, "noseg@e.com", "USER").await;
        let token = dashboard_token(&s, &user_id).await;

        let app: Router = Router::new()
            .route("/no-segment", get(guarded))
            .layer(CookieManagerLayer::new())
            .with_state(s.state.clone());
        let mut request = Request::new(axum::body::Body::empty());
        *request.uri_mut() = "/no-segment".parse().unwrap_or_default();
        if let Ok(value) = http::HeaderValue::from_str(&format!("access_token={token}")) {
            request.headers_mut().insert(http::header::COOKIE, value);
        }
        let status = app
            .oneshot(request)
            .await
            .map(|response| response.status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
