//! The error code each guard answers with, pinned beside the vocabulary it must share with
//! nest-auth's guards: a client that branches on `error.code` sees one answer per cause on either
//! backend. The platform guard answers `auth.platform_auth_required` only for a validly signed
//! token of the wrong kind and `auth.token_invalid` for every other refusal; the self-or-admin
//! guard answers `auth.insufficient_role` when it refuses.

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use bymax_auth_core::config::TokenDelivery;
use bymax_auth_types::{AuthError, PlatformClaims, PlatformType};
use http::Request;
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;

use super::{AdminRole, PlatformUser, SelfOrAdmin};
use crate::response::AuthRejection;
use crate::test_support::{
    Scaffold, dashboard_token, mint_token, parts_empty, parts_with_bearer, scaffold, seed,
};
use axum::extract::FromRequestParts;

struct Admin;

impl AdminRole for Admin {
    const NAME: &'static str = "ADMIN";
}

/// Platform claims valid for a long time, with `exp` overridable.
fn platform_claims(exp: i64) -> PlatformClaims {
    PlatformClaims {
        iss: None,
        aud: None,
        sub: "admin-1".to_owned(),
        jti: "jti-platform".to_owned(),
        role: "SUPER_ADMIN".to_owned(),
        token_type: PlatformType::Platform,
        mfa_enabled: false,
        mfa_verified: false,
        iat: 1_700_000_000,
        exp,
        epoch: 0,
    }
}

/// The code `PlatformUser` refuses `parts` with, or `None` when it admits them.
async fn platform_refusal(s: &Scaffold, mut parts: http::request::Parts) -> Option<AuthError> {
    match PlatformUser::from_request_parts(&mut parts, &s.state).await {
        Ok(_) => None,
        Err(AuthRejection(error)) => Some(error),
    }
}

#[tokio::test]
async fn the_platform_guard_answers_token_invalid_for_every_refusal_but_a_wrong_kind() {
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };

    let absent = platform_refusal(&s, parts_empty()).await;
    assert!(
        matches!(absent, Some(AuthError::TokenInvalid)),
        "{absent:?}"
    );

    let garbage = platform_refusal(&s, parts_with_bearer("not.a.jwt")).await;
    assert!(
        matches!(garbage, Some(AuthError::TokenInvalid)),
        "{garbage:?}"
    );

    let foreign_key = bymax_auth_jwt::HsKey::from_bytes(b"ffffffffffffffffffffffffffffffff");
    let forged =
        bymax_auth_jwt::sign(&platform_claims(4_700_000_000), &foreign_key).unwrap_or_default();
    let forged = platform_refusal(&s, parts_with_bearer(&forged)).await;
    assert!(
        matches!(forged, Some(AuthError::TokenInvalid)),
        "{forged:?}"
    );

    let expired = mint_token(&platform_claims(1_700_000_100));
    let expired = platform_refusal(&s, parts_with_bearer(&expired)).await;
    assert!(
        matches!(expired, Some(AuthError::TokenInvalid)),
        "{expired:?}"
    );
}

#[tokio::test]
async fn the_platform_guard_answers_platform_auth_required_for_a_valid_dashboard_token() {
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
    let user_id = seed(&s.users, "wrong-kind@e.com", "USER").await;
    let dashboard = dashboard_token(&s, &user_id).await;

    let refusal = platform_refusal(&s, parts_with_bearer(&dashboard)).await;

    assert!(
        matches!(refusal, Some(AuthError::PlatformAuthRequired)),
        "{refusal:?}"
    );
}

/// Drive a request through `SelfOrAdmin<Admin>` and return the `error.code` it answered with,
/// or `None` when the request was admitted.
async fn self_or_admin_code(s: &Scaffold, route: &str, uri: &str, token: &str) -> Option<String> {
    async fn guarded(_guard: SelfOrAdmin<Admin>) -> http::StatusCode {
        http::StatusCode::OK
    }
    let app: Router = Router::new()
        .route(route, get(guarded))
        .layer(CookieManagerLayer::new())
        .with_state(s.state.clone());
    let mut request = Request::new(Body::empty());
    *request.uri_mut() = uri.parse().unwrap_or_default();
    if let Ok(value) = http::HeaderValue::from_str(&format!("access_token={token}")) {
        request.headers_mut().insert(http::header::COOKIE, value);
    }
    let response = app.oneshot(request).await.ok()?;
    if response.status().is_success() {
        return None;
    }
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .ok()?;
    let body: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    body["error"]["code"].as_str().map(str::to_owned)
}

#[tokio::test]
async fn self_or_admin_answers_insufficient_role_when_it_refuses() {
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
    let user_id = seed(&s.users, "plain@e.com", "USER").await;
    let token = dashboard_token(&s, &user_id).await;

    // Someone else's id, and a route with no id at all, are both a role refusal.
    let other = self_or_admin_code(&s, "/users/{user_id}", "/users/other-id", &token).await;
    assert_eq!(other.as_deref(), Some("auth.insufficient_role"));
    let missing = self_or_admin_code(&s, "/no-segment", "/no-segment", &token).await;
    assert_eq!(missing.as_deref(), Some("auth.insufficient_role"));

    // Their own id is admitted.
    let own_uri = format!("/users/{user_id}");
    let own = self_or_admin_code(&s, "/users/{user_id}", &own_uri, &token).await;
    assert_eq!(own, None);
}

/// An MFA-challenge token for a platform administrator, valid until `exp`.
fn challenge_claims(exp: i64) -> bymax_auth_types::MfaTempClaims {
    bymax_auth_types::MfaTempClaims {
        sub: "admin-1".to_owned(),
        jti: "6f1d5c2e-8f3a-4b1e-9a57-0c1d2e3f4a5b".to_owned(),
        token_type: bymax_auth_types::MfaTempType::MfaChallenge,
        context: bymax_auth_types::MfaContext::Platform,
        tenant_id: None,
        epoch: 0,
        iat: 1_700_000_000,
        exp,
        iss: None,
        aud: None,
    }
}

#[tokio::test]
async fn a_validly_signed_mfa_challenge_token_on_a_platform_route_is_platform_auth_required() {
    // The same rule as a dashboard token: signed by this deployment but not a platform token.
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };

    let token = mint_token(&challenge_claims(4_700_000_000));
    let refusal = platform_refusal(&s, parts_with_bearer(&token)).await;

    assert!(
        matches!(refusal, Some(AuthError::PlatformAuthRequired)),
        "{refusal:?}"
    );
}

#[tokio::test]
async fn an_unsigned_or_expired_mfa_challenge_token_on_a_platform_route_is_token_invalid() {
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };

    let foreign_key = bymax_auth_jwt::HsKey::from_bytes(b"ffffffffffffffffffffffffffffffff");
    let forged =
        bymax_auth_jwt::sign(&challenge_claims(4_700_000_000), &foreign_key).unwrap_or_default();
    let forged = platform_refusal(&s, parts_with_bearer(&forged)).await;
    assert!(
        matches!(forged, Some(AuthError::TokenInvalid)),
        "{forged:?}"
    );

    let expired = mint_token(&challenge_claims(1_700_000_100));
    let expired = platform_refusal(&s, parts_with_bearer(&expired)).await;
    assert!(
        matches!(expired, Some(AuthError::TokenInvalid)),
        "{expired:?}"
    );
}

#[tokio::test]
async fn self_or_admin_reads_the_id_whatever_else_the_route_captures() {
    let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
    let user_id = seed(&s.users, "multi@e.com", "USER").await;
    let token = dashboard_token(&s, &user_id).await;
    let route = "/tenants/{tenant}/users/{user_id}";

    // The owner is admitted and someone else's id is refused, with a second capture present.
    let own = self_or_admin_code(&s, route, &format!("/tenants/t1/users/{user_id}"), &token).await;
    assert_eq!(own, None);
    let other = self_or_admin_code(&s, route, "/tenants/t1/users/other-id", &token).await;
    assert_eq!(other.as_deref(), Some("auth.insufficient_role"));

    // A route that names its capture `id` is read the same way; `user_id` wins when both exist.
    let by_id = format!("/sessions/t1/{user_id}");
    assert_eq!(
        self_or_admin_code(&s, "/sessions/{tenant}/{id}", &by_id, &token).await,
        None
    );
    let both = format!("/pairs/{user_id}/other-id");
    assert_eq!(
        self_or_admin_code(&s, "/pairs/{user_id}/{id}", &both, &token).await,
        None
    );
}
