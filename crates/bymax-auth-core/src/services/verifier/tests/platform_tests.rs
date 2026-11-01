//! The platform arm of the combined verifier: the plane is named by the caller, a dashboard token
//! is told apart from a malformed one, and the administrator's status is re-read on every call.
//! Layer: unit tests over the in-memory doubles.

use std::collections::HashMap;
use std::sync::Arc;

use bymax_auth_types::{AuthError, AuthPlatformUser, PlatformClaims, PlatformType};
use time::OffsetDateTime;

use super::super::{AuthPlane, VerifiedAccessToken, VerifyAccessOptions};
use crate::config::{AuthConfig, Environment};
use crate::engine::AuthEngine;
use crate::services::auth::test_support::base_config;
use crate::services::{new_uuid_v4, now_unix};
use crate::testing::{InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository};
use crate::traits::SessionStore as _;

fn platform_config() -> AuthConfig {
    let mut cfg = base_config();
    cfg.roles.platform_hierarchy = Some(HashMap::from([("SUPER_ADMIN".to_owned(), Vec::new())]));
    cfg.platform.enabled = true;
    cfg
}

fn admin(id: &str, status: &str) -> AuthPlatformUser {
    AuthPlatformUser {
        id: id.to_owned(),
        email: format!("{id}@admin.io"),
        name: "Admin".to_owned(),
        password_hash: String::new(),
        role: "SUPER_ADMIN".to_owned(),
        status: status.to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn claims_for(sub: &str) -> PlatformClaims {
    PlatformClaims {
        iss: None,
        aud: None,
        sub: sub.to_owned(),
        jti: new_uuid_v4(),
        role: "SUPER_ADMIN".to_owned(),
        token_type: PlatformType::Platform,
        mfa_enabled: false,
        mfa_verified: false,
        iat: now_unix(),
        exp: now_unix() + 900,
        epoch: 0,
    }
}

fn engine(admins: &Arc<InMemoryPlatformUserRepository>) -> Option<AuthEngine> {
    AuthEngine::builder()
        .config(platform_config())
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .platform_user_repository(admins.clone())
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build()
        .ok()
}

fn platform() -> VerifyAccessOptions<'static> {
    VerifyAccessOptions::new(AuthPlane::Platform)
}

#[tokio::test]
async fn a_live_administrator_verifies_and_is_tagged_with_its_plane() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    let Some(engine) = engine(&admins) else { return };
    let token = engine
        .tokens()
        .issue_platform_access(&claims_for("a1"))
        .unwrap_or_default();
    let verified = engine.verify_access(&token, &platform()).await;
    assert!(
        matches!(&verified, Ok(VerifiedAccessToken::Platform(c)) if c.sub == "a1"),
        "{verified:?}"
    );
}

#[tokio::test]
async fn a_dashboard_token_on_the_platform_plane_asks_for_platform_auth() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let Some(engine) = engine(&admins) else { return };
    let dashboard = engine
        .tokens()
        .issue_access(&super::dashboard_tests::claims_for("u1"))
        .unwrap_or_default();
    let refused = engine.verify_access(&dashboard, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::PlatformAuthRequired)),
        "{refused:?}"
    );
    // Garbage is not "the other context's token".
    let garbage = engine.verify_access("not-a-jwt", &platform()).await;
    assert!(
        matches!(garbage, Err(AuthError::TokenInvalid)),
        "{garbage:?}"
    );
}

#[tokio::test]
async fn a_platform_token_on_the_dashboard_plane_is_token_invalid() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    let Some(engine) = engine(&admins) else { return };
    let token = engine
        .tokens()
        .issue_platform_access(&claims_for("a1"))
        .unwrap_or_default();
    let refused = engine
        .verify_access(&token, &VerifyAccessOptions::new(AuthPlane::Dashboard))
        .await;
    assert!(
        matches!(refused, Err(AuthError::TokenInvalid)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_blocked_or_missing_administrator_is_refused_and_the_check_can_be_waived() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "SUSPENDED"));
    let Some(engine) = engine(&admins) else { return };
    let blocked = engine
        .tokens()
        .issue_platform_access(&claims_for("a1"))
        .unwrap_or_default();
    let gone = engine
        .tokens()
        .issue_platform_access(&claims_for("nobody"))
        .unwrap_or_default();

    let refused = engine.verify_access(&blocked, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::AccountSuspended)),
        "{refused:?}"
    );
    let missing = engine.verify_access(&gone, &platform()).await;
    assert!(
        matches!(missing, Err(AuthError::TokenInvalid)),
        "{missing:?}"
    );
    let waived = engine
        .verify_access(&blocked, &platform().check_status(false))
        .await;
    assert!(waived.is_ok(), "{waived:?}");
}

#[tokio::test]
async fn a_pending_challenge_follows_the_status_check_on_the_platform_plane() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    admins.insert(admin("a2", "BANNED"));
    let Some(engine) = engine(&admins) else { return };
    let pending = |sub: &str| PlatformClaims {
        mfa_enabled: true,
        ..claims_for(sub)
    };
    let usable = engine
        .tokens()
        .issue_platform_access(&pending("a1"))
        .unwrap_or_default();
    let banned = engine
        .tokens()
        .issue_platform_access(&pending("a2"))
        .unwrap_or_default();

    let challenge = engine.verify_access(&usable, &platform()).await;
    assert!(
        matches!(challenge, Err(AuthError::MfaRequired)),
        "{challenge:?}"
    );
    let status_first = engine.verify_access(&banned, &platform()).await;
    assert!(
        matches!(status_first, Err(AuthError::AccountBanned)),
        "{status_first:?}"
    );
}

#[tokio::test]
async fn an_engine_without_a_platform_repository_refuses_instead_of_skipping_the_gate() {
    let Some(h) = crate::services::auth::test_support::harness(base_config(), None) else {
        return;
    };
    let refused = h.engine.assert_platform_active("a1").await;
    assert!(
        matches!(refused, Err(AuthError::TokenInvalid)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_expired_administrator_token_is_token_invalid() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    let Some(engine) = engine(&admins) else { return };
    let expired = PlatformClaims {
        exp: now_unix() - 60,
        ..claims_for("a1")
    };
    let token = engine
        .tokens()
        .issue_platform_access(&expired)
        .unwrap_or_default();
    let refused = engine.verify_access(&token, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::TokenInvalid)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_revoked_dashboard_token_on_the_platform_plane_is_still_the_wrong_plane() {
    // The type is judged before revocation, as in nest-auth: the caller learns it presented the
    // other context's token, not that it was revoked.
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let Some(engine) = AuthEngine::builder()
        .config(platform_config())
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .platform_user_repository(admins)
        .redis_stores(stores.clone())
        .build()
        .ok()
    else {
        return;
    };
    let claims = super::dashboard_tests::claims_for("u1");
    let token = engine.tokens().issue_access(&claims).unwrap_or_default();
    assert!(stores.blacklist_access(&claims.jti, 600).await.is_ok());
    let refused = engine.verify_access(&token, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::PlatformAuthRequired)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_revoked_administrator_token_is_token_invalid_not_the_wrong_plane() {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    let stores = Arc::new(InMemoryStores::new());
    let Some(engine) = AuthEngine::builder()
        .config(platform_config())
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .platform_user_repository(admins)
        .redis_stores(stores.clone())
        .build()
        .ok()
    else {
        return;
    };
    let claims = claims_for("a1");
    let token = engine
        .tokens()
        .issue_platform_access(&claims)
        .unwrap_or_default();
    assert!(stores.blacklist_access(&claims.jti, 600).await.is_ok());
    let refused = engine.verify_access(&token, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::TokenInvalid)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_malformed_dashboard_token_on_the_platform_plane_is_judged_by_shape_first() {
    // nest-auth checks the claim shape before the token type, so a signed token with a malformed
    // jti is `token_invalid` whichever plane it was presented on.
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let Some(engine) = engine(&admins) else { return };
    let malformed = bymax_auth_types::DashboardClaims {
        jti: "abc".to_owned(),
        ..super::dashboard_tests::claims_for("u1")
    };
    let token = engine.tokens().issue_access(&malformed).unwrap_or_default();
    let refused = engine.verify_access(&token, &platform()).await;
    assert!(
        matches!(refused, Err(AuthError::TokenInvalid)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_malformed_administrator_jti_or_subject_is_refused_even_when_signed() {
    // Each operand of the shape check is exercised alone, so neither can be dropped.
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    admins.insert(admin("a1", "ACTIVE"));
    let Some(engine) = engine(&admins) else { return };
    let bad_jti = PlatformClaims {
        jti: "abc".to_owned(),
        ..claims_for("a1")
    };
    let long_sub = claims_for(&"x".repeat(257));
    for claims in [bad_jti, long_sub] {
        let token = engine
            .tokens()
            .issue_platform_access(&claims)
            .unwrap_or_default();
        let refused = engine.verify_access(&token, &platform()).await;
        assert!(
            matches!(refused, Err(AuthError::TokenInvalid)),
            "{refused:?}"
        );
    }
}
