//! A platform logout that could not revoke everything it was asked to revoke says so, and a retry
//! finishes the job: the refresh session of the highest-privilege identity must not outlive a
//! logout that answered success.

use super::*;

/// A harness with an admin signed in.
async fn signed_in() -> Option<(PlatformHarness, bymax_auth_types::PlatformAuthResult)> {
    let h = harness(platform_config())?;
    seed_admin(&h.admins, "out@admin.io", "pw");
    let svc = h.engine.platform_auth()?;
    let Ok(PlatformLoginResult::Success(auth)) =
        svc.login("out@admin.io", "pw", "1.2.3.4", "agent").await
    else {
        return None;
    };
    Some((h, *auth))
}

#[tokio::test]
async fn a_refused_blacklist_write_fails_the_logout_and_a_retry_finishes_it() {
    let Some((h, auth)) = signed_in().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };

    h.stores.fail_next_blacklist_writes(1);
    let outcome = svc.logout(&auth.access_token, &auth.refresh_token).await;
    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );

    // The refresh session was still revoked, and the access token still authenticates.
    let rotated = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
    assert!(matches!(rotated, Err(AuthError::RefreshTokenInvalid)));
    let tokens = h.engine.tokens();
    assert!(
        tokens
            .verify_platform_access(&auth.access_token)
            .await
            .is_ok()
    );

    // The retry finishes the blacklist write.
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    let after = tokens.verify_platform_access(&auth.access_token).await;
    assert!(matches!(after, Err(AuthError::TokenRevoked)));
}

#[tokio::test]
async fn refused_cleanup_writes_fail_the_logout_yet_the_access_token_is_revoked() {
    let Some((h, auth)) = signed_in().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };

    h.stores.fail_next_cleanup_writes(2);
    let (events, capture) = crate::log_capture::capture_events();
    let outcome = svc.logout(&auth.access_token, &auth.refresh_token).await;
    drop(capture);

    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );
    assert!(events.contains_at(tracing::Level::WARN, "logout: session cleanup"));
    assert!(events.contains_at(tracing::Level::WARN, "logout: grace pointer cleanup"));
    let revoked = h
        .engine
        .tokens()
        .verify_platform_access(&auth.access_token)
        .await;
    assert!(matches!(revoked, Err(AuthError::TokenRevoked)));

    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    let rotated = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
    assert!(matches!(rotated, Err(AuthError::RefreshTokenInvalid)));
}

#[tokio::test]
async fn a_session_lookup_that_fails_ends_the_logout_before_any_write() {
    let Some((h, auth)) = signed_in().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };

    h.stores.fail_next_session_lookups(1);
    let outcome = svc.logout(&auth.access_token, &auth.refresh_token).await;
    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );

    // Nothing was written: the access token still verifies and the session still rotates.
    let tokens = h.engine.tokens();
    assert!(
        tokens
            .verify_platform_access(&auth.access_token)
            .await
            .is_ok()
    );
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    let after = tokens.verify_platform_access(&auth.access_token).await;
    assert!(matches!(after, Err(AuthError::TokenRevoked)));
}
