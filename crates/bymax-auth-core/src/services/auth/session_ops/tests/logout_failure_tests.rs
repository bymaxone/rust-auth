//! A logout that could not revoke everything it was asked to revoke says so, and a retry finishes
//! the job. A `204` for a logout that left the access token or the refresh session alive tells a
//! user who signed out of a lost device that it worked.

use super::logout_hook_tests::LogoutSpy;
use super::*;
use std::sync::Arc;

/// Whether the refresh session named by `auth` is still stored.
async fn session_alive(h: &Harness, auth: &AuthResult) -> bool {
    let hash = bymax_auth_jwt::RawRefreshToken::from_raw(auth.refresh_token.clone()).redis_hash();
    let store: &dyn crate::traits::SessionStore = h.stores.as_ref();
    matches!(
        store.find_session(SessionKind::Dashboard, &hash).await,
        Ok(Some(_))
    )
}

/// A harness with email verification off and an account signed in.
async fn signed_in(
    hooks: Option<Arc<dyn crate::traits::AuthHooks>>,
) -> Option<(Harness, AuthResult)> {
    let mut cfg = base_config();
    cfg.email_verification.required = false;
    let h = harness(cfg, hooks)?;
    let (_id, auth) = logged_in(&h, "out@example.com", "pw").await?;
    Some((h, auth))
}

#[tokio::test]
async fn a_refused_blacklist_write_fails_the_logout_and_a_retry_finishes_it() {
    let Some((h, auth)) = signed_in(None).await else { return };

    h.stores.fail_next_blacklist_writes(1);
    let outcome = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );

    // The other revocations were still attempted: the long-lived credential is gone.
    assert!(!session_alive(&h, &auth).await);
    // The access token is still accepted, which is why the caller has to hear about it.
    assert!(
        h.engine
            .tokens()
            .verify_access(&auth.access_token)
            .await
            .is_ok()
    );

    // The retry has nothing left to delete and finishes the blacklist write.
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    let after = h.engine.tokens().verify_access(&auth.access_token).await;
    assert!(matches!(after, Err(AuthError::TokenRevoked)));
}

#[tokio::test]
async fn refused_cleanup_writes_fail_the_logout_yet_the_access_token_is_revoked() {
    // The session delete and the grace-pointer delete both refuse. The blacklist write is
    // attempted regardless and lands; the logout reports the failure and the retry clears the
    // session. Both refusals are logged: the log is the operator's only view of which step failed.
    let Some((h, auth)) = signed_in(None).await else { return };

    h.stores.fail_next_cleanup_writes(2);
    let (events, capture) = crate::log_capture::capture_events();
    let outcome = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    drop(capture);

    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );
    assert!(events.contains_at(tracing::Level::WARN, "logout: session cleanup"));
    assert!(events.contains_at(tracing::Level::WARN, "logout: grace pointer cleanup"));
    let revoked = h.engine.tokens().verify_access(&auth.access_token).await;
    assert!(matches!(revoked, Err(AuthError::TokenRevoked)));
    assert!(session_alive(&h, &auth).await);

    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert!(!session_alive(&h, &auth).await);
}

#[tokio::test]
async fn the_hook_fires_once_the_logout_has_actually_succeeded() {
    // A failed logout signed nobody out, so it notifies nobody; the retry that completes it does.
    let spy = Arc::new(LogoutSpy::default());
    let hooks: Arc<dyn crate::traits::AuthHooks> = spy.clone();
    let Some((h, auth)) = signed_in(Some(hooks)).await else { return };

    h.stores.fail_next_cleanup_writes(1);
    assert!(h.engine.logout("", &auth.refresh_token).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(spy.subjects.lock().map(|s| s.is_empty()).unwrap_or(false));

    assert!(h.engine.logout("", &auth.refresh_token).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(spy.subjects.lock().map(|s| s.len()).unwrap_or(0), 1);
}

#[tokio::test]
async fn a_session_lookup_that_fails_ends_the_logout_before_any_write() {
    // The owner is read first and fails closed: nothing is blacklisted and nothing is deleted,
    // so the retry starts from the same state the first attempt found.
    let Some((h, auth)) = signed_in(None).await else { return };

    h.stores.fail_next_session_lookups(1);
    let outcome = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );
    assert!(session_alive(&h, &auth).await);
    assert!(
        h.engine
            .tokens()
            .verify_access(&auth.access_token)
            .await
            .is_ok()
    );

    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert!(!session_alive(&h, &auth).await);
}
