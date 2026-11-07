//! A logout that fails a revocation write leaves the owner marker its retry reads, and the retry
//! that completes the logout announces it once. The marker is a hint and never a session.

use std::sync::Arc;

use super::logout_failure_tests::{signed_in, signed_in_with};
use super::logout_hook_tests::LogoutSpy;
use super::*;
use crate::traits::LogoutOwner;

fn marker_hash(auth: &AuthResult) -> String {
    bymax_auth_jwt::RawRefreshToken::from_raw(auth.refresh_token.clone()).redis_hash()
}

/// A signed-in account whose engine reports to `spy`.
async fn watched() -> Option<(Harness, AuthResult, Arc<LogoutSpy>)> {
    let spy = Arc::new(LogoutSpy::default());
    let hooks: Arc<dyn crate::traits::AuthHooks> = spy.clone();
    let (h, auth) = signed_in(Some(hooks)).await?;
    Some((h, auth, spy))
}

async fn announced(spy: &LogoutSpy) -> usize {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    spy.subjects.lock().map(|s| s.len()).unwrap_or(0)
}

#[tokio::test]
async fn a_failed_attempt_leaves_the_owner_for_the_access_lifetime() {
    let Some((h, auth)) = signed_in(None).await else { return };
    h.stores.fail_next_blacklist_writes(1);
    let attempt = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(attempt.is_err());
    let marker = h
        .stores
        .peek_logout_pending(SessionKind::Dashboard, &marker_hash(&auth));
    let owner = LogoutOwner {
        user_id: auth.user.id.clone(),
        tenant_id: Some(auth.user.tenant_id.clone()),
    };
    // The default access lifetime is fifteen minutes.
    assert_eq!(marker, Some((owner, 900)));
}

#[tokio::test]
async fn a_short_access_lifetime_still_keeps_the_marker_five_minutes() {
    let tune = |cfg: &mut crate::config::AuthConfig| {
        cfg.jwt.access_expires_in = std::time::Duration::from_secs(60);
    };
    let Some((h, auth)) = signed_in_with(None, tune).await else { return };
    h.stores.fail_next_blacklist_writes(1);
    let attempt = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(attempt.is_err());
    let marker = h
        .stores
        .peek_logout_pending(SessionKind::Dashboard, &marker_hash(&auth));
    assert_eq!(marker.map(|(_, ttl)| ttl), Some(300));
}

#[tokio::test]
async fn a_retry_that_fails_again_leaves_the_first_marker_as_it_was() {
    let Some((h, auth)) = signed_in(None).await else { return };
    let hash = marker_hash(&auth);
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    // Re-stamp the marker with a lifetime no attempt would write, to see whether it is rewritten.
    let owner = LogoutOwner {
        user_id: auth.user.id.clone(),
        tenant_id: Some("t1".to_owned()),
    };
    let store: &dyn crate::traits::SessionStore = h.stores.as_ref();
    assert!(
        store
            .put_logout_pending(SessionKind::Dashboard, &hash, &owner, 7)
            .await
            .is_ok()
    );
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    let marker = h.stores.peek_logout_pending(SessionKind::Dashboard, &hash);
    assert_eq!(marker.map(|(_, ttl)| ttl), Some(7));
}

#[tokio::test]
async fn a_completed_logout_with_a_live_session_clears_a_stale_marker_and_announces() {
    let Some((h, auth, spy)) = watched().await else { return };
    let hash = marker_hash(&auth);
    let owner = LogoutOwner {
        user_id: auth.user.id.clone(),
        tenant_id: None,
    };
    let store: &dyn crate::traits::SessionStore = h.stores.as_ref();
    assert!(
        store
            .put_logout_pending(SessionKind::Dashboard, &hash, &owner, 900)
            .await
            .is_ok()
    );
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(announced(&spy).await, 1);
    assert_eq!(
        h.stores.peek_logout_pending(SessionKind::Dashboard, &hash),
        None
    );
}

#[tokio::test]
async fn an_unreadable_marker_ends_the_retry_before_any_write() {
    let Some((h, auth, spy)) = watched().await else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    h.stores.fail_logout_pending_ops(0, 1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    // Nothing was written by that retry: the access token is still accepted.
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
    assert_eq!(announced(&spy).await, 1);
}

#[tokio::test]
async fn an_unclaimable_marker_fails_the_retry_and_announces_only_once_it_can() {
    let Some((h, auth, spy)) = watched().await else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    // The marker is read, then the claim on it fails.
    h.stores.fail_logout_pending_ops(1, 1);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert_eq!(announced(&spy).await, 0);
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(announced(&spy).await, 1);
}
