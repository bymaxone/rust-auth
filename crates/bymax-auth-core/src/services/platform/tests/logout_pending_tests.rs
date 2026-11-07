//! A platform logout that fails a revocation write leaves the owner marker its retry reads, and
//! the retry that completes the logout announces it once. The platform plane keeps no tenant, so
//! the marker names the admin alone.

use super::*;
use crate::traits::LogoutOwner;

fn marker_hash(auth: &bymax_auth_types::PlatformAuthResult) -> String {
    bymax_auth_jwt::RawRefreshToken::from_raw(auth.refresh_token.clone()).redis_hash()
}

/// A harness whose hooks report to `spy`, with an admin signed in.
async fn watched() -> Option<(
    PlatformHarness,
    bymax_auth_types::PlatformAuthResult,
    Arc<LogoutSpy>,
)> {
    let spy = Arc::new(LogoutSpy::default());
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    let h = harness_with_hooks(platform_config(), Some(hooks))?;
    let id = seed_admin(&h.admins, "pending@admin.io", "pw");
    drop(id);
    let svc = h.engine.platform_auth()?;
    let Ok(PlatformLoginResult::Success(auth)) = svc
        .login("pending@admin.io", "pw", "1.2.3.4", "agent")
        .await
    else {
        return None;
    };
    Some((h, *auth, spy))
}

async fn announced(spy: &LogoutSpy) -> usize {
    tokio::time::sleep(Duration::from_millis(300)).await;
    spy.platform.lock().map(|seen| seen.len()).unwrap_or(0)
}

#[tokio::test]
async fn a_failed_attempt_leaves_the_admin_with_no_tenant_for_the_access_lifetime() {
    let Some((h, auth, _spy)) = watched().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    let marker = h
        .stores
        .peek_logout_pending(SessionKind::Platform, &marker_hash(&auth));
    let owner = LogoutOwner {
        user_id: auth.admin.id.clone(),
        tenant_id: None,
    };
    assert_eq!(marker, Some((owner, 900)));
}

#[tokio::test]
async fn the_retry_that_completes_a_failed_logout_announces_it_once() {
    let Some((h, auth, spy)) = watched().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert_eq!(announced(&spy).await, 0);
    let retried = svc.logout(&auth.access_token, &auth.refresh_token).await;
    assert_eq!(retried.ok(), Some(auth.admin.id.clone()));
    assert_eq!(announced(&spy).await, 1);
    // Another logout of the same token finds nothing to claim and announces nothing more.
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(announced(&spy).await, 1);
    assert_eq!(
        h.stores
            .peek_logout_pending(SessionKind::Platform, &marker_hash(&auth)),
        None
    );
}

#[tokio::test]
async fn an_unclaimable_marker_fails_the_platform_retry_and_announces_nothing_yet() {
    let Some((h, auth, spy)) = watched().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    h.stores.fail_logout_pending_ops(1, 1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert_eq!(announced(&spy).await, 0);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(announced(&spy).await, 1);
}

#[tokio::test]
async fn an_unreadable_marker_ends_the_platform_retry_before_any_write() {
    let Some((h, auth, _spy)) = watched().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };
    h.stores.fail_next_blacklist_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    h.stores.fail_logout_pending_ops(0, 1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert!(
        h.engine
            .tokens()
            .verify_platform_access(&auth.access_token)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_stale_marker_that_survives_a_completed_platform_logout_is_announced_by_the_retry_alone()
{
    let Some((h, auth, spy)) = watched().await else { return };
    let Some(svc) = h.engine.platform_auth() else { return };
    h.stores.fail_next_cleanup_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    // The failed delete left the session live and a marker beside it; this attempt deletes the
    // session, and removing the marker then fails.
    h.stores.fail_logout_pending_ops(0, 1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert_eq!(announced(&spy).await, 0);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(announced(&spy).await, 1);
}
