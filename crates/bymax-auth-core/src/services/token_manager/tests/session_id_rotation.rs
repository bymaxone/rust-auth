//! Regression tests for the `sid` claim across a refresh rotation (dashboard and platform
//! planes): the access token of a login, of its rotation and of a grace-window recovery all
//! name the same session.
//!
//! Layer: unit tests of `TokenManagerService`, sharing the fixtures of the parent test module.

use super::*;

/// The `sid` of a dashboard login, of its rotation and of a grace-window replay of the first
/// refresh token, or `None` when any of those steps failed.
async fn dashboard_sids(svc: &TokenManagerService) -> Option<[Option<String>; 3]> {
    let issued = issued_for(svc).await?;
    let rotated = rotated_for(svc, &issued.refresh_token).await?;
    let recovered = rotated_for(svc, &issued.refresh_token).await?;
    let login = svc.verify_access(&issued.access_token).await.ok()?.sid;
    let next = svc.verify_access(&rotated.access_token).await.ok()?.sid;
    let grace = svc.verify_access(&recovered.access_token).await.ok()?.sid;
    Some([login, next, grace])
}

/// The platform twin of [`dashboard_sids`].
#[cfg(feature = "platform")]
async fn platform_sids(svc: &TokenManagerService) -> Option<[Option<String>; 3]> {
    let issued = platform_issued_for(svc).await?;
    let rotated = platform_rotated_for(svc, &issued.refresh_token).await?;
    let recovered = platform_rotated_for(svc, &issued.refresh_token).await?;
    let verify = |token: String| async move { svc.verify_platform_access(&token).await.ok() };
    let login = verify(issued.access_token).await?.sid;
    let next = verify(rotated.access_token).await?.sid;
    let grace = verify(recovered.access_token).await?.sid;
    Some([login, next, grace])
}

#[tokio::test]
async fn rotation_and_grace_recovery_keep_the_session_id_of_the_login() {
    let svc = service(Arc::new(InMemoryStores::new()));
    let sids = dashboard_sids(&svc).await;
    assert!(
        matches!(&sids, Some([Some(login), Some(next), Some(grace)])
            if login == next && login == grace),
        "{sids:?}"
    );
}

#[cfg(feature = "platform")]
#[tokio::test]
async fn platform_rotation_and_grace_recovery_keep_the_session_id_of_the_login() {
    let svc = service(Arc::new(InMemoryStores::new()));
    let sids = platform_sids(&svc).await;
    assert!(
        matches!(&sids, Some([Some(login), Some(next), Some(grace)])
            if login == next && login == grace),
        "{sids:?}"
    );
}
