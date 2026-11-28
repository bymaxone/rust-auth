//! Regression tests for the `sid` claim across a refresh rotation (dashboard and platform
//! planes): the access token of a login, of its rotation and of a grace-window recovery all
//! name the same session, and a rotated record with no well-formed family id names none.
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

/// Seed a session whose record carries `family_id`, rotate it, and return the `sid` of the new
/// access token, or `None` when any of those steps failed.
async fn rotated_sid_of(family_id: &str) -> Option<Option<String>> {
    let store = Arc::new(InMemoryStores::new());
    let svc = service(store.clone());
    let record = SessionRecord {
        user_id: user().id,
        tenant_id: Some(user().tenant_id),
        role: user().role,
        device: "Chrome".to_owned(),
        ip: "203.0.113.4".to_owned(),
        created_at: now_offset(),
        mfa_enabled: false,
        mfa_verified: false,
        family_id: family_id.to_owned(),
        family_created_at: Some(now_offset()),
    };
    let old = RawRefreshToken::generate();
    store
        .create_session(
            SessionKind::Dashboard,
            &dashboard_subject(),
            &old.redis_hash(),
            &record,
            3600,
        )
        .await
        .ok()?;
    let rotated = rotated_for(&svc, old.expose_secret()).await?;
    Some(svc.verify_access(&rotated.access_token).await.ok()?.sid)
}

#[tokio::test]
async fn a_rotated_record_without_a_well_formed_family_id_names_no_session() {
    for family_id in ["", "fam-1", "00000000-0000-4000-8000-00000000000A"] {
        let sid = rotated_sid_of(family_id).await;
        assert!(matches!(sid, Some(None)), "{family_id:?} gave {sid:?}");
    }
}
