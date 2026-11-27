//! What a platform logout and a revoke-all remove, and which hook a platform logout notifies
//! (layer: core services, test support).

use super::*;

#[tokio::test]
async fn the_logout_spy_would_see_a_dashboard_logout() {
    // The "after_logout received nothing" assertion below is only evidence if the spy
    // records a dashboard logout when one happens. Calling it directly shows that it does.
    let spy = LogoutSpy::default();
    let ctx = identity_only_context("u1");
    assert!(spy.after_logout("u1", &ctx).await.is_ok());
    let seen = spy.dashboard.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(seen, vec!["u1".to_owned()]);
}

#[tokio::test]
async fn logout_notifies_after_platform_logout_and_not_the_dashboard_hook() {
    // The notification is fire-and-forget, so nothing in the logout's own result reflects
    // it — a hook that was never invoked looks exactly like one that was. A deployment
    // wires this to close down its own sessions, so silently dropping it is a real loss.
    // And it is a separate hook from the dashboard's `after_logout`, which a consumer wrote
    // for tenant users: handing it an administrator would change what it receives without
    // it having asked.
    let spy = Arc::new(LogoutSpy::default());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    let built = AuthEngine::builder()
        .config(platform_config())
        .environment(Environment::Test)
        .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
        .platform_user_repository(admins.clone())
        .redis_stores(stores)
        .hooks(hooks)
        .build();
    let Ok(engine) = built else { unreachable!() };
    let id = seed_admin(&admins, "hooked@admin.io", "pw");
    let Some(svc) = engine.platform_auth() else { unreachable!() };
    let logged = svc.login("hooked@admin.io", "pw", "1.2.3.4", "agent").await;
    let Ok(PlatformLoginResult::Success(auth)) = logged else { unreachable!() };
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    // Long enough for the detached task to have run.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let platform = spy.platform.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(
        platform,
        vec![(id, crate::traits::HookPlane::Platform, None)]
    );
    let dashboard = spy.dashboard.lock().map(|s| s.clone()).unwrap_or_default();
    assert!(dashboard.is_empty(), "after_logout received {dashboard:?}");
}

#[tokio::test]
async fn logout_works_without_a_live_access_token() {
    // The route used to require a live `PlatformUser`, so an operator who stepped away for
    // longer than the fifteen-minute access lifetime could not sign out at all — and the
    // refresh session of the highest-privilege identity in the system stayed live on a
    // console they believed they had left. The refresh token is what authorizes this; the
    // stored record names its owner.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "away@admin.io", "pw");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let logged = svc.login("away@admin.io", "pw", "1.2.3.4", "agent").await;
    let Ok(PlatformLoginResult::Success(auth)) = logged else { unreachable!() };

    // No access token at all — the shape a client sends once its bearer token has expired
    // and it has nothing live to present.
    let owner = svc.logout("", &auth.refresh_token).await;
    assert_eq!(owner.ok(), Some(id));

    // The session is gone: the refresh token no longer rotates.
    assert!(
        svc.refresh(&auth.refresh_token, "1.2.3.4", "agent")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn logout_blacklists_the_jti_and_revokes_the_session() {
    // After logout the platform access jti is blacklisted (verify rejects it) and the
    // refresh session is gone, so the refresh token no longer rotates.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _id = seed_admin(&h.admins, "out@admin.io", "pw");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let logged = svc.login("out@admin.io", "pw", "1.2.3.4", "agent").await;
    let Ok(PlatformLoginResult::Success(auth)) = logged else { unreachable!() };
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert!(matches!(
        h.engine
            .tokens()
            .verify_platform_access(&auth.access_token)
            .await,
        Err(AuthError::TokenRevoked)
    ));
    assert!(matches!(
        svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await,
        Err(AuthError::RefreshTokenInvalid)
    ));
    // Logout tolerates a non-shaped refresh token, a garbage access token, and an unknown
    // admin, still succeeding.
    assert!(svc.logout("not-a-jwt", "unknown-refresh").await.is_ok());
}

#[tokio::test]
async fn logout_cleans_the_grace_pointer_and_reuse_of_the_old_token_revokes_the_family() {
    // Login, then refresh (which plants a grace pointer for the OLD token). Logging out the
    // OLD token cleans BOTH its primary key (already consumed by the rotation) AND its grace
    // pointer, so a follow-up rotation of the old token can no longer recover through the
    // grace window. The consumed-family marker outlives the grace pointer, so that follow-up
    // is now caught as a REUSE of a consumed token — the signature of a stolen token — and
    // revokes the whole family, taking the live rotated token down with it.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _id = seed_admin(&h.admins, "grace@admin.io", "pw");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let logged = svc.login("grace@admin.io", "pw", "1.2.3.4", "agent").await;
    let Ok(PlatformLoginResult::Success(auth)) = logged else { unreachable!() };
    // Rotate: the old refresh token is consumed and a grace pointer is planted for it.
    let rotation = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
    let Ok(rotated) = rotation else { unreachable!() };
    // Logging out the OLD token cleans its grace pointer.
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    // Replaying the OLD token can no longer recover through the (now-cleaned) grace window; it
    // is rejected as a reuse of a consumed token, which revokes the family.
    assert!(matches!(
        svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await,
        Err(AuthError::RefreshTokenInvalid)
    ));
    // The reuse revoked the whole lineage, so even the freshly rotated (previously live)
    // token no longer rotates — a stolen token can never keep a parallel chain alive.
    assert!(matches!(
        svc.refresh(&rotated.refresh_token, "1.2.3.4", "agent")
            .await,
        Err(AuthError::RefreshTokenInvalid)
    ));
}

#[tokio::test]
async fn revoke_all_invalidates_every_platform_session() {
    // Two logins for the same admin, then revoke-all leaves neither refresh token usable.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "all@admin.io", "pw");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let first_login = svc.login("all@admin.io", "pw", "1.2.3.4", "agent").await;
    let Ok(PlatformLoginResult::Success(first)) = first_login else { unreachable!() };
    let second_login = svc.login("all@admin.io", "pw", "5.6.7.8", "agent").await;
    let Ok(PlatformLoginResult::Success(second)) = second_login else { unreachable!() };
    // Before the revoke, the first login's ACCESS token verifies.
    assert!(
        h.engine
            .tokens()
            .verify_platform_access(&first.access_token)
            .await
            .is_ok()
    );
    assert!(svc.revoke_all_platform_sessions(&id).await.is_ok());
    assert!(matches!(
        svc.refresh(&first.refresh_token, "1.2.3.4", "agent").await,
        Err(AuthError::RefreshTokenInvalid)
    ));
    assert!(matches!(
        svc.refresh(&second.refresh_token, "5.6.7.8", "agent").await,
        Err(AuthError::RefreshTokenInvalid)
    ));
    // The outstanding ACCESS tokens die with the refresh sessions: revoke-all bumps the
    // platform token epoch, and every token stamped below it stops verifying. Without
    // the bump, "log out everywhere" left every access token working to expiry.
    assert!(
        h.engine
            .tokens()
            .verify_platform_access(&first.access_token)
            .await
            .is_err()
    );
    assert!(
        h.engine
            .tokens()
            .verify_platform_access(&second.access_token)
            .await
            .is_err()
    );
}
