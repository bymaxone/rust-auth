//! A temp token belongs to the plane that issued it: the platform challenge refuses a dashboard
//! token before anything is consumed, and the plane-agnostic challenge serves either. The adapter
//! tests drive the same behaviour through the routes; these hold it at the service so a change to
//! the check is caught without the HTTP layer.

use bymax_auth_types::{AuthError, MfaContext};

use super::LoginResultMfa;
use super::hook_tests::{enrol_admin, enrol_user, seed_admin};
use super::tests::{Harness, build, code, login_temp_token, register};
use crate::traits::{PlatformUserRepository, UserRepository};

/// A harness with a platform repository wired, so both planes can be challenged.
fn rig() -> Option<Harness> {
    build(false, true)
}

#[tokio::test]
async fn the_platform_challenge_refuses_a_dashboard_token_and_spends_nothing() {
    let Some(h) = rig() else { return };
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    let Some(secret) = enrol_user(&h, &uid).await else { return };
    let Some(temp) = login_temp_token(&h.engine, "d@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let before = h
        .users
        .find_by_id(&uid, Some("t1"))
        .await
        .ok()
        .flatten()
        .map(|u| u.last_login_at);

    let refused = mfa
        .challenge_platform_only(&temp, &code(&secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(refused, Err(AuthError::PlatformAuthRequired)),
        "{refused:?}"
    );

    // Nothing was spent: the login time did not move, and the same token with the same code still
    // clears the challenge on the plane it belongs to (a spent code would be refused as a replay).
    let after = h
        .users
        .find_by_id(&uid, Some("t1"))
        .await
        .ok()
        .flatten()
        .map(|u| u.last_login_at);
    assert_eq!(after, before, "a refused call stamped a login");
    let redeemed = mfa
        .challenge(&temp, &code(&secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(redeemed, Ok(LoginResultMfa::Dashboard(_))),
        "{redeemed:?}"
    );
}

#[tokio::test]
async fn the_platform_challenge_serves_a_platform_token() {
    let Some(h) = rig() else { return };
    seed_admin(&h);
    let Some(secret) = enrol_admin(&h).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p1", MfaContext::Platform, None)
        .await
    else {
        return;
    };

    let served = mfa
        .challenge_platform_only(&temp, &code(&secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(served, Ok(LoginResultMfa::Platform(_))),
        "{served:?}"
    );
    // The last-login stamp is written by a detached task, so wait for it.
    let mut stamped = false;
    for _ in 0..100 {
        let stored = h.platform.find_by_id("p1").await;
        stamped = matches!(stored, Ok(Some(ref admin)) if admin.last_login_at.is_some());
        if stamped {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(stamped, "the platform login never completed");
}

#[tokio::test]
async fn the_plane_agnostic_challenge_serves_a_platform_token() {
    let Some(h) = rig() else { return };
    seed_admin(&h);
    let Some(secret) = enrol_admin(&h).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p1", MfaContext::Platform, None)
        .await
    else {
        return;
    };

    let served = mfa
        .challenge(&temp, &code(&secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(served, Ok(LoginResultMfa::Platform(_))),
        "{served:?}"
    );
}
