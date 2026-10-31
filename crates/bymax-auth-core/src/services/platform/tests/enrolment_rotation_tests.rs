//! Rotation of a platform session after the admin enrols a second factor with the role unchanged.

use super::*;

/// The `SUPPORT` admin the enrolment test signs in as; only `mfa_enabled` varies.
fn enrolling_admin(mfa: bool) -> AuthPlatformUser {
    AuthPlatformUser {
        id: "admin-enrolling".to_owned(),
        email: "enrolling@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password("pw"),
        role: "SUPPORT".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: mfa,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[tokio::test]
async fn enrolling_a_second_factor_alone_reaches_the_very_next_rotation() {
    // The role is untouched here, so the role half of the re-stamp condition is satisfied
    // and the MFA flag is the only thing standing between the stale `prt:` record and the
    // token. `a_demoted_admin_stops_carrying_the_old_role_on_the_very_next_rotation` changes
    // the role on every step, which lets a broken MFA comparison hide behind the role mismatch.
    let Some(h) = harness(platform_config()) else { return };
    h.admins.insert(enrolling_admin(false));
    let Some(svc) = h.engine.platform_auth() else { return };
    let signed_in = svc.login("enrolling@admin.io", "pw", "1.2.3.4", "a").await;
    let Ok(PlatformLoginResult::Success(auth)) = signed_in else { return };

    // Nothing changed: the rotated token still carries the account's role and no MFA.
    let unchanged = svc.refresh(&auth.refresh_token, "1.2.3.4", "a").await;
    assert!(unchanged.is_ok(), "rotation must succeed: {unchanged:?}");
    let Ok(unchanged) = unchanged else { return };
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&unchanged.access_token)
        .await;
    assert!(claims.is_ok(), "the token must verify: {claims:?}");
    let Ok(claims) = claims else { return };
    assert_eq!(claims.role, "SUPPORT");
    assert!(!claims.mfa_enabled);

    // The admin enrols: same role, new factor.
    h.admins.insert(enrolling_admin(true));
    let enrolled = svc.refresh(&unchanged.refresh_token, "1.2.3.4", "a").await;
    assert!(enrolled.is_ok(), "rotation must succeed: {enrolled:?}");
    let Ok(enrolled) = enrolled else { return };
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&enrolled.access_token)
        .await;
    assert!(claims.is_ok(), "the token must verify: {claims:?}");
    let Ok(claims) = claims else { return };
    assert_eq!(claims.role, "SUPPORT");
    assert!(claims.mfa_enabled, "the MFA flag never reached the token");
}
