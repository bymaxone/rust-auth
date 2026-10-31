//! Recovery-code redemption against the stored set: spending one code removes exactly that code
//! from the dashboard or platform record and leaves the rest redeemable. Shares the fixtures of
//! the main MFA test module.

use bymax_auth_types::{AuthPlatformUser, MfaContext};
use time::OffsetDateTime;

use super::LoginResultMfa;
use super::tests::{
    Harness, PASSWORD, admin_password_hash, build, code, login_temp_token, register,
};
use crate::traits::{PlatformUserRepository, UserRepository};

/// The recovery codes stored for a dashboard user, or an empty set when unreadable.
async fn stored_dashboard_codes(h: &Harness, uid: &str) -> Vec<String> {
    match h.users.find_by_id(uid, None).await {
        Ok(Some(u)) => u.mfa_recovery_codes.unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Enrol a dashboard user in MFA and return two distinct recovery codes from the issued set.
async fn enrol_dashboard(h: &Harness, uid: &str) -> Option<(String, String)> {
    let mfa = h.engine.mfa()?;
    let setup = mfa
        .setup(uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
        .ok()?;
    let enabled = mfa
        .verify_and_enable(
            uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(enabled.is_ok(), "enrolment should succeed: {enabled:?}");
    Some((
        setup.recovery_codes.first().cloned()?,
        setup.recovery_codes.get(1).cloned()?,
    ))
}

/// Spending one recovery code removes exactly that code from the stored set and leaves the
/// others redeemable. A splice that removed a different entry, or none, would either lock the
/// owner out of a code they still hold or leave the spent one on the record.
#[tokio::test]
async fn spending_a_dashboard_recovery_code_removes_only_that_code() {
    let Some(h) = build(true, false) else { return };
    let Some(uid) = register(&h.engine, "spend@example.com").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else {
        return;
    };
    let Some((kept, spent)) = enrol_dashboard(&h, &uid).await else {
        return;
    };
    let before = stored_dashboard_codes(&h, &uid).await;
    assert!(before.len() > 2, "the fixture needs a set to splice from");

    let Some(temp) = login_temp_token(&h.engine, "spend@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, &spent, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    let mut expected = before.clone();
    expected.remove(1);
    assert_eq!(
        stored_dashboard_codes(&h, &uid).await,
        expected,
        "only the spent code leaves the set"
    );

    // The untouched code still redeems.
    let Some(temp2) = login_temp_token(&h.engine, "spend@example.com").await else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp2, &kept, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
}

/// The recovery codes stored for a platform admin, or an empty set when unreadable.
#[cfg(feature = "platform")]
async fn stored_platform_codes(h: &Harness, id: &str) -> Vec<String> {
    match h.platform.find_by_id(id).await {
        Ok(Some(a)) => a.mfa_recovery_codes.unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Seed a platform admin, enrol it in MFA and return two distinct recovery codes from the set.
#[cfg(feature = "platform")]
async fn enrol_platform(h: &Harness) -> Option<(String, String)> {
    h.platform.insert(AuthPlatformUser {
        id: "p-spend".to_owned(),
        email: "spend@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
        role: "SUPER".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    let mfa = h.engine.mfa()?;
    let setup = mfa
        .setup("p-spend", MfaContext::Platform, None, Some(PASSWORD))
        .await
        .ok()?;
    let enabled = mfa
        .verify_and_enable(
            "p-spend",
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await;
    assert!(enabled.is_ok(), "enrolment should succeed: {enabled:?}");
    Some((
        setup.recovery_codes.first().cloned()?,
        setup.recovery_codes.get(1).cloned()?,
    ))
}

/// The platform plane's splice has the same contract: the spent code is persisted out of the
/// admin record, and only that one.
#[cfg(feature = "platform")]
#[tokio::test]
async fn spending_a_platform_recovery_code_removes_only_that_code() {
    let Some(h) = build(false, true) else { return };
    let Some(mfa) = h.engine.mfa() else {
        return;
    };
    let Some((kept, spent)) = enrol_platform(&h).await else {
        return;
    };
    let before = stored_platform_codes(&h, "p-spend").await;
    assert!(before.len() > 2, "the fixture needs a set to splice from");

    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-spend", MfaContext::Platform, None)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp, &spent, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
    let mut expected = before.clone();
    expected.remove(1);
    assert_eq!(
        stored_platform_codes(&h, "p-spend").await,
        expected,
        "only the spent code leaves the set"
    );

    let Ok(temp2) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-spend", MfaContext::Platform, None)
        .await
    else {
        return;
    };
    assert!(matches!(
        mfa.challenge(&temp2, &kept, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
}
