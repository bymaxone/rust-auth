//! What each MFA hook is reported with: the plane, and a credential-free user that is a platform
//! administrator (no tenant) on the platform plane. A completed challenge also stamps the
//! last-login time and fires `after_login` on both planes. Shares the fixtures of the main MFA
//! test module.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::{AuthPlatformUser, MfaContext, SafeAuthUser};
use time::OffsetDateTime;

use super::LoginResultMfa;
use super::tests::{
    Harness, PASSWORD, admin_password_hash, build_with, code, login_temp_token, register,
};
use crate::traits::{
    AuthHooks, HookContext, HookError, HookPlane, PlatformUserRepository, UserRepository,
};

/// One hook call: its name, the plane on its context, and the user it was handed.
type Call = (&'static str, HookPlane, SafeAuthUser);

/// Records every MFA and login hook the engine fires.
#[derive(Default)]
struct Spy {
    calls: Mutex<Vec<Call>>,
}

impl Spy {
    fn record(&self, name: &'static str, ctx: &HookContext, user: &SafeAuthUser) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((name, ctx.plane, user.clone()));
        }
    }

    /// Wait for every call to the detached hook `name`, as many as have landed after a pause.
    async fn calls_named(&self, name: &str) -> Vec<Call> {
        let _ = self.call(name).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.calls
            .lock()
            .map(|c| c.iter().filter(|c| c.0 == name).cloned().collect())
            .unwrap_or_default()
    }

    /// Wait for the detached hook `name` to land, then return its call.
    async fn call(&self, name: &str) -> Option<Call> {
        for _ in 0..100 {
            let found = self
                .calls
                .lock()
                .ok()
                .and_then(|calls| calls.iter().find(|c| c.0 == name).cloned());
            if found.is_some() {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }
}

#[async_trait]
impl AuthHooks for Spy {
    async fn after_login(&self, user: &SafeAuthUser, ctx: &HookContext) -> Result<(), HookError> {
        self.record("after_login", ctx, user);
        Ok(())
    }
    async fn after_mfa_enabled(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record("after_mfa_enabled", ctx, user);
        Ok(())
    }
    async fn after_mfa_disabled(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record("after_mfa_disabled", ctx, user);
        Ok(())
    }
    async fn after_mfa_recovery_codes_regenerated(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record("after_mfa_recovery_codes_regenerated", ctx, user);
        Ok(())
    }
}

/// A harness with a platform repository and a [`Spy`] wired as the engine's hooks.
fn rig() -> Option<(Harness, Arc<Spy>)> {
    let spy = Arc::new(Spy::default());
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    build_with(false, true, None, Some(hooks)).map(|h| (h, spy))
}

/// Seed the administrator `p1`.
pub(super) fn seed_admin(h: &Harness) {
    h.platform.insert(AuthPlatformUser {
        id: "p1".to_owned(),
        email: "admin@example.com".to_owned(),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
}

/// Enrol the seeded administrator in MFA and return the TOTP secret.
pub(super) async fn enrol_admin(h: &Harness) -> Option<String> {
    let mfa = h.engine.mfa()?;
    let setup = mfa
        .setup("p1", MfaContext::Platform, None, Some(PASSWORD))
        .await
        .ok()?;
    let enabled = mfa
        .verify_and_enable(
            "p1",
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await;
    assert!(enabled.is_ok(), "{enabled:?}");
    Some(setup.secret)
}

/// The call a platform administrator's hook received must say platform and carry no tenant.
fn assert_platform_admin(call: Option<Call>, name: &str) {
    assert!(call.is_some(), "{name} never fired for the administrator");
    let Some((_, plane, user)) = call else { return };
    assert_eq!(plane, HookPlane::Platform, "{name}");
    assert_eq!(user.id, "p1", "{name}");
    assert_eq!(user.tenant_id, "", "{name}: an administrator has no tenant");
    assert!(
        user.email_verified,
        "{name}: administrators owe no verification"
    );
}

#[tokio::test]
async fn enabling_mfa_on_a_platform_admin_fires_the_hook_on_the_platform_plane() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    assert!(enrol_admin(&h).await.is_some());
    assert_platform_admin(spy.call("after_mfa_enabled").await, "after_mfa_enabled");
}

#[tokio::test]
async fn regenerating_a_platform_admins_recovery_codes_fires_the_hook() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    let Some(secret) = enrol_admin(&h).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let done = mfa
        .regenerate_recovery_codes(
            "p1",
            &code(&secret, 30),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await;
    assert!(done.is_ok(), "{done:?}");
    let name = "after_mfa_recovery_codes_regenerated";
    assert_platform_admin(spy.call(name).await, name);
}

#[tokio::test]
async fn disabling_mfa_on_a_platform_admin_fires_the_hook() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    let Some(secret) = enrol_admin(&h).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let done = mfa
        .disable(
            "p1",
            &code(&secret, 60),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await;
    assert!(done.is_ok(), "{done:?}");
    assert_platform_admin(spy.call("after_mfa_disabled").await, "after_mfa_disabled");
}

#[tokio::test]
async fn a_dashboard_users_mfa_hook_still_says_dashboard_and_names_the_tenant() {
    let Some((h, spy)) = rig() else { return };
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let enabled = mfa
        .verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(enabled.is_ok(), "{enabled:?}");
    let call = spy.call("after_mfa_enabled").await;
    assert!(call.is_some(), "after_mfa_enabled never fired");
    let Some((_, plane, user)) = call else { return };
    assert_eq!(plane, HookPlane::Dashboard);
    assert_eq!((user.id, user.tenant_id), (uid, "t1".to_owned()));
}

#[tokio::test]
async fn a_platform_admin_who_clears_the_challenge_gets_a_last_login_and_the_login_hook() {
    let Some((h, spy)) = rig() else { return };
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
    let result = mfa
        .challenge(&temp, &code(&secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(result, Ok(LoginResultMfa::Platform(_))),
        "{result:?}"
    );
    assert_platform_admin(spy.call("after_login").await, "after_login");
    let stored = h.platform.find_by_id("p1").await;
    assert!(
        matches!(stored, Ok(Some(ref a)) if a.last_login_at.is_some()),
        "the last-login time never moved: {stored:?}"
    );
}

#[tokio::test]
async fn a_dashboard_user_who_clears_the_challenge_gets_a_last_login_and_the_login_hook() {
    let Some((h, spy)) = rig() else { return };
    let Some(uid) = register(&h.engine, "c@example.com").await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(setup) = mfa
        .setup(&uid, MfaContext::Dashboard, Some("t1"), Some(PASSWORD))
        .await
    else {
        return;
    };
    let enabled = mfa
        .verify_and_enable(
            &uid,
            &code(&setup.secret, 0),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(enabled.is_ok(), "{enabled:?}");
    let before = h.users.find_by_id(&uid, Some("t1")).await;
    assert!(
        matches!(before, Ok(Some(ref u)) if u.last_login_at.is_none()),
        "{before:?}"
    );

    let Some(temp) = login_temp_token(&h.engine, "c@example.com").await else { return };
    let result = mfa
        .challenge(&temp, &code(&setup.secret, 30), "1.2.3.4", "ua")
        .await;
    assert!(
        matches!(result, Ok(LoginResultMfa::Dashboard(_))),
        "{result:?}"
    );
    let call = spy.call("after_login").await;
    assert!(
        matches!(&call, Some((_, HookPlane::Dashboard, u)) if u.id == uid),
        "{call:?}"
    );
    assert!(
        last_login_moved(&h, &uid).await,
        "the last-login time never moved after the challenge"
    );
}

/// Whether the dashboard user's last-login time has been stamped, waiting for the detached write.
async fn last_login_moved(h: &Harness, uid: &str) -> bool {
    for _ in 0..100 {
        let now = h.users.find_by_id(uid, Some("t1")).await;
        if matches!(now, Ok(Some(ref u)) if u.last_login_at.is_some()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Enrol the dashboard user `uid` in MFA under tenant `t1` and return the TOTP secret.
pub(super) async fn enrol_user(h: &Harness, uid: &str) -> Option<String> {
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
    assert!(enabled.is_ok(), "{enabled:?}");
    Some(setup.secret)
}

/// The account a hook is handed describes the state the transition produced, not the record read
/// before it: `mfa_enabled` is `expected`, and the stored record is not what was mutated.
fn assert_reports_mfa(call: Option<Call>, name: &str, expected: bool) {
    assert!(call.is_some(), "{name} never fired");
    let Some((_, _, user)) = call else { return };
    assert_eq!(user.mfa_enabled, expected, "{name}: mfa_enabled");
}

#[tokio::test]
async fn after_mfa_enabled_reports_mfa_as_enabled_on_both_planes() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    assert!(enrol_admin(&h).await.is_some());
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    assert!(enrol_user(&h, &uid).await.is_some());
    let calls = spy.calls_named("after_mfa_enabled").await;
    assert_eq!(calls.len(), 2, "one enable hook per plane");
    for call in calls {
        assert_reports_mfa(Some(call), "after_mfa_enabled", true);
    }
}

#[tokio::test]
async fn after_mfa_disabled_reports_mfa_as_disabled_for_a_user_disable() {
    let Some((h, spy)) = rig() else { return };
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    let Some(secret) = enrol_user(&h, &uid).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let done = mfa
        .disable(
            &uid,
            &code(&secret, 60),
            "1.2.3.4",
            "ua",
            MfaContext::Dashboard,
            Some("t1"),
        )
        .await;
    assert!(done.is_ok(), "{done:?}");
    assert_reports_mfa(
        spy.call("after_mfa_disabled").await,
        "after_mfa_disabled",
        false,
    );
}

#[tokio::test]
async fn after_mfa_disabled_reports_mfa_as_disabled_for_a_platform_disable() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    let Some(secret) = enrol_admin(&h).await else { return };
    let Some(mfa) = h.engine.mfa() else { return };
    let done = mfa
        .disable(
            "p1",
            &code(&secret, 60),
            "1.2.3.4",
            "ua",
            MfaContext::Platform,
            None,
        )
        .await;
    assert!(done.is_ok(), "{done:?}");
    assert_reports_mfa(
        spy.call("after_mfa_disabled").await,
        "after_mfa_disabled",
        false,
    );
}

#[tokio::test]
async fn an_administrative_reset_reports_mfa_as_disabled_on_both_planes() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    assert!(enrol_admin(&h).await.is_some());
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    assert!(enrol_user(&h, &uid).await.is_some());
    let Some(mfa) = h.engine.mfa() else { return };
    assert!(
        mfa.reset_mfa("p1", MfaContext::Platform, None)
            .await
            .is_ok()
    );
    assert!(
        mfa.reset_mfa(&uid, MfaContext::Dashboard, Some("t1"))
            .await
            .is_ok()
    );
    let calls = spy.calls_named("after_mfa_disabled").await;
    assert_eq!(calls.len(), 2, "one disable hook per plane");
    for call in calls {
        assert_reports_mfa(Some(call), "after_mfa_disabled", false);
    }
}

#[tokio::test]
async fn the_mfa_hooks_change_only_the_flag_and_never_the_stored_record() {
    let Some((h, spy)) = rig() else { return };
    let Some(uid) = register(&h.engine, "d@example.com").await else { return };
    let before = h.users.find_by_id(&uid, Some("t1")).await.ok().flatten();
    assert!(enrol_user(&h, &uid).await.is_some());
    let Some((_, _, handed)) = spy.call("after_mfa_enabled").await else { return };
    let Some(before) = before else { return };
    let expected = SafeAuthUser {
        mfa_enabled: true,
        ..SafeAuthUser::from(before)
    };
    assert_eq!(
        handed, expected,
        "the hook payload is the account with only the flag moved"
    );
}

#[tokio::test]
async fn a_platform_admins_mfa_hook_payload_moves_only_the_flag_and_leaves_the_record() {
    let Some((h, spy)) = rig() else { return };
    seed_admin(&h);
    assert!(enrol_admin(&h).await.is_some());
    let Some((_, _, handed)) = spy.call("after_mfa_enabled").await else { return };
    assert!(
        handed.mfa_enabled,
        "the hook reports the enrolment it follows"
    );
    assert_eq!(
        (handed.tenant_id.as_str(), handed.email_verified),
        ("", true)
    );
    let stored = h.platform.find_by_id("p1").await.ok().flatten();
    assert!(
        stored.is_some_and(|a| a.mfa_enabled && a.mfa_secret.is_some()),
        "the stored record keeps its own state and its secret"
    );
}
