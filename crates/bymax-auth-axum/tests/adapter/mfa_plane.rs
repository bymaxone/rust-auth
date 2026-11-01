//! An MFA temp token belongs to the plane that issued it. Presenting it at the other plane's
//! challenge route is refused before the challenge runs, so it neither creates a session nor
//! spends the token; the dashboard route serves a platform token with the platform session.
//! Shares the fixtures of the parent test file.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_core::traits::{AuthHooks, HookContext, HookError, SessionInfo, UserRepository};
use bymax_auth_types::SafeAuthUser;

use super::*;

/// A dashboard account with MFA enrolled, and its TOTP secret.
async fn enrolled_user(h: &common::Harness, app: &axum::Router, email: &str) -> (String, String) {
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": email, "password": "glidingwalnut42", "name": "Mfa", "tenantId": TENANT
        }))
        .send(app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, common::now_unix()) }))
        .send(app)
        .await;
    let user_id = h
        .users
        .find_by_email(email, TENANT)
        .await
        .ok()
        .flatten()
        .map(|user| user.id)
        .unwrap_or_default();
    (user_id, secret)
}

/// The temp token a dashboard login hands an MFA-enabled account.
async fn dashboard_temp_token(app: &axum::Router, email: &str) -> String {
    let login = login(app, email, "glidingwalnut42").await;
    login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

/// A platform admin with MFA enrolled, its TOTP secret, and a fresh platform temp token.
async fn enrolled_admin(h: &common::Harness, app: &axum::Router, email: &str) -> (String, String) {
    seed_admin(h, email, "SUPER_ADMIN").await;
    let access = platform_access(&platform_login(app, email).await);
    let setup = Req::post("/auth/platform/mfa/setup")
        .bearer(&access)
        .json(serde_json::json!({ "password": "adminpass123" }))
        .send(app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/platform/mfa/verify-enable")
        .bearer(&access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, common::now_unix()) }))
        .send(app)
        .await;
    let relogin = platform_login(app, email).await;
    let temp = relogin.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    (secret, temp)
}

/// Records the login hooks the engine fires, so a test can say that a refused call fired none.
#[derive(Default)]
struct LoginHooks {
    fired: Mutex<Vec<&'static str>>,
}

impl LoginHooks {
    /// How many login hooks have landed once the detached ones have had time to run.
    async fn settled_count(&self) -> usize {
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.fired.lock().map(|fired| fired.len()).unwrap_or(0)
    }
}

#[async_trait]
impl AuthHooks for LoginHooks {
    async fn after_login(&self, _: &SafeAuthUser, _: &HookContext) -> Result<(), HookError> {
        if let Ok(mut fired) = self.fired.lock() {
            fired.push("after_login");
        }
        Ok(())
    }
    async fn on_new_session(
        &self,
        _: &SafeAuthUser,
        _: &SessionInfo,
        _: &HookContext,
    ) -> Result<(), HookError> {
        if let Ok(mut fired) = self.fired.lock() {
            fired.push("on_new_session");
        }
        Ok(())
    }
}

fn both_planes(hooks: &Arc<LoginHooks>) -> EngineSpec {
    let recorder: Arc<dyn AuthHooks> = hooks.clone();
    EngineSpec {
        platform: true,
        mfa: true,
        sessions: true,
        hooks: Some(recorder),
        ..EngineSpec::default()
    }
}

/// What a challenge attempt can spend for one account: its sessions, its last-login time and the
/// login hooks fired so far.
#[derive(Debug, PartialEq, Eq)]
struct Spent {
    sessions: Option<usize>,
    last_login: Option<Option<time::OffsetDateTime>>,
    hooks: usize,
}

async fn spent(h: &common::Harness, hooks: &LoginHooks, user_id: &str) -> Spent {
    Spent {
        sessions: h
            .engine
            .list_user_sessions(TENANT, user_id, None)
            .await
            .map(|found| found.len())
            .ok(),
        last_login: h
            .users
            .find_by_id(user_id, Some(TENANT))
            .await
            .ok()
            .flatten()
            .map(|user| user.last_login_at),
        hooks: hooks.settled_count().await,
    }
}

#[tokio::test]
async fn a_dashboard_temp_token_at_the_platform_route_is_refused_with_nothing_spent() {
    let hooks = Arc::new(LoginHooks::default());
    let Some(h) = build(both_planes(&hooks)) else { return };
    let app = router(&h);
    let (user_id, secret) = enrolled_user(&h, &app, "plane-d@e.com").await;
    let temp = dashboard_temp_token(&app, "plane-d@e.com").await;
    assert!(
        !temp.is_empty(),
        "an MFA-enabled login hands out a temp token"
    );
    let base = common::now_unix();
    let before = spent(&h, &hooks, &user_id).await;

    let refused = Req::post("/auth/platform/mfa/challenge")
        .json(serde_json::json!({
            "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 30)
        }))
        .send(&app)
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused.json()["error"]["code"],
        "auth.platform_auth_required"
    );

    // The refusal came before the challenge ran, so nothing was spent: no session was created,
    // the last-login time did not move and no login hook fired...
    let after = spent(&h, &hooks, &user_id).await;
    assert_eq!(before.sessions, Some(0));
    assert_eq!(after, before, "a refused call spent something");
    // ...and the token was not spent, so its own route still redeems it.
    let redeemed = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({
            "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 60)
        }))
        .send(&app)
        .await;
    assert_eq!(redeemed.status, StatusCode::OK);
}

#[tokio::test]
async fn a_platform_temp_token_at_the_dashboard_route_returns_the_platform_session() {
    let hooks = Arc::new(LoginHooks::default());
    let Some(h) = build(both_planes(&hooks)) else { return };
    let app = router(&h);
    let (secret, temp) = enrolled_admin(&h, &app, "plane-p@e.com").await;
    let base = common::now_unix();

    let served = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({
            "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 30)
        }))
        .send(&app)
        .await;
    assert_eq!(served.status, StatusCode::OK);
    // The platform body, never cookies: a platform session is not a browser session.
    assert_eq!(served.json()["admin"]["email"], "plane-p@e.com");
    assert!(served.json()["accessToken"].is_string());
    assert!(served.json()["refreshToken"].is_string());
    assert!(served.set_cookies.is_empty());
    // It is one login, completed once, and the token is spent by it.
    let again = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({
            "mfaTempToken": temp, "code": common::totp_at_abs(&secret, base + 60)
        }))
        .send(&app)
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}
