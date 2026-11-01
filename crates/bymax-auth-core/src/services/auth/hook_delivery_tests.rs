//! The notification hooks run detached, and say who and which session they are about. A hook
//! that blocks until the test opens its gate must not hold the response that scheduled it: if
//! the engine still awaited it inline, the response would never come back. Drives the real engine
//! over the in-memory doubles.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, AuthResult, LoginResult, SafeAuthUser};
use tokio::sync::Semaphore;

use crate::services::auth::LoginInput;
use crate::services::auth::detached::settle_until;
use crate::services::auth::test_support::{Harness, SeedUser, base_config, ctx, harness};
use crate::traits::email::SessionInfo;
use crate::traits::{AuthHooks, HookContext, HookError, LoginFailure, SessionKind, SessionStore};

/// Notification hooks that wait on a gate before recording, and an `after_logout` that does not.
struct Gated {
    gate: Semaphore,
    events: Mutex<Vec<String>>,
    logout_tenants: Mutex<Vec<Option<String>>>,
}

impl Gated {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: Semaphore::new(0),
            events: Mutex::new(Vec::new()),
            logout_tenants: Mutex::new(Vec::new()),
        })
    }

    /// Let every blocked hook through.
    fn open(&self) {
        self.gate.add_permits(1000);
    }

    async fn record(&self, event: String) -> Result<(), HookError> {
        let _permit = self.gate.acquire().await;
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
        Ok(())
    }

    fn seen(&self, prefix: &str) -> Vec<String> {
        let events = self.events.lock().map(|e| e.clone()).unwrap_or_default();
        events
            .into_iter()
            .filter(|e| e.starts_with(prefix))
            .collect()
    }
}

#[async_trait]
impl AuthHooks for Gated {
    async fn on_login_failed(
        &self,
        failure: &LoginFailure<'_>,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record(format!("failed:{}", failure.reason)).await
    }
    async fn on_lockout(
        &self,
        email: &str,
        _tenant_id: &str,
        _retry_after_seconds: u64,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record(format!("lockout:{email}")).await
    }
    async fn on_new_session(
        &self,
        _user: &SafeAuthUser,
        session: &SessionInfo,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record(format!("new:{}", session.session_hash)).await
    }
    async fn on_session_evicted(
        &self,
        _user_id: &str,
        evicted_session_hash: &str,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record(format!("evicted:{evicted_session_hash}")).await
    }
    async fn on_refresh_token_reuse_detected(
        &self,
        user_id: &str,
        _family_id: &str,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.record(format!("reuse:{user_id}")).await
    }
    async fn after_logout(&self, _user_id: &str, ctx: &HookContext) -> Result<(), HookError> {
        if let Ok(mut tenants) = self.logout_tenants.lock() {
            tenants.push(ctx.tenant_id.clone());
        }
        Ok(())
    }
}

/// Await `future`, or give up after a few seconds: an engine that awaits a blocked hook inline
/// never answers, and a hang is a worse failure than a clear assertion.
async fn within<F: std::future::Future>(future: F) -> Option<F::Output> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .ok()
}

fn input(email: &str, password: &str) -> LoginInput {
    LoginInput {
        email: email.to_owned(),
        password: password.to_owned(),
        tenant_id: Some("t1".to_owned()),
    }
}

fn rig(sessions: bool) -> Option<(Harness, Arc<Gated>)> {
    let spy = Gated::new();
    let mut cfg = base_config();
    cfg.email_verification.required = false;
    cfg.sessions.enabled = sessions;
    cfg.sessions.default_max_sessions = 1;
    let hooks: Arc<dyn AuthHooks> = spy.clone();
    harness(cfg, Some(hooks)).map(|h| (h, spy))
}

/// Log the seeded user in, giving up if the engine does not answer.
async fn sign_in(h: &Harness, email: &str) -> Option<AuthResult> {
    match within(h.engine.login(input(email, "right"), &ctx())).await {
        Some(Ok(LoginResult::Success(auth))) => Some(*auth),
        _ => None,
    }
}

#[tokio::test]
async fn a_blocked_failure_hook_does_not_delay_the_refusal() {
    let Some((h, spy)) = rig(false) else { return };
    let _ = h.seed(SeedUser::active("a@example.com", "right")).await;
    let refused = within(h.engine.login(input("a@example.com", "wrong"), &ctx())).await;
    assert!(
        matches!(refused, Some(Err(AuthError::InvalidCredentials))),
        "{refused:?}"
    );

    spy.open();
    settle_until(|| !spy.seen("failed:").is_empty()).await;
    assert_eq!(
        spy.seen("failed:"),
        vec!["failed:invalid_credentials".to_owned()]
    );
}

#[tokio::test]
async fn a_blocked_lockout_hook_does_not_delay_the_attempt_that_locks() {
    let Some((h, spy)) = rig(false) else { return };
    let _ = h.seed(SeedUser::active("l@example.com", "right")).await;
    for _ in 0..5 {
        let refused = within(h.engine.login(input("l@example.com", "wrong"), &ctx())).await;
        assert!(
            refused.is_some(),
            "an attempt never returned while a hook was blocked"
        );
    }

    spy.open();
    settle_until(|| !spy.seen("lockout:").is_empty()).await;
    assert_eq!(
        spy.seen("lockout:"),
        vec!["lockout:l@example.com".to_owned()]
    );
}

#[tokio::test]
async fn blocked_session_hooks_do_not_delay_a_login_and_the_eviction_names_the_stored_hash() {
    let Some((h, spy)) = rig(true) else { return };
    let _ = h.seed(SeedUser::active("s@example.com", "right")).await;
    let Some(first) = sign_in(&h, "s@example.com").await else { return };
    // The cap is one, so this second login evicts the first session.
    assert!(
        sign_in(&h, "s@example.com").await.is_some(),
        "the second login never returned"
    );

    spy.open();
    settle_until(|| spy.seen("new:").len() >= 2 && !spy.seen("evicted:").is_empty()).await;
    let first_hash = RawRefreshToken::from_raw(first.refresh_token).redis_hash();
    assert_eq!(spy.seen("evicted:"), vec![format!("evicted:{first_hash}")]);
    assert_eq!(first_hash.len(), 64);
    assert!(spy.seen("new:").iter().all(|e| e.len() == "new:".len() + 8));
}

#[tokio::test]
async fn a_blocked_reuse_hook_does_not_delay_the_refusal() {
    let Some((h, spy)) = rig(false) else { return };
    let uid = h.seed(SeedUser::active("r@example.com", "right")).await;
    let Some(auth) = sign_in(&h, "r@example.com").await else { return };
    let rotated = h
        .engine
        .refresh(&auth.refresh_token, "1.2.3.4", "agent")
        .await;
    assert!(rotated.is_ok(), "the first rotation failed");
    // Close the grace window so replaying the old token is reuse, not a lost race.
    let old_hash = RawRefreshToken::from_raw(auth.refresh_token.clone()).redis_hash();
    assert!(
        h.stores
            .delete_grace_pointer(SessionKind::Dashboard, &old_hash)
            .await
            .is_ok()
    );

    let replay = within(h.engine.refresh(&auth.refresh_token, "1.2.3.4", "agent")).await;
    assert!(
        matches!(replay, Some(Err(AuthError::RefreshTokenInvalid))),
        "the replay was not refused in time"
    );

    spy.open();
    settle_until(|| !spy.seen("reuse:").is_empty()).await;
    assert_eq!(spy.seen("reuse:"), vec![format!("reuse:{uid}")]);
}

#[tokio::test]
async fn the_logout_hook_names_the_tenant_of_the_session_that_ended() {
    let Some((h, spy)) = rig(false) else { return };
    let _ = h.seed(SeedUser::active("o@example.com", "right")).await;
    let Some(auth) = sign_in(&h, "o@example.com").await else { return };
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );

    settle_until(|| {
        spy.logout_tenants
            .lock()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    })
    .await;
    let tenants = spy
        .logout_tenants
        .lock()
        .map(|t| t.clone())
        .unwrap_or_default();
    assert_eq!(tenants, vec![Some("t1".to_owned())]);
}
