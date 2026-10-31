//! The logout hook names the user the session belonged to and stays silent for a session with no owner.

use super::*;
use std::sync::Arc;

/// A hook spy that records the subject of every `after_logout` notification.
#[derive(Default)]
struct LogoutSpy {
    subjects: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl crate::traits::AuthHooks for LogoutSpy {
    async fn after_logout(
        &self,
        user_id: &str,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        if let Ok(mut subjects) = self.subjects.lock() {
            subjects.push(user_id.to_owned());
        }
        Ok(())
    }
}

/// The `after_logout` hook names the user the session belonged to, and does not fire at
/// all for a logout that resolved to nobody: an empty subject handed to a deployment's
/// "signed out" mailer or session-teardown would target no account or the wrong one.
#[tokio::test]
async fn logout_notifies_the_hook_only_when_the_session_named_a_user() {
    let spy = Arc::new(LogoutSpy::default());
    let hooks: Arc<dyn crate::traits::AuthHooks> = spy.clone();
    let mut cfg = base_config();
    cfg.email_verification.required = false;
    let Some(h) = harness(cfg, Some(hooks)) else { return };
    let Some((id, auth)) = logged_in(&h, "hook@example.com", "pw").await else { return };

    // A refresh token that matches no session names nobody.
    assert!(h.engine.logout("", &"0".repeat(64)).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let seen = spy.subjects.lock().map(|s| s.clone()).unwrap_or_default();
    assert!(seen.is_empty(), "no owner, no notification: {seen:?}");

    // The live session names its owner.
    assert!(h.engine.logout("", &auth.refresh_token).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let seen = spy.subjects.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(seen, vec![id]);
}
