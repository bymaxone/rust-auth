//! Ending the sessions the concurrent-session cap pushed out (service layer).

use super::SessionService;
use crate::traits::HookContext;
use bymax_auth_types::AuthError;

impl SessionService {
    /// End the oldest `over` of `candidates`, the account's other sessions oldest first. Ending
    /// one removes its whole sign-in, so once `over` of the candidates are gone no further live
    /// one is ended; a chosen session already gone with an earlier one's sign-in still fires the
    /// eviction hook. A victim that cannot be removed is not replaced.
    pub(super) async fn evict(
        &self,
        subject: &str,
        user_id: &str,
        candidates: &[String],
        over: usize,
        ctx: &HookContext,
    ) {
        let mut removed = Vec::new();
        for victim in candidates.iter().take(over) {
            if !removed.contains(victim) {
                let gone = candidates.iter().filter(|hash| removed.contains(hash));
                if gone.count() >= over {
                    continue;
                }
                self.evict_one(subject, victim, &mut removed).await;
            }
            self.fire_session_evicted(user_id, victim, ctx);
        }
    }

    /// End one victim, best-effort: the new session is already committed, so eviction never fails
    /// the operation that scheduled it. One a concurrent logout already removed counts as gone.
    async fn evict_one(&self, subject: &str, victim: &str, removed: &mut Vec<String>) {
        match self.end_session(subject, victim, removed).await {
            Ok(_) => {}
            Err(AuthError::SessionNotFound) => removed.push(victim.to_owned()),
            Err(error) => {
                // Swallowed, but visible: a store that keeps refusing the eviction is a cap that
                // is not being enforced, which reads as "no error" on every response.
                let cause = crate::services::failure_cause(&error);
                tracing::warn!(
                    event = "RUST_AUTH_SESSION_EVICTION_FAILED",
                    cause,
                    "sessions: eviction of an over-cap session failed"
                );
            }
        }
    }
}
