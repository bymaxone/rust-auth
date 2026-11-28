//! Ending the sessions the concurrent-session cap pushed out (service layer).

use super::SessionService;
use crate::traits::{HookContext, SessionKind};
use bymax_auth_types::AuthError;

impl SessionService {
    /// End the oldest `over` of `candidates`, the account's other sessions oldest first. Ending
    /// one removes its whole sign-in, so after the first removal the index is read again before
    /// each further live victim, which is ended only if that read shows more than `cap`; a chosen
    /// session already gone with an earlier one's sign-in still fires the eviction hook. A victim
    /// that cannot be removed is not replaced.
    pub(super) async fn evict(
        &self,
        subject: &str,
        user_id: &str,
        candidates: &[String],
        over: usize,
        cap: usize,
        ctx: &HookContext,
    ) {
        let mut removed = Vec::new();
        for victim in candidates.iter().take(over) {
            if !removed.contains(victim) {
                if !removed.is_empty() && !self.still_over(subject, cap, &removed).await {
                    continue;
                }
                self.evict_one(subject, victim, &mut removed).await;
            }
            self.fire_session_evicted(user_id, victim, ctx);
        }
    }

    /// Whether the live index still lists more than `cap` sessions besides those in `removed`,
    /// which a refused index write may have left listed. An index that cannot be read answers no:
    /// no live session is ended without a successful read.
    async fn still_over(&self, subject: &str, cap: usize, removed: &[String]) -> bool {
        match self
            .store
            .list_session_entries(SessionKind::Dashboard, subject)
            .await
        {
            Ok(entries) => {
                let left = entries
                    .iter()
                    .filter(|entry| !removed.contains(&entry.session_hash));
                left.count() > cap
            }
            Err(error) => {
                let cause = crate::services::failure_cause(&error);
                tracing::warn!(
                    event = "RUST_AUTH_SESSION_CAP_NOT_ENFORCED",
                    cause,
                    "sessions: the session cap was not enforced"
                );
                false
            }
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
