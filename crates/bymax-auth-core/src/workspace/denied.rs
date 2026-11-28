//! The report of a refused workspace access to the host, bounded per account (layer: domain).
//!
//! `workspaceRealtime.rules.accessDeniedEvents` in the shared wire contract pins the event, its
//! counters and the order they are touched in. The report runs detached from the decision: it
//! never changes or delays the answer, and a counter store that fails emits nothing.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bymax_auth_types::{AuthError, MfaContext};
use time::OffsetDateTime;

use crate::config::AccessDeniedEventsConfig;
use crate::engine::AuthEngine;
use crate::services::auth::spawn_guarded;
use crate::services::user_subject_hash;
use crate::services::workspace::WorkspaceRuntime;
use crate::traits::{AuthHooks, HookContext, HookPlane, MembershipCacheStore};
use crate::workspace::access::WorkspaceRefusal;
use crate::workspace::audit::{AccessSurface, AuditKind, WorkspaceAuditEvent, iso_instant};
use crate::workspace::domain::MembershipRef;

/// How long the count of unreported refusals lasts: longer than the longest window.
pub(crate) const SUPPRESSED_COUNT_TTL_SECONDS: u64 = 86_400;

/// When the process last said that the counter store was unavailable.
static LAST_WARNING: Mutex<Option<Instant>> = Mutex::new(None);

/// Whether a warning is due at `now`, and if so records it: one per `window`.
pub(crate) fn warning_due(last: &Mutex<Option<Instant>>, now: Instant, window: Duration) -> bool {
    let mut last = last.lock().unwrap_or_else(PoisonError::into_inner);
    let due = last.is_none_or(|then| now.saturating_duration_since(then) >= window);
    if due {
        *last = Some(now);
    }
    due
}

/// Counts one refusal. `Some` when it is to be reported, with the refusals left unreported since
/// the last report; `None` when the window is spent.
async fn admit(
    store: &dyn MembershipCacheStore,
    digest: &str,
    limits: AccessDeniedEventsConfig,
) -> Result<Option<u64>, AuthError> {
    let window = u64::from(limits.window_seconds);
    if store.count_denial(digest, window).await? > u64::from(limits.max) {
        store
            .count_suppressed(digest, SUPPRESSED_COUNT_TTL_SECONDS)
            .await?;
        return Ok(None);
    }
    let held = store.take_suppressed(digest).await?;
    Ok(Some(held.map_or(0, |count| suppressed_from(&count))))
}

/// The stored count of unreported refusals; a value that is not an integer reads as 0.
pub(crate) fn suppressed_from(stored: &str) -> u64 {
    stored.parse().unwrap_or_else(|_| {
        tracing::warn!(
            event = "RUST_AUTH_ACCESS_DENIED_COUNT_INVALID",
            "the suppressed count of access.denied was not an integer; reported as 0"
        );
        0
    })
}

/// One refusal on its way to the host.
struct Report {
    store: Arc<dyn MembershipCacheStore>,
    hooks: Arc<dyn AuthHooks>,
    limits: AccessDeniedEventsConfig,
    digest: String,
    tenant_id: String,
    workspace_id: String,
    user_id: String,
    surface: AccessSurface,
    refusal: WorkspaceRefusal,
}

impl Report {
    /// Counts the refusal and hands the host the event the budget allows.
    async fn send(self) -> Result<(), &'static str> {
        let suppressed_count = match admit(self.store.as_ref(), &self.digest, self.limits).await {
            Ok(Some(count)) => count,
            Ok(None) => return Ok(()),
            Err(error) => {
                self.warn_unavailable(&error);
                return Ok(());
            }
        };
        let mut ctx = HookContext::detached(HookPlane::Dashboard, &self.user_id, "", "");
        ctx.tenant_id = Some(self.tenant_id.clone());
        let event = self.event(suppressed_count);
        // The hook's own error is dropped: its text is the host's and can quote an address.
        let delivered = self.hooks.on_workspace_event(&event, &ctx).await;
        delivered.map_err(|_| "the workspace-event hook failed for access.denied")
    }

    /// Says once per window that nothing is being emitted.
    fn warn_unavailable(&self, error: &AuthError) {
        let window = Duration::from_secs(u64::from(self.limits.window_seconds));
        if warning_due(&LAST_WARNING, Instant::now(), window) {
            let cause = crate::services::failure_cause(error);
            tracing::warn!(
                event = "RUST_AUTH_ACCESS_DENIED_UNAVAILABLE",
                cause,
                "access.denied events are not being emitted: the counter store is unavailable. \
                 The access decision is unaffected."
            );
        }
    }

    /// The event as the host receives it.
    fn event(&self, suppressed_count: u64) -> WorkspaceAuditEvent {
        WorkspaceAuditEvent {
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            actor_user_id: Some(self.user_id.clone()),
            at: iso_instant(OffsetDateTime::now_utc()),
            kind: AuditKind::AccessDenied {
                user_id: self.user_id.clone(),
                surface: self.surface,
                code: self.refusal.code,
                reason: self.refusal.reason,
                suppressed_count,
            },
        }
    }
}

impl AuthEngine {
    /// Reports that the access decision refused `member`, a dashboard account, detached and
    /// within the account's budget.
    pub(crate) fn report_access_denied(
        &self,
        runtime: &WorkspaceRuntime,
        member: MembershipRef<'_>,
        surface: AccessSurface,
        refusal: WorkspaceRefusal,
    ) {
        let digest = user_subject_hash(
            &runtime.identifier_key,
            MfaContext::Dashboard,
            Some(member.tenant_id),
            member.user_id,
        );
        let report = Report {
            store: runtime.cache_store.clone(),
            hooks: self.hooks().clone(),
            limits: runtime.resolved.access_denied_events,
            digest,
            tenant_id: member.tenant_id.to_owned(),
            workspace_id: member.workspace_id.to_owned(),
            user_id: member.user_id.to_owned(),
            surface,
            refusal,
        };
        spawn_guarded(report.send());
    }
}
