//! The access decision for one request guarded by a service API key, with its audit event.
//!
//! A transport adapter reads the configured header, names the route it is guarding and the
//! scopes that route declares, and gets back either the principal or the error to answer with.
//! Keeping the decision here means every adapter gives the same answers in the same order:
//! route configuration first (before any credential work), then the key, then its scopes, then
//! the audit.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use bymax_auth_types::AuthError;

use super::{ApiKeyRejection, ApiKeyRuntime, ApiKeyVerdict};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::normalize::log_safe;
use crate::services::auth::{DETACHED_TASK_TIMEOUT, spawn_guarded};
use crate::traits::{
    ApiKey, ApiKeyAccessEvent, ApiKeyDenyReason, ApiKeyOutcome, ApiKeyPrincipal, HookContext,
    HookError, HookPlane,
};

/// The route a request reached and the scopes it declares.
#[derive(Clone, Copy, Debug)]
pub struct ApiKeyRoute<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The route PATTERN (`/videos/{id}`), never the concrete URL; empty when none matched.
    pub pattern: &'a str,
    /// The scopes the route declares. A key must hold ALL of them. An empty list is an
    /// undeclared route and is refused before any credential work.
    pub required_scopes: &'a [&'a str],
}

/// The outcome that goes into an audit event, before the request details are added.
struct Verdict<'a> {
    outcome: ApiKeyOutcome,
    reason: Option<ApiKeyDenyReason>,
    key: Option<&'a ApiKey>,
}

impl AuthEngine {
    /// Decide whether a request guarded by a service API key is admitted.
    ///
    /// `header` is the value of the configured header, `None` when it was absent. A header that
    /// appeared more than once is malformed: pass a value that does not parse (an empty string).
    ///
    /// # Errors
    ///
    /// - [`AuthError::Forbidden`] when the route declares no scopes, before the key is read.
    /// - [`AuthError::ApiKeyInvalid`] for an absent, malformed, unknown, wrong, revoked or expired
    ///   key: one answer, so the response is no oracle.
    /// - [`AuthError::ApiKeyScopeInsufficient`] for a valid key missing a declared scope.
    /// - [`AuthError::Internal`] when the key store fails, when API keys are not enabled, or when
    ///   `api_keys.audit_mode` is `Required` and the audit hook failed for an admitted request.
    pub async fn authorize_api_key(
        &self,
        header: Option<&str>,
        route: &ApiKeyRoute<'_>,
        ctx: &RequestContext,
    ) -> Result<ApiKeyPrincipal, AuthError> {
        let runtime = self.enabled_api_keys()?;

        if route.required_scopes.is_empty() {
            tracing::error!(
                method = %log_safe(route.method),
                route = %log_safe(route.pattern),
                "api-key: route is guarded but declares no scopes; refused"
            );
            let _ = self
                .audit_api_key(
                    runtime,
                    route,
                    ctx,
                    &denied(ApiKeyDenyReason::RouteUndeclared),
                )
                .await;
            return Err(AuthError::Forbidden);
        }

        let verdict = match runtime.verify(header).await {
            Ok(verdict) => verdict,
            Err(error) => {
                tracing::error!(error = %error, "api-key: key store unavailable");
                let _ = self
                    .audit_api_key(runtime, route, ctx, &denied(ApiKeyDenyReason::StoreError))
                    .await;
                return Err(AuthError::Internal(Box::new(error)));
            }
        };

        let key = match verdict {
            ApiKeyVerdict::Accepted(key) => key,
            ApiKeyVerdict::Rejected { reason, key } => {
                let audited = Verdict {
                    outcome: ApiKeyOutcome::Denied,
                    reason: Some(deny_reason(reason)),
                    key: key.as_ref(),
                };
                let _ = self.audit_api_key(runtime, route, ctx, &audited).await;
                return Err(AuthError::ApiKeyInvalid);
            }
        };

        if !route
            .required_scopes
            .iter()
            .all(|scope| key.scopes.iter().any(|held| held == scope))
        {
            let audited = Verdict {
                outcome: ApiKeyOutcome::Denied,
                reason: Some(ApiKeyDenyReason::ScopeInsufficient),
                key: Some(&key),
            };
            let _ = self.audit_api_key(runtime, route, ctx, &audited).await;
            return Err(AuthError::ApiKeyScopeInsufficient);
        }

        let allowed = Verdict {
            outcome: ApiKeyOutcome::Allowed,
            reason: None,
            key: Some(&key),
        };
        // In `Required` mode a request whose audit row could not be written is not admitted.
        if !self.audit_api_key(runtime, route, ctx, &allowed).await {
            return Err(AuthError::Internal("api-key audit hook failed".into()));
        }
        Ok(ApiKeyPrincipal {
            id: key.id,
            label: key.label,
            scopes: key.scopes,
        })
    }

    /// Fire the audit hook for one request. Returns whether the request may proceed: always
    /// `true` in best-effort mode (the hook is detached and a failure is only logged), and in
    /// `Required` mode `true` only when the awaited hook succeeded within the detached-task ceiling.
    async fn audit_api_key(
        &self,
        runtime: &ApiKeyRuntime,
        route: &ApiKeyRoute<'_>,
        ctx: &RequestContext,
        verdict: &Verdict<'_>,
    ) -> bool {
        let event = ApiKeyAccessEvent {
            outcome: verdict.outcome,
            reason: verdict.reason,
            key_id: verdict.key.map(|key| key.id.clone()),
            label: verdict.key.map(|key| key.label.clone()),
            method: route.method.to_owned(),
            route: route.pattern.to_owned(),
            required_scopes: route
                .required_scopes
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ip: ctx.ip.clone(),
        };
        let mut hook_ctx = HookContext::from_request(HookPlane::ApiKey, ctx, None, None, None);
        // The adapter strips credential headers already; the key's own header is dropped again
        // here so a misconfigured sanitizer can never copy a key into an audit row.
        hook_ctx.sanitized_headers = without(&hook_ctx.sanitized_headers, &runtime.header);

        let hooks = self.hooks().clone();
        if runtime.audit_mode == crate::config::ApiKeyAuditMode::Required {
            return run_required_audit(
                DETACHED_TASK_TIMEOUT,
                hooks.on_api_key_request(&event, &hook_ctx),
            )
            .await;
        }
        spawn_guarded(async move { hooks.on_api_key_request(&event, &hook_ctx).await });
        true
    }
}

/// Await the audit hook of a `Required` audit under `timeout`: `true` only when it succeeded in time.
/// A failure and a hook that never returns are both a refusal to admit the request.
pub(super) async fn run_required_audit(
    timeout: Duration,
    call: impl Future<Output = Result<(), HookError>>,
) -> bool {
    match tokio::time::timeout(timeout, call).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::error!(error = %error, "api-key: audit hook failed");
            false
        }
        Err(_) => {
            tracing::error!("api-key: audit hook exceeded the timeout ceiling");
            false
        }
    }
}

/// A refusal that identified no key.
fn denied(reason: ApiKeyDenyReason) -> Verdict<'static> {
    Verdict {
        outcome: ApiKeyOutcome::Denied,
        reason: Some(reason),
        key: None,
    }
}

/// The audit spelling of a verifier rejection.
fn deny_reason(reason: ApiKeyRejection) -> ApiKeyDenyReason {
    match reason {
        ApiKeyRejection::Missing => ApiKeyDenyReason::Missing,
        ApiKeyRejection::Malformed => ApiKeyDenyReason::Malformed,
        ApiKeyRejection::Unknown => ApiKeyDenyReason::Unknown,
        ApiKeyRejection::WrongSecret => ApiKeyDenyReason::WrongSecret,
        ApiKeyRejection::Revoked => ApiKeyDenyReason::Revoked,
        ApiKeyRejection::Expired => ApiKeyDenyReason::Expired,
    }
}

/// `headers` without the entry named `name`.
fn without(headers: &BTreeMap<String, String>, name: &str) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(key, _)| key.as_str() != name)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
