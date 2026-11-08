//! The access decision for one request guarded by a service API key, with its audit event.
//!
//! A transport adapter reads the configured header, names the route it is guarding and the
//! scopes that route declares, and gets back either the principal or the error to answer with.
//! Keeping the decision here means every adapter gives the same answers in the same order:
//! route configuration first (before any credential work), then the key, then its scopes, then
//! the audit.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
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
        let guarded = Guarded {
            engine: self,
            runtime: self.enabled_api_keys()?,
            route,
            ctx,
        };
        if route.required_scopes.is_empty() {
            return Err(guarded.undeclared_route().await);
        }
        let key = guarded.verified_key(header).await?;
        guarded.admit(key).await
    }
}

/// One guarded request: the engine, the runtime and what the adapter said about the request.
struct Guarded<'a> {
    engine: &'a AuthEngine,
    runtime: &'a ApiKeyRuntime,
    route: &'a ApiKeyRoute<'a>,
    ctx: &'a RequestContext,
}

impl Guarded<'_> {
    /// The route is guarded but declares no scopes: a configuration error, refused before the
    /// key is read.
    async fn undeclared_route(&self) -> AuthError {
        // Bound first: a call inside a `tracing` field expression is not evaluated without an
        // installed subscriber, which would leave these lines unexercised.
        let method = log_safe(self.route.method);
        let pattern = log_safe(self.route.pattern);
        tracing::error!(%method, route = %pattern, "api-key: route is guarded but declares no scopes; refused");
        self.refuse(ApiKeyDenyReason::RouteUndeclared, None).await;
        AuthError::Forbidden
    }

    /// Read and verify the presented key: the row when it is valid, otherwise the error to answer
    /// with (after auditing the refusal).
    async fn verified_key(&self, header: Option<&str>) -> Result<ApiKey, AuthError> {
        match self.runtime.verify(header).await {
            Ok(ApiKeyVerdict::Accepted(key)) => Ok(key),
            Ok(ApiKeyVerdict::Rejected { reason, key }) => {
                self.refuse(deny_reason(reason), key.as_ref()).await;
                Err(AuthError::ApiKeyInvalid)
            }
            Err(error) => {
                tracing::error!(error = %error, "api-key: key store unavailable");
                self.refuse(ApiKeyDenyReason::StoreError, None).await;
                Err(AuthError::Internal(Box::new(error)))
            }
        }
    }

    /// A valid key is admitted when it holds EVERY declared scope and the audit allows it.
    async fn admit(&self, key: ApiKey) -> Result<ApiKeyPrincipal, AuthError> {
        let holds_all = self
            .route
            .required_scopes
            .iter()
            .all(|scope| key.scopes.iter().any(|held| held == scope));
        if !holds_all {
            self.refuse(ApiKeyDenyReason::ScopeInsufficient, Some(&key))
                .await;
            return Err(AuthError::ApiKeyScopeInsufficient);
        }
        let allowed = Verdict {
            outcome: ApiKeyOutcome::Allowed,
            reason: None,
            key: Some(&key),
        };
        // In `Required` mode a request whose audit row could not be written is not admitted.
        if !self.audit(&allowed).await {
            return Err(AuthError::Internal("api-key audit hook failed".into()));
        }
        Ok(ApiKeyPrincipal {
            id: key.id,
            label: key.label,
            scopes: key.scopes,
        })
    }

    /// Audit a refusal. The answer is already decided, so the audit's own outcome never changes it.
    async fn refuse(&self, reason: ApiKeyDenyReason, key: Option<&ApiKey>) {
        let verdict = Verdict {
            outcome: ApiKeyOutcome::Denied,
            reason: Some(reason),
            key,
        };
        let _ = self.audit(&verdict).await;
    }

    /// Fire the audit hook for one request. Returns whether the request may proceed: always
    /// `true` in best-effort mode (the hook is detached and a failure is only logged), and in
    /// `Required` mode `true` only when the awaited hook succeeded within the detached-task ceiling.
    async fn audit(&self, verdict: &Verdict<'_>) -> bool {
        let (route, ctx) = (self.route, self.ctx);
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
        // The key's own header is dropped so a key can never be copied into an audit row.
        hook_ctx.sanitized_headers = without(&hook_ctx.sanitized_headers, &self.runtime.header);

        let hooks = self.engine.hooks().clone();
        if self.runtime.audit_mode == crate::config::ApiKeyAuditMode::Required {
            let call = Box::pin(hooks.on_api_key_request(&event, &hook_ctx));
            return run_required_audit(DETACHED_TASK_TIMEOUT, call).await;
        }
        spawn_guarded(async move { hooks.on_api_key_request(&event, &hook_ctx).await });
        true
    }
}

/// The audit hook's call, type-erased.
pub(super) type AuditFuture<'a> = Pin<Box<dyn Future<Output = Result<(), HookError>> + Send + 'a>>;

/// Await the audit hook of a `Required` audit under `timeout`: `true` only when it succeeded in time.
/// A failure and a hook that never returns are both a refusal to admit the request.
///
/// The future is boxed so the function is compiled once: a generic parameter would give each
/// call site its own copy, and a copy that never reaches the timeout or error arm counts as
/// uncovered however well another copy is tested.
pub(super) async fn run_required_audit(timeout: Duration, call: AuditFuture<'_>) -> bool {
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

/// The audit spelling of a verifier rejection.
pub(super) fn deny_reason(reason: ApiKeyRejection) -> ApiKeyDenyReason {
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
