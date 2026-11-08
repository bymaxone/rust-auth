//! Service API keys over HTTP (layer: HTTP adapter), behind the `api-keys` feature.
//!
//! [`require_api_key_scopes`] builds a per-route layer: it reads the configured header, asks the
//! engine for the access decision with the scopes the route declares, and either answers with the
//! library's error envelope or lets the request through carrying a [`CurrentApiKey`]. The decision
//! itself lives in the core.
//!
//! The key is read from the configured header only, never from the query string, and a header that
//! appears twice is a malformed key rather than a choice between two.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{FromRequestParts, MatchedPath};
use axum::response::{IntoResponse, Response};
use bymax_auth_core::traits::ApiKeyPrincipal;
use bymax_auth_core::{AuthEngine, ConfigError};
use bymax_auth_types::AuthError;
use http::header::Entry;
use http::request::Parts;
use http::{HeaderMap, HeaderName, Request};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::{Layer, Service};

use crate::response::AuthRejection;
use crate::routes::request_context;
use crate::state::AuthState;

/// The layer [`require_api_key_scopes`] builds. Apply it with `Router::route_layer`, so the route
/// pattern is known and a request no route matched is never charged to a key.
#[derive(Clone)]
pub struct ApiKeyScopesLayer {
    state: AuthState,
    header: HeaderName,
    scopes: &'static [&'static str],
}

/// Guard routes with service API keys: a request is admitted only when it presents a valid key
/// that holds EVERY scope in `scopes`.
///
/// An empty `scopes` is not "no requirement": a guarded route that declares nothing is refused
/// with `auth.forbidden` before any key is verified, so forgetting to declare a scope can never
/// open a route.
///
/// The client address recorded for the request is the one the adapter's client-address layer
/// stored, or the TCP peer (`ConnectInfo`) when that layer did not run.
///
/// # Errors
///
/// [`ConfigError::ApiKeyGuardWithoutApiKeys`] when the engine's `api_keys` group is off.
pub fn require_api_key_scopes(
    state: &AuthState,
    scopes: &'static [&'static str],
) -> Result<ApiKeyScopesLayer, ConfigError> {
    let config = &state.engine().config().config().api_keys;
    // The configured name is validated lowercase ASCII at startup, so it always parses; the same
    // refusal covers a group that is off.
    let header = HeaderName::from_bytes(config.header.as_bytes())
        .ok()
        .filter(|_| state.engine().api_key_repository().is_some())
        .ok_or(ConfigError::ApiKeyGuardWithoutApiKeys)?;
    Ok(ApiKeyScopesLayer {
        state: state.clone(),
        header,
        scopes,
    })
}

impl<S> Layer<S> for ApiKeyScopesLayer {
    type Service = ApiKeyScopes<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyScopes {
            inner,
            guard: self.clone(),
        }
    }
}

/// The service [`ApiKeyScopesLayer`] wraps a route with.
#[derive(Clone)]
pub struct ApiKeyScopes<S> {
    inner: S,
    guard: ApiKeyScopesLayer,
}

impl<S> Service<Request<Body>> for ApiKeyScopes<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // The clone that was polled ready is the one that serves this request.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let guard = self.guard.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            match guard.admit(&mut parts).await {
                Ok(()) => inner.call(Request::from_parts(parts, body)).await,
                Err(error) => Ok(AuthRejection(error).into_response()),
            }
        })
    }
}

impl ApiKeyScopesLayer {
    /// Decide the request and, when admitted, leave the principal in its extensions.
    async fn admit(&self, parts: &mut Parts) -> Result<(), AuthError> {
        let presented = presented_key(&parts.headers, &self.header);
        mark_sensitive(&mut parts.headers, &self.header);
        let pattern = parts
            .extensions
            .get::<MatchedPath>()
            .map_or("", MatchedPath::as_str)
            .to_owned();
        let route = bymax_auth_core::services::api_key::ApiKeyRoute {
            method: parts.method.as_str(),
            pattern: &pattern,
            required_scopes: self.scopes,
        };
        let ctx = request_context(parts);
        let principal = self
            .state
            .engine()
            .authorize_api_key(presented.as_deref(), &route, &ctx)
            .await?;
        parts.extensions.insert(principal);
        Ok(())
    }
}

/// The value of the key header: `None` when absent, an empty string (which never parses as a key)
/// when it is repeated or not visible ASCII, otherwise its text.
fn presented_key(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return Some(String::new());
    }
    Some(first.to_str().map(str::to_owned).unwrap_or_default())
}

/// Mark every value of the key header sensitive, so a `Debug` print of the request headers shows
/// `Sensitive` instead of the key.
fn mark_sensitive(headers: &mut HeaderMap, name: &HeaderName) {
    if let Entry::Occupied(mut entry) = headers.entry(name) {
        for value in entry.iter_mut() {
            value.set_sensitive(true);
        }
    }
}

/// The key a guarded request was admitted with: its id, label and scopes, never its digest.
///
/// Available only behind [`require_api_key_scopes`]. A handler that asks for it on a route without
/// the layer is a wiring mistake, answered as an internal error rather than as a missing credential.
#[derive(Clone, Debug)]
pub struct CurrentApiKey(pub ApiKeyPrincipal);

impl<S: Send + Sync> FromRequestParts<S> for CurrentApiKey {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ApiKeyPrincipal>()
            .cloned()
            .map(Self)
            .ok_or_else(|| {
                AuthRejection(AuthError::Internal(
                    "CurrentApiKey used on a route without require_api_key_scopes".into(),
                ))
            })
    }
}

/// The background task that writes the coalesced last-used instants.
///
/// The core runs no timer; this task, owned by the adapter, flushes the batch every
/// `api_keys.last_used_flush` and once more when it is stopped. A failed write stays queued
/// for the next round.
pub struct ApiKeyFlushTask {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

/// Start the last-used flush task. Must be called inside a Tokio runtime.
///
/// # Errors
///
/// [`ConfigError::ApiKeyGuardWithoutApiKeys`] when the engine's `api_keys` group is off.
pub fn spawn_api_key_flush(engine: Arc<AuthEngine>) -> Result<ApiKeyFlushTask, ConfigError> {
    if engine.api_key_repository().is_none() {
        return Err(ConfigError::ApiKeyGuardWithoutApiKeys);
    }
    let period = engine.config().config().api_keys.last_used_flush;
    let (stop, stopped) = oneshot::channel();
    let join = tokio::spawn(flush_until_stopped(engine, period, stopped));
    Ok(ApiKeyFlushTask { stop, join })
}

impl ApiKeyFlushTask {
    /// Stop the task after one last flush, and wait for it. `true` when it ended normally.
    pub async fn shutdown(self) -> bool {
        // The task may already have ended; either way the join below returns.
        let _ = self.stop.send(());
        self.join.await.is_ok()
    }
}

/// Flush every `period` until `stopped` fires, then once more.
async fn flush_until_stopped(
    engine: Arc<AuthEngine>,
    period: Duration,
    mut stopped: oneshot::Receiver<()>,
) {
    loop {
        let keep_going = tokio::time::timeout(period, &mut stopped).await.is_err();
        if let Err(error) = engine.flush_api_key_last_used().await {
            tracing::warn!(error = %error, "api-key: last-used flush failed; retrying next round");
        }
        if !keep_going {
            return;
        }
    }
}
