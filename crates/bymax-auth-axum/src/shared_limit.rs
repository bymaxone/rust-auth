//! The per-route rate limit backed by the engine's shared counter (layer: HTTP adapter).
//!
//! When the engine holds a [`bymax_auth_core::traits::RateLimitStore`] the limit is counted there
//! — one fixed window per (route, client bucket), shared by every instance on that store — and
//! the in-process limiter is not attached. Without a store the routes keep the in-process
//! limiter, which holds per instance only.

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bymax_auth_core::AuthEngine;
use bymax_auth_types::AuthError;
use tower_governor::key_extractor::KeyExtractor;

use crate::rate_limit::{PeerIpBucketKeyExtractor, RateLimit, RightmostForwardedIpKeyExtractor};
use crate::response::error_response;
use crate::state::ClientIpSource;

/// The bucket requests with no readable address share. A constant, not a per-request value: an
/// unreadable address must not mean an unlimited budget.
const UNKNOWN_CLIENT: &str = "unknown";

/// How the per-route limits are enforced for one router: the client-address strategy, and the
/// engine to count in when it holds a shared counter.
#[derive(Clone)]
pub(crate) struct Throttle {
    source: ClientIpSource,
    shared: Option<Arc<AuthEngine>>,
}

impl Throttle {
    /// Decide how limits are enforced for `engine`: shared when it holds a counter, in-process
    /// otherwise.
    pub(crate) fn new(source: ClientIpSource, engine: &Arc<AuthEngine>) -> Self {
        let shared = engine
            .rate_limit_store()
            .is_some()
            .then(|| Arc::clone(engine));
        Self { source, shared }
    }

    /// The client-address strategy the in-process limiter keys on.
    pub(crate) fn source(&self) -> ClientIpSource {
        self.source
    }

    /// Whether limits are counted in the shared store rather than in process.
    pub(crate) fn is_shared(&self) -> bool {
        self.shared.is_some()
    }

    /// The state the shared-counter middleware needs for `limit`, or `None` when the route has no
    /// limit or limits stay in-process.
    pub(crate) fn shared_state(&self, limit: Option<RateLimit>) -> Option<SharedLimit> {
        Some(SharedLimit {
            engine: Arc::clone(self.shared.as_ref()?),
            limit: limit?,
            source: self.source,
        })
    }
}

/// One route's shared-counter limit: what to count in, how much, and how to find the client.
#[derive(Clone)]
pub(crate) struct SharedLimit {
    engine: Arc<AuthEngine>,
    limit: RateLimit,
    source: ClientIpSource,
}

/// The address bucket a request is charged to, or [`UNKNOWN_CLIENT`] when none can be read.
fn client_bucket(source: ClientIpSource, request: &Request) -> String {
    let key = match source {
        ClientIpSource::PeerAddr => PeerIpBucketKeyExtractor.extract(request),
        ClientIpSource::TrustedForwardedFor => RightmostForwardedIpKeyExtractor.extract(request),
    };
    key.map_or_else(|_| UNKNOWN_CLIENT.to_owned(), |ip| ip.to_string())
}

/// Count the request in the shared store and refuse it with the `auth.too_many_requests` envelope
/// once the window's budget is spent. `Retry-After` is the full window, not the time left: the
/// time left would tell a caller exactly when its window opened. A store failure is answered as
/// the internal error it is rather than waving the request through.
pub(crate) async fn shared_limit(
    State(shared): State<SharedLimit>,
    request: Request,
    next: Next,
) -> Response {
    let route = format!(
        "{} {}",
        request.method(),
        request
            .extensions()
            .get::<MatchedPath>()
            .map_or("", MatchedPath::as_str)
    );
    let bucket = client_bucket(shared.source, &request);
    let window = shared.limit.per_seconds.max(1);
    let counted = shared
        .engine
        .count_rate_limited_request(&route, &bucket, window)
        .await;
    match counted {
        Ok(Some(hits)) if hits > i64::from(shared.limit.burst.max(1)) => {
            error_response(&AuthError::TooManyRequests {
                retry_after_seconds: Some(window),
            })
            .into_response()
        }
        Ok(_) => next.run(request).await,
        Err(error) => error_response(&error).into_response(),
    }
}
