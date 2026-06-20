//! The ordered tower middleware stack applied around the whole router (§8.8).
//!
//! Layers, outermost first: structured tracing spans, a request-body size cap,
//! sensitive-header redaction (so the credential-bearing headers never reach trace output),
//! an optional consumer-supplied CORS layer, and the cookie manager that makes the typed
//! `CookieJar` available to extractors and the delivery layer. Rate-limit layers are
//! **not** here — they attach per route group (§16). The adapter emits `tracing` spans but
//! installs **no** subscriber: the consuming application owns subscriber setup.

use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

use crate::routes::sensitive_header_names;
use crate::state::AuthState;

/// Apply the ordered middleware stack to an assembled router. `max_body_bytes` caps the
/// request body. The `TraceLayer` is applied last, so it is the **outermost** layer and every
/// request — including a CORS preflight — is traced first; `cors`, when `Some`, sits just
/// inside tracing (it answers the preflight before the redaction/body-limit/cookie layers
/// run). The cookie manager is innermost so the typed jar is populated for every extractor and
/// handler.
pub(crate) fn apply_middleware(
    router: Router<AuthState>,
    max_body_bytes: usize,
    cors: Option<tower_http::cors::CorsLayer>,
) -> Router<AuthState> {
    // Redact the credential-bearing request headers from any trace span/event, mirroring
    // nest-auth's `sanitizeHeaders`. The set is sourced from the same `SENSITIVE_HEADERS`
    // list that `sanitize_headers` strips from the engine context, so `authorization`,
    // `cookie`, and `x-csrf-token` are all masked before the tracing layer records them.
    let sensitive = SetSensitiveRequestHeadersLayer::new(sensitive_header_names());

    // Layered innermost-last: the cookie manager runs closest to the handler so the jar is
    // ready, then body-limit, redaction, optional CORS, and tracing wrap outward.
    let router = router
        .layer(CookieManagerLayer::new())
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(sensitive);

    let router = match cors {
        Some(cors) => router.layer(cors),
        None => router,
    };

    router.layer(TraceLayer::new_for_http())
}
