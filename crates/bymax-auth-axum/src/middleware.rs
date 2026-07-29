//! The ordered tower middleware stack applied around the whole router (§8.8).
//!
//! Layers, outermost first: structured tracing spans, an optional consumer-supplied CORS
//! layer, the `Cache-Control: no-store` response stamp (RFC 6749 §5.1 — no auth response is
//! ever cacheable), sensitive-header redaction (so the credential-bearing headers never
//! reach trace output), a request-body size cap, and the cookie manager that makes the typed
//! `CookieJar` available to extractors and the delivery layer. Rate-limit layers are
//! **not** here — they attach per route group (§16). The adapter emits `tracing` spans but
//! installs **no** subscriber: the consuming application owns subscriber setup.

use axum::Router;
use http::HeaderValue;
use http::header::{CACHE_CONTROL, PRAGMA};
use tower_cookies::CookieManagerLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::{
    SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer,
};
use tower_http::set_header::SetResponseHeaderLayer;
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
    state: AuthState,
    max_body_bytes: usize,
    cors: Option<tower_http::cors::CorsLayer>,
) -> Router<AuthState> {
    // Redact the credential-bearing request headers from any trace span/event, mirroring
    // nest-auth's `sanitizeHeaders`. The set is sourced from the same `SENSITIVE_HEADERS`
    // list that `sanitize_headers` strips from the engine context, so `authorization`,
    // `cookie`, and `x-csrf-token` are all masked before the tracing layer records them.
    let sensitive = SetSensitiveRequestHeadersLayer::new(sensitive_header_names());

    // The same treatment for the response side, where the credential travels outward: every
    // successful login, refresh, and OAuth callback answers with `Set-Cookie: access_token=<a
    // signed JWT>`. Request redaction alone leaves that value printable, so a deployment whose
    // tracing records response headers — a reasonable thing to switch on while debugging —
    // writes live session tokens into its logs, where they outlive the session and are read by
    // people the session was never issued to. Marking the header sensitive costs nothing and
    // makes that mistake unavailable.
    let sensitive_out = SetSensitiveResponseHeadersLayer::new([http::header::SET_COOKIE]);

    // Layered innermost-last: the cookie manager runs closest to the handler so the jar is
    // ready, then body-limit, redaction, optional CORS, and tracing wrap outward.
    // The cross-site check sits innermost, next to the handlers: it must see the request
    // exactly as the handler would, and it must not answer a CORS preflight (which the CORS
    // layer above already handles before this ever runs).
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::trusted_origin::enforce_trusted_origin,
        ))
        .layer(CookieManagerLayer::new())
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(sensitive)
        .layer(sensitive_out)
        // Every response of every route this router serves is stamped `Cache-Control:
        // no-store` (plus `Pragma: no-cache` for HTTP/1.0 intermediaries). RFC 6749 §5.1
        // requires it on any response carrying a token, and every route here either carries
        // one, sets an auth cookie, or answers a question about an authenticated identity —
        // all of which a shared cache must never replay to the next caller. Stamped as a
        // layer, not per handler, so a future route cannot forget it; placed outside the
        // body-limit so even a 413 goes out uncacheable. `nest-auth` stamps the identical
        // headers via a controller interceptor.
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            PRAGMA,
            HeaderValue::from_static("no-cache"),
        ));

    let router = match cors {
        Some(cors) => router.layer(cors),
        None => router,
    };

    router.layer(TraceLayer::new_for_http())
}
