//! The cross-site request check for cookie-authenticated, state-changing requests (§8.8).
//!
//! `SameSite` carries this on its own for `Lax`/`Strict` — the browser simply does not send the
//! cookie. It does **not** for `SameSite=None`, which the library allows (embedded widgets,
//! iframes, cross-domain SPAs) and which sends the session cookie on every cross-site request.
//! That is the one configuration where this adapter has a CSRF exposure at all, and this layer
//! is what closes it.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bymax_auth_types::AuthError;

use crate::response::error_response;
use crate::state::AuthState;

/// `Sec-Fetch-Site` values that prove the request did not come from another site.
///
/// `same-origin` is the app calling itself; `none` is a user-initiated navigation (a typed URL,
/// a bookmark), which no attacker page can cause.
const SAFE_FETCH_SITES: [&str; 2] = ["same-origin", "none"];

/// Reject a state-changing request that would otherwise be authenticated by the browser's
/// ambient session cookie and came from an origin the deployment does not trust.
///
/// The decision uses only headers a page cannot forge:
///
/// 1. A safe method changes nothing — allowed. `OPTIONS` in particular must pass, or every
///    cross-origin call would fail at the preflight.
/// 2. A request carrying none of the module's auth cookies has no ambient credential to abuse,
///    so a bearer-token client is never affected — allowed.
/// 3. `Sec-Fetch-Site: same-origin` / `none` proves the request is not cross-site — allowed.
/// 4. An `Origin` present must be in `cookies.trusted_origins` — allowed only then.
/// 5. `Sec-Fetch-Site` present and cross-site with no `Origin`: a browser that sends one header
///    sends the other on a state-changing request, so this shape is refused.
/// 6. Neither header at all — a non-browser client. Allowed: an attacker's page cannot make a
///    browser *omit* `Origin` on a cross-site request, so the absence is evidence there is no
///    browser involved, not a way around the check.
///
/// The request's own origin is never reconstructed from `Host` or `X-Forwarded-Proto`: both are
/// client-controlled, and a check that trusts them is not a check. Same-origin requests are
/// recognised by `Sec-Fetch-Site` alone.
pub(crate) async fn enforce_trusted_origin(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    if request.method().is_safe() {
        return next.run(request).await;
    }

    let cookies = state.config().cookies.clone();
    if !carries_auth_cookie(&request, &cookies.access_name, &cookies.refresh_name) {
        return next.run(request).await;
    }

    let fetch_site = header(&request, "sec-fetch-site");
    if fetch_site.is_some_and(|site| SAFE_FETCH_SITES.contains(&site)) {
        return next.run(request).await;
    }

    match header(&request, "origin") {
        Some(origin) => {
            if cookies
                .trusted_origins
                .iter()
                .any(|allowed| allowed == origin)
            {
                next.run(request).await
            } else {
                error_response(&AuthError::UntrustedOrigin).into_response()
            }
        }
        // A browser that sent `Sec-Fetch-Site` would have sent `Origin` here too.
        None if fetch_site.is_some() => error_response(&AuthError::UntrustedOrigin).into_response(),
        None => next.run(request).await,
    }
}

/// Read a header as UTF-8, or `None` when it is absent or not valid UTF-8.
fn header<'r>(request: &'r Request, name: &str) -> Option<&'r str> {
    request.headers().get(name)?.to_str().ok()
}

/// Whether the request carries one of the module's credential-bearing cookies.
///
/// Only those two count. The session-signal cookie is readable by JavaScript by design and
/// authenticates nothing, so a request carrying only that one has no ambient credential for an
/// attacker page to spend.
fn carries_auth_cookie(request: &Request, access_name: &str, refresh_name: &str) -> bool {
    let Some(header) = header(request, "cookie") else {
        return false;
    };
    header.split(';').any(|pair| {
        let name = pair.split('=').next().unwrap_or_default().trim();
        name == access_name || name == refresh_name
    })
}
