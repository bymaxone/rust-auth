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
/// 2. An empty `cookies.trusted_origins` means no origin has been authorized and none needs to
///    be: config validation refuses an empty list wherever it would be consulted, so an empty
///    one is a posture where the browser never delivers the cookie cross-origin — allowed.
/// 3. `Sec-Fetch-Site: same-origin` / `none` proves the request is not cross-site — allowed.
/// 4. An `Origin` present must be in `cookies.trusted_origins` — allowed only then.
/// 5. `Sec-Fetch-Site` present and cross-site with no `Origin`: a browser that sends one header
///    sends the other on a state-changing request, so this shape is refused.
/// 6. Neither header at all — a non-browser client. Allowed: an attacker's page cannot make a
///    browser *omit* `Origin` on a cross-site request, so the absence is evidence there is no
///    browser involved, not a way around the check.
///
/// **The check does not depend on the request already being authenticated.** It used to: a
/// request carrying none of the module's cookies went straight to allowed, on the reasoning
/// that there was no ambient credential to abuse. The reasoning missed the requests that MINT
/// one. This layer wraps the whole router, `POST /auth/login` and `/auth/register` included —
/// they carry no cookie and answer with a session — so under `SameSite=None` an attacker's page
/// could log a victim's browser into the ATTACKER's account and then read back whatever the
/// victim did there believing it was their own. A non-browser client is unaffected: it sends
/// neither header, and rule 6 still admits that shape.
///
/// Step 2 replaced that skip and closes the opposite failure. `Origin` is sent on a SAME-origin
/// POST too, and with no `Sec-Fetch-Site` the two cannot be told apart, so the check assumed
/// cross-site — correct where a cross-site cookie can arrive, wrong where it cannot. Under
/// `Lax`/`Strict` with no shared cookie domain the browser withholds the cookie itself and the
/// allowlist is required to be empty, yet every same-origin POST from a browser that omits
/// `Sec-Fetch-Site` was refused. Gating on `same_site == None` instead would reopen a real
/// hole: a shared cookie domain makes sibling origins SAME-site under `Lax`, the browser does
/// send the cookie on a POST between them, and `same-site` is deliberately not one of the
/// values in [`SAFE_FETCH_SITES`].
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

    // Scoped so every borrow of `state` and `request` ends before the request is moved into the
    // next layer, and so the allowlist is read where it lives instead of being cloned — this
    // runs on every state-changing request, and the clone copied the whole `Vec` each time.
    let allowed = {
        let trusted = &state.config().cookies.trusted_origins;
        if trusted.is_empty() {
            true
        } else {
            let fetch_site = header(&request, "sec-fetch-site");
            if fetch_site.is_some_and(|site| SAFE_FETCH_SITES.contains(&site)) {
                true
            } else {
                match header(&request, "origin") {
                    // Scheme and host are case-insensitive (RFC 6454 §4), so two origins that
                    // differ only in case ARE the same origin and must compare equal. ASCII
                    // folding specifically: Unicode case folding can map distinct hosts onto
                    // one another, which in an allowlist is a way in rather than a convenience.
                    Some(origin) => trusted
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(origin)),
                    // A browser that sent `Sec-Fetch-Site` would have sent `Origin` here too.
                    None => fetch_site.is_none(),
                }
            }
        }
    };

    if allowed {
        next.run(request).await
    } else {
        error_response(&AuthError::UntrustedOrigin).into_response()
    }
}

/// Read a header as UTF-8, or `None` when it is absent or not valid UTF-8.
fn header<'r>(request: &'r Request, name: &str) -> Option<&'r str> {
    request.headers().get(name)?.to_str().ok()
}

