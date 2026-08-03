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
/// 2. `Sec-Fetch-Site: same-origin` / `none` proves the request is not cross-site — allowed.
/// 3. `Sec-Fetch-Site` present with any other value (`cross-site`, `same-site`) is the browser
///    stating the request came from somewhere else. Allowed only if `Origin` is listed in
///    `cookies.trusted_origins`; refused otherwise, **including when the list is empty** — an
///    empty list means no other origin is authorized, not that every one is.
/// 4. `Sec-Fetch-Site` absent and `Origin` present: allowed if listed. Otherwise refused when a
///    list is configured, and allowed when it is empty — see the ambiguity below.
/// 5. Neither header at all — a non-browser client. Allowed: an attacker's page cannot make a
///    browser *omit* `Origin` on a cross-site request, so the absence is evidence there is no
///    browser involved, not a way around the check.
///
/// **The check does not depend on the request already being authenticated.** It used to: a
/// request carrying none of the module's cookies went straight to allowed, on the reasoning
/// that there was no ambient credential to abuse. The reasoning missed the requests that MINT
/// one. This layer wraps the whole router, `POST /auth/login` and `/auth/register` included —
/// they carry no cookie and answer with a session — so an attacker's page could log a victim's
/// browser into the ATTACKER's account and then read back whatever the victim did there
/// believing it was their own.
///
/// **Nor does it depend on the allowlist being populated**, which was the same bug one level up.
/// An empty list used to short-circuit the whole check, justified here as "config validation
/// refuses an empty list wherever it would be consulted". That justification was false:
/// `SameSite=Lax` with `resolve_domains` configured and an empty list validates cleanly, and
/// that is precisely the deployment where a shared cookie domain makes sibling origins SAME-site
/// so the browser DOES send the session cookie on a POST between them. It was also beside the
/// point for a login CSRF, where the credentials ride in the attacker's own body and no cookie
/// need be sent at all. Since an empty list is the default, the check was inert on most
/// deployments while this comment claimed the class was closed.
///
/// **The one case that stays permissive, and why.** `Origin` is sent on a SAME-origin POST too,
/// and this crate never learns its own origin — reconstructing it from `Host` or
/// `X-Forwarded-Proto` would trust a client-controlled header, and a check that trusts them is
/// not a check. So an `Origin` with no `Sec-Fetch-Site` cannot be classified, and refusing it
/// would answer 403 to every same-origin POST from such a browser. `Sec-Fetch-Site` resolves the
/// ambiguity wherever it is present — Chrome 76, Firefox 90 and Safari 16.4 all send it — so the
/// residual gap is a browser old enough to send `Origin` without it, closed by listing the
/// deployment's own origin in `cookies.trusted_origins`.
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
        let fetch_site = header(&request, "sec-fetch-site");
        if fetch_site.is_some_and(|site| SAFE_FETCH_SITES.contains(&site)) {
            true
        } else {
            match header(&request, "origin") {
                // Scheme and host are case-insensitive (RFC 6454 §4), so two origins that
                // differ only in case ARE the same origin and must compare equal. ASCII
                // folding specifically: Unicode case folding can map distinct hosts onto
                // one another, which in an allowlist is a way in rather than a convenience.
                Some(origin) => {
                    trusted
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(origin))
                        // Unlisted. Refused whenever the browser has already said the request is
                        // not our own, and whenever a list exists to be checked against. What is
                        // left — no `Sec-Fetch-Site`, empty list — is the shape this layer cannot
                        // classify at all, since it does not know its own origin.
                        || (fetch_site.is_none() && trusted.is_empty())
                }
                // A browser that sent `Sec-Fetch-Site` would have sent `Origin` here too.
                None => fetch_site.is_none(),
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
