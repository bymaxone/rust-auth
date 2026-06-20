//! The `oauth` route group (§8.2.7), gated behind the `oauth` feature: initiate (302 to the
//! provider) and callback (200-JSON or 302-redirect per §11.3.3). Both are public and
//! exempt from the MFA-required check. Redirect targets are operator-configured at startup,
//! never request-derived (no open-redirect).

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bymax_auth_core::OAuthOutcome;
use http::{HeaderValue, StatusCode, header};
use tower_cookies::Cookies;

use crate::delivery::TokenDelivery;
use crate::dto::{OAuthCallbackQuery, OAuthInitiateQuery};
use crate::response::error_response;
use crate::routes::RequestMeta;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedQuery;

/// The `?error=` short-code surfaced on an error redirect (§11.4): the suffix of the OAuth
/// failure code, never the `auth.`-namespaced form.
const OAUTH_ERROR_SHORT_CODE: &str = "oauth_failed";

/// Build a `302 Found` redirect to `url`, matching nest-auth's redirect status byte-for-byte
/// (axum's `Redirect::temporary` is 307; the OAuth flow uses the classic 302). A `url` that is
/// not a valid header value degrades to a generic 500-style oauth failure rather than a
/// header-injection.
fn found(url: &str) -> Response {
    match HeaderValue::from_str(url) {
        Ok(location) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => error_response(&bymax_auth_types::AuthError::OauthFailed),
    }
}

/// Assemble the `oauth` group under the `oauth` segment with per-route rate limits. Axum 0.8
/// brace path syntax: `/{provider}` and `/{provider}/callback`.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/oauth/{provider}",
            crate::router::throttled(get(initiate), limits.oauth_initiate, ip_source),
        )
        .route(
            "/oauth/{provider}/callback",
            crate::router::throttled(get(callback), limits.oauth_callback, ip_source),
        )
}

/// `GET /auth/oauth/{provider}` (302). Public. Redirects to the provider authorize URL.
async fn initiate(
    State(state): State<AuthState>,
    Path(provider): Path<String>,
    ValidatedQuery(query): ValidatedQuery<OAuthInitiateQuery>,
) -> Response {
    match state
        .engine()
        .oauth_initiate(&provider, &query.tenant_id)
        .await
    {
        Ok(authorize_url) => found(&authorize_url),
        Err(error) => error_response(&error),
    }
}

/// `GET /auth/oauth/{provider}/callback` (200 / 302). Public. Shapes the `OAuthOutcome` into
/// a JSON body or a redirect per the configured redirect URLs (§11.3.3).
async fn callback(
    State(state): State<AuthState>,
    cookies: Cookies,
    Path(provider): Path<String>,
    RequestMeta(ctx): RequestMeta,
    ValidatedQuery(query): ValidatedQuery<OAuthCallbackQuery>,
) -> Response {
    let outcome = state
        .engine()
        .oauth_callback(&provider, &query.code, &query.state, &ctx)
        .await;
    match outcome {
        Ok(OAuthOutcome::Authenticated(result)) => {
            let delivery = TokenDelivery::new(state.config());
            match state.engine().oauth_success_redirect_url() {
                // Browser flow: plant the auth cookies into the jar (the cookie-manager layer
                // emits them on the redirect response), then 302 to the configured URL.
                Some(url) => {
                    delivery.set_auth_cookies_for_browser(&cookies, &result);
                    found(url)
                }
                // SPA/API flow: 200 with the delivered auth body.
                None => delivery.deliver_auth(&cookies, &result, StatusCode::OK),
            }
        }
        Ok(OAuthOutcome::MfaChallenge(challenge)) => {
            let delivery = TokenDelivery::new(state.config());
            // Plant the ephemeral MFA-temp cookie so the challenge endpoint can consume it.
            delivery.set_mfa_temp_cookie(&cookies, &challenge.mfa_temp_token);
            match state.engine().oauth_mfa_redirect_url() {
                Some(url) => found(url),
                None => delivery.deliver_mfa_challenge(&challenge),
            }
        }
        Err(error) => {
            // Only an `OauthFailed`-family error is converted to an error redirect; any other
            // (e.g. an internal transport failure) propagates so monitoring sees it.
            if matches!(error, bymax_auth_types::AuthError::OauthFailed)
                && let Some(url) = state
                    .engine()
                    .oauth_error_redirect_url(OAUTH_ERROR_SHORT_CODE)
            {
                return found(&url);
            }
            error_response(&error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_builds_a_302_and_falls_back_on_an_invalid_url() {
        // A valid URL yields a 302 with the Location header; a header-invalid value (a control
        // character) degrades to the generic oauth-failed envelope rather than panicking.
        let ok = found("https://provider.test/authorize?state=abc");
        assert_eq!(ok.status(), StatusCode::FOUND);
        assert!(ok.headers().contains_key(header::LOCATION));

        let bad = found("https://provider.test/\u{0}bad");
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    }
}
