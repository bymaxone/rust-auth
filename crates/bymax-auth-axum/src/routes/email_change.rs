//! The `email` route group (§8.2.9): requesting an address change behind a password re-prove,
//! and confirming it with the token that was mailed to the new address.
//!
//! The split is the security property. The request is authenticated and changes nothing; the
//! confirmation is public because the person holding the token is proving control of a
//! mailbox, not of a session — requiring a login there would break the case the flow exists to
//! serve, where someone confirms from the device their new mail is on.

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http::StatusCode;

use crate::dto::{ChangeEmailDto, ConfirmEmailChangeDto};
use crate::extractors::AuthUser;
use crate::response::error_response;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `email` group under the `email` segment with per-route limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/email/change",
            crate::router::throttled(post(request), limits.email_change_request, ip_source),
        )
        .route(
            "/email/change/confirm",
            crate::router::throttled(post(confirm), limits.email_change_confirm, ip_source),
        )
}

/// `POST /auth/email/change` (204). Requires [`AuthUser`]. The account comes from the caller's
/// claims — never the body — so a request cannot move someone else's address.
///
/// Answers 204 and nothing else: the failure modes worth reporting (the address is taken, the
/// password was wrong) are already errors, and anything beyond that would be describing the
/// state of an account to whoever is holding its token.
async fn request(
    State(state): State<AuthState>,
    user: AuthUser,
    ValidatedJson(dto): ValidatedJson<ChangeEmailDto>,
) -> Response {
    match state
        .engine()
        .request_email_change(&user.0.sub, &dto.new_email, &dto.current_password)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/email/change/confirm` (204). Public and rate-limited. Guessing is bounded by the
/// token being 256 bits of entropy looked up by its SHA-256 — a wrong value reaches no record.
async fn confirm(
    State(state): State<AuthState>,
    ValidatedJson(dto): ValidatedJson<ConfirmEmailChangeDto>,
) -> Response {
    match state.engine().confirm_email_change(&dto.token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}
