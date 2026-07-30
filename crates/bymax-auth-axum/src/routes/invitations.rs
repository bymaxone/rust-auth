//! The `invitations` route group (§8.2.8), gated behind the `invitations` feature: create
//! (authenticated; `tenant_id` derived from the inviter's claims, **never** the body) and
//! accept (public, 201), and revoke (authenticated; withdraws a pending invitation).

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bymax_auth_core::services::auth::AcceptInvitationInput;
use http::StatusCode;
use tower_cookies::Cookies;

use crate::delivery::TokenDelivery;
use crate::dto::{AcceptInvitationDto, CreateInvitationDto, RevokeInvitationDto};
use crate::extractors::AuthUser;
use crate::response::error_response;
use crate::routes::{CookieDomains, RequestMeta};
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;
use bymax_auth_types::AuthResult;

/// Assemble the `invitations` group under the `invitations` segment with per-route limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/invitations",
            crate::router::throttled(post(create), limits.invitation_create, ip_source),
        )
        .route(
            "/invitations/accept",
            crate::router::throttled(post(accept), limits.invitation_accept, ip_source),
        )
        .route(
            "/invitations/revoke",
            crate::router::throttled(post(revoke), limits.invitation_revoke, ip_source),
        )
}

/// `POST /auth/invitations` (204). Requires [`AuthUser`]. The `tenant_id` is taken from the
/// inviter's claims — never the body — so a request cannot inject a cross-tenant invitation.
async fn create(
    State(state): State<AuthState>,
    user: AuthUser,
    ValidatedJson(dto): ValidatedJson<CreateInvitationDto>,
) -> Response {
    match state
        .engine()
        .invite(
            &user.0.sub,
            &dto.email,
            &dto.role,
            &user.0.tenant_id,
            dto.tenant_name.as_deref(),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/invitations/revoke` (204). Requires [`AuthUser`]. The `tenant_id` comes from
/// the caller's claims — never the body — so a request cannot withdraw another tenant's
/// invitations.
///
/// Answers 204 whether or not anything was pending: reporting the difference would turn the
/// endpoint into an oracle for which addresses have invitations.
async fn revoke(
    State(state): State<AuthState>,
    user: AuthUser,
    ValidatedJson(dto): ValidatedJson<RevokeInvitationDto>,
) -> Response {
    match state
        .engine()
        .revoke_invitation(&user.0.sub, &dto.email, &user.0.tenant_id)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/invitations/accept` (201). Public. Consumes the single-use token, creates the
/// verified user, and issues a full session.
async fn accept(
    State(state): State<AuthState>,
    cookies: Cookies,
    CookieDomains(domains): CookieDomains,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<AcceptInvitationDto>,
) -> Response {
    let input = AcceptInvitationInput {
        token: dto.token,
        name: dto.name,
        password: dto.password,
    };
    match state
        .engine()
        .accept_invitation(
            input,
            &ctx.ip,
            &ctx.user_agent,
            ctx.sanitized_headers.clone(),
        )
        .await
    {
        Ok(result) => deliver_accept(&state, &cookies, &domains, &result),
        Err(error) => error_response(&error),
    }
}

/// Deliver a successful invitation acceptance (201) per the configured mode.
fn deliver_accept(
    state: &AuthState,
    cookies: &Cookies,
    domains: &[String],
    result: &AuthResult,
) -> Response {
    TokenDelivery::with_domains(state.config(), domains).deliver_auth(
        cookies,
        result,
        StatusCode::CREATED,
    )
}
