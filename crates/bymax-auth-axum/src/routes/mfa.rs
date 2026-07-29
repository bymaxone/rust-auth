//! The `mfa` route group (§8.2.2), gated behind the `mfa` feature: setup / verify-enable /
//! challenge / disable / recovery-codes.
//!
//! `setup` and `verify-enable` take [`AuthUser`] **without** `MfaSatisfied` (the `@SkipMfa()`
//! semantic — a user enrolling MFA must not be locked out); `challenge` is public (the
//! post-login exchange); `disable` and `recovery-codes` require an authenticated user plus a
//! valid TOTP in the body (the strong re-auth gate). Each handler delegates to an engine
//! method that resolves the MFA service (guaranteed present because the group mounts only
//! when MFA is configured).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bymax_auth_types::{AuthError, MfaContext};
use http::StatusCode;
use serde_json::json;

use crate::delivery::TokenDelivery;
use crate::dto::{
    MfaChallengeDto, MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaSetupDto, MfaVerifyDto,
};
use crate::extractors::AuthUser;
use crate::response::error_response;
use crate::routes::RequestMeta;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `mfa` group under the `mfa` segment, with per-route rate-limit layers.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new().nest(
        "/mfa",
        Router::new()
            .route(
                "/setup",
                crate::router::throttled(post(setup), limits.mfa_setup, ip_source),
            )
            .route(
                "/verify-enable",
                crate::router::throttled(post(verify_enable), limits.mfa_verify_enable, ip_source),
            )
            .route(
                "/challenge",
                crate::router::throttled(post(challenge), limits.mfa_challenge, ip_source),
            )
            .route(
                "/disable",
                crate::router::throttled(post(disable), limits.mfa_disable, ip_source),
            )
            .route(
                "/recovery-codes",
                crate::router::throttled(post(recovery_codes), limits.mfa_setup, ip_source),
            ),
    )
}

/// `POST /auth/mfa/setup` (201). Requires [`AuthUser`], not `MfaSatisfied` (enrolment).
///
/// 201 Created, not 200: nest-auth's `MfaController.setup` carries no `@HttpCode`, so it uses
/// Nest's `POST` default of 201, and enrolment does create the pending setup record.
async fn setup(
    State(state): State<AuthState>,
    user: AuthUser,
    body: axum::body::Bytes,
) -> Response {
    // The body carries the account password. It is optional on the wire — an OAuth-only
    // account has none — so an absent or unparseable body degrades to "no password supplied"
    // and the engine decides, rather than 400-ing before it can.
    let dto: MfaSetupDto = serde_json::from_slice(&body).unwrap_or_default();
    match state
        .engine()
        .mfa_setup(&user.0.sub, MfaContext::Dashboard, dto.password.as_deref())
        .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(json!({
                "secret": result.secret,
                "qrCodeUri": result.qr_code_uri,
                "recoveryCodes": result.recovery_codes,
            })),
        )
            .into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/mfa/verify-enable` (204). Requires [`AuthUser`], not `MfaSatisfied`.
async fn verify_enable(
    State(state): State<AuthState>,
    user: AuthUser,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaVerifyDto>,
) -> Response {
    match state
        .engine()
        .mfa_verify_enable(
            &user.0.sub,
            &dto.code,
            &ctx.ip,
            &ctx.user_agent,
            MfaContext::Dashboard,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/mfa/challenge` (200). Public — the post-login exchange. Returns a full
/// dashboard session on success.
///
/// The temp token comes from `mfaTempToken` in the body **or**, when the body omits it, from
/// the HttpOnly `mfa_temp_token` cookie the OAuth callback planted (see
/// [`crate::routes::oauth`]). The body wins when both are present — that is the historical
/// contract of the password-login path. Without this fallback the browser OAuth + MFA flow
/// could never complete: the callback 302s to the configured MFA page, which has no way to
/// read the HttpOnly cookie it would have to echo back.
///
/// When the cookie supplied the token it is cleared per nest-auth's policy (documented on
/// [`TokenDelivery::clear_mfa_temp_cookie`]): on success and on an invalid temp token, but not
/// on a wrong code, so the user can retry inside the token's 5-minute lifetime.
async fn challenge(
    State(state): State<AuthState>,
    cookies: tower_cookies::Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaChallengeDto>,
) -> Response {
    let delivery = TokenDelivery::new(state.config());
    let cookie_token = mfa_temp_cookie(&cookies);
    // Neither channel carried a token: that is an invalid temp token (nest-auth throws
    // `MFA_TEMP_TOKEN_INVALID` here), never a generic field-validation 400.
    let Some(temp_token) = dto.mfa_temp_token.as_deref().or(cookie_token.as_deref()) else {
        return error_response(&AuthError::MfaTempTokenInvalid);
    };

    match state
        .engine()
        .dashboard_mfa_challenge(temp_token, &dto.code, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(auth) => {
            if cookie_token.is_some() {
                delivery.clear_mfa_temp_cookie(&cookies);
            }
            delivery.deliver_auth(&cookies, &auth, StatusCode::OK)
        }
        Err(error) => {
            // A dead token can never be retried under the same cookie, so drop it; any other
            // failure (wrong code, lockout, store hiccup) leaves the cookie in place.
            if cookie_token.is_some() && matches!(error, AuthError::MfaTempTokenInvalid) {
                delivery.clear_mfa_temp_cookie(&cookies);
            }
            error_response(&error)
        }
    }
}

/// Read the `mfa_temp_token` cookie, treating an empty value as absent so an already-cleared
/// cookie never masquerades as a supplied token.
fn mfa_temp_cookie(cookies: &tower_cookies::Cookies) -> Option<String> {
    cookies
        .get(bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned())
        .filter(|value| !value.is_empty())
}

/// `POST /auth/mfa/disable` (204). Requires [`AuthUser`] + a valid TOTP (strong re-auth).
async fn disable(
    State(state): State<AuthState>,
    user: AuthUser,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaDisableDto>,
) -> Response {
    match state
        .engine()
        .mfa_disable(
            &user.0.sub,
            &dto.code,
            &ctx.ip,
            &ctx.user_agent,
            MfaContext::Dashboard,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/mfa/recovery-codes` (200). Requires [`AuthUser`] + a valid TOTP; returns the
/// regenerated codes exactly once.
async fn recovery_codes(
    State(state): State<AuthState>,
    user: AuthUser,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaRegenerateRecoveryCodesDto>,
) -> Response {
    match state
        .engine()
        .mfa_regenerate_recovery_codes(
            &user.0.sub,
            &dto.code,
            &ctx.ip,
            &ctx.user_agent,
            MfaContext::Dashboard,
        )
        .await
    {
        Ok(codes) => (StatusCode::OK, Json(json!({ "recoveryCodes": codes }))).into_response(),
        Err(error) => error_response(&error),
    }
}
