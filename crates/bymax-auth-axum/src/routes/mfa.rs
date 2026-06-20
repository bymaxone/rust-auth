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
use bymax_auth_types::MfaContext;
use http::StatusCode;
use serde_json::json;

use crate::delivery::TokenDelivery;
use crate::dto::{MfaChallengeDto, MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaVerifyDto};
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

/// `POST /auth/mfa/setup` (200). Requires [`AuthUser`], not `MfaSatisfied` (enrolment).
async fn setup(State(state): State<AuthState>, user: AuthUser) -> Response {
    match state
        .engine()
        .mfa_setup(&user.0.sub, MfaContext::Dashboard)
        .await
    {
        Ok(result) => (
            StatusCode::OK,
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
async fn challenge(
    State(state): State<AuthState>,
    cookies: tower_cookies::Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaChallengeDto>,
) -> Response {
    match state
        .engine()
        .dashboard_mfa_challenge(&dto.mfa_temp_token, &dto.code, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(auth) => {
            TokenDelivery::new(state.config()).deliver_auth(&cookies, &auth, StatusCode::OK)
        }
        Err(error) => error_response(&error),
    }
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
