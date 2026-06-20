//! The `platform_mfa` route group (§8.2.6), gated behind `platform` + `mfa`: setup /
//! verify-enable / disable / recovery-codes for platform admins. All require [`PlatformUser`]
//! and run against the MFA service with the `platform` context (via the engine's MFA methods).
//! Their edge limits reuse the dashboard MFA limits (§16.3).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bymax_auth_types::MfaContext;
use http::StatusCode;
use serde_json::json;

use crate::dto::{MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaVerifyDto};
use crate::extractors::PlatformUser;
use crate::response::error_response;
use crate::routes::RequestMeta;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `platform_mfa` group under the `platform/mfa` segment, reusing the dashboard
/// MFA edge limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/platform/mfa/setup",
            crate::router::throttled(post(setup), limits.mfa_setup, ip_source),
        )
        .route(
            "/platform/mfa/verify-enable",
            crate::router::throttled(post(verify_enable), limits.mfa_verify_enable, ip_source),
        )
        .route(
            "/platform/mfa/disable",
            crate::router::throttled(post(disable), limits.mfa_disable, ip_source),
        )
        .route(
            "/platform/mfa/recovery-codes",
            crate::router::throttled(post(recovery_codes), limits.mfa_setup, ip_source),
        )
}

/// `POST /auth/platform/mfa/setup` (200). Requires [`PlatformUser`].
async fn setup(State(state): State<AuthState>, user: PlatformUser) -> Response {
    match state
        .engine()
        .mfa_setup(&user.0.sub, MfaContext::Platform)
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

/// `POST /auth/platform/mfa/verify-enable` (204). Requires [`PlatformUser`].
async fn verify_enable(
    State(state): State<AuthState>,
    user: PlatformUser,
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
            MfaContext::Platform,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/platform/mfa/disable` (204). Requires [`PlatformUser`].
async fn disable(
    State(state): State<AuthState>,
    user: PlatformUser,
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
            MfaContext::Platform,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/platform/mfa/recovery-codes` (200). Requires [`PlatformUser`].
async fn recovery_codes(
    State(state): State<AuthState>,
    user: PlatformUser,
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
            MfaContext::Platform,
        )
        .await
    {
        Ok(codes) => (StatusCode::OK, Json(json!({ "recoveryCodes": codes }))).into_response(),
        Err(error) => error_response(&error),
    }
}
