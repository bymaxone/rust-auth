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
            // `mfa_disable`, not `mfa_setup` — see the dashboard twin in `routes/mfa.rs`.
            crate::router::throttled(post(recovery_codes), limits.mfa_disable, ip_source),
        )
}

/// `POST /auth/platform/mfa/setup` (201). Requires [`PlatformUser`]. 201 for the same reason
/// the dashboard enrolment is 201 — the shared nest-auth `MfaController.setup` has no
/// `@HttpCode`, so it answers with Nest's `POST` default.
async fn setup(
    State(state): State<AuthState>,
    user: PlatformUser,
    headers: http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // See the dashboard route: the password body is optional on the wire and the engine is
    // what decides whether this account needs one.
    let dto: crate::dto::MfaSetupDto =
        match crate::validation::validate_optional_json(&headers, &body) {
            Ok(dto) => dto,
            Err(rejection) => return rejection.into_response(),
        };
    match state
        .engine()
        .mfa_setup(
            &user.0.sub,
            MfaContext::Platform,
            // A platform admin is cross-tenant by definition, so there is no tenant to scope by.
            None,
            dto.password.as_deref(),
        )
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
            // A platform admin is cross-tenant by definition, so there is no tenant to scope by.
            None,
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
            // A platform admin is cross-tenant by definition, so there is no tenant to scope by.
            None,
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
            // A platform admin is cross-tenant by definition, so there is no tenant to scope by.
            None,
        )
        .await
    {
        Ok(codes) => (StatusCode::OK, Json(json!({ "recoveryCodes": codes }))).into_response(),
        Err(error) => error_response(&error),
    }
}
