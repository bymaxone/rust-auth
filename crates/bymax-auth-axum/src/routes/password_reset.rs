//! The `password_reset` route group (§8.2.3): forgot-password / reset-password / verify-otp
//! / resend-otp. All four are public; forgot-password and resend-otp are anti-enumeration
//! (identical status/body regardless of email existence, with engine-normalized timing).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bymax_auth_core::services::auth::{
    ForgotPasswordInput, ResendResetOtpInput, ResetPasswordInput, VerifyResetOtpInput,
};
use http::StatusCode;
use serde_json::json;

use super::RequestMeta;
use crate::dto::{
    ChangePasswordDto, ForgotPasswordDto, ResendOtpDto, ResetPasswordDto, VerifyOtpDto,
};
use crate::extractors::{AuthUser, UserStatus};
use crate::response::error_response;
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `password_reset` group, scoped under the `password` segment, with per-route
/// rate-limit layers.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new().nest(
        "/password",
        Router::new()
            .route(
                "/forgot-password",
                crate::router::throttled(post(forgot_password), limits.forgot_password, ip_source),
            )
            .route(
                "/reset-password",
                crate::router::throttled(post(reset_password), limits.reset_password, ip_source),
            )
            .route(
                "/verify-otp",
                crate::router::throttled(post(verify_otp), limits.verify_otp, ip_source),
            )
            .route(
                "/resend-otp",
                crate::router::throttled(post(resend_otp), limits.resend_password_otp, ip_source),
            )
            .route(
                "/change",
                crate::router::throttled(post(change_password), limits.change_password, ip_source),
            ),
    )
}

/// `POST /auth/password/forgot-password` (200). Public + anti-enumeration.
async fn forgot_password(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ForgotPasswordDto>,
) -> Response {
    let input = ForgotPasswordInput {
        email: dto.email,
        tenant_id: dto.tenant_id,
    };
    // Anti-enumeration: the response is uniform regardless of the outcome (existence, blocked
    // status, or an infra hiccup), so even an `Err` collapses to the same 200 body — surfacing
    // it would leak a distinguishable signal the engine's timing-normalized contract forbids.
    let _ = state.engine().initiate_reset(input, &ctx).await;
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// `POST /auth/password/change` (204). **Authenticated** — the only route in this group that
/// is, which is the point: the four beside it answer to anyone who can read the account's
/// mailbox, and this one answers only to someone who holds a live session *and* knows the
/// password.
///
/// ASVS v5 §6.2.2 and §6.2.3 require it at Level 1. Without it a user who wants to rotate a
/// password they already know has to go through the anonymous recovery flow, and an attacker
/// holding a stolen session cannot be raced out of the account by the owner changing it.
async fn change_password(
    State(state): State<AuthState>,
    _status: UserStatus,
    user: AuthUser,
    ValidatedJson(dto): ValidatedJson<ChangePasswordDto>,
) -> Response {
    match state
        .engine()
        .change_password(
            &user.0.sub,
            &dto.current_password,
            &dto.new_password,
            dto.refresh_token.as_deref(),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/password/reset-password` (204). Public.
async fn reset_password(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ResetPasswordDto>,
) -> Response {
    let input = ResetPasswordInput {
        email: dto.email,
        tenant_id: dto.tenant_id,
        new_password: dto.new_password,
        token: dto.token,
        otp: dto.otp,
        verified_token: dto.verified_token,
    };
    match state.engine().reset_password(input, &ctx).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/password/verify-otp` (200). Public. Returns the short-lived verified token.
async fn verify_otp(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<VerifyOtpDto>,
) -> Response {
    let input = VerifyResetOtpInput {
        email: dto.email,
        tenant_id: dto.tenant_id,
        otp: dto.otp,
    };
    match state.engine().verify_reset_otp(input, &ctx).await {
        Ok(verified_token) => (
            StatusCode::OK,
            Json(json!({ "verifiedToken": verified_token })),
        )
            .into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/password/resend-otp` (200). Public + anti-enumeration.
async fn resend_otp(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ResendOtpDto>,
) -> Response {
    let input = ResendResetOtpInput {
        email: dto.email,
        tenant_id: dto.tenant_id,
    };
    // Anti-enumeration: uniform response regardless of the outcome (see `forgot_password`).
    let _ = state.engine().resend_reset_otp(input, &ctx).await;
    (StatusCode::OK, Json(json!({}))).into_response()
}
