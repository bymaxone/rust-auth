//! The `platform` route group (§8.2.5), gated behind the `platform` feature: login /
//! mfa-challenge / me / logout / refresh / revoke-all-sessions.
//!
//! `login`, `mfa/challenge`, and `refresh` are public; the rest require [`PlatformUser`].
//! Platform tokens carry no `tenantId` and live in the platform session keyspaces. Each
//! handler delegates to an engine method that resolves the platform service (guaranteed
//! present because the group mounts only when the platform domain is enabled).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use bymax_auth_types::{PlatformAuthResult, PlatformLoginResult, RotatedTokens};
use http::StatusCode;
use serde_json::json;
use tower_cookies::Cookies;

use crate::delivery::TokenDelivery;
use crate::dto::{MfaChallengeDto, PlatformLoginDto, RefreshDto};
use crate::extractors::PlatformUser;
use crate::response::error_response;
use crate::routes::{PresentedAccessToken, RequestMeta, source_refresh_token};
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `platform` group under the `platform` segment with per-route rate limits.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    Router::new()
        .route(
            "/platform/login",
            crate::router::throttled(post(login), limits.platform_login, ip_source),
        )
        .route(
            "/platform/mfa/challenge",
            crate::router::throttled(post(mfa_challenge), limits.mfa_challenge, ip_source),
        )
        .route("/platform/me", get(me))
        .route("/platform/logout", post(logout))
        .route(
            "/platform/refresh",
            crate::router::throttled(post(refresh), limits.refresh, ip_source),
        )
        .route("/platform/sessions", delete(revoke_all))
}

/// `POST /auth/platform/login` (200). Public. Full platform session or an MFA challenge.
async fn login(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<PlatformLoginDto>,
) -> Response {
    match state
        .engine()
        .platform_login(&dto.email, &dto.password, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(PlatformLoginResult::Success(result)) => {
            deliver_platform(&state, &cookies, &result, StatusCode::OK)
        }
        Ok(PlatformLoginResult::MfaChallenge(challenge)) => {
            TokenDelivery::new(state.config()).deliver_mfa_challenge(&challenge)
        }
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/platform/mfa/challenge` (200). Public — the platform post-login exchange.
async fn mfa_challenge(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaChallengeDto>,
) -> Response {
    // The MFA challenge is served by the MFA service; the temp token's `context: platform`
    // discriminant routes it through the platform store and yields a platform session. A
    // dashboard-context result is folded into a typed mismatch error inside the engine, so the
    // handler has only the success/error arms.
    #[cfg(feature = "mfa")]
    {
        match state
            .engine()
            .platform_mfa_challenge(&dto.mfa_temp_token, &dto.code, &ctx.ip, &ctx.user_agent)
            .await
        {
            Ok(auth) => deliver_platform(&state, &cookies, &auth, StatusCode::OK),
            Err(error) => error_response(&error),
        }
    }
    // A platform build without the MFA surface cannot complete a challenge.
    #[cfg(not(feature = "mfa"))]
    {
        let _ = (&state, &cookies, &ctx, &dto);
        error_response(&bymax_auth_types::AuthError::MfaNotEnabled)
    }
}

/// `GET /auth/platform/me` (200). Requires [`PlatformUser`].
async fn me(State(state): State<AuthState>, user: PlatformUser) -> Response {
    match state.engine().platform_me(&user.0.sub).await {
        Ok(safe) => (StatusCode::OK, Json(json!({ "user": safe }))).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/platform/logout` (204). Requires [`PlatformUser`].
async fn logout(
    State(state): State<AuthState>,
    cookies: Cookies,
    user: PlatformUser,
    PresentedAccessToken(access_token): PresentedAccessToken,
) -> Response {
    let refresh = source_refresh_token(&cookies, &state.config().cookies.refresh_name, None);
    let _ = state
        .engine()
        .platform_logout(&access_token, &refresh, &user.0.sub)
        .await;
    TokenDelivery::new(state.config()).clear_session(&cookies);
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /auth/platform/refresh` (200). Public. Rotates the platform token pair.
async fn refresh(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    body: axum::body::Bytes,
) -> Response {
    let dto = match parse_optional_refresh_body(&body) {
        Ok(dto) => dto,
        Err(()) => {
            return error_response(&bymax_auth_types::AuthError::Validation {
                details: vec![bymax_auth_types::FieldError {
                    field: "body".to_owned(),
                    message: "invalid refresh body".to_owned(),
                }],
            });
        }
    };
    let body_refresh = dto.refresh_token.as_deref();
    let refresh =
        source_refresh_token(&cookies, &state.config().cookies.refresh_name, body_refresh);
    match state
        .engine()
        .platform_refresh(&refresh, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(tokens) => deliver_refresh(&state, &cookies, &tokens),
        Err(error) => error_response(&error),
    }
}

/// `DELETE /auth/platform/sessions` (204). Requires [`PlatformUser`]. Revokes every platform
/// session for the admin.
async fn revoke_all(State(state): State<AuthState>, user: PlatformUser) -> Response {
    match state.engine().platform_revoke_all(&user.0.sub).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// Deliver a successful platform authentication (the same cookie/bearer/both delivery as the
/// dashboard path; isolation is by the `type` claim).
fn deliver_platform(
    state: &AuthState,
    cookies: &Cookies,
    result: &PlatformAuthResult,
    status: StatusCode,
) -> Response {
    TokenDelivery::new(state.config()).deliver_platform_auth(cookies, result, status)
}

/// Deliver a platform refresh rotation.
fn deliver_refresh(state: &AuthState, cookies: &Cookies, tokens: &RotatedTokens) -> Response {
    TokenDelivery::new(state.config()).deliver_refresh(cookies, tokens)
}

/// Parse an optional platform refresh body (empty → default; present → validated `RefreshDto`).
fn parse_optional_refresh_body(bytes: &[u8]) -> Result<RefreshDto, ()> {
    if bytes.is_empty() {
        return Ok(RefreshDto::default());
    }
    serde_json::from_slice::<RefreshDto>(bytes).map_err(|_| ())
}
