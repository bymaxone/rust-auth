//! The `platform` route group (§8.2.5), gated behind the `platform` feature: login /
//! mfa-challenge / me / logout / refresh / revoke-all-sessions.
//!
//! `login`, `mfa/challenge`, and `refresh` are public; the rest require [`PlatformUser`].
//! Platform tokens carry no `tenantId` and live in the platform session keyspaces. Each
//! handler delegates to an engine method that resolves the platform service (guaranteed
//! present because the group mounts only when the platform domain is enabled).
//!
//! **The whole group is bearer-only, whatever the configured delivery mode is** (§7.11.1 /
//! §7.11.4): no platform response ever plants a cookie, the access token is read from the
//! `Authorization: Bearer` header, and the refresh token is read from the request body. The
//! operator dashboard is not a browser session, and a dashboard cookie must never be mistaken
//! for a platform credential.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use bymax_auth_types::{PlatformAuthResult, PlatformLoginResult, RotatedTokens};
use http::StatusCode;
use serde_json::json;

use crate::delivery::TokenDelivery;
use crate::dto::{MfaChallengeDto, PlatformLoginDto};
use crate::extractors::PlatformUser;
use crate::response::error_response;
use crate::routes::{PresentedPlatformAccessToken, RequestMeta, parse_optional_refresh_body};
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
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<PlatformLoginDto>,
) -> Response {
    match state
        .engine()
        .platform_login(&dto.email, &dto.password, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(PlatformLoginResult::Success(result)) => {
            deliver_platform(&state, &result, StatusCode::OK)
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
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<MfaChallengeDto>,
) -> Response {
    // The MFA challenge is served by the MFA service; the temp token's `context: platform`
    // discriminant routes it through the platform store and yields a platform session. A
    // dashboard-context result is folded into a typed mismatch error inside the engine, so the
    // handler has only the success/error arms.
    #[cfg(feature = "mfa")]
    {
        // `MfaChallengeDto::mfa_temp_token` is optional so the browser OAuth + MFA flow can
        // carry it in the `mfa_temp_token` cookie instead of the body. That flow is dashboard-
        // only (there is no platform OAuth callback), so here the token MUST come from the
        // body — an absent one is an invalid temp token, exactly as nest-auth's
        // `PlatformAuthController.mfaChallenge` reports it. (A present-but-empty value cannot
        // reach here: the DTO's `inner(length(min = 1))` rule rejects it first.)
        let Some(temp_token) = dto.mfa_temp_token.as_deref() else {
            return error_response(&bymax_auth_types::AuthError::MfaTempTokenInvalid);
        };
        match state
            .engine()
            .platform_mfa_challenge(temp_token, &dto.code, &ctx.ip, &ctx.user_agent)
            .await
        {
            Ok(auth) => deliver_platform(&state, &auth, StatusCode::OK),
            Err(error) => error_response(&error),
        }
    }
    // A platform build without the MFA surface cannot complete a challenge.
    #[cfg(not(feature = "mfa"))]
    {
        let _ = (&state, &ctx, &dto);
        error_response(&bymax_auth_types::AuthError::MfaNotEnabled)
    }
}

/// `GET /auth/platform/me` (200). Requires [`PlatformUser`]. Returns the credential-free admin
/// as the top-level body (no wrapper), mirroring `PlatformAuthController.me`.
async fn me(State(state): State<AuthState>, user: PlatformUser) -> Response {
    match state.engine().platform_me(&user.0.sub).await {
        Ok(safe) => (StatusCode::OK, Json(json!(safe))).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/platform/logout` (204). Requires [`PlatformUser`].
///
/// The refresh token is read from the request body only: platform delivery never planted a
/// cookie, so there is none to read, and honouring the dashboard refresh cookie here would let
/// it shadow the body value and leave the platform session alive after logout.
async fn logout(
    State(state): State<AuthState>,
    user: PlatformUser,
    PresentedPlatformAccessToken(access_token): PresentedPlatformAccessToken,
    body: axum::body::Bytes,
) -> Response {
    // Best-effort, as the dashboard logout is: an unparseable body degrades to "no token"
    // rather than blocking the revocation of the access JTI.
    let dto = parse_optional_refresh_body(&body).unwrap_or_default();
    let refresh = dto.refresh_token.unwrap_or_default();
    let _ = state
        .engine()
        .platform_logout(&access_token, &refresh, &user.0.sub)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /auth/platform/refresh` (200). Public. Rotates the platform token pair and echoes the
/// admin alongside it, as `PlatformAuthController.refresh` does. The presented refresh token is
/// read from the body only (platform is always bearer).
async fn refresh(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    body: axum::body::Bytes,
) -> Response {
    let dto = match parse_optional_refresh_body(&body) {
        Ok(dto) => dto,
        Err(error) => return error_response(&error),
    };
    let refresh = dto.refresh_token.unwrap_or_default();
    let tokens = match state
        .engine()
        .platform_refresh(&refresh, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(tokens) => tokens,
        Err(error) => return error_response(&error),
    };
    match rotated_into_platform_result(&state, tokens).await {
        Ok(result) => deliver_platform(&state, &result, StatusCode::OK),
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

/// Deliver a successful platform authentication: always the bearer body
/// `{ admin, accessToken, refreshToken }`, never a cookie.
fn deliver_platform(
    state: &AuthState,
    result: &PlatformAuthResult,
    status: StatusCode,
) -> Response {
    TokenDelivery::new(state.config()).deliver_platform_auth(result, status)
}

/// Pair a rotated platform token pair with the admin it belongs to, producing the
/// [`PlatformAuthResult`] the refresh body carries. The subject comes from the freshly-minted
/// platform access token (it verifies by construction) and the record is re-read through
/// `platform_me` — the "rotate, then `getMe`" sequence nest-auth's controller performs.
async fn rotated_into_platform_result(
    state: &AuthState,
    tokens: RotatedTokens,
) -> Result<PlatformAuthResult, bymax_auth_types::AuthError> {
    let claims = state
        .engine()
        .verify_platform_token(&tokens.access_token)
        .await?;
    let admin = state.engine().platform_me(&claims.sub).await?;
    Ok(PlatformAuthResult {
        admin,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    })
}
