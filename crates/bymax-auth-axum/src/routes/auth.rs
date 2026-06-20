//! The `auth` route group (§8.2.1): register / login / logout / refresh / me / verify-email
//! / resend-verification, plus the `websocket`-gated `ws-ticket` mint endpoint.
//!
//! `register`, `login`, `refresh`, `verify-email`, and `resend-verification` are public;
//! `logout` and `me` require [`AuthUser`]. The handlers source request metadata, call an
//! engine method, and deliver the outcome via [`TokenDelivery`].

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bymax_auth_core::services::auth::{LoginInput, RegisterInput};
use bymax_auth_types::{LoginResult, RotatedTokens};
use http::StatusCode;
use tower_cookies::Cookies;

use crate::delivery::{TokenDelivery, user_body};
use crate::dto::{LoginDto, RegisterDto, ResendVerificationDto, VerifyEmailDto};
use crate::extractors::AuthUser;
use crate::response::error_response;
use crate::routes::{
    PresentedAccessToken, RequestMeta, parse_optional_refresh_body, source_refresh_token,
};
use crate::state::{AuthState, AxumAuthConfig, ClientIpSource};
use crate::validation::ValidatedJson;

/// Assemble the `auth` group with per-route rate-limit layers.
pub(crate) fn routes(config: &AxumAuthConfig, ip_source: ClientIpSource) -> Router<AuthState> {
    let limits = &config.rate_limits;
    let router = Router::new()
        .route(
            "/register",
            crate::router::throttled(post(register), limits.register, ip_source),
        )
        .route(
            "/login",
            crate::router::throttled(post(login), limits.login, ip_source),
        )
        .route("/logout", post(logout))
        .route(
            "/refresh",
            crate::router::throttled(post(refresh), limits.refresh, ip_source),
        )
        .route("/me", get(me))
        .route(
            "/verify-email",
            crate::router::throttled(post(verify_email), limits.verify_email, ip_source),
        )
        .route(
            "/resend-verification",
            crate::router::throttled(
                post(resend_verification),
                limits.resend_verification,
                ip_source,
            ),
        );

    // The WS-ticket mint endpoint compiles only under the `websocket` feature; it is NOT
    // assigned an edge limit (§16.3) — it is an authenticated, status- and MFA-gated route,
    // not a credential-entry path. A consumer needing to cap mint volume adds an outer limit.
    #[cfg(feature = "websocket")]
    let router = router.route("/ws-ticket", post(crate::ws::ws_ticket));

    router
}

/// `POST /auth/register` (201). Public. Issues a full session (even with verification
/// pending) and delivers it per the configured mode.
async fn register(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<RegisterDto>,
) -> Response {
    let input = RegisterInput {
        email: dto.email,
        name: dto.name,
        password: dto.password,
        tenant_id: dto.tenant_id,
    };
    match state.engine().register(input, &ctx).await {
        Ok(result) => deliver_login(&state, &cookies, result, StatusCode::CREATED),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/login` (200). Public. Returns a full session or an MFA challenge.
async fn login(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<LoginDto>,
) -> Response {
    let input = LoginInput {
        email: dto.email,
        password: dto.password,
        tenant_id: dto.tenant_id,
    };
    match state.engine().login(input, &ctx).await {
        Ok(result) => deliver_login(&state, &cookies, result, StatusCode::OK),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/logout` (204). Requires [`AuthUser`]. Revokes the access JTI and the refresh
/// session, then clears the auth cookies.
async fn logout(
    State(state): State<AuthState>,
    cookies: Cookies,
    user: AuthUser,
    PresentedAccessToken(access_token): PresentedAccessToken,
) -> Response {
    let refresh = source_refresh_token(&cookies, &state.config().cookies.refresh_name, None);
    let _ = state
        .engine()
        .logout(&access_token, &refresh, &user.0.sub)
        .await;
    TokenDelivery::new(state.config()).clear_session(&cookies);
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /auth/refresh` (200). Public. Rotates the refresh token (cookie or body) into a
/// fresh pair and delivers it.
async fn refresh(
    State(state): State<AuthState>,
    cookies: Cookies,
    RequestMeta(ctx): RequestMeta,
    body: axum::body::Bytes,
) -> Response {
    // The refresh body is optional (cookie mode sends none). Parse it leniently: an empty
    // body yields no body-supplied token, a present body must be a valid `RefreshDto`.
    let dto = match parse_optional_refresh_body(&body) {
        Ok(dto) => dto,
        Err(error) => return error_response(&error),
    };
    let body_refresh = dto.refresh_token.as_deref();
    let refresh =
        source_refresh_token(&cookies, &state.config().cookies.refresh_name, body_refresh);
    match state
        .engine()
        .refresh(&refresh, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(tokens) => deliver_refresh(&state, &cookies, &tokens),
        Err(error) => error_response(&error),
    }
}

/// `GET /auth/me` (200). Requires [`AuthUser`]. Returns the credential-free user.
async fn me(State(state): State<AuthState>, user: AuthUser) -> Response {
    match state.engine().me(&user.0.sub).await {
        Ok(safe) => (StatusCode::OK, user_body(&safe)).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/verify-email` (204). Public. Consumes the OTP and marks the account verified.
async fn verify_email(
    State(state): State<AuthState>,
    ValidatedJson(dto): ValidatedJson<VerifyEmailDto>,
) -> Response {
    match state
        .engine()
        .verify_email(&dto.tenant_id, &dto.email, &dto.otp)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/resend-verification` (204). Public + anti-enumeration: the same response
/// regardless of account existence.
async fn resend_verification(
    State(state): State<AuthState>,
    ValidatedJson(dto): ValidatedJson<ResendVerificationDto>,
) -> Response {
    // Anti-enumeration: the response is uniform regardless of the outcome, so even an `Err`
    // collapses to the same 204 — surfacing it would leak a distinguishable signal.
    let _ = state
        .engine()
        .resend_verification_email(&dto.tenant_id, &dto.email)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

/// Shared delivery for a [`LoginResult`] (login/register): a full session in the configured
/// mode, or the MFA-challenge body.
fn deliver_login(
    state: &AuthState,
    cookies: &Cookies,
    result: LoginResult,
    success_status: StatusCode,
) -> Response {
    let delivery = TokenDelivery::new(state.config());
    match result {
        LoginResult::Success(auth) => delivery.deliver_auth(cookies, &auth, success_status),
        LoginResult::MfaChallenge(challenge) => delivery.deliver_mfa_challenge(&challenge),
    }
}

/// Shared delivery for a refresh rotation.
fn deliver_refresh(state: &AuthState, cookies: &Cookies, tokens: &RotatedTokens) -> Response {
    TokenDelivery::new(state.config()).deliver_refresh(cookies, tokens)
}
