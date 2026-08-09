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
use bymax_auth_types::{AuthResult, LoginResult};
use http::StatusCode;
use tower_cookies::Cookies;

use crate::delivery::{TokenDelivery, user_body};
use crate::dto::{LoginDto, RegisterDto, ResendVerificationDto, VerifyEmailDto};
use crate::extractors::AuthUser;
use crate::response::{anti_enumerating_outcome, error_response};
use crate::routes::{
    CookieDomains, PresentedAccessToken, RequestMeta, parse_optional_refresh_body,
    source_refresh_token,
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
        .route(
            "/logout",
            crate::router::throttled(post(logout), limits.logout, ip_source),
        )
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

    // The WS-ticket mint endpoint compiles only under the `websocket` feature. It IS limited,
    // despite being authenticated and status/MFA-gated: every call writes a fresh single-use
    // ticket key, so without a ceiling one authenticated caller can mint them without bound.
    #[cfg(feature = "websocket")]
    let router = router.route(
        "/ws-ticket",
        crate::router::throttled(post(crate::ws::ws_ticket), limits.ws_ticket, ip_source),
    );

    router
}

/// `POST /auth/register` (201). Public. Issues a full session (even with verification
/// pending) and delivers it per the configured mode.
async fn register(
    State(state): State<AuthState>,
    cookies: Cookies,
    CookieDomains(domains): CookieDomains,
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
        Ok(result) => deliver_login(&state, &cookies, &domains, result, StatusCode::CREATED),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/login` (200). Public. Returns a full session or an MFA challenge.
async fn login(
    State(state): State<AuthState>,
    cookies: Cookies,
    CookieDomains(domains): CookieDomains,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<LoginDto>,
) -> Response {
    let input = LoginInput {
        email: dto.email,
        password: dto.password,
        tenant_id: dto.tenant_id,
    };
    match state.engine().login(input, &ctx).await {
        Ok(result) => deliver_login(&state, &cookies, &domains, result, StatusCode::OK),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/logout` (204). Public. Revokes the access JTI and the refresh session, then
/// clears the auth cookies.
///
/// Deliberately **not** behind [`AuthUser`]. The common case is a user returning after their
/// access token expired and signing out — under that extractor the request answered 401, so
/// the engine never ran and the refresh session stayed live for its full lifetime on a device
/// the user had just told the system to sign out. The refresh token is what authorizes this,
/// and the engine reads the session's owner from the stored record rather than from the
/// caller, so an absent or forged access token cannot aim the revocation elsewhere.
///
/// The refresh token is sourced from the cookie **or** the request body, exactly as nest-auth
/// does (`AuthController.logout` → `extractRefreshToken`). Reading only the cookie left a real
/// gap: a bearer-mode deployment plants no cookie, so the refresh session survived logout and
/// the "revoked" client could keep rotating it.
async fn logout(
    State(state): State<AuthState>,
    cookies: Cookies,
    CookieDomains(domains): CookieDomains,
    PresentedAccessToken(access_token): PresentedAccessToken,
    body: axum::body::Bytes,
) -> Response {
    // Logout is best-effort and idempotent end to end (the engine swallows store failures), so
    // an unparseable body degrades to "no body-supplied token" rather than 400-ing and leaving
    // the session alive — the cookie channel still gets its chance.
    let dto = parse_optional_refresh_body(&body).unwrap_or_default();
    let refresh = source_refresh_token(
        &cookies,
        &state.config().cookies.refresh_name,
        dto.refresh_token.as_deref(),
    );
    let _ = state.engine().logout(&access_token, &refresh).await;
    TokenDelivery::with_domains(state.config(), &domains).clear_session(&cookies);
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /auth/refresh` (200). Public. Rotates the refresh token (cookie or body) into a
/// fresh pair and delivers it **with the account echoed alongside**, as nest-auth does
/// (`AuthController.refresh` re-reads the user via `getMe` and hands an `AuthResult` to the
/// delivery layer). Returning the bare pair — or an empty `{}` in cookie mode — would force
/// every client into a second `GET /auth/me` round trip after each rotation.
async fn refresh(
    State(state): State<AuthState>,
    cookies: Cookies,
    CookieDomains(domains): CookieDomains,
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
    let refreshed = match state
        .engine()
        .refresh(&refresh, &ctx.ip, &ctx.user_agent)
        .await
    {
        Ok(refreshed) => refreshed,
        Err(error) => return error_response(&error),
    };
    // No second verify-and-look-up here: `refresh` already re-read the account to apply the
    // status and email-verification gates, and hands it back with the tokens.
    let result = AuthResult {
        user: refreshed.user,
        access_token: refreshed.tokens.access_token,
        refresh_token: refreshed.tokens.refresh_token,
    };
    TokenDelivery::with_domains(state.config(), &domains).deliver_refresh(&cookies, &result)
}

/// `GET /auth/me` (200). Requires [`AuthUser`]. Returns the credential-free user as the
/// top-level body (no wrapper) — see [`user_body`].
async fn me(State(state): State<AuthState>, user: AuthUser) -> Response {
    match state.engine().me(&user.0.sub).await {
        Ok(safe) => (StatusCode::OK, user_body(&safe)).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /auth/verify-email` (204). Public. Consumes the OTP and marks the account verified.
async fn verify_email(
    State(state): State<AuthState>,
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<VerifyEmailDto>,
) -> Response {
    match state
        .engine()
        .verify_email(dto.tenant_id.as_deref(), &dto.email, &dto.otp, &ctx)
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
    RequestMeta(ctx): RequestMeta,
    ValidatedJson(dto): ValidatedJson<ResendVerificationDto>,
) -> Response {
    // Anti-enumeration: the response is uniform regardless of what the account's state turns
    // out to be, so those `Err`s collapse to the same 204 — surfacing one would leak a
    // distinguishable signal. A request that cannot be scoped at all is the exception; see
    // `anti_enumerating_outcome`.
    let outcome = state
        .engine()
        .resend_verification_email(dto.tenant_id.as_deref(), &dto.email, &ctx)
        .await;
    anti_enumerating_outcome(&outcome, StatusCode::NO_CONTENT.into_response())
}

/// Shared delivery for a [`LoginResult`] (login/register): a full session in the configured
/// mode, or the MFA-challenge body.
fn deliver_login(
    state: &AuthState,
    cookies: &Cookies,
    domains: &[String],
    result: LoginResult,
    success_status: StatusCode,
) -> Response {
    let delivery = TokenDelivery::with_domains(state.config(), domains);
    match result {
        LoginResult::Success(auth) => delivery.deliver_auth(cookies, &auth, success_status),
        LoginResult::MfaChallenge(challenge) => delivery.deliver_mfa_challenge(&challenge),
    }
}
