//! Axum HTTP adapter for `bymax-auth`. It exposes every `AuthEngine` capability
//! over HTTP: the router factory, the `FromRequestParts` extractors and role
//! guards, `garde`-backed DTO validation, the `AuthError` → response mapping,
//! cookie/bearer token delivery, per-route rate limiting, and the WebSocket
//! upgrade-ticket flow. The adapter depends on the core; the core never depends
//! on the adapter.
//!
//! # Routing is derived from the engine
//!
//! [`auth_router`] reads the engine's resolved `ControllerToggles` and mounts exactly the
//! enabled groups under the configured prefix — a disabled toggle (or an absent Cargo
//! feature) contributes **zero** routes, so the route surface can never disagree with what
//! the engine wired (§24 invariant 11).
//!
//! # No token ever comes from the query string
//!
//! Every HTTP guard sources the access token from the cookie or the `Authorization` header
//! only (§24 invariant 4). The single, deliberately narrow exception is the WebSocket
//! upgrade ticket — a single-use, ~30 s opaque credential redeemed exactly once at the
//! upgrade endpoint, never a JWT.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod delivery;
mod dto;
mod extractors;
mod middleware;
mod rate_limit;
mod response;
mod router;
mod routes;
mod state;
mod validation;

#[cfg(feature = "websocket")]
mod ws;

#[cfg(test)]
mod test_support;

pub use dto::{
    AcceptInvitationDto, CreateInvitationDto, ForgotPasswordDto, LoginDto, MfaChallengeDto,
    MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaVerifyDto, OAuthCallbackQuery,
    OAuthInitiateQuery, PlatformLoginDto, RefreshDto, RegisterDto, ResendOtpDto,
    ResendVerificationDto, ResetPasswordDto, VerifyEmailDto, VerifyOtpDto,
};
pub use extractors::{
    AdminRole, AuthUser, CurrentUser, MfaSatisfied, OptionalAuthUser, RequireRole, Role,
    SelfOrAdmin, UserStatus,
};
pub use rate_limit::{RateLimit, RateLimitConfig};
pub use response::{AuthRejection, error_response};
pub use router::{AuthRouter, auth_router};
pub use state::{AuthState, AxumAuthConfig, ClientIpSource, DEFAULT_MAX_BODY_BYTES, RouteGroups};
pub use validation::{ValidatedJson, ValidatedQuery};

#[cfg(feature = "platform")]
pub use extractors::{PlatformRole, PlatformUser, RequirePlatformRole};

#[cfg(feature = "websocket")]
pub use ws::{WsAuthUser, WsAuthUserFromHeader};
