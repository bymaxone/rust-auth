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

#[cfg(feature = "api-keys")]
mod api_key;
mod client_ip;
mod delivery;
mod dto;
mod encoding_policy;
mod extractors;
mod middleware;
#[cfg(feature = "openapi")]
pub mod openapi;
mod rate_limit;
mod request_schemas;
mod response;
mod router;
mod routes;
mod shared_limit;
mod state;
mod structure;
#[cfg(test)]
mod structure_tests;
mod transport;
mod trusted_origin;
mod validation;

#[cfg(feature = "websocket")]
mod ws;

#[cfg(test)]
mod test_support;

#[cfg(all(test, feature = "api-keys"))]
mod api_key_tests;

#[cfg(all(test, feature = "openapi"))]
mod openapi_descriptions_tests;
#[cfg(all(test, feature = "openapi"))]
mod openapi_operations_tests;
#[cfg(all(test, feature = "openapi"))]
mod openapi_structures_tests;
#[cfg(all(test, feature = "openapi"))]
mod openapi_tests;

#[cfg(feature = "api-keys")]
pub use api_key::{
    ApiKeyFlushTask, ApiKeyScopes, ApiKeyScopesLayer, CurrentApiKey, require_api_key_scopes,
    spawn_api_key_flush,
};
pub use dto::{
    AcceptInvitationDto, ChangePasswordDto, CreateInvitationDto, ForgotPasswordDto, LoginDto,
    MfaChallengeDto, MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaSetupDto, MfaVerifyDto,
    OAuthCallbackQuery, OAuthInitiateQuery, PlatformLoginDto, RefreshDto, RegisterDto,
    ResendOtpDto, ResendVerificationDto, ResetPasswordDto, RevokeInvitationDto, VerifyEmailDto,
    VerifyOtpDto,
};
pub use extractors::{
    AdminRole, AuthUser, CurrentUser, MfaSatisfied, OptionalAuthUser, RequireRole, Role,
    SelfOrAdmin, UserStatus, VerifiedUser,
};
pub use rate_limit::{RateLimit, RateLimitConfig};
pub use response::{AuthRejection, error_response};
pub use router::{AuthRouter, auth_router};
pub use state::{
    AuthState, AxumAuthConfig, ClientIpSource, DEFAULT_MAX_BODY_BYTES, RouteGroups, TrustedProxyFn,
};
pub use transport::BodyRejection;
pub use validation::{ValidatedJson, ValidatedQuery};

#[cfg(feature = "platform")]
pub use extractors::{PlatformRole, PlatformUser, RequirePlatformRole};

#[cfg(feature = "websocket")]
pub use ws::{WsAuthUser, WsAuthUserFromHeader};
