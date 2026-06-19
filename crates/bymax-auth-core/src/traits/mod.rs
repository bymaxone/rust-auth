//! The host-pluggable contract set — the architectural seam between the engine and the
//! deployment's infrastructure. Every trait here is object-safe and held on the engine
//! as `Arc<dyn _>`: the repositories, the email provider, the lifecycle hooks, the
//! Redis-store abstraction, the OAuth providers, and the dependency-free
//! [`HttpClient`] transport.

pub mod email;
pub mod hooks;
pub mod http;
pub mod oauth;
pub mod repository;
pub mod store;

#[doc(inline)]
pub use email::{EmailError, EmailProvider, InviteData, NoOpEmailProvider, SessionInfo};
#[doc(inline)]
pub use hooks::{
    AuthHooks, BeforeRegisterResult, HookContext, HookError, NoOpAuthHooks, OAuthLoginResult,
    RegisterAttempt, RegisterOverrides,
};
#[doc(inline)]
pub use http::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
#[doc(inline)]
pub use oauth::{OAuthProfile, OAuthProvider, OAuthProviderError, OAuthProviders, OAuthTokens};
#[doc(inline)]
pub use repository::{PlatformUserRepository, UserRepository};
#[doc(inline)]
pub use store::{
    BruteForceStore, OtpPurpose, OtpStore, RotateOutcome, SessionDetail, SessionKind,
    SessionRecord, SessionRotation, SessionStore, WsTicketSnapshot, WsTicketStore,
};

#[cfg(feature = "oauth-reqwest")]
#[doc(inline)]
pub use http::ReqwestHttpClient;
