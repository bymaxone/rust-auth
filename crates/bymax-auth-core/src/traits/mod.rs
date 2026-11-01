//! The host-pluggable contract set — the architectural seam between the engine and the
//! deployment's infrastructure. Every trait here is object-safe and held on the engine
//! as `Arc<dyn _>`: the repositories, the email provider, the lifecycle hooks, the
//! Redis-store abstraction, the OAuth providers, and the dependency-free
//! [`HttpClient`] transport.

pub mod breach;
pub mod common_password;
pub mod default_email;
pub mod email;
pub mod hooks;
pub mod http;
pub mod oauth;
pub mod rate_limit;
pub mod repository;
pub mod store;
pub mod user_status_cache;

#[cfg(feature = "breach")]
#[doc(inline)]
pub use breach::HibpBreachChecker;
#[doc(inline)]
pub use breach::{AllowAllBreachChecker, PasswordBreachChecker};
pub use common_password::{CommonPasswordChecker, reduce_to_base_word};
#[doc(inline)]
pub use default_email::{
    AuthEmailCatalogue, AuthEmailContext, AuthEmailMessage, AuthEmailSink,
    DefaultAuthEmailCatalogue, DefaultAuthEmailProvider, DeliveryErrorPolicy, OutgoingEmail,
};
pub use email::{
    EmailError, EmailProvider, InviteData, NoOpEmailProvider, PLATFORM_EMAIL_TENANT, SessionInfo,
};
#[doc(inline)]
pub use hooks::{
    AuthHooks, BeforeRegisterResult, HookContext, HookError, HookPlane, LoginFailure,
    LoginFailureReason, NoOpAuthHooks, OAuthLoginResult, RegisterAttempt, RegisterOverrides,
};
#[doc(inline)]
pub use http::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
#[doc(inline)]
pub use oauth::{OAuthProfile, OAuthProvider, OAuthProviderError, OAuthProviders, OAuthTokens};
#[doc(inline)]
pub use rate_limit::RateLimitStore;
#[doc(inline)]
pub use repository::{PlatformUserRepository, UserRepository};
#[cfg(feature = "mfa")]
#[doc(inline)]
pub use store::MfaStore;
#[cfg(feature = "oauth")]
#[doc(inline)]
pub use store::OAuthStateStore;
#[doc(inline)]
pub use store::{
    BruteForceStore, EmailChangeContext, InvitationStore, OtpPurpose, OtpStore, PasswordResetStore,
    ResetContext, RotateOutcome, SessionDetail, SessionEntry, SessionKind, SessionRecord,
    SessionRotation, SessionStore, StoredInvitation, TOKEN_EPOCH_RETENTION_SECS, WsTicketSnapshot,
    WsTicketStore,
};
#[doc(inline)]
pub use user_status_cache::UserStatusCacheStore;
