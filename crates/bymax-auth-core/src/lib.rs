//! Framework-agnostic authentication engine for `bymax-auth`. This crate owns the
//! `AuthEngine` orchestration type, the `AuthEngineBuilder`, the resolved
//! `AuthConfig`, every authentication flow, and the object-safe plugin trait set
//! (repositories, email provider, hooks, stores, OAuth, and the dependency-free
//! `HttpClient`). It has no knowledge of HTTP, routing, or any datastore: all
//! infrastructure sits on the far side of a trait, so the engine compiles and is
//! tested with no web framework and no Redis present.
//!
//! # Layout
//!
//! - [`config`] — the strongly-typed [`config::AuthConfig`], its two default profiles,
//!   the [`config::Environment`] input, the resolver traits, and startup validation.
//! - [`context`] — the framework-neutral [`context::RequestContext`] and the
//!   credential-dropping `to_safe_*` projections.
//! - [`traits`] — the host-pluggable contracts: repositories, the email provider,
//!   lifecycle hooks, the Redis-store abstraction, OAuth providers, and the pluggable
//!   [`traits::HttpClient`] transport.
//! - [`engine`] — the [`engine::AuthEngine`] composition root and its
//!   [`engine::AuthEngineBuilder`].
//!
//! # Async-trait discipline
//!
//! Every trait stored on the engine as `Arc<dyn _>` is object-safe: the async ones use
//! `#[async_trait]`, and the purely-synchronous [`config::CookieDomainResolver`] needs
//! no macro. Secrets ([`config::JwtConfig`]'s signing secret and the MFA key) are held
//! in `secrecy` wrappers so they are redacted in `Debug`/`Display` and zeroized on drop.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod context;
pub mod engine;
mod error;
#[cfg(feature = "oauth")]
pub mod providers;
pub mod services;
pub mod traits;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[doc(inline)]
pub use config::{AuthConfig, Environment};
#[doc(inline)]
pub use engine::{AuthEngine, AuthEngineBuilder};
#[doc(inline)]
pub use error::{ConfigError, RepositoryError};
#[cfg(feature = "oauth")]
#[doc(inline)]
pub use providers::GoogleOAuthProvider;
#[cfg(feature = "oauth-reqwest")]
#[doc(inline)]
pub use providers::ReqwestHttpClient;
#[cfg(feature = "mfa")]
#[doc(inline)]
pub use services::mfa::{LoginResultMfa, MfaService, MfaSetupResult};
#[cfg(feature = "oauth")]
#[doc(inline)]
pub use services::oauth::OAuthOutcome;
