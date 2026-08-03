//! `bymax-auth` is the single crates.io entry point for the authentication and
//! authorization engine. It re-exports the internal `bymax-auth-*` crates behind
//! feature flags, so a consumer adds one dependency and imports from one root.
//!
//! Every feature here forwards to the internal crate that implements it, and the re-exports
//! below follow the same gating — so a build that enables `mfa` gets the MFA-capable engine,
//! and one that does not cannot reach the MFA surface at all. The features used to be empty
//! placeholders, which meant `bymax-auth/mfa` turned nothing on in `bymax-auth-core`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// At least one password-hasher feature must be enabled. `scrypt` is on by default;
// `argon2` is the recommended choice for new projects via
// `AuthConfig::secure_defaults()`. Building with neither is rejected at compile
// time rather than failing later at runtime.
#[cfg(not(any(feature = "scrypt", feature = "argon2")))]
compile_error!(
    "bymax-auth requires at least one password-hasher feature: enable `scrypt` \
     (default) or `argon2` (recommended for new projects via \
     AuthConfig::secure_defaults())."
);

/// The engine, its configuration and its trait seams.
pub use bymax_auth_core as core;
/// The shared domain types and the `auth.*` error catalogue.
pub use bymax_auth_types as types;

/// The Redis-backed store implementations.
#[cfg(feature = "redis")]
#[cfg_attr(docsrs, doc(cfg(feature = "redis")))]
pub use bymax_auth_redis as redis;

/// The axum HTTP adapter: router, extractors and middleware.
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub use bymax_auth_axum as axum;

/// The typed HTTP client for the auth API.
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use bymax_auth_client as client;
