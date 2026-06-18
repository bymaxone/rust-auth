//! `bymax-auth` is the single crates.io entry point for the authentication and
//! authorization engine. It re-exports the internal `bymax-auth-*` crates behind
//! feature flags, so a consumer adds one dependency and imports from one root.
//!
//! The feature taxonomy and the at-least-one-hasher guard are in place; the
//! re-export surface is layered in as the internal crates gain content.
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
