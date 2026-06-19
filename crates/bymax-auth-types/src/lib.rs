//! Shared, framework-agnostic data contracts for `bymax-auth`: domain users, JWT
//! claim structures, result and error types, and the shared constants. The crate is
//! pure data (serde-(de)serializable, optionally `ts-rs`-annotated) with no async
//! and no I/O, which keeps it compilable for `wasm32-unknown-unknown`.
//!
//! # Single source of truth
//!
//! Every type that crosses the HTTP boundary lives here once and is mirrored to
//! TypeScript by `ts-rs` (under the `ts-export` feature), so the npm `./shared`
//! surface can never drift from the Rust contract. The wire shapes are byte-for-byte
//! compatible with `@bymax-one/nest-auth` (camelCase field names, the `type`
//! discriminator, the `auth.*` error codes).
//!
//! # Feature flags
//!
//! - **`ts-export`** — pulls in `ts-rs` and turns on the derives that regenerate the
//!   committed TypeScript declarations. Build/dev-only; never enabled in a runtime
//!   build, so `ts-rs` stays out of a crates.io consumer's dependency tree.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod constants;
pub mod domain;
pub mod error;
pub mod results;

#[doc(inline)]
pub use claims::{
    DashboardClaims, DashboardType, MfaContext, MfaTempClaims, MfaTempType, PlatformClaims,
    PlatformType,
};
#[doc(inline)]
pub use domain::{
    AuthPlatformUser, AuthUser, CreateUserData, CreateWithOAuthData, SafeAuthPlatformUser,
    SafeAuthUser, UpdateMfaData, UpdatePlatformMfaData,
};
#[doc(inline)]
pub use error::{
    AuthError, AuthErrorBody, AuthErrorCode, AuthErrorEnvelope, AuthErrorResponse, FieldError,
};
#[doc(inline)]
pub use results::{
    AuthResult, LoginResult, MfaChallengeResult, PlatformAuthResult, PlatformLoginResult,
    RotatedTokens,
};
