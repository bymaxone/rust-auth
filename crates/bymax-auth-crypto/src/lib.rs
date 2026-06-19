//! Pure-Rust, `wasm32`-safe cryptographic primitives for `bymax-auth`: password
//! hashing (scrypt / Argon2id), constant-time comparison, CSPRNG secure-token
//! generation, SHA-256 and keyed HMAC-SHA-256, and the MFA-gated set (AES-256-GCM
//! and RFC 6238 TOTP). All primitives are synchronous CPU work over in-memory
//! bytes — no async, no I/O — and are implemented over RustCrypto only.
//!
//! # Synchronous by design
//!
//! Password hashing here is **synchronous** and memory-hard (~100–200 ms per call).
//! Callers running on an async runtime MUST dispatch [`password::hash`] and
//! [`password::verify`] through `tokio::task::spawn_blocking` (or equivalent) so a
//! single login cannot stall the runtime worker that drives every other request.
//! This crate intentionally takes no async-runtime dependency.
//!
//! # Feature flags
//!
//! - **`scrypt`** *(default)* — scrypt password hashing (the parity default writer).
//! - **`argon2`** — Argon2id password hashing (recommended for new deployments).
//! - **`mfa`** — the multi-factor set: AES-256-GCM secret encryption ([`aead`]) and
//!   RFC 6238 TOTP ([`totp`]). Pulls in `aes-gcm`, `sha1`, and `data-encoding`, all
//!   of which are absent from a build without this feature.
//!
//! At least one password-hasher feature must be enabled; see the `compile_error!`
//! below.
//!
//! # WebAssembly
//!
//! The crate compiles to `wasm32-unknown-unknown`. Following `getrandom`'s guidance
//! for reusable libraries, it does **not** select a wasm RNG backend by default. To
//! build for the web, enable this crate's **`wasm-js`** feature, which forwards to
//! `getrandom`'s browser backend (`getrandom/js`) so randomness routes to Web Crypto.
//! This crate's own wasm tests turn it on; the eventual edge consumer (the
//! `bymax-auth-wasm` binding) will enable it the same way.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// At least one password-hasher feature must be enabled. A default build has `scrypt`;
// an `--no-default-features` build must opt back into `scrypt` or `argon2`. Without a
// hasher the crate cannot hash a password at all, so this is a hard build-time error
// rather than a runtime surprise.
#[cfg(not(any(feature = "scrypt", feature = "argon2")))]
compile_error!(
    "bymax-auth-crypto requires at least one password-hasher feature: \
     enable `scrypt` (default) or `argon2`."
);

mod error;

pub mod compare;
pub mod mac;
pub mod password;
pub mod token;

#[cfg(feature = "mfa")]
pub mod aead;
#[cfg(feature = "mfa")]
pub mod totp;

pub use error::CryptoError;
