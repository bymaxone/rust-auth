//! Pure-Rust HS256 JSON Web Token primitive for `bymax-auth`: [`sign`], [`verify`],
//! and display-only [`decode_unverified`], with the algorithm pinned to HS256 (the
//! inbound `alg` header is never trusted to select an algorithm). The crate is
//! synchronous and depends only on `bymax-auth-crypto` and `bymax-auth-types`, so it
//! compiles unchanged to `wasm32-unknown-unknown` for edge verification.
//!
//! # Algorithm pinning
//!
//! [`verify`] asserts `header.alg == "HS256"` before any signature math and rejects
//! `none`, `RS256`, `ES256`, and every other algorithm. The HMAC tag is compared in
//! constant time, and there is exactly one (symmetric) key type, so the
//! algorithm-confusion class (CVE-2015-9235) is structurally impossible.
//!
//! # Refresh tokens are not JWTs
//!
//! [`RawRefreshToken`] is the opaque, high-entropy refresh credential. It is never
//! signed or parsed as a JWT; only its [`RawRefreshToken::redis_hash`] is persisted.
//!
//! # WebAssembly
//!
//! Signing and verification use no randomness and compile cleanly to `wasm32`. Because
//! [`RawRefreshToken::generate`] pulls `getrandom` transitively, a wasm build enables
//! this crate's `wasm-js` feature (which forwards `bymax-auth-crypto/wasm-js`) to route
//! randomness to the Web Crypto API; the edge build supplies the current time to
//! [`verify`] via [`VerifyOptions::now_unix`] since the bare-wasm target has no clock.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod hs256;
pub mod keys;

#[doc(inline)]
pub use error::JwtError;
#[doc(inline)]
pub use hs256::{decode_unverified, sign, verify};
#[doc(inline)]
pub use keys::{HsKey, JwtClaims, RawRefreshToken, VerifyOptions};
