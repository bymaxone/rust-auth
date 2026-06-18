//! Pure-Rust HS256 JSON Web Token primitive for `bymax-auth`: `sign`, `verify`,
//! and display-only `decode_unverified`, with the algorithm pinned to HS256 (the
//! inbound `alg` header is never trusted to select an algorithm). The crate is
//! synchronous and depends only on `bymax-auth-crypto` and `bymax-auth-types`, so
//! it compiles unchanged to `wasm32-unknown-unknown` for edge verification.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
