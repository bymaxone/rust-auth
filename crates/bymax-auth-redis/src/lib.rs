//! Redis-backed implementations of the `bymax-auth-core` store traits
//! (`SessionStore`, `OtpStore`, `BruteForceStore`, and the single-purpose stores).
//! Atomic operations — refresh rotation with a grace window, the brute-force
//! window, OTP verify-and-consume, and the single-use WebSocket ticket — are
//! implemented as Lua scripts. Keys are namespaced and carry no PII (high-entropy
//! secrets are SHA-256-hashed, low-entropy identifiers HMAC-SHA-256-hashed), and
//! every key has a TTL. This crate is never linked into the `wasm32` build.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
