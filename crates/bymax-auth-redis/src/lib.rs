//! Redis-backed implementations of the `bymax-auth-core` store traits
//! ([`SessionStore`](bymax_auth_core::traits::SessionStore),
//! [`OtpStore`](bymax_auth_core::traits::OtpStore),
//! [`BruteForceStore`](bymax_auth_core::traits::BruteForceStore), and
//! [`WsTicketStore`](bymax_auth_core::traits::WsTicketStore)) over `redis` +
//! `deadpool-redis`.
//!
//! Every read-decide-write transition that could race under concurrency — refresh rotation
//! with a grace window, the ownership-checked session revoke, the revoke-all transaction,
//! the fixed-window brute-force counter, the attempt-bounded OTP verify, and the single-use
//! WebSocket ticket — runs as a single atomic Lua script (section 12.5). Keys are namespaced
//! and carry no PII: high-entropy secrets are SHA-256-hashed and low-entropy identifiers are
//! HMAC-SHA-256-hashed by the engine before they reach this crate, the WebSocket ticket is
//! hashed here, and every key has a TTL (section 24, invariants 9 and 15). Stored JSON is
//! camelCase, byte-identical to nest-auth so the two backends can share one Redis.
//!
//! A single [`RedisStores`] handle implements all four traits, so it wires straight into
//! `AuthEngineBuilder::redis_stores`. This crate depends on `tokio` and the Redis driver and
//! is **never** linked into the `wasm32` edge build.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod keys;
mod pool;
mod script;
mod stores;

pub use error::RedisStoreError;
pub use keys::{NamespacedRedis, Prefix};
pub use pool::RedisStores;
