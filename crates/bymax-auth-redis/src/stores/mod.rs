//! The concrete `bymax-auth-core` store-trait implementations over the pooled Redis handle.
//!
//! Each submodule implements one trait on [`crate::RedisStores`]: refresh-session lifecycle
//! plus access-token blacklist ([`session`]), one-time passwords ([`otp`]), the fixed-window
//! brute-force counter ([`brute_force`]), and the single-use WebSocket ticket ([`ws_ticket`]).
//! The atomic, race-sensitive transitions run as Lua scripts (section 12.5); the rest are
//! single commands. Every fallible Redis interaction is funneled through a private
//! `Result<_, RedisStoreError>` helper, and the trait method projects that into the engine's
//! [`bymax_auth_types::AuthError`] at the boundary.

mod brute_force;
mod otp;
mod session;
mod ws_ticket;
