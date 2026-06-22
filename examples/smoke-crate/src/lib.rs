//! Pre-publish dogfood smoke for the crate side of `rust-auth`.
//!
//! This crate carries no runtime code: the smoke is an integration test
//! (`tests/smoke.rs`) that boots the Axum router over a real `testcontainers`
//! Redis and drives the happy path against the to-be-published surface. Running it
//! before a tag proves the assembled library actually authenticates a user end to
//! end, not just that each crate compiles in isolation.
