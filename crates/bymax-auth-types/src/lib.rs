//! Shared, framework-agnostic data contracts for `bymax-auth`: domain users, JWT
//! claim structures, result and error types, and configuration value types. The
//! crate is pure data (serde-(de)serializable, `ts-rs`-annotated) with no async
//! and no I/O, which keeps it compilable for `wasm32-unknown-unknown`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
