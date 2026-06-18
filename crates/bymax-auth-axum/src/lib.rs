//! Axum HTTP adapter for `bymax-auth`. It exposes every `AuthEngine` capability
//! over HTTP: the router factory, the `FromRequestParts` extractors and role
//! guards, `garde`-backed DTO validation, the `AuthError` → response mapping,
//! cookie/bearer token delivery, per-route rate limiting, and the WebSocket
//! upgrade-ticket flow. The adapter depends on the core; the core never depends
//! on the adapter.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
