//! Framework-agnostic authentication engine for `bymax-auth`. This crate owns the
//! `AuthEngine` orchestration type, the `AuthEngineBuilder`, the resolved
//! `AuthConfig`, every authentication flow, and the object-safe plugin trait set
//! (repositories, email provider, hooks, stores, OAuth, and the dependency-free
//! `HttpClient`). It has no knowledge of HTTP, routing, or any datastore: all
//! infrastructure sits on the far side of a trait, so the engine compiles and is
//! tested with no web framework and no Redis present.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
