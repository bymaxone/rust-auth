//! WASM edge bindings for `bymax-auth` (npm-only; not published to crates.io).
//!
//! This is the only first-party crate that cannot `forbid(unsafe_code)`, because
//! `wasm-bindgen` emits generated `unsafe` glue at the JS boundary. That `unsafe`
//! is confined to the bindgen boundary; the crate uses
//! `#![deny(unsafe_op_in_unsafe_fn)]` so any hand-written `unsafe` must still be
//! spelled out explicitly inside an `unsafe` block.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
