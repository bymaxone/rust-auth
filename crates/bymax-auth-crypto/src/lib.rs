//! Pure-Rust, `wasm32`-safe cryptographic primitives for `bymax-auth`: password
//! hashing (scrypt / Argon2id), constant-time comparison, CSPRNG secure-token
//! generation, SHA-256 and keyed HMAC-SHA-256, and the MFA-gated set (AES-256-GCM
//! and RFC 6238 TOTP). All primitives are synchronous CPU work over in-memory
//! bytes — no async, no I/O — and are implemented over RustCrypto only.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
