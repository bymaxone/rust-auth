//! WASM edge bindings for `bymax-auth` (npm-only; not published to crates.io).
//!
//! This crate compiles the wasm-safe subset of [`bymax_auth_jwt`] to WebAssembly so the
//! edge runtime verifies JWTs with the EXACT same Rust code the native server runs —
//! eliminating the historical Web-Crypto-vs-Node drift. The JS surface is three thin
//! wrappers: [`verify_jwt_hs256`] (authoritative, signature-checked), [`decode_jwt`]
//! (decode-only header+payload), and [`extract_claims`] (decode-only typed projection).
//!
//! # Server / edge only
//!
//! [`verify_jwt_hs256`] receives the HS256 secret. The npm package marks this module and
//! its TypeScript caller `server-only`, so it can never be bundled into a browser: the
//! secret must not reach the client. The secret is moved straight into a zeroizing key and
//! wiped from WASM linear memory the instant verification finishes.
//!
//! # Algorithm pinning
//!
//! HS256 is pinned inside [`bymax_auth_jwt::verify`]; `none`/`RS256`/`ES256` are rejected
//! before any signature math, so the algorithm-confusion class is closed at the source.
//!
//! # Unsafe posture
//!
//! This is the only first-party crate that cannot `forbid(unsafe_code)`, because
//! `wasm-bindgen` emits generated `unsafe` glue at the JS boundary. That `unsafe` is
//! confined to the bindgen boundary; the crate uses `#![deny(unsafe_op_in_unsafe_fn)]` so
//! any hand-written `unsafe` must still be spelled out explicitly inside an `unsafe` block.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

mod jwt_edge;

use wasm_bindgen::prelude::wasm_bindgen;

/// Verify a backend-signed HS256 token at the edge, returning its claims as a JSON string
/// when the token is valid and unexpired, or `undefined` otherwise.
///
/// Only HS256 is accepted (`none`/`RS256`/`ES256` are rejected in Rust). `leeway_secs` is
/// the clock-skew tolerance for `exp`/`iat`; when omitted it defaults to the edge default
/// (30 seconds). The current time is read from the host clock (the JS `Date` clock on the
/// edge). The `secret` is consumed and zeroized immediately after the HMAC check — it must
/// never be exposed to a browser bundle.
#[wasm_bindgen]
pub fn verify_jwt_hs256(token: &str, secret: String, leeway_secs: Option<u32>) -> Option<String> {
    let leeway = leeway_secs.map_or(jwt_edge::DEFAULT_EDGE_LEEWAY_SECS, u64::from);
    jwt_edge::verify_claims_json(token, secret, leeway, now_unix_secs()).ok()
}

/// Decode a token's header and payload to `{"header":…,"payload":…}` JSON, or `undefined`
/// when the token is not three base64url segments / a segment is not base64url or JSON.
/// Performs **no** signature check — decode-only and non-authoritative, never gate a
/// decision on it.
#[wasm_bindgen]
pub fn decode_jwt(token: &str) -> Option<String> {
    jwt_edge::decode_header_payload(token).ok()
}

/// Project a token's claims into the matching shared claim shape and re-serialize as JSON,
/// or `undefined` when the token is malformed, carries an unknown `type`, or does not match
/// a shared claim shape. Performs **no** signature check — decode-only, non-authoritative.
#[wasm_bindgen]
pub fn extract_claims(token: &str) -> Option<String> {
    jwt_edge::extract_claims_json(token).ok()
}

/// Current Unix time in seconds, read from the JS `Date` clock on the wasm edge. The bare
/// `wasm32-unknown-unknown` target has no system clock, so the time is sourced from JS.
#[cfg(target_arch = "wasm32")]
fn now_unix_secs() -> i64 {
    // `Date::now()` is milliseconds since the epoch; floor to whole seconds.
    (js_sys::Date::now() / 1000.0) as i64
}

/// Current Unix time in seconds, read from the host system clock. Used on non-wasm hosts
/// (the unit-test/coverage build); the wasm edge uses the JS clock instead.
#[cfg(not(target_arch = "wasm32"))]
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

/// Verify a password against its stored PHC hash at the edge — the optional `wasm-extra`
/// surface, EXCLUDED from the npm-distributed JWT-only build. The password is consumed and
/// zeroized after the comparison. Returns `false` for any failure (wrong password or an
/// unparseable hash), never an oracle.
#[cfg(feature = "wasm-extra")]
#[wasm_bindgen]
pub fn verify_password(password: String, phc: &str) -> bool {
    let bytes = zeroize::Zeroizing::new(password.into_bytes());
    bymax_auth_crypto::password::verify(&bytes, phc).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_jwt_hs256_round_trips_through_the_wrapper() {
        // The wrapper reads the host clock, so sign a token whose window spans "now": a
        // far-future `exp` and a zero `iat` verify under the real system time.
        let secret = "an-edge-test-hs256-secret-key-0123456789";
        let token = sign_dashboard(secret, 0, i64::MAX);
        // Default leeway (the `None` arm).
        assert!(verify_jwt_hs256(&token, secret.to_owned(), None).is_some());
        // Explicit leeway (the `Some` arm).
        assert!(verify_jwt_hs256(&token, secret.to_owned(), Some(5)).is_some());
        // An already-expired token yields `undefined`.
        let expired = sign_dashboard(secret, 0, 1);
        assert!(verify_jwt_hs256(&expired, secret.to_owned(), None).is_none());
    }

    #[test]
    fn decode_jwt_returns_the_view_or_undefined() {
        let secret = "an-edge-test-hs256-secret-key-0123456789";
        let token = sign_dashboard(secret, 0, i64::MAX);
        assert!(decode_jwt(&token).is_some());
        // A malformed token yields `undefined`.
        assert!(decode_jwt("not-a-token").is_none());
    }

    #[test]
    fn extract_claims_returns_the_projection_or_undefined() {
        let secret = "an-edge-test-hs256-secret-key-0123456789";
        let token = sign_dashboard(secret, 0, i64::MAX);
        assert!(extract_claims(&token).is_some());
        assert!(extract_claims("not-a-token").is_none());
    }

    #[test]
    fn now_unix_secs_reads_a_plausible_host_clock() {
        // The host branch returns a positive, post-2020 timestamp.
        assert!(now_unix_secs() > 1_577_836_800);
    }

    /// Sign a dashboard token with the given secret and validity window for the wrapper
    /// tests (which run against the real host clock).
    fn sign_dashboard(secret: &str, iat: i64, exp: i64) -> String {
        use bymax_auth_jwt::{HsKey, sign};
        use bymax_auth_types::{DashboardClaims, DashboardType};
        let claims = DashboardClaims {
            sub: "u_1".to_owned(),
            jti: "jti-1".to_owned(),
            tenant_id: "t_1".to_owned(),
            role: "member".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: true,
            mfa_verified: false,
            iat,
            exp,
            epoch: 0,
        };
        sign(&claims, &HsKey::from_bytes(secret.as_bytes())).unwrap_or_default()
    }
}

#[cfg(all(test, feature = "wasm-extra"))]
mod extra_tests {
    use super::*;
    use bymax_auth_crypto::password::{PasswordParams, hash};

    #[test]
    fn verify_password_accepts_the_right_password_and_rejects_others() {
        // Hash a password (host-side, with RNG), then the edge wrapper verifies it.
        let phc = hash(b"correct horse", &PasswordParams::default()).unwrap_or_default();
        assert!(verify_password("correct horse".to_owned(), &phc));
        // A wrong password fails, and an unparseable hash fails closed (never panics).
        assert!(!verify_password("wrong".to_owned(), &phc));
        assert!(!verify_password(
            "correct horse".to_owned(),
            "not-a-phc-string"
        ));
    }
}
