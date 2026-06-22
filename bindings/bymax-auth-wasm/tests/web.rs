//! `wasm-pack test --node` smoke tests for the edge binding.
//!
//! These run the binding inside a real WebAssembly runtime (Node, no browser required —
//! the JWT surface is pure compute and needs no Web Crypto), exercising the actual
//! `#[wasm_bindgen]` exports and the JS `Date` clock path that the host-side unit tests
//! cannot reach. The exhaustive decision coverage lives in the host `#[cfg(test)]` units;
//! this file proves the wasm artifact itself works end to end.
#![cfg(target_arch = "wasm32")]

use bymax_auth_jwt::{HsKey, sign};
use bymax_auth_types::{DashboardClaims, DashboardType};
use bymax_auth_wasm::{decode_jwt, extract_claims, verify_jwt_hs256};
use wasm_bindgen_test::wasm_bindgen_test;

/// The fixed edge secret used across the wasm smoke tests.
const SECRET: &str = "an-edge-test-hs256-secret-key-0123456789";

/// Sign a dashboard token with the given validity window.
fn sign_dashboard(iat: i64, exp: i64) -> String {
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
    };
    sign(&claims, &HsKey::from_bytes(SECRET.as_bytes())).unwrap_or_default()
}

#[wasm_bindgen_test]
fn verifies_a_backend_signed_token_in_wasm() {
    // A token whose window spans the JS `Date` clock verifies in the real wasm runtime —
    // the server/edge-parity property, proven against the actual artifact.
    let token = sign_dashboard(0, i64::MAX);
    let claims = verify_jwt_hs256(&token, SECRET.to_owned(), None);
    assert!(claims.is_some());
    assert!(
        claims
            .unwrap_or_default()
            .contains("\"type\":\"dashboard\"")
    );
}

#[wasm_bindgen_test]
fn rejects_an_expired_token_in_wasm() {
    // An already-expired token yields `undefined` under the live clock.
    let expired = sign_dashboard(0, 1);
    assert!(verify_jwt_hs256(&expired, SECRET.to_owned(), None).is_none());
}

#[wasm_bindgen_test]
fn rejects_a_wrong_secret_in_wasm() {
    // A token signed with one secret does not verify under another.
    let token = sign_dashboard(0, i64::MAX);
    assert!(
        verify_jwt_hs256(
            &token,
            "a-different-edge-secret-key-abcdef0".to_owned(),
            None
        )
        .is_none()
    );
}

#[wasm_bindgen_test]
fn rejects_an_alg_confusion_token_in_wasm() {
    // An RS256 header (algorithm-confusion attempt) is rejected inside Rust — the edge
    // never honors the inbound `alg`.
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let rs256_header = B64.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = B64.encode(r#"{"type":"dashboard","sub":"u","jti":"j","tenantId":"t","role":"r","status":"ACTIVE","mfaEnabled":false,"mfaVerified":false,"iat":0,"exp":9999999999}"#);
    let forged = format!("{rs256_header}.{payload}.sig");
    assert!(verify_jwt_hs256(&forged, SECRET.to_owned(), None).is_none());
}

#[wasm_bindgen_test]
fn decode_and_extract_round_trip_in_wasm() {
    // The decode-only views work in the wasm runtime (no signature check).
    let token = sign_dashboard(0, i64::MAX);
    let decoded = decode_jwt(&token);
    assert!(decoded.is_some());
    assert!(decoded.unwrap_or_default().contains("\"HS256\""));
    let claims = extract_claims(&token);
    assert!(claims.is_some());
    assert!(claims.unwrap_or_default().contains("\"sub\":\"u_1\""));
}

#[wasm_bindgen_test]
fn decode_jwt_returns_undefined_on_a_malformed_token_in_wasm() {
    // A malformed token surfaces as `undefined` across the boundary.
    assert!(decode_jwt("not-a-token").is_none());
}
