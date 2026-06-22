//! The pure-Rust edge JWT core: signature verification, decode-only projection, and the
//! raw header+payload view. Every function here is host-testable and free of any JS
//! boundary, so the workspace coverage gate exercises the whole decision surface on the
//! host; the `#[wasm_bindgen]` wrappers in [`crate`] stay thin.
//!
//! # One implementation, server and edge
//!
//! Verification delegates to [`bymax_auth_jwt::verify`] — the EXACT codec the native
//! server uses — so the edge and the server can never disagree on whether a token is
//! valid. HS256 is pinned inside that codec: `none`/`RS256`/`ES256` are rejected before
//! any signature math, closing the algorithm-confusion class at the source.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bymax_auth_jwt::{HsKey, JwtError, VerifyOptions, decode_unverified, verify};
use bymax_auth_types::{DashboardClaims, MfaTempClaims, PlatformClaims};
use serde::Deserialize;
use serde::Serialize;

/// Failure category for the edge surface. Like [`JwtError`], the variants name only the
/// *category* so an error value can never become an oracle: a caller learns "this token
/// is not usable", never which internal step failed.
#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    /// The token failed signature/temporal verification or typed decoding.
    #[error("invalid token")]
    Jwt(#[from] JwtError),
    /// The token is not three base64url segments, a segment is not base64url, or a
    /// segment is not JSON (the decode-only paths that never reach the JWT codec).
    #[error("malformed token")]
    Malformed,
    /// The payload carries no recognized `type` discriminator, so it maps to none of the
    /// shared claim structures.
    #[error("unknown token type")]
    UnknownType,
}

/// Default edge clock-skew tolerance, in seconds. Edge nodes may drift slightly from the
/// issuing server (§13.6), so the edge accepts a small leeway the authoritative server
/// does not. Kept far below the access-token lifetime, so it never meaningfully extends a
/// token. Adjustable per call via the binding's `leeway_secs` argument.
pub const DEFAULT_EDGE_LEEWAY_SECS: u64 = 30;

/// The three shared claim shapes the edge can verify, selected by the `type`
/// discriminator. The codec's [`bymax_auth_jwt::JwtClaims`] trait is sealed, so the edge
/// dispatches over exactly these structs rather than a generic claims type.
enum TokenKind {
    /// A tenant/dashboard access token (`type: "dashboard"`).
    Dashboard,
    /// A platform-admin access token (`type: "platform"`).
    Platform,
    /// A short-lived MFA-temp token (`type: "mfa_challenge"`).
    MfaTemp,
}

/// Minimal projection used to read the (still unverified) `type` discriminator before
/// dispatching to the matching claim struct. The discriminator only steers which struct
/// is deserialized; [`verify`] still requires a valid signature, so a forged `type`
/// cannot bypass authentication.
#[derive(Deserialize)]
struct TypePeek {
    /// The wire discriminator (`type`).
    #[serde(rename = "type")]
    token_type: String,
}

/// Read the unverified `type` discriminator and map it to a [`TokenKind`].
fn peek_kind(token: &str) -> Result<TokenKind, EdgeError> {
    let peek: TypePeek = decode_unverified(token)?;
    match peek.token_type.as_str() {
        "dashboard" => Ok(TokenKind::Dashboard),
        "platform" => Ok(TokenKind::Platform),
        "mfa_challenge" => Ok(TokenKind::MfaTemp),
        _ => Err(EdgeError::UnknownType),
    }
}

/// Serialize verified/decoded claims back to a JSON string.
fn to_json<C: Serialize>(claims: &C) -> Result<String, EdgeError> {
    serde_json::to_string(claims).map_err(|_| EdgeError::Malformed)
}

/// Verify a backend-signed HS256 token at the edge and return its claims as JSON.
///
/// The `secret` is taken by value and moved straight into a [`HsKey`] (a `Zeroizing`
/// buffer), so the only Rust-side copy of the secret is wiped from WASM linear memory the
/// instant verification finishes — including on every early-return path, since the key is
/// constructed before the first fallible step. Returns the canonical JSON of the verified
/// claims, or an [`EdgeError`] if the signature, expiry, `iat`, or claim shape is invalid.
///
/// HS256 is pinned in [`bymax_auth_jwt::verify`]; `none`/`RS256`/`ES256` are rejected
/// before any signature math.
///
/// # Errors
///
/// Returns [`EdgeError`] when the token is malformed, carries an unknown `type`, fails the
/// HMAC/temporal checks, or does not deserialize into the matching claim struct.
pub fn verify_claims_json(
    token: &str,
    secret: String,
    leeway_secs: u64,
    now_unix: i64,
) -> Result<String, EdgeError> {
    // Construct the zeroizing key FIRST, before any fallible step, so the secret bytes are
    // wiped on drop no matter which path returns. `into_bytes` reuses the String's buffer,
    // so there is no second lingering copy of the secret.
    let key = HsKey::new(secret.into_bytes());
    let opts = VerifyOptions {
        leeway_secs,
        validate_exp: true,
        validate_iat: true,
        now_unix: Some(now_unix),
    };
    let result = match peek_kind(token) {
        Ok(TokenKind::Dashboard) => verify::<DashboardClaims>(token, &key, &opts)
            .map_err(EdgeError::Jwt)
            .and_then(|c| to_json(&c)),
        Ok(TokenKind::Platform) => verify::<PlatformClaims>(token, &key, &opts)
            .map_err(EdgeError::Jwt)
            .and_then(|c| to_json(&c)),
        Ok(TokenKind::MfaTemp) => verify::<MfaTempClaims>(token, &key, &opts)
            .map_err(EdgeError::Jwt)
            .and_then(|c| to_json(&c)),
        Err(error) => Err(error),
    };
    // Drop the key the instant verification is done — the secret bytes are zeroized here.
    drop(key);
    result
}

/// Project a token's claims into the matching shared claim struct and re-serialize, with
/// **no** signature or temporal check. For display/diagnostics only — the result is
/// unauthenticated and MUST NEVER gate an authorization decision.
///
/// # Errors
///
/// Returns [`EdgeError`] if the token is malformed, carries an unknown `type`, or does not
/// deserialize into the matching claim struct.
pub fn extract_claims_json(token: &str) -> Result<String, EdgeError> {
    match peek_kind(token)? {
        TokenKind::Dashboard => to_json(&decode_unverified::<DashboardClaims>(token)?),
        TokenKind::Platform => to_json(&decode_unverified::<PlatformClaims>(token)?),
        TokenKind::MfaTemp => to_json(&decode_unverified::<MfaTempClaims>(token)?),
    }
}

/// Decode a token's header and payload to a `{"header":…,"payload":…}` JSON object, with
/// **no** signature check (decode-only, non-authoritative). Mirrors nest-auth's display
/// `decodeToken`, but returns the header too.
///
/// # Errors
///
/// Returns [`EdgeError::Malformed`] if the token is not three base64url segments, a
/// segment is not valid base64url, or a segment is not JSON.
pub fn decode_header_payload(token: &str) -> Result<String, EdgeError> {
    let (header_b64, payload_b64) = split_header_payload(token)?;
    let header = decode_segment_json(header_b64)?;
    let payload = decode_segment_json(payload_b64)?;
    let combined = serde_json::json!({ "header": header, "payload": payload });
    serde_json::to_string(&combined).map_err(|_| EdgeError::Malformed)
}

/// Split a compact JWS into its header and payload segments, rejecting anything that is
/// not exactly three `.`-separated parts.
fn split_header_payload(token: &str) -> Result<(&str, &str), EdgeError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(_signature), None) => Ok((header, payload)),
        _ => Err(EdgeError::Malformed),
    }
}

/// Base64url-decode a segment and parse it as a JSON value.
fn decode_segment_json(segment: &str) -> Result<serde_json::Value, EdgeError> {
    let bytes = B64.decode(segment).map_err(|_| EdgeError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| EdgeError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bymax_auth_jwt::sign;
    use bymax_auth_types::{DashboardType, MfaContext, MfaTempType, PlatformType};

    /// A fixed secret so signatures are reproducible across runs.
    const SECRET: &[u8] = b"an-edge-test-hs256-secret-key-0123456789";

    fn secret_string() -> String {
        // The verify entrypoint takes the secret by value (it is moved into the zeroizing
        // key), so each test hands it a fresh owned copy.
        String::from_utf8(SECRET.to_vec()).unwrap_or_default()
    }

    fn dashboard(iat: i64, exp: i64) -> DashboardClaims {
        DashboardClaims {
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
        }
    }

    fn sign_dashboard(iat: i64, exp: i64) -> String {
        sign(&dashboard(iat, exp), &HsKey::from_bytes(SECRET)).unwrap_or_default()
    }

    #[test]
    fn verifies_a_dashboard_token_and_returns_its_claims_json() {
        // A backend-signed access token verifies at the edge and the JSON carries the
        // wire field names (the server/edge-parity guarantee).
        let token = sign_dashboard(1_000, 2_000);
        let json = verify_claims_json(&token, secret_string(), 0, 1_500).unwrap_or_default();
        assert!(json.contains("\"type\":\"dashboard\""));
        assert!(json.contains("\"tenantId\":\"t_1\""));
        assert!(json.contains("\"mfaEnabled\":true"));
    }

    #[test]
    fn verifies_a_platform_token() {
        // Platform access tokens dispatch to PlatformClaims and round-trip to JSON.
        let claims = PlatformClaims {
            sub: "p_1".to_owned(),
            jti: "jti-2".to_owned(),
            role: "admin".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: true,
            iat: 1_000,
            exp: 2_000,
        };
        let token = sign(&claims, &HsKey::from_bytes(SECRET)).unwrap_or_default();
        let json = verify_claims_json(&token, secret_string(), 0, 1_500);
        assert!(matches!(&json, Ok(j) if j.contains("\"type\":\"platform\"")));
    }

    #[test]
    fn verifies_an_mfa_temp_token() {
        // MFA-temp tokens dispatch to MfaTempClaims.
        let claims = MfaTempClaims {
            sub: "u_1".to_owned(),
            jti: "jti-3".to_owned(),
            token_type: MfaTempType::MfaChallenge,
            context: MfaContext::Platform,
            iat: 1_000,
            exp: 2_000,
        };
        let token = sign(&claims, &HsKey::from_bytes(SECRET)).unwrap_or_default();
        let json = verify_claims_json(&token, secret_string(), 0, 1_500);
        assert!(matches!(&json, Ok(j) if j.contains("\"type\":\"mfa_challenge\"")));
    }

    #[test]
    fn rejects_an_expired_token() {
        // `exp` is the first invalid second; at `exp` the edge rejects.
        let token = sign_dashboard(1_000, 2_000);
        assert!(verify_claims_json(&token, secret_string(), 0, 2_000).is_err());
        // One second earlier it is still valid.
        assert!(verify_claims_json(&token, secret_string(), 0, 1_999).is_ok());
    }

    #[test]
    fn leeway_extends_validity_up_to_the_edge() {
        // A small edge leeway keeps an expiring token valid up to (but not including)
        // `exp + leeway`, tolerating edge clock drift.
        let token = sign_dashboard(1_000, 2_000);
        assert!(verify_claims_json(&token, secret_string(), 5, 2_004).is_ok());
        assert!(verify_claims_json(&token, secret_string(), 5, 2_005).is_err());
    }

    #[test]
    fn rejects_a_token_issued_in_the_future_beyond_leeway() {
        // An `iat` beyond now+leeway is an invalid token (TokenInvalid at the boundary).
        let token = sign_dashboard(5_000, 9_000);
        assert!(verify_claims_json(&token, secret_string(), 0, 1_000).is_err());
    }

    #[test]
    fn rejects_a_wrong_secret() {
        // A token signed with one secret must not verify under another.
        let token = sign_dashboard(1_000, 2_000);
        let other = String::from("a-different-edge-secret-9876543210ab-xx");
        assert!(verify_claims_json(&token, other, 0, 1_500).is_err());
    }

    #[test]
    fn rejects_an_unknown_token_type() {
        // A payload whose `type` is not one of the three shared shapes maps to no claim
        // struct — UnknownType, never a verified result.
        let weird = sign(
            &serde_json::json!({ "type": "session", "iat": 1, "exp": 9 }),
            &HsKey::from_bytes(SECRET),
        )
        .unwrap_or_default();
        assert!(matches!(
            verify_claims_json(&weird, secret_string(), 0, 5),
            Err(EdgeError::UnknownType)
        ));
        // And the decode-only projection rejects it the same way.
        assert!(matches!(
            extract_claims_json(&weird),
            Err(EdgeError::UnknownType)
        ));
    }

    #[test]
    fn rejects_a_payload_without_a_type() {
        // No `type` field at all is a decode failure on the peek (mapped through Jwt).
        let no_type =
            sign(&serde_json::json!({ "x": 1 }), &HsKey::from_bytes(SECRET)).unwrap_or_default();
        assert!(verify_claims_json(&no_type, secret_string(), 0, 5).is_err());
    }

    #[test]
    fn rejects_a_type_mismatch_against_the_signed_shape() {
        // `type: "dashboard"` but signed as a platform-shaped payload: the signature is
        // valid, but DashboardClaims fails to deserialize → rejected (no bypass).
        let token = sign(
            &serde_json::json!({
                "type": "dashboard", "sub": "p", "jti": "j", "role": "admin",
                "mfaEnabled": false, "mfaVerified": true, "iat": 1, "exp": 9
            }),
            &HsKey::from_bytes(SECRET),
        )
        .unwrap_or_default();
        assert!(verify_claims_json(&token, secret_string(), 0, 5).is_err());
    }

    #[test]
    fn extract_claims_projects_each_type_without_verifying() {
        // The decode-only projection returns typed claims even when the signature is wrong
        // (it never checks it) — for display only.
        let mut segments: Vec<String> = sign_dashboard(1_000, 2_000)
            .split('.')
            .map(str::to_owned)
            .collect();
        segments[2] = B64.encode([0u8; 32]); // forge the signature; decode ignores it
        let forged = segments.join(".");
        let json = extract_claims_json(&forged);
        assert!(matches!(&json, Ok(j) if j.contains("\"sub\":\"u_1\"")));

        // Exercise the platform and mfa-temp projection arms too.
        let platform = sign(
            &PlatformClaims {
                sub: "p_1".to_owned(),
                jti: "jti-2".to_owned(),
                role: "admin".to_owned(),
                token_type: PlatformType::Platform,
                mfa_enabled: false,
                mfa_verified: true,
                iat: 1_000,
                exp: 2_000,
            },
            &HsKey::from_bytes(SECRET),
        )
        .unwrap_or_default();
        assert!(
            matches!(extract_claims_json(&platform), Ok(j) if j.contains("\"type\":\"platform\""))
        );

        let mfa = sign(
            &MfaTempClaims {
                sub: "u_1".to_owned(),
                jti: "jti-3".to_owned(),
                token_type: MfaTempType::MfaChallenge,
                context: MfaContext::Dashboard,
                iat: 1_000,
                exp: 2_000,
            },
            &HsKey::from_bytes(SECRET),
        )
        .unwrap_or_default();
        assert!(
            matches!(extract_claims_json(&mfa), Ok(j) if j.contains("\"type\":\"mfa_challenge\""))
        );
    }

    #[test]
    fn extract_claims_rejects_a_malformed_token() {
        // A structurally broken token cannot be projected.
        assert!(extract_claims_json("not-a-token").is_err());
    }

    #[test]
    fn decode_header_payload_returns_both_segments() {
        // The decode-only view exposes the header (alg/typ) and the payload, no sig check.
        let token = sign_dashboard(1_000, 2_000);
        let json = decode_header_payload(&token).unwrap_or_default();
        assert!(json.contains("\"header\""));
        assert!(json.contains("\"HS256\""));
        assert!(json.contains("\"payload\""));
        assert!(json.contains("\"sub\":\"u_1\""));
    }

    #[test]
    fn decode_header_payload_rejects_malformed_framing() {
        // Not three segments, bad base64url, and non-JSON segments are all Malformed.
        assert!(matches!(
            decode_header_payload("a.b"),
            Err(EdgeError::Malformed)
        ));
        assert!(matches!(
            decode_header_payload("a.b.c.d"),
            Err(EdgeError::Malformed)
        ));
        assert!(matches!(
            decode_header_payload("!!!.b.c"),
            Err(EdgeError::Malformed)
        ));
        // Valid base64url header, but the bytes are not JSON.
        let not_json = B64.encode("not json");
        let token = format!("{not_json}.{not_json}.sig");
        assert!(matches!(
            decode_header_payload(&token),
            Err(EdgeError::Malformed)
        ));
    }

    #[test]
    fn edge_error_displays_a_category_only() {
        // The Display strings name only the category, never an internal step — no oracle.
        assert_eq!(EdgeError::Malformed.to_string(), "malformed token");
        assert_eq!(EdgeError::UnknownType.to_string(), "unknown token type");
        assert_eq!(
            EdgeError::Jwt(JwtError::BadSignature).to_string(),
            "invalid token"
        );
    }

    #[test]
    fn default_edge_leeway_is_small() {
        // The shipped default leeway is well under the access lifetime so it never
        // meaningfully extends a token.
        assert_eq!(DEFAULT_EDGE_LEEWAY_SECS, 30);
    }
}
