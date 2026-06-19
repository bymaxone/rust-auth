//! The pure-Rust HS256 JWS codec: [`sign`], [`verify`], and [`decode_unverified`].
//!
//! Built on `bymax-auth-crypto`'s HMAC-SHA-256 and constant-time comparison plus
//! base64url + `serde_json`. The algorithm is pinned to HS256: [`verify`] asserts
//! `header.alg == "HS256"` before any signature math and rejects `alg: none`, `RS256`,
//! and every other algorithm (closing the algorithm-confusion class, CVE-2015-9235);
//! there is exactly one (symmetric) key type, so there is no asymmetric public key an
//! attacker could repurpose.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_crypto::mac::hmac_sha256;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::JwtError;
use crate::keys::{HsKey, JwtClaims, VerifyOptions};

/// The fixed compact-JWS header. HS256 is hard-wired, so the header is a constant —
/// there is nothing to serialize and no `alg` to choose.
const HEADER_JSON: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// The pinned signing algorithm.
const HS256: &str = "HS256";

/// Minimal view of the JWS header — only the `alg` is consulted (and pinned).
#[derive(serde::Deserialize)]
struct Header {
    /// The signature algorithm; must equal [`HS256`].
    alg: String,
}

/// Sign `claims` into a compact HS256 JWS string: `base64url(header).base64url(payload).
/// base64url(HMAC-SHA256(header.payload))`.
///
/// # Errors
///
/// Returns [`JwtError::Decode`] if the claims fail to serialize (unreachable for the
/// crate's claim types, which derive `Serialize`).
pub fn sign<C: Serialize>(claims: &C, key: &HsKey) -> Result<String, JwtError> {
    let payload_json = serde_json::to_vec(claims).map_err(|_| JwtError::Decode)?;
    let header_b64 = B64.encode(HEADER_JSON);
    let payload_b64 = B64.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = hmac_sha256(key.as_bytes(), signing_input.as_bytes());
    let signature_b64 = B64.encode(signature);
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verify a compact HS256 JWS and deserialize its claims.
///
/// Enforces, in order: three base64url segments → `header.alg == "HS256"` (before any
/// signature math) → constant-time HMAC tag check → `exp`/`iat` per `opts`. JTI-blacklist
/// consultation is a separate guard/store step and is **not** performed here.
///
/// # Errors
///
/// - [`JwtError::Malformed`] — not three segments, a segment is not base64url, the header
///   is not JSON, or `iat` is in the future beyond the leeway.
/// - [`JwtError::UnsupportedAlg`] — `alg` is anything other than `HS256` (including `none`).
/// - [`JwtError::BadSignature`] — the HMAC tag does not match.
/// - [`JwtError::Expired`] — `exp` is in the past beyond the leeway.
/// - [`JwtError::Decode`] — the payload does not deserialize into `C`.
pub fn verify<C: DeserializeOwned + JwtClaims>(
    token: &str,
    key: &HsKey,
    opts: &VerifyOptions,
) -> Result<C, JwtError> {
    let (header_b64, payload_b64, signature_b64) = split_segments(token)?;

    // Pin the algorithm BEFORE any signature math (algorithm-confusion / `alg:none`).
    let header_bytes = B64.decode(header_b64).map_err(|_| JwtError::Malformed)?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
    if header.alg != HS256 {
        return Err(JwtError::UnsupportedAlg);
    }

    // Recompute the tag over the exact `header.payload` bytes and compare in constant
    // time; never trust the claims before the signature checks out.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected = hmac_sha256(key.as_bytes(), signing_input.as_bytes());
    let provided = B64.decode(signature_b64).map_err(|_| JwtError::Malformed)?;
    if !constant_time_eq(&expected, &provided) {
        return Err(JwtError::BadSignature);
    }

    let payload_bytes = B64.decode(payload_b64).map_err(|_| JwtError::Malformed)?;
    let claims: C = serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::Decode)?;

    validate_temporal(&claims, opts)?;
    Ok(claims)
}

/// Decode a token's claims **without** verifying the signature or expiry. For display
/// and diagnostics only — mirrors nest-auth's `decodeToken`.
///
/// # Security
///
/// The result is unauthenticated and MUST NEVER feed an authorization decision. Use
/// [`verify`] for anything that gates access.
///
/// # Errors
///
/// [`JwtError::Malformed`] if the token is not three base64url segments; [`JwtError::Decode`]
/// if the payload does not deserialize into `C`.
pub fn decode_unverified<C: DeserializeOwned>(token: &str) -> Result<C, JwtError> {
    let (_header_b64, payload_b64, _signature_b64) = split_segments(token)?;
    let payload_bytes = B64.decode(payload_b64).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::Decode)
}

/// Split a compact JWS into exactly three segments. Anything else is malformed. A
/// single match keeps the only failure region (the `_` arm) reachable, since the first
/// `split` element always exists.
fn split_segments(token: &str) -> Result<(&str, &str, &str), JwtError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature), None) => Ok((header, payload, signature)),
        _ => Err(JwtError::Malformed),
    }
}

/// Validate `exp`/`iat` against `opts` and the resolved current time.
fn validate_temporal<C: JwtClaims>(claims: &C, opts: &VerifyOptions) -> Result<(), JwtError> {
    // Saturating cast: a leeway beyond `i64::MAX` is clamped rather than wrapped.
    let leeway = opts.leeway_secs.min(i64::MAX as u64) as i64;
    let now = resolve_now(opts);
    if opts.validate_exp && now > claims.exp().saturating_add(leeway) {
        return Err(JwtError::Expired);
    }
    if opts.validate_iat && claims.iat() > now.saturating_add(leeway) {
        // Issued in the future: not "expired", but an invalid token. Reported as
        // Malformed so it maps straight to the public `token_invalid`.
        return Err(JwtError::Malformed);
    }
    Ok(())
}

/// The current Unix time for the temporal check: the caller-supplied `now_unix`, or the
/// host system clock when `None` (native server). The bare-wasm edge always supplies
/// `Some`, so the system-clock path is never taken there.
fn resolve_now(opts: &VerifyOptions) -> i64 {
    match opts.now_unix {
        Some(now) => now,
        None => system_now_unix(),
    }
}

/// Read the host system clock as Unix seconds (clamped to `0` before the epoch).
fn system_now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bymax_auth_types::{
        DashboardClaims, DashboardType, MfaContext, MfaTempClaims, MfaTempType, PlatformClaims,
        PlatformType,
    };
    use proptest::prelude::*;

    /// A test key — fixed so signatures are reproducible across runs.
    fn key() -> HsKey {
        HsKey::from_bytes(b"a-test-hs256-secret-key-0123456789")
    }

    /// Verify options pinned to a fixed `now` so the temporal checks are deterministic.
    fn opts_at(now: i64) -> VerifyOptions {
        VerifyOptions {
            now_unix: Some(now),
            ..VerifyOptions::default()
        }
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

    /// Assemble a raw `h.p.s` token from already-encoded segments (for crafting the
    /// adversarial inputs that `sign` would never produce).
    fn craft(header_b64: &str, payload_b64: &str, signature_b64: &str) -> String {
        format!("{header_b64}.{payload_b64}.{signature_b64}")
    }

    #[test]
    fn round_trips_each_claim_type() {
        // The codec must sign and verify every claim type back to identical claims —
        // the property the whole token layer rests on.
        let key = key();
        let opts = opts_at(1_500);

        let token = sign(&dashboard(1_000, 2_000), &key).unwrap_or_default();
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts).ok(),
            Some(dashboard(1_000, 2_000))
        );

        let platform = PlatformClaims {
            sub: "p_1".to_owned(),
            jti: "jti-2".to_owned(),
            role: "admin".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: true,
            iat: 1_000,
            exp: 2_000,
        };
        let ptoken = sign(&platform, &key).unwrap_or_default();
        assert_eq!(
            verify::<PlatformClaims>(&ptoken, &key, &opts).ok(),
            Some(platform)
        );

        let mfa = MfaTempClaims {
            sub: "u_1".to_owned(),
            jti: "jti-3".to_owned(),
            token_type: MfaTempType::MfaChallenge,
            context: MfaContext::Platform,
            iat: 1_000,
            exp: 2_000,
        };
        let mtoken = sign(&mfa, &key).unwrap_or_default();
        assert_eq!(
            verify::<MfaTempClaims>(&mtoken, &key, &opts).ok(),
            Some(mfa)
        );
    }

    #[test]
    fn rejects_a_swapped_alg_header_before_signature_math() {
        // A token whose header claims RS256 must be rejected as UnsupportedAlg — proving
        // the verifier never honors the inbound `alg` (RS256-confusion defense). Even a
        // correctly computed tag over these segments cannot get past the alg gate.
        let key = key();
        let payload_b64 =
            B64.encode(serde_json::to_vec(&dashboard(1_000, 2_000)).unwrap_or_default());
        let rs256_header = B64.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let signing_input = format!("{rs256_header}.{payload_b64}");
        let tag = B64.encode(hmac_sha256(key.as_bytes(), signing_input.as_bytes()));
        let token = craft(&rs256_header, &payload_b64, &tag);
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts_at(1_500)),
            Err(JwtError::UnsupportedAlg)
        );
    }

    #[test]
    fn rejects_alg_none() {
        // The classic `alg:none` unsigned-token attack is rejected before signature
        // math, regardless of the (empty) signature segment.
        let key = key();
        let payload_b64 =
            B64.encode(serde_json::to_vec(&dashboard(1_000, 2_000)).unwrap_or_default());
        let none_header = B64.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let token = craft(&none_header, &payload_b64, "");
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts_at(1_500)),
            Err(JwtError::UnsupportedAlg)
        );
    }

    #[test]
    fn rejects_a_tampered_payload() {
        // Flipping the payload after signing breaks the tag — the integrity guarantee.
        let key = key();
        let token = sign(&dashboard(1_000, 2_000), &key).unwrap_or_default();
        let mut segments: Vec<&str> = token.split('.').collect();
        let forged_payload =
            B64.encode(serde_json::to_vec(&dashboard(1_000, 9_999)).unwrap_or_default());
        segments[1] = &forged_payload;
        let tampered = segments.join(".");
        assert_eq!(
            verify::<DashboardClaims>(&tampered, &key, &opts_at(1_500)),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn rejects_a_wrong_key() {
        // A token signed with one key must not verify under another — the core HMAC
        // secrecy property.
        let token = sign(&dashboard(1_000, 2_000), &key()).unwrap_or_default();
        let other = HsKey::from_bytes(b"a-different-secret-key-9876543210ab");
        assert_eq!(
            verify::<DashboardClaims>(&token, &other, &opts_at(1_500)),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn rejects_an_expired_token() {
        // Past `exp` (beyond leeway) is Expired; the engine maps this to the public
        // token_invalid via the internal token_expired.
        let key = key();
        let token = sign(&dashboard(1_000, 2_000), &key).unwrap_or_default();
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts_at(2_001)),
            Err(JwtError::Expired)
        );
        // Within leeway, the same just-expired token still verifies.
        let lenient = VerifyOptions {
            leeway_secs: 5,
            now_unix: Some(2_003),
            ..VerifyOptions::default()
        };
        assert!(verify::<DashboardClaims>(&token, &key, &lenient).is_ok());
    }

    #[test]
    fn rejects_a_token_issued_in_the_future() {
        // An `iat` beyond now+leeway is an invalid token (reported Malformed, mapping to
        // token_invalid) — not an "expired" one.
        let key = key();
        let token = sign(&dashboard(5_000, 9_000), &key).unwrap_or_default();
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts_at(1_000)),
            Err(JwtError::Malformed)
        );
    }

    #[test]
    fn can_disable_temporal_checks() {
        // With both temporal checks off, an otherwise-expired token verifies — the edge
        // may turn these off and rely on the short access lifetime plus its own clock.
        let key = key();
        let token = sign(&dashboard(1_000, 2_000), &key).unwrap_or_default();
        let no_temporal = VerifyOptions {
            validate_exp: false,
            validate_iat: false,
            now_unix: Some(9_999),
            ..VerifyOptions::default()
        };
        assert!(verify::<DashboardClaims>(&token, &key, &no_temporal).is_ok());
    }

    #[test]
    fn uses_the_system_clock_when_now_is_unset() {
        // With `now_unix: None` the verifier reads the host clock; a token expiring far
        // in the future therefore still verifies under the real time.
        let key = key();
        let token = sign(&dashboard(0, i64::MAX), &key).unwrap_or_default();
        assert!(verify::<DashboardClaims>(&token, &key, &VerifyOptions::default()).is_ok());
    }

    #[test]
    fn rejects_malformed_framing() {
        // Anything that is not exactly three base64url segments is Malformed.
        let key = key();
        let opts = opts_at(1_500);
        assert_eq!(
            verify::<DashboardClaims>("a.b", &key, &opts),
            Err(JwtError::Malformed)
        );
        assert_eq!(
            verify::<DashboardClaims>("a.b.c.d", &key, &opts),
            Err(JwtError::Malformed)
        );
        // Bad base64 in the header segment.
        assert_eq!(
            verify::<DashboardClaims>("!!!.b.c", &key, &opts),
            Err(JwtError::Malformed)
        );
        // Valid base64 header that is not JSON.
        let not_json = B64.encode("not json");
        assert_eq!(
            verify::<DashboardClaims>(&craft(&not_json, "b", "c"), &key, &opts),
            Err(JwtError::Malformed)
        );
    }

    #[test]
    fn rejects_bad_base64_in_the_signature_segment() {
        // After the alg gate, a signature segment that is not valid base64url is
        // Malformed (decoded before the tag comparison).
        let key = key();
        let header = B64.encode(HEADER_JSON);
        let payload = B64.encode(serde_json::to_vec(&dashboard(1_000, 2_000)).unwrap_or_default());
        assert_eq!(
            verify::<DashboardClaims>(&craft(&header, &payload, "!!!"), &key, &opts_at(1_500)),
            Err(JwtError::Malformed)
        );
    }

    #[test]
    fn rejects_bad_base64_payload_even_with_a_valid_signature() {
        // A correctly signed token whose payload segment is not valid base64url is
        // Malformed: the tag matches (it is computed over the literal segments), then the
        // payload fails to decode.
        let key = key();
        let header = B64.encode(HEADER_JSON);
        let bad_payload = "@@@@"; // valid length but outside the base64url alphabet
        let signing_input = format!("{header}.{bad_payload}");
        let tag = B64.encode(hmac_sha256(key.as_bytes(), signing_input.as_bytes()));
        assert_eq!(
            verify::<DashboardClaims>(&craft(&header, bad_payload, &tag), &key, &opts_at(1_500)),
            Err(JwtError::Malformed)
        );
    }

    #[test]
    fn rejects_a_valid_signature_over_non_claims_payload() {
        // A correctly signed token whose payload is not the requested claims type fails
        // with Decode — not a signature error.
        let key = key();
        let token = sign(&serde_json::json!({ "unexpected": "shape" }), &key).unwrap_or_default();
        assert_eq!(
            verify::<DashboardClaims>(&token, &key, &opts_at(1_500)),
            Err(JwtError::Decode)
        );
    }

    #[test]
    fn sign_reports_decode_on_a_failing_serialize() {
        // `sign` surfaces a serialization failure as Decode (unreachable for the real
        // claim types, but covered here for completeness).
        struct FailSerialize;
        impl Serialize for FailSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("always fails"))
            }
        }
        assert_eq!(sign(&FailSerialize, &key()), Err(JwtError::Decode));
    }

    #[test]
    fn decode_unverified_reads_claims_without_checking_the_signature() {
        // The display-only decoder returns the claims even when the signature is wrong
        // (it never checks it).
        let key = key();
        let mut segments: Vec<String> = sign(&dashboard(1_000, 2_000), &key)
            .unwrap_or_default()
            .split('.')
            .map(str::to_owned)
            .collect();
        // Replace the signature with a different valid base64url value — decode ignores it.
        segments[2] = B64.encode([0u8; 32]);
        let forged = segments.join(".");
        assert_eq!(
            decode_unverified::<DashboardClaims>(&forged)
                .ok()
                .map(|c| c.sub),
            Some("u_1".to_owned())
        );
        // …but a structurally broken token is still Malformed.
        assert_eq!(
            decode_unverified::<DashboardClaims>("nope"),
            Err(JwtError::Malformed)
        );
        // …a 3-segment token with a non-base64url payload is Malformed.
        let header = B64.encode(HEADER_JSON);
        assert_eq!(
            decode_unverified::<DashboardClaims>(&craft(&header, "@@@@", "sig")),
            Err(JwtError::Malformed)
        );
        // …and a valid-base64 but non-deserializable payload is Decode.
        let weird = sign(&serde_json::json!({ "x": 1 }), &key).unwrap_or_default();
        assert_eq!(
            decode_unverified::<DashboardClaims>(&weird),
            Err(JwtError::Decode)
        );
    }

    proptest! {
        #[test]
        fn sign_then_verify_round_trips_for_arbitrary_claims(
            sub in "[a-z0-9]{1,24}",
            jti in "[a-z0-9-]{1,36}",
            role in "[a-z_]{1,16}",
            iat in 0i64..1_000_000,
            span in 1i64..100_000,
            mfa_enabled in any::<bool>(),
            mfa_verified in any::<bool>(),
        ) {
            // For any well-formed claims, a signed token verifies back to the same
            // claims at a time within the validity window — the codec's core invariant.
            let key = key();
            let exp = iat + span;
            let claims = DashboardClaims {
                sub, jti, tenant_id: "t".to_owned(), role,
                token_type: DashboardType::Dashboard, status: "ACTIVE".to_owned(),
                mfa_enabled, mfa_verified, iat, exp,
            };
            let token = sign(&claims, &key).unwrap_or_default();
            prop_assert_eq!(verify::<DashboardClaims>(&token, &key, &opts_at(iat)).ok(), Some(claims));
        }

        #[test]
        fn corrupting_the_signature_is_always_rejected(seed in 0u8..255) {
            // XORing the first signature byte with any non-zero value breaks the tag —
            // a fuzz over the tamper-rejection guarantee.
            let key = key();
            let token = sign(&dashboard(1_000, 2_000), &key).unwrap_or_default();
            let mut segments: Vec<String> = token.split('.').map(str::to_owned).collect();
            let mut sig = B64.decode(&segments[2]).unwrap_or_default();
            // The HMAC-SHA256 tag is always 32 bytes, so byte 0 always exists.
            sig[0] ^= seed.max(1);
            segments[2] = B64.encode(&sig);
            prop_assert_eq!(
                verify::<DashboardClaims>(&segments.join("."), &key, &opts_at(1_500)),
                Err(JwtError::BadSignature)
            );
        }
    }
}
