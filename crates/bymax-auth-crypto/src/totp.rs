//! RFC 4226 (HOTP) / RFC 6238 (TOTP) one-time passwords over HMAC-SHA1, Base32
//! secret encoding, and the `otpauth://` provisioning URI (`mfa` feature).
//!
//! Code verification is constant-time and tolerant of a configurable drift window.
//! Anti-replay is the caller's responsibility (it lives in the engine), not this
//! primitive's. SHA-1 appears here *only* inside the RFC-mandated TOTP HMAC and must
//! never be used for general hashing.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::{Choice, ConstantTimeEq};

use crate::CryptoError;

/// TOTP time step in seconds (RFC 6238 default).
const TOTP_STEP_SECS: u64 = 30;
/// TOTP code length in digits (the authenticator-app default).
const TOTP_DIGITS: u32 = 6;
/// HMAC-SHA1 output length in bytes.
const HMAC_SHA1_LEN: usize = 20;
/// Upper-case hex alphabet for percent-encoding.
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Compute HMAC-SHA1 of the 8-byte big-endian `counter` under `secret`.
///
/// Infallible: HMAC accepts any key length; the unreachable init-error path falls back
/// to a zeroed digest (which produces a non-matching code — fail-closed).
fn hmac_sha1(secret: &[u8], counter: u64) -> [u8; HMAC_SHA1_LEN] {
    Hmac::<Sha1>::new_from_slice(secret)
        .map(|mut mac| {
            mac.update(&counter.to_be_bytes());
            let tag = mac.finalize().into_bytes();
            let mut out = [0u8; HMAC_SHA1_LEN];
            out.copy_from_slice(&tag);
            out
        })
        .unwrap_or([0u8; HMAC_SHA1_LEN])
}

/// Generate an HOTP value (RFC 4226) for `counter`, truncated to `digits` digits.
///
/// Uses HMAC-SHA1 and the RFC dynamic-truncation step. Authenticator apps use 6–8
/// digits; `digits` of 10 or more (which would overflow the modulus) falls back to the
/// 6-digit modulus, and `0` yields a constant `0`.
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::totp::hotp;
/// // RFC 4226 Appendix D, counter 0.
/// assert_eq!(hotp(b"12345678901234567890", 0, 6), 755_224);
/// ```
#[must_use]
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let hash = hmac_sha1(secret, counter);
    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte selects a
    // 4-byte window; `offset + 3 <= 18`, so the indexing never goes out of bounds.
    let offset = usize::from(hash[HMAC_SHA1_LEN - 1] & 0x0f);
    let binary = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let modulus = 10u32.checked_pow(digits).unwrap_or(1_000_000);
    binary % modulus
}

/// Generate a TOTP value (RFC 6238) for `unix_time`, with `step_secs` time step and
/// `digits` digits. A `step_secs` of zero is treated as time-counter 0 (avoids a
/// division by zero).
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::totp::totp;
/// // RFC 6238 Appendix B, T=59, SHA1, 6 digits (low six of 94287082).
/// assert_eq!(totp(b"12345678901234567890", 59, 30, 6), 287_082);
/// ```
#[must_use]
pub fn totp(secret: &[u8], unix_time: u64, step_secs: u64, digits: u32) -> u32 {
    // `checked_div` returns `None` for a zero step, treated as time-counter 0.
    let counter = unix_time.checked_div(step_secs).unwrap_or(0);
    hotp(secret, counter, digits)
}

/// Verify a 6-digit TOTP `code` against `secret` at `unix_time`, accepting any code
/// within `±window` 30-second steps. The digit comparison is constant time and every
/// window step is evaluated (no early return), so neither the code value nor the
/// matching step leaks through timing.
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::totp::verify;
/// assert!(verify(b"12345678901234567890", "287082", 59, 1));
/// assert!(!verify(b"12345678901234567890", "000000", 59, 1));
/// ```
#[must_use]
pub fn verify(secret: &[u8], code: &str, unix_time: u64, window: u8) -> bool {
    let current_step = unix_time / TOTP_STEP_SECS;
    let window = i64::from(window);
    let mut matched = Choice::from(0u8);
    for delta in -window..=window {
        let counter = current_step.wrapping_add_signed(delta);
        let candidate = format!(
            "{:0>width$}",
            hotp(secret, counter, TOTP_DIGITS),
            width = TOTP_DIGITS as usize
        );
        // Accumulate into a `subtle::Choice` (not an early-returning `bool`): every
        // window step is always evaluated and the OR is opaque to the optimizer, so
        // neither the code value nor which step matched leaks through timing.
        matched |= candidate.as_bytes().ct_eq(code.as_bytes());
    }
    matched.into()
}

/// Base32-encode a secret (RFC 4648, upper-case, no padding) for an `otpauth://` URI.
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::totp::encode_secret_base32;
/// assert_eq!(encode_secret_base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
/// ```
#[must_use]
pub fn encode_secret_base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

/// Decode a Base32 secret, leniently stripping whitespace and hyphens and upper-casing
/// before decoding (authenticator apps display secrets in spaced, mixed-case groups).
///
/// # Errors
///
/// Returns [`CryptoError::Encoding`] if the cleaned input is not valid Base32.
pub fn decode_secret_base32(secret: &str) -> Result<Vec<u8>, CryptoError> {
    // Single pass: drop separators and upper-case in one allocation.
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| CryptoError::Encoding)
}

/// Build an `otpauth://totp/...` provisioning URI for an authenticator app.
///
/// Produces `otpauth://totp/{issuer}:{account}?secret=...&issuer=...&period=30&digits=6&algorithm=SHA1`
/// with the label and `issuer` parameter percent-encoded.
///
/// The returned string embeds the Base32 secret and is therefore **sensitive** — the
/// caller should display it (e.g. as a QR code) and drop it promptly rather than log
/// or persist it.
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::totp::provisioning_uri;
/// let uri = provisioning_uri(b"12345678901234567890", "alice@example.com", "Bymax One");
/// assert!(uri.starts_with("otpauth://totp/Bymax%20One:alice%40example.com?secret="));
/// ```
#[must_use]
pub fn provisioning_uri(secret: &[u8], account: &str, issuer: &str) -> String {
    let secret_b32 = encode_secret_base32(secret);
    let issuer_enc = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer_enc}:{account}?secret={secret_b32}&issuer={issuer_enc}\
         &period={TOTP_STEP_SECS}&digits={TOTP_DIGITS}&algorithm=SHA1",
        account = percent_encode(account),
    )
}

/// Percent-encode a string per RFC 3986, leaving only the unreserved set unescaped.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[usize::from(byte >> 4)] as char);
            out.push(HEX_UPPER[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 4226 / RFC 6238 shared test secret (ASCII "12345678901234567890").
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        // RFC 4226 Appendix D known-answer values for counters 0..=9 — pins HOTP to
        // the standard (HMAC-SHA1 + dynamic truncation), interoperable with every app.
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, counter as u64, 6), *want);
        }
    }

    #[test]
    fn totp_matches_rfc6238_vectors() {
        // RFC 6238 Appendix B times (SHA1), reduced to the low six digits of the
        // published eight-digit values — proves the TOTP time-step math.
        assert_eq!(totp(RFC_SECRET, 59, 30, 6), 287_082); // 94287082
        assert_eq!(totp(RFC_SECRET, 1_111_111_109, 30, 6), 81_804); // 07081804
        assert_eq!(totp(RFC_SECRET, 1_234_567_890, 30, 6), 5_924); // 89005924
        assert_eq!(totp(RFC_SECRET, 2_000_000_000, 30, 6), 279_037); // 69279037
    }

    #[test]
    fn totp_treats_zero_step_as_counter_zero() {
        // A zero step must not divide by zero; it pins the counter to 0 so the result
        // equals HOTP at counter 0 — a defensive guard on the time-step input.
        assert_eq!(totp(RFC_SECRET, 12_345, 0, 6), hotp(RFC_SECRET, 0, 6));
    }

    #[test]
    fn hotp_large_digit_count_falls_back_to_six() {
        // A digit count that would overflow the modulus falls back to six digits
        // rather than panicking — covers the checked-pow guard.
        assert_eq!(hotp(RFC_SECRET, 0, 12), hotp(RFC_SECRET, 0, 6));
    }

    #[test]
    fn verify_accepts_codes_within_the_window() {
        // The current step and the ±1 neighbours verify; a step two periods away does
        // not (window=1) — the drift tolerance and its boundary.
        assert!(verify(RFC_SECRET, "287082", 59, 1)); // exact step
        assert!(verify(RFC_SECRET, "287082", 89, 1)); // one step late (delta -1)
        assert!(verify(RFC_SECRET, "287082", 29, 1)); // one step early (delta +1)
        assert!(!verify(RFC_SECRET, "287082", 200, 1)); // far outside the window
    }

    #[test]
    fn verify_rejects_a_wrong_code() {
        // A code that matches no step in the window is rejected — the negative case
        // that guards against accepting an arbitrary string.
        assert!(!verify(RFC_SECRET, "000000", 59, 1));
        assert!(!verify(RFC_SECRET, "not-a-code", 59, 1));
    }

    #[test]
    fn base32_round_trips_and_matches_known_vector() {
        // Encoding matches the RFC 6238 secret's canonical Base32, and a leniently
        // formatted (spaced, lower-case) secret decodes back to the same bytes.
        assert_eq!(
            encode_secret_base32(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        let decoded =
            decode_secret_base32("gezd gnbv-gy3t qojq gezd gnbv-gy3t qojq").unwrap_or_default();
        assert_eq!(decoded, RFC_SECRET);
    }

    #[test]
    fn base32_rejects_invalid_input() {
        // Non-Base32 characters (e.g. `1`, `8`, `0` are outside the RFC 4648 alphabet)
        // produce an opaque Encoding error rather than silently mis-decoding.
        assert!(matches!(
            decode_secret_base32("8888"),
            Err(CryptoError::Encoding)
        ));
    }

    #[test]
    fn provisioning_uri_is_well_formed_and_encoded() {
        // The URI carries the standard parameters and percent-encodes the label and
        // issuer (space → %20, `@` → %40) — what an authenticator app scans.
        let uri = provisioning_uri(RFC_SECRET, "alice@example.com", "Bymax One");
        assert!(uri.starts_with("otpauth://totp/Bymax%20One:alice%40example.com?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Bymax%20One"));
        assert!(uri.contains("&period=30&digits=6&algorithm=SHA1"));
    }

    proptest! {
        #[test]
        fn base32_round_trip_for_arbitrary_secrets(secret in proptest::collection::vec(any::<u8>(), 0..40)) {
            // Any byte sequence Base32-encodes and decodes back unchanged — the codec
            // round-trip property across the input space.
            let encoded = encode_secret_base32(&secret);
            prop_assert_eq!(decode_secret_base32(&encoded).unwrap_or_default(), secret);
        }

        #[test]
        fn freshly_generated_code_verifies(unix_time in 0u64..4_000_000_000) {
            // A code generated for a given time always verifies at that time within a
            // zero window — generation and verification agree across the time range.
            let code = format!("{:0>6}", totp(RFC_SECRET, unix_time, 30, 6));
            prop_assert!(verify(RFC_SECRET, &code, unix_time, 0));
        }
    }
}
