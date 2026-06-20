//! The engine's internal service collaborators and the authentication flows built on
//! top of them. These types are constructed by [`crate::AuthEngineBuilder::build`] from
//! the resolved configuration and the host-supplied stores/repositories, and are driven
//! by the flow methods on [`crate::AuthEngine`].
//!
//! - [`password`] — the async [`password::PasswordService`] (hash/verify off the runtime,
//!   rehash-on-verify detection, and the anti-enumeration sentinel hash).
//! - [`token_manager`] — the [`token_manager::TokenManagerService`] (HS256 access JWT +
//!   opaque refresh, atomic rotation with a grace window, the JTI revocation blacklist,
//!   and the short MFA temp token).
//! - [`brute_force`] — the [`brute_force::BruteForceService`] (HMAC-identifier fixed-window
//!   lockout with the identifier-injection guard).
//! - [`otp`] — the [`otp::OtpService`] (CSPRNG numeric OTP generation, attempt-bounded
//!   verify with timing normalization, and the resend cooldown).
//! - [`session`] — the [`session::SessionService`] (concurrent-session tracking, FIFO
//!   eviction, device/IP metadata, ownership-checked revoke, and atomic detail rotation).
//! - [`auth`] — the local authentication flows (register, login, logout, me, refresh,
//!   email verification, password reset, invitations, and password-less issuance).

pub mod auth;
pub mod brute_force;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod otp;
pub mod password;
pub mod session;
pub mod token_manager;

use bymax_auth_types::AuthError;
use time::OffsetDateTime;

/// Lower-case hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Build a generic internal [`AuthError`] whose cause is a static label. The label feeds
/// `tracing`/logs only and never carries a secret, so it is safe to surface as the boxed
/// source of an opaque `auth.internal` error.
pub(crate) fn internal_error(context: &'static str) -> AuthError {
    AuthError::Internal(context.into())
}

/// Lower-case hex-encode a byte slice. Used to render a digest (a SHA-256 / HMAC-SHA-256
/// output) into the no-PII identifier form a store key uses.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_ALPHABET[usize::from(byte >> 4)] as char);
        out.push(HEX_ALPHABET[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Mint a fresh RFC 4122 version-4 UUID from the CSPRNG, hyphenated and lower-case. Used
/// for every access-token `jti` (the revocation-blacklist key) and the MFA temp-token
/// `jti`. Hand-rolled over the crate's CSPRNG so no `uuid` dependency is pulled in.
pub(crate) fn new_uuid_v4() -> String {
    let mut b = bymax_auth_crypto::token::random_array::<16>();
    // Version 4 (random) in the high nibble of byte 6; RFC 4122 variant in byte 8.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = to_hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The current time as Unix seconds, for JWT `iat`/`exp`.
pub(crate) fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// The current time as an [`OffsetDateTime`], for the session-record `created_at`.
pub(crate) fn now_offset() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// The fixed shape of an engine-issued opaque refresh token: exactly 64 lower-case hex
/// characters (256 bits, the `generate_secure_token(32)` output). Checking the shape before
/// hashing rejects an oversized or malformed value cheaply — without an allocation and a
/// SHA-256 over an unbounded input — and such a value could never match a stored hash anyway.
pub(crate) fn is_refresh_token_shape(raw: &str) -> bool {
    raw.len() == 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_refresh_token_shape_accepts_only_64_lowercase_hex() {
        // A genuine engine-issued token (64 lower-case hex) passes; wrong length, an
        // upper-case digit, and a non-hex character are each rejected before any hashing.
        assert!(is_refresh_token_shape(&"a1".repeat(32)));
        assert!(!is_refresh_token_shape(&"a".repeat(63)));
        assert!(!is_refresh_token_shape(&"a".repeat(65)));
        assert!(!is_refresh_token_shape(&"A".repeat(64)));
        assert!(!is_refresh_token_shape(&"g".repeat(64)));
        assert!(!is_refresh_token_shape(""));
    }

    #[test]
    fn to_hex_encodes_lowercase_two_chars_per_byte() {
        // The encoder must be lower-case and fixed-width — the identifier/key contract.
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn new_uuid_v4_has_the_canonical_version_4_layout() {
        // 8-4-4-4-12 hyphenation, the version nibble pinned to '4', and the variant nibble
        // in {8,9,a,b} — the structural proof a minted value is a v4 UUID (§24 invariant 2).
        let id = new_uuid_v4();
        assert_eq!(id.len(), 36);
        let bytes = id.as_bytes();
        assert_eq!(bytes[8], b'-');
        assert_eq!(bytes[13], b'-');
        assert_eq!(bytes[18], b'-');
        assert_eq!(bytes[23], b'-');
        assert_eq!(bytes[14], b'4', "version nibble must be 4");
        assert!(
            matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
            "variant nibble"
        );
        assert!(
            id.bytes()
                .all(|c| c == b'-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        );
        // Two successive draws differ (CSPRNG).
        assert_ne!(new_uuid_v4(), new_uuid_v4());
    }

    #[test]
    fn internal_error_carries_the_generic_code() {
        // The helper yields the opaque internal error; the static label is the boxed cause.
        let err = internal_error("unit-test label");
        assert!(matches!(err, AuthError::Internal(_)));
        assert_eq!(err.code(), bymax_auth_types::AuthErrorCode::Internal);
    }

    #[test]
    fn now_helpers_are_monotonic_enough_to_be_sane() {
        // The clocks must return a positive, post-epoch value so claims/records timestamp
        // forward — a smoke test that the time source is wired, not a precision assertion.
        assert!(now_unix() > 1_600_000_000);
        assert!(now_offset().unix_timestamp() > 1_600_000_000);
    }
}
