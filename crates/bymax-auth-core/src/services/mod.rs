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
//! - `platform` (feature `platform`) — the [`platform::PlatformAuthService`]: the operator
//!   identity domain (login/MFA-challenge, me, logout, refresh, revoke-all), isolated from the
//!   tenant domain with platform claims (no `tenantId`) and the platform session keyspaces.

/// The thin public engine surface the HTTP adapter calls (token verification, role/status
/// checks, WebSocket ticket mint/redeem). Each method delegates to an existing service.
mod adapter_api;

pub use adapter_api::WS_TICKET_TTL_SECONDS;

pub mod auth;
pub mod brute_force;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod otp;
pub mod password;
#[cfg(feature = "platform")]
pub mod platform;
pub mod session;
pub mod token_manager;

use bymax_auth_types::{AuthError, MfaContext};
use time::OffsetDateTime;

/// Lower-case hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Build a generic internal [`AuthError`] whose cause is a static label. The label feeds
/// `tracing`/logs only and never carries a secret, so it is safe to surface as the boxed
/// source of an opaque `auth.internal` error.
pub(crate) fn internal_error(context: &'static str) -> AuthError {
    AuthError::Internal(context.into())
}

/// Read `identifierPreimages.{name}` from the shared cross-implementation wire contract and
/// return just the template inside the quotes.
///
/// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
/// can back the same deployment over the same Redis. Reading it here rather than repeating
/// its values means a preimage change on either side turns that side red immediately,
/// instead of surfacing later as counters and records that silently stopped being shared.
#[cfg(test)]
pub(crate) fn contract_preimage(name: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    let rendered = root
        .get("identifierPreimages")
        .and_then(|s| s.get(name))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    // `hmac_sha256(hmacKey, '<template>')` — take what is between the single quotes.
    rendered.split('\'').nth(1).unwrap_or_default().to_owned()
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

/// The subject every per-account store key in this library derives from:
/// `dashboard:{utf8_byte_len(tenant_id)}:{tenant_id}:{user_id}`, or `platform:{user_id}` on the
/// plane whose admins are cross-tenant and carry no tenant at all.
///
/// The shared contract calls this the `userSubject` and lists what derives from it under
/// `userSubjectDerivedKeys`: the MFA setup record, the recent-authentication marker, the TOTP
/// anti-replay marker, the recovery-code claim, the three MFA failure counters, and — since the
/// keyspace was scoped — the dashboard/platform **session index** and **token epoch**. It
/// outgrew MFA, which is why it no longer carries that name.
///
/// # The length prefix is load-bearing
///
/// Without it the dashboard preimage is not injective. Both components may contain `:` — a
/// `tenant_id` is validated for length and control characters only, and a user id is whatever
/// the host's repository assigns — so two unrelated pairs collapse onto one preimage:
///
/// ```text
/// tenant "acme:prod" + user "u1"      -> dashboard:acme:prod:u1
/// tenant "acme"      + user "prod:u1" -> dashboard:acme:prod:u1
/// ```
///
/// Everything derived from it collided there, `rcu:` included — the marker that stops one
/// recovery code being spent twice. Prefixing the tenant's length makes the parse unambiguous:
/// `dashboard:9:acme:prod:u1` against `dashboard:4:acme:prod:u1`.
///
/// `str::len()` counts UTF-8 **bytes**, which is what this must be. The symmetric mistake on the
/// TypeScript side is `String.length`, which counts UTF-16 units: the two agree on ASCII and
/// derive different keys for the first accented tenant id — a split that surfaces only in
/// production, and only in some locales.
///
/// The platform arm takes no length prefix and no tenant: one component after the plane, nothing
/// to disambiguate. The PLANE decides the shape, never whether a tenant happened to be supplied,
/// so a platform caller that passes one cannot move the preimage off `platform:{user_id}`.
pub(crate) fn user_subject(plane: MfaContext, tenant_id: Option<&str>, user_id: &str) -> String {
    match (plane, tenant_id) {
        (MfaContext::Dashboard, Some(tenant)) => {
            format!("{}:{}:{tenant}:{user_id}", plane.as_str(), tenant.len())
        }
        _ => format!("{}:{user_id}", plane.as_str()),
    }
}

/// The store-key suffix for a subject: `hmac_sha256(identifier_key, user_subject)` in lower-case
/// hex.
///
/// Keyed, never a bare digest, and never the raw id: a user id is low-entropy enough to reverse
/// out of a plain SHA-256, and a key carrying it in the clear turns anyone with store access into
/// a reader of account identifiers. The same reasoning the `lf:` login counter already applies.
pub(crate) fn user_subject_hash(
    identifier_key: &[u8; 64],
    plane: MfaContext,
    tenant_id: Option<&str>,
    user_id: &str,
) -> String {
    to_hex(&bymax_auth_crypto::mac::hmac_sha256(
        identifier_key,
        user_subject(plane, tenant_id, user_id).as_bytes(),
    ))
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

/// Whether `raw` could be a refresh token this deployment would have issued.
///
/// The current shape is exactly 64 lower-case hex characters (256 bits, the
/// `generate_secure_token(32)` output). Checking before hashing rejects an oversized or
/// malformed value cheaply — no allocation and no SHA-256 over unbounded input — and such a
/// value could never match a stored hash anyway.
///
pub(crate) fn is_refresh_token_shape(raw: &str) -> bool {
    is_hex_token_shape(raw)
}

/// The current shape: 64 lower-case hex characters.
fn is_hex_token_shape(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(is_lower_hex)
}

/// Whether `byte` is a lower-case hexadecimal digit.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
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
    fn is_refresh_token_shape_rejects_anything_but_64_hex() {
        // A UUID is not a refresh token: the shape is 64 lower-case hex characters and
        // nothing else, so a dash in any position, an upper-case digit, a non-hex character
        // and a wrong length are all refused before any hashing happens.
        assert!(!is_refresh_token_shape(
            "111111112-222-4333-8444-555555555555"
        ));
        assert!(!is_refresh_token_shape(
            "11111111-2222-4333-8444-55555555555Z"
        ));
        assert!(!is_refresh_token_shape(
            "AAAAAAAA-2222-4333-8444-555555555555"
        ));
        assert!(!is_refresh_token_shape(
            "11111111-2222-4333-8444-5555555555"
        ));
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
        // Drawn repeatedly rather than once: the version and variant nibbles are forced on
        // top of CSPRNG bytes, so a masking bug leaves them correct for a good fraction of
        // draws. A single sample would pass by luck.
        for _ in 0..64 {
            let id = new_uuid_v4();
            assert_eq!(id.len(), 36);
            let bytes = id.as_bytes();
            assert_eq!(bytes[8], b'-');
            assert_eq!(bytes[13], b'-');
            assert_eq!(bytes[18], b'-');
            assert_eq!(bytes[23], b'-');
            assert_eq!(bytes[14], b'4', "version nibble must be 4: {id}");
            assert!(
                matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
                "variant nibble: {id}"
            );
            assert!(
                id.bytes()
                    .all(|c| c == b'-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
            );
        }
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
