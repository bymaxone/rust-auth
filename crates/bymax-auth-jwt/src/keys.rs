//! Keys, verification policy, the sealed [`JwtClaims`] trait, and the opaque
//! [`RawRefreshToken`].

use std::fmt;

use bymax_auth_crypto::mac::sha256;
use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_types::{DashboardClaims, MfaTempClaims, PlatformClaims};
use zeroize::Zeroizing;

/// Lower-case hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Bytes per opaque refresh token before hex-encoding (256 bits of entropy).
const REFRESH_TOKEN_BYTES: usize = 32;

/// The symmetric HS256 signing/verifying key.
///
/// Wraps the secret in a [`Zeroizing`] buffer so it is wiped from memory on drop, and
/// its [`fmt::Debug`] is redacted so the bytes can never slip into a log line, panic
/// message, or error.
///
/// # Security
///
/// HS256 requires a key of at least the hash output size — 32 bytes / 256 bits (RFC 7518
/// §3.2); a shorter secret weakens the MAC proportionally. These constructors accept any
/// length so the primitive stays infallible and dependency-free; the key-length and
/// entropy floor is enforced once, centrally, when the engine resolves its configuration
/// at startup (a misconfigured secret fails the build rather than silently weakening
/// every token).
pub struct HsKey(Zeroizing<Vec<u8>>);

impl HsKey {
    /// Build a key from owned secret bytes (e.g. the configured `jwt.secret`).
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self(Zeroizing::new(secret))
    }

    /// Build a key by copying secret bytes from a slice.
    #[must_use]
    pub fn from_bytes(secret: &[u8]) -> Self {
        Self(Zeroizing::new(secret.to_vec()))
    }

    /// The raw key bytes, for the HMAC computation. Crate-internal so callers cannot
    /// read the secret out of the type.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret bytes.
        f.write_str("HsKey([REDACTED])")
    }
}

/// Policy for [`crate::verify`]. The algorithm is **not** a field — HS256 is pinned
/// internally and is never selected from the token.
#[derive(Clone, Copy, Debug)]
pub struct VerifyOptions {
    /// Clock-skew tolerance, in seconds. The native server runs with `0` (its clock is
    /// authoritative); the edge accepts a small value because edge nodes may drift.
    pub leeway_secs: u64,
    /// Whether to enforce `exp` (expiry).
    pub validate_exp: bool,
    /// Whether to enforce `iat` (reject tokens issued in the future).
    pub validate_iat: bool,
    /// The current time (Unix seconds) to validate `exp`/`iat` against. `None` reads the
    /// host system clock — correct for the native server. The `wasm32-unknown-unknown`
    /// edge build has no system clock and MUST set `Some(now)` (e.g. from the JS clock);
    /// leaving it `None` there would read an unavailable clock.
    pub now_unix: Option<i64>,
}

impl Default for VerifyOptions {
    /// Server defaults: zero leeway, both temporal checks on, system clock.
    fn default() -> Self {
        Self {
            leeway_secs: 0,
            validate_exp: true,
            validate_iat: true,
            now_unix: None,
        }
    }
}

mod sealed {
    /// Private supertrait that seals [`super::JwtClaims`] so only this crate can name
    /// the set of types accepted by [`crate::verify`].
    pub trait Sealed {}
    impl Sealed for bymax_auth_types::DashboardClaims {}
    impl Sealed for bymax_auth_types::PlatformClaims {}
    impl Sealed for bymax_auth_types::MfaTempClaims {}
}

/// Sealed marker for the claim types [`crate::verify`] accepts, exposing the temporal
/// claims it validates. Implemented only by `DashboardClaims`, `PlatformClaims`, and
/// `MfaTempClaims`; it cannot be implemented downstream.
pub trait JwtClaims: sealed::Sealed {
    /// Expiry, in Unix seconds.
    fn exp(&self) -> i64;
    /// Issued-at, in Unix seconds.
    fn iat(&self) -> i64;
}

impl JwtClaims for DashboardClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
    fn iat(&self) -> i64 {
        self.iat
    }
}

impl JwtClaims for PlatformClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
    fn iat(&self) -> i64 {
        self.iat
    }
}

impl JwtClaims for MfaTempClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
    fn iat(&self) -> i64 {
        self.iat
    }
}

/// An opaque refresh token: a high-entropy random value that is **never a JWT** and is
/// never signed or parsed. Only its [`RawRefreshToken::redis_hash`] is ever persisted
/// (under `rt:`/`prt:`), so a store snapshot leaks no live credential; the raw value is
/// returned to the client exactly once.
///
/// The raw value is held in a [`Zeroizing`] buffer and its [`fmt::Debug`] is redacted.
pub struct RawRefreshToken(Zeroizing<String>);

impl RawRefreshToken {
    /// Mint a fresh token from the CSPRNG (256 bits, hex-encoded).
    ///
    /// # Panics
    ///
    /// Panics if the OS/browser CSPRNG is unavailable — an unrecoverable entropy failure
    /// under which no secure token can be produced. This is deliberate fail-closed
    /// behavior (see `bymax_auth_crypto::token::generate_secure_token`): minting a
    /// predictable refresh token would be worse than aborting.
    #[must_use]
    pub fn generate() -> Self {
        Self(Zeroizing::new(generate_secure_token(REFRESH_TOKEN_BYTES)))
    }

    /// Wrap an already-issued raw token value (e.g. one presented by a client on
    /// refresh) so it can be hashed for the store lookup.
    #[must_use]
    pub fn from_raw(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The raw token to return to the client. Greppable by name: every read of the
    /// secret value goes through this method.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// `sha256(token)` hex — the only form persisted in the store. The raw token is
    /// never written.
    #[must_use]
    pub fn redis_hash(&self) -> String {
        to_hex(&sha256(self.0.as_bytes()))
    }
}

impl fmt::Debug for RawRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the raw token.
        f.write_str("RawRefreshToken([REDACTED])")
    }
}

/// Lower-case hex-encode a byte slice (used for the SHA-256 store-hash).
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_ALPHABET[usize::from(byte >> 4)] as char);
        out.push(HEX_ALPHABET[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hs_key_debug_is_redacted() {
        // The signing secret must never appear in Debug output — a log/panic that
        // formats the key would otherwise leak it.
        let key = HsKey::from_bytes(b"top-secret-signing-key");
        assert_eq!(format!("{key:?}"), "HsKey([REDACTED])");
        // `new` and `from_bytes` agree on the stored bytes.
        let owned = HsKey::new(b"top-secret-signing-key".to_vec());
        assert_eq!(key.as_bytes(), owned.as_bytes());
    }

    #[test]
    fn verify_options_default_is_server_strict() {
        // The default is the authoritative-clock server posture: no leeway, both
        // temporal checks enabled, system clock.
        let opts = VerifyOptions::default();
        assert_eq!(opts.leeway_secs, 0);
        assert!(opts.validate_exp);
        assert!(opts.validate_iat);
        assert_eq!(opts.now_unix, None);
        // It is Copy/Debug for ergonomic call sites.
        let copy = opts;
        assert!(format!("{copy:?}").contains("VerifyOptions"));
    }

    #[test]
    fn raw_refresh_token_is_opaque_and_hashes_stably() {
        // The token is 64 hex chars (256 bits); its store hash is a 64-char SHA-256 hex
        // that is stable for a given token and never equals the raw value.
        let token = RawRefreshToken::generate();
        assert_eq!(token.expose_secret().len(), 64);
        assert!(token.expose_secret().bytes().all(|c| c.is_ascii_hexdigit()));
        let hash = token.redis_hash();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, token.redis_hash(), "hash must be deterministic");
        assert_ne!(
            hash,
            token.expose_secret(),
            "hash must not equal the raw token"
        );
        // Two minted tokens differ (CSPRNG).
        assert_ne!(
            token.expose_secret(),
            RawRefreshToken::generate().expose_secret()
        );
    }

    #[test]
    fn raw_refresh_token_debug_is_redacted_and_from_raw_round_trips() {
        // Debug must not leak the value; `from_raw` reconstructs a token for hashing a
        // client-presented value, matching a known SHA-256 vector for "abc".
        let token = RawRefreshToken::from_raw("abc".to_owned());
        assert_eq!(format!("{token:?}"), "RawRefreshToken([REDACTED])");
        assert_eq!(token.expose_secret(), "abc");
        assert_eq!(
            token.redis_hash(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn jwt_claims_expose_temporal_fields() {
        // The sealed trait surfaces exp/iat for the temporal check; confirm each claim
        // type forwards its own fields.
        let dashboard = DashboardClaims {
            sub: "u".to_owned(),
            jti: "j".to_owned(),
            tenant_id: "t".to_owned(),
            role: "r".to_owned(),
            token_type: bymax_auth_types::DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: 10,
            exp: 20,
        };
        assert_eq!(JwtClaims::iat(&dashboard), 10);
        assert_eq!(JwtClaims::exp(&dashboard), 20);

        let platform = PlatformClaims {
            sub: "u".to_owned(),
            jti: "j".to_owned(),
            role: "r".to_owned(),
            token_type: bymax_auth_types::PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: 11,
            exp: 21,
        };
        assert_eq!(JwtClaims::iat(&platform), 11);
        assert_eq!(JwtClaims::exp(&platform), 21);

        let mfa = MfaTempClaims {
            sub: "u".to_owned(),
            jti: "j".to_owned(),
            token_type: bymax_auth_types::MfaTempType::MfaChallenge,
            context: bymax_auth_types::MfaContext::Dashboard,
            iat: 12,
            exp: 22,
        };
        assert_eq!(JwtClaims::iat(&mfa), 12);
        assert_eq!(JwtClaims::exp(&mfa), 22);
    }
}
