//! Unkeyed and keyed digests: SHA-256 and HMAC-SHA-256.
//!
//! SHA-256 hashes high-entropy secrets (tokens) into Redis key suffixes; keyed
//! HMAC-SHA-256 hashes low-entropy identifiers (emails, `tenant:email`) so they are
//! not dictionary-reversible. Digest equality is always checked in constant time.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::compare::constant_time_eq;

/// Length in bytes of a SHA-256 / HMAC-SHA-256 digest.
const DIGEST_LEN: usize = 32;

/// Compute the SHA-256 digest of `input`.
///
/// Used to fold a high-entropy secret (a refresh / reset / invitation token, OAuth
/// `state`, or an MFA temp token) into a fixed-length Redis key suffix so the raw
/// secret never resides in the store.
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::mac::sha256;
///
/// // Known-answer vector: SHA-256("abc").
/// let digest = sha256(b"abc");
/// assert_eq!(digest[0], 0xba);
/// ```
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; DIGEST_LEN] {
    let out = <Sha256 as Digest>::digest(input);
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// Compute the keyed HMAC-SHA-256 of `input` under `key`.
///
/// Used to key low-entropy identifiers (email, `tenant:email`, recovery codes) with a
/// server secret so the stored value is not dictionary- or rainbow-reversible — unlike
/// a bare SHA-256 of an email.
///
/// HMAC accepts a key of any length, so construction is infallible in practice; the
/// unreachable initialization-error path falls back to a zeroed digest (fail-closed:
/// it would never match a real digest) rather than panicking, keeping the function
/// total on the library path.
///
/// # Security
///
/// The whole point of keying is that `key` is a high-entropy server secret (at least
/// 128 bits). An empty or low-entropy key reduces the output to an effectively unkeyed
/// SHA-256, which is dictionary-reversible for low-entropy identifiers — defeating the
/// reason to use HMAC here. Callers must supply a strong key.
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::mac::hmac_sha256;
///
/// let tag = hmac_sha256(b"server-key", b"tenant:user@example.com");
/// assert_eq!(tag.len(), 32);
/// ```
#[must_use]
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; DIGEST_LEN] {
    Hmac::<Sha256>::new_from_slice(key)
        .map(|mut mac| {
            mac.update(input);
            let tag = mac.finalize().into_bytes();
            let mut digest = [0u8; DIGEST_LEN];
            digest.copy_from_slice(&tag);
            digest
        })
        .unwrap_or([0u8; DIGEST_LEN])
}

/// Compare two fixed-length digests in constant time.
///
/// A thin wrapper over [`constant_time_eq`] so callers never reach for `==` when
/// comparing two SHA-256 / HMAC-SHA-256 outputs (e.g. a stored token hash against a
/// freshly computed one).
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::mac::{sha256, verify_digest};
///
/// let a = sha256(b"token");
/// let b = sha256(b"token");
/// assert!(verify_digest(&a, &b));
/// ```
#[must_use]
pub fn verify_digest(a: &[u8; DIGEST_LEN], b: &[u8; DIGEST_LEN]) -> bool {
    constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_answer_vectors() {
        // NIST/FIPS-180 known-answer vectors for SHA-256 over "abc" and the empty
        // string — pins the digest to the standard so a wiring regression is caught.
        // Comparing the hex encoding of the actual digest keeps the assertion
        // infallible (no fallible hex-decode, which the no-`expect` lint forbids).
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_vectors() {
        // RFC 4231 §4.2/§4.3 HMAC-SHA-256 known-answer vectors — proves the keyed
        // digest is the standard HMAC-SHA-256, interoperable with every other impl.
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_is_key_dependent() {
        // The same message under two different keys must yield different tags — the
        // property that makes HMAC suitable for keying low-entropy identifiers.
        let a = hmac_sha256(b"key-one", b"identifier");
        let b = hmac_sha256(b"key-two", b"identifier");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_sha256_accepts_empty_and_long_keys() {
        // HMAC must accept any key length (empty and longer-than-block-size) without
        // error — guards the infallible-construction contract this module relies on.
        assert_eq!(hmac_sha256(b"", b"data").len(), DIGEST_LEN);
        assert_eq!(hmac_sha256(&[0xAA; 200], b"data").len(), DIGEST_LEN);
    }

    #[test]
    fn verify_digest_distinguishes_equal_and_unequal() {
        // verify_digest must report true for matching digests and false otherwise —
        // covers both arms of the constant-time digest comparison helper.
        let a = sha256(b"token");
        let b = sha256(b"token");
        let c = sha256(b"other");
        assert!(verify_digest(&a, &b));
        assert!(!verify_digest(&a, &c));
    }
}
