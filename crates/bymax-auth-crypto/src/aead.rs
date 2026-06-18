//! AES-256-GCM authenticated encryption for the TOTP secret at rest (`mfa` feature).
//!
//! Each encryption draws a fresh 12-byte CSPRNG nonce and emits a self-describing
//! wire string `base64(nonce):base64(tag):base64(ciphertext)`. On the decryption path
//! every failure mode (bad format, wrong length, wrong key, tampered ciphertext or
//! tag) collapses to one opaque [`CryptoError::Decrypt`] so the failure type is not an
//! oracle. Encryption can only fail on an implausibly large plaintext and reports
//! [`CryptoError::InvalidParams`].

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use data_encoding::BASE64;
use zeroize::Zeroizing;

use crate::{CryptoError, token};

/// AES-GCM nonce (IV) length in bytes (96-bit, the GCM standard).
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes (128-bit).
const TAG_LEN: usize = 16;

/// Encrypt `plaintext` under the 32-byte `key` with AES-256-GCM.
///
/// A fresh 12-byte nonce is drawn from the CSPRNG for every call (GCM nonce reuse under
/// one key is catastrophic). The returned wire string is
/// `base64(nonce):base64(tag):base64(ciphertext)`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] if the underlying cipher rejects the input
/// (only reachable for an implausibly large plaintext — TOTP secrets are tiny).
///
/// # Examples
///
/// ```
/// # use bymax_auth_crypto::aead::{encrypt, decrypt};
/// let key = [7u8; 32];
/// let wire = encrypt(b"totp-secret", &key).unwrap();
/// assert_eq!(decrypt(&wire, &key).unwrap(), b"totp-secret");
/// ```
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<String, CryptoError> {
    let key = Zeroizing::new(*key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    // Stack-allocated nonce (no heap allocation in the hot path).
    let nonce_bytes = token::random_array::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encryption only fails on an implausibly large plaintext; the `.ok()...ok_or` form
    // maps that unreachable error to `InvalidParams` without an untestable `?` branch
    // (the error value is constructed on every call).
    cipher
        .encrypt(nonce, plaintext)
        .ok()
        .map(|combined| {
            // aes-gcm returns `ciphertext || tag`; split the trailing 16-byte tag.
            let split = combined.len().saturating_sub(TAG_LEN);
            let (ciphertext, tag) = combined.split_at(split);
            format!(
                "{}:{}:{}",
                BASE64.encode(&nonce_bytes),
                BASE64.encode(tag),
                BASE64.encode(ciphertext)
            )
        })
        .ok_or(CryptoError::InvalidParams)
}

/// Decrypt a `base64(nonce):base64(tag):base64(ciphertext)` wire string under `key`.
///
/// # Errors
///
/// Returns [`CryptoError::Decrypt`] for any failure — malformed wire, wrong segment
/// length, a wrong key, or a tampered ciphertext/tag — without distinguishing them.
pub fn decrypt(wire: &str, key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let mut parts = wire.split(':');
    let (Some(nonce_b64), Some(tag_b64), Some(ct_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CryptoError::Decrypt);
    };
    let nonce = BASE64
        .decode(nonce_b64.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;
    let tag = BASE64
        .decode(tag_b64.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;
    let ciphertext = BASE64
        .decode(ct_b64.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;
    if nonce.len() != NONCE_LEN || tag.len() != TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let key = Zeroizing::new(*key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    // Reassemble the `ciphertext || tag` layout aes-gcm's combined API expects.
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    // Length is validated above, so `from_slice` cannot panic.
    cipher
        .decrypt(Nonce::from_slice(&nonce), combined.as_ref())
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn round_trips_plaintext() {
        // Encrypt then decrypt under the same key returns the original plaintext,
        // including the empty-plaintext edge — the core authenticated-encryption
        // contract for the at-rest TOTP secret.
        for pt in [b"".as_slice(), b"totp-secret-bytes"] {
            let wire = encrypt(pt, &KEY).unwrap_or_default();
            assert!(matches!(decrypt(&wire, &KEY), Ok(ref got) if got == pt));
        }
    }

    #[test]
    fn nonce_is_fresh_per_encryption() {
        // Two encryptions of the same plaintext produce different wires (fresh random
        // nonce) — guards against catastrophic GCM nonce reuse.
        assert_ne!(
            encrypt(b"same", &KEY).unwrap_or_default(),
            encrypt(b"same", &KEY).unwrap_or_default()
        );
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        // A wrong key fails the tag check and yields the opaque Decrypt error — the
        // confidentiality guarantee for the encrypted secret.
        let wire = encrypt(b"secret", &KEY).unwrap_or_default();
        let other = [0x99; 32];
        assert!(matches!(decrypt(&wire, &other), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampering_with_ciphertext_or_tag_is_detected() {
        // Flipping a bit in the ciphertext or the tag fails authentication — the
        // tamper-detection guarantee GCM provides.
        let wire = encrypt(b"authentic message", &KEY).unwrap_or_default();
        let parts: Vec<&str> = wire.split(':').collect();
        // Re-encode with a mutated tag segment (flip the first decoded byte).
        let mut tag = BASE64.decode(parts[1].as_bytes()).unwrap_or_default();
        tag[0] ^= 0x01;
        let tampered_tag = format!("{}:{}:{}", parts[0], BASE64.encode(&tag), parts[2]);
        assert!(matches!(
            decrypt(&tampered_tag, &KEY),
            Err(CryptoError::Decrypt)
        ));
        // And with a mutated ciphertext segment.
        let mut ct = BASE64.decode(parts[2].as_bytes()).unwrap_or_default();
        ct[0] ^= 0x01;
        let tampered_ct = format!("{}:{}:{}", parts[0], parts[1], BASE64.encode(&ct));
        assert!(matches!(
            decrypt(&tampered_ct, &KEY),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn malformed_wire_is_rejected() {
        // Wrong segment count, non-base64 content, and wrong nonce/tag lengths all map
        // to the opaque Decrypt error — exercises every parse-time guard.
        assert!(matches!(
            decrypt("only-one-segment", &KEY),
            Err(CryptoError::Decrypt)
        ));
        assert!(matches!(
            decrypt("a:b:c:d", &KEY),
            Err(CryptoError::Decrypt)
        )); // too many
        assert!(matches!(
            decrypt("!!!:!!!:!!!", &KEY),
            Err(CryptoError::Decrypt)
        )); // bad base64 (nonce)
        let wire = encrypt(b"x", &KEY).unwrap_or_default();
        let parts: Vec<&str> = wire.split(':').collect();
        let bad_tag = format!("{}:{}:{}", parts[0], "!!!", parts[2]); // bad base64 (tag)
        assert!(matches!(decrypt(&bad_tag, &KEY), Err(CryptoError::Decrypt)));
        let bad_ct = format!("{}:{}:{}", parts[0], parts[1], "!!!"); // bad base64 (ciphertext)
        assert!(matches!(decrypt(&bad_ct, &KEY), Err(CryptoError::Decrypt)));
        // Valid base64 but wrong nonce length (one byte instead of twelve).
        let short_nonce = format!("{}:{}:{}", BASE64.encode(&[0u8]), parts[1], parts[2]);
        assert!(matches!(
            decrypt(&short_nonce, &KEY),
            Err(CryptoError::Decrypt)
        ));
        // Valid base64 but wrong tag length.
        let short_tag = format!("{}:{}:{}", parts[0], BASE64.encode(&[0u8]), parts[2]);
        assert!(matches!(
            decrypt(&short_tag, &KEY),
            Err(CryptoError::Decrypt)
        ));
    }

    proptest! {
        #[test]
        fn round_trip_for_arbitrary_plaintext_and_key(
            pt in proptest::collection::vec(any::<u8>(), 0..256),
            key in proptest::array::uniform32(any::<u8>()),
        ) {
            // For any plaintext and key, decrypt(encrypt(m, k), k) == m — the
            // round-trip property across the input space.
            let wire = encrypt(&pt, &key).unwrap_or_default();
            prop_assert!(matches!(decrypt(&wire, &key), Ok(ref got) if *got == pt));
        }
    }
}
