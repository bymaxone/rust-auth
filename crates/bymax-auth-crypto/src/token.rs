//! CSPRNG-backed secure random bytes and tokens.
//!
//! Opaque refresh tokens, password-reset and invitation tokens, OAuth `state`, and
//! the WebSocket upgrade ticket are all generated here from the OS/browser CSPRNG
//! (`getrandom`/`OsRng`); never from a predictably seeded PRNG.

use rand::RngCore;
use rand::rngs::OsRng;

/// Lower-case hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Fill a fresh `Vec` of `n` bytes from the cryptographically secure RNG.
///
/// Randomness comes from the OS CSPRNG (`OsRng`, backed by `getrandom`); on
/// `wasm32-unknown-unknown` the `wasm-js` feature routes it to the Web Crypto
/// `getRandomValues` API. This is the raw entropy source behind every opaque token,
/// salt, and nonce in the library.
///
/// # Panics
///
/// Panics only if the OS/browser CSPRNG is unavailable — an unrecoverable entropy
/// failure under which no secure value can be produced (the deliberate, fail-closed
/// behavior shared by the whole RustCrypto/`rand` ecosystem).
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::token::random_bytes;
///
/// let bytes = random_bytes(16);
/// assert_eq!(bytes.len(), 16);
/// ```
#[must_use]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Fill a fixed-size `[u8; N]` from the CSPRNG on the stack — no heap allocation.
///
/// Prefer this over [`random_bytes`] whenever the length is known at compile time
/// (nonces, fixed-width keys): it avoids the `Vec` allocation entirely.
///
/// # Panics
///
/// Panics only on an unrecoverable OS/browser CSPRNG failure (see [`random_bytes`]).
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::token::random_array;
///
/// let nonce: [u8; 12] = random_array();
/// assert_eq!(nonce.len(), 12);
/// ```
#[must_use]
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a hex-encoded secure random token carrying `byte_len * 8` bits of entropy.
///
/// Draws `byte_len` bytes from the CSPRNG ([`random_bytes`]) and lower-case
/// hex-encodes them, so the returned string is `2 * byte_len` characters drawn from
/// `[0-9a-f]`. The default of 32 bytes yields a 256-bit, 64-character token.
///
/// # Panics
///
/// Panics only on an unrecoverable OS/browser CSPRNG failure (see [`random_bytes`]).
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::token::generate_secure_token;
///
/// let token = generate_secure_token(32);
/// assert_eq!(token.len(), 64); // 32 bytes -> 64 hex chars (256 bits)
/// ```
#[must_use]
pub fn generate_secure_token(byte_len: usize) -> String {
    encode_hex(&random_bytes(byte_len))
}

/// Lower-case hex-encode a byte slice.
///
/// Hand-rolled (rather than pulling a runtime hex dependency) because encoding is a
/// pure, security-insensitive transform: each byte becomes its high then low nibble.
fn encode_hex(bytes: &[u8]) -> String {
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
    use proptest::prelude::*;

    #[test]
    fn random_bytes_returns_requested_length() {
        // The buffer length must equal the request, including the zero-length edge —
        // a short read would silently weaken any token built on top of it.
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(32).len(), 32);
    }

    #[test]
    fn random_array_is_fixed_size_and_fresh() {
        // The stack array has the const length and two draws differ — guards the
        // zero-allocation CSPRNG path used for fixed-size nonces (collision 2^-256).
        let a = random_array::<32>();
        let b = random_array::<32>();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_eq!(random_array::<0>().len(), 0);
    }

    #[test]
    fn token_has_expected_length_and_charset() {
        // A 32-byte token is exactly 64 lower-case hex chars — pins the documented
        // 256-bit / 64-char contract that downstream Redis key suffixes rely on.
        let token = generate_secure_token(32);
        assert_eq!(token.len(), 64);
        assert!(
            token
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn successive_tokens_differ() {
        // Two 32-byte tokens must differ — a smoke test that the RNG is actually
        // sampled per call rather than returning a constant (collision odds are 2^-256).
        assert_ne!(generate_secure_token(32), generate_secure_token(32));
    }

    proptest! {
        #[test]
        fn token_length_and_charset_hold_for_any_size(byte_len in 0usize..64) {
            // For any requested size the token is `2 * byte_len` lower-case hex
            // characters — the format invariant across the whole input range.
            let token = generate_secure_token(byte_len);
            prop_assert_eq!(token.len(), byte_len * 2);
            prop_assert!(token.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }
}
