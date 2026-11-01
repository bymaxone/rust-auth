//! Service API-key format, digest and comparison.
//!
//! Layer: a pure primitive, with no configuration and no I/O beyond the CSPRNG draw in
//! [`generate_secret`].
//!
//! A key is `{prefix}_{key_id}_{secret}`. The `key_id` is a public lookup handle (a lowercase
//! canonical UUID), the `secret` is 32 random bytes in unpadded base64url (43 characters), and only
//! the HMAC-SHA-256 of the secret under a server-held pepper is ever stored. The grammar and the
//! digest are pinned by the `apiKeys` section of `conformance/wire-contract.json`, because
//! nest-auth mints and verifies the same keys and a deployment may re-issue them from one backend
//! and verify them on the other.

use crate::mac::{hmac_sha256, verify_digest};
use crate::token::{encode_hex, random_array};

/// Separator between the three parts of a key. The base64url alphabet contains it, which is why
/// [`parse`] splits on the first two only.
pub const SEPARATOR: char = '_';

/// The prefix a deployment gets when it configures none.
pub const DEFAULT_PREFIX: &str = "bak";

/// Length of the `key_id` part: a canonical UUID.
pub const KEY_ID_LEN: usize = 36;

/// Length of the `secret` part: 32 bytes in unpadded base64url.
pub const SECRET_LEN: usize = 43;

/// Bytes in a SHA-256 / HMAC-SHA-256 digest.
const DIGEST_LEN: usize = 32;

/// Bytes of entropy in a secret: the HMAC-SHA-256 output length, the floor RFC 2104 §3 gives a key.
const SECRET_BYTES: usize = 32;

/// Characters in a stored digest: 32 bytes as lowercase hex.
const DIGEST_HEX_LEN: usize = DIGEST_LEN * 2;

/// The `key_id` verification substitutes for a key that did not parse, so the store lookup runs on
/// every request. A canonical UUID no issued key carries, because issued ids are random v4.
pub const DUMMY_KEY_ID: &str = "00000000-0000-4000-8000-000000000000";

/// The secret substituted for a key that did not parse, so the digest step runs on every request.
pub const DUMMY_SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The digest compared against when no row was found. All zero, so no HMAC the library computes
/// equals it in practice, and the verdict never rests on this comparison alone.
pub const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The unpadded base64url alphabet (RFC 4648 §5).
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A key split into the two parts verification needs.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedApiKey<'a> {
    /// The public lookup handle: the id of the stored row.
    pub key_id: &'a str,
    /// The secret half, never stored and never logged.
    pub secret: &'a str,
}

/// Draw a fresh secret from the CSPRNG: 43 base64url characters carrying 256 bits.
#[must_use]
pub fn generate_secret() -> String {
    encode_base64url(&random_array::<SECRET_BYTES>())
}

/// Join the three parts into the string a caller presents. The plaintext key is handed to its
/// holder once and never stored.
#[must_use]
pub fn format(prefix: &str, key_id: &str, secret: &str) -> String {
    format!("{prefix}{SEPARATOR}{key_id}{SEPARATOR}{secret}")
}

/// Split a presented key, or answer `None` for anything that is not exactly the grammar.
///
/// Splits on the first two separators only: the prefix and a UUID contain none, and a secret may.
/// Never panics, and a malformed key is not distinguishable from a wrong one by anything but this
/// return value.
#[must_use]
pub fn parse<'a>(raw: &'a str, prefix: &str) -> Option<ParsedApiKey<'a>> {
    let rest = raw.strip_prefix(prefix)?.strip_prefix(SEPARATOR)?;
    let key_id = rest.get(..KEY_ID_LEN)?;
    if rest.as_bytes().get(KEY_ID_LEN) != Some(&(SEPARATOR as u8)) {
        return None;
    }
    let secret = rest.get(KEY_ID_LEN + 1..)?;
    (is_key_id(key_id) && is_secret(secret)).then_some(ParsedApiKey { key_id, secret })
}

/// The digest stored for a secret: lowercase hex HMAC-SHA-256 keyed with the pepper.
///
/// Labels and scopes are deliberately not part of the input: they are mutable metadata, and a
/// digest that covered them would change when an operator edited either.
#[must_use]
pub fn digest(secret: &str, pepper: &str) -> String {
    encode_hex(&hmac_sha256(pepper.as_bytes(), secret.as_bytes()))
}

/// Compare two digests in constant time over two 32-byte buffers.
///
/// A value that is not 64 lowercase hex characters, for example a corrupted row, is replaced by a
/// zero buffer and forced to a mismatch: the comparison still runs, and a malformed value never
/// matches anything. Two well-formed equal values match.
#[must_use]
pub fn digests_match(computed: &str, stored: &str) -> bool {
    let (left, left_ok) = decode_digest(computed);
    let (right, right_ok) = decode_digest(stored);
    let equal = verify_digest(&left, &right);
    equal && left_ok && right_ok
}

/// Whether `s` is a canonical lowercase UUID: 8-4-4-4-12 lowercase hex.
fn is_key_id(s: &str) -> bool {
    s.len() == KEY_ID_LEN
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// Whether `s` is exactly 43 unpadded base64url characters.
fn is_secret(s: &str) -> bool {
    s.len() == SECRET_LEN && s.bytes().all(|b| BASE64URL.contains(&b))
}

/// Decode 64 lowercase hex characters, or a zero buffer and `false` for anything else.
fn decode_digest(hex: &str) -> ([u8; DIGEST_LEN], bool) {
    let bytes = hex.as_bytes();
    let well_formed = bytes.len() == DIGEST_HEX_LEN
        && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let mut out = [0u8; DIGEST_LEN];
    if well_formed {
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            *slot = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
    }
    (out, well_formed)
}

/// The value of a lowercase hex digit already known to be one.
fn nibble(b: u8) -> u8 {
    if b.is_ascii_digit() {
        b - b'0'
    } else {
        b - b'a' + 10
    }
}

/// Unpadded base64url. Hand-rolled, like the hex encoder, because encoding is a pure,
/// security-insensitive transform and a runtime dependency for it is not worth carrying.
fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        // Three bytes make one 24-bit group, read as four 6-bit indices.
        let n = usize::from(b0) * 65_536 + usize::from(b1) * 256 + usize::from(b2);
        let group = [n / 262_144 % 64, n / 4_096 % 64, n / 64 % 64, n % 64];
        // 1 byte yields 2 characters, 2 bytes yield 3, 3 bytes yield 4.
        for &index in &group[..chunk.len() + 1] {
            out.push(char::from(BASE64URL[index]));
        }
    }
    out
}

#[cfg(test)]
mod tests;
