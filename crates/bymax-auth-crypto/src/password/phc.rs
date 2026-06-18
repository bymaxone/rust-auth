//! PHC parsing, verification, rehash detection, and the legacy `scrypt:hex:hex`
//! compatibility parser.

use password_hash::{PasswordHash, PasswordVerifier};

#[cfg(feature = "argon2")]
use argon2::Argon2;
#[cfg(feature = "scrypt")]
use scrypt::Scrypt;

use super::{PasswordAlgorithm, PasswordParams};

/// Verify `password` against a PHC string, auto-selecting the verifier from the PHC
/// algorithm prefix. Returns `false` for a wrong password, a malformed string, or an
/// algorithm whose feature is not compiled in — never panics.
pub(super) fn verify_phc(password: &[u8], phc: &str) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else {
        return false;
    };
    let verifiers: &[&dyn PasswordVerifier] = &[
        #[cfg(feature = "scrypt")]
        &Scrypt,
        #[cfg(feature = "argon2")]
        &Argon2::default(),
    ];
    hash.verify_password(verifiers, password).is_ok()
}

/// Return `true` when the PHC hash should be re-hashed under `current` — a different
/// algorithm than `current.active`, weaker-than-current parameters, or an unparseable
/// string.
pub(super) fn needs_rehash_phc(phc: &str, current: &PasswordParams) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else {
        return true;
    };
    let ident = hash.algorithm.as_str();
    match current.active {
        #[cfg(feature = "scrypt")]
        PasswordAlgorithm::Scrypt => scrypt_is_stale(&hash, ident, &current.scrypt),
        // Scrypt is the active writer but its feature is absent: the stored hash can
        // never match the (uncompiled) active algorithm, so it is always stale.
        #[cfg(not(feature = "scrypt"))]
        PasswordAlgorithm::Scrypt => true,
        #[cfg(feature = "argon2")]
        PasswordAlgorithm::Argon2id => argon2_is_stale(&hash, ident, &current.argon2),
    }
}

/// Read a decimal PHC parameter (e.g. `ln`, `m`, `t`, `p`) as a `u32`.
fn decimal_param(hash: &PasswordHash, name: &str) -> Option<u32> {
    hash.params.get_decimal(name)
}

/// Stale-check for a stored hash against the current scrypt configuration.
#[cfg(feature = "scrypt")]
fn scrypt_is_stale(hash: &PasswordHash, ident: &str, current: &super::ScryptParams) -> bool {
    if ident != "scrypt" {
        return true;
    }
    let current_ln = current.cost_factor.trailing_zeros();
    match (
        decimal_param(hash, "ln"),
        decimal_param(hash, "r"),
        decimal_param(hash, "p"),
    ) {
        (Some(ln), Some(r), Some(p)) => {
            ln < current_ln || r < current.block_size || p < current.parallelization
        }
        // A scrypt-tagged hash missing its cost parameters is malformed → rehash.
        _ => true,
    }
}

/// Stale-check for a stored hash against the current Argon2id configuration.
#[cfg(feature = "argon2")]
fn argon2_is_stale(hash: &PasswordHash, ident: &str, current: &super::Argon2Params) -> bool {
    if ident != "argon2id" {
        return true;
    }
    match (
        decimal_param(hash, "m"),
        decimal_param(hash, "t"),
        decimal_param(hash, "p"),
    ) {
        (Some(m), Some(t), Some(p)) => {
            m < current.memory_kib || t < current.iterations || p < current.parallelism
        }
        // An argon2id-tagged hash missing its cost parameters is malformed → rehash.
        _ => true,
    }
}

/// Cheap detection of the legacy nest-auth `scrypt:{salt_hex}:{hash_hex}` format,
/// distinguished from a PHC scrypt hash by its `scrypt:` (not `$scrypt$`) prefix.
#[cfg(feature = "scrypt")]
pub(super) fn is_legacy(phc: &str) -> bool {
    phc.starts_with("scrypt:")
}

/// Largest derived-key length, in bytes, the legacy verifier will accept. nest-auth's
/// corpus used a 32-byte key; 64 leaves headroom while bounding the work a crafted
/// over-long hash could force the KDF to do (an attacker controls neither the stored
/// hash nor a verification endpoint, but the cap removes the amplification entirely).
#[cfg(feature = "scrypt")]
const LEGACY_MAX_KEY_LEN: usize = 64;

/// nest-auth's stored scrypt corpus used `N = 2^15`, `r = 8`, `p = 1` (spec §17.1 /
/// §19.1); the legacy verifier recomputes the KDF with exactly these parameters.
#[cfg(feature = "scrypt")]
const LEGACY_LOG_N: u8 = 15;
#[cfg(feature = "scrypt")]
const LEGACY_BLOCK_SIZE: u32 = 8;
#[cfg(feature = "scrypt")]
const LEGACY_PARALLELISM: u32 = 1;

/// Parse a legacy `scrypt:{salt_hex}:{hash_hex}` string into `(salt, expected)` bytes.
/// Returns `None` for any other format, invalid hex, or a derived key longer than
/// [`LEGACY_MAX_KEY_LEN`].
#[cfg(feature = "scrypt")]
pub(super) fn parse_legacy(phc: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let rest = phc.strip_prefix("scrypt:")?;
    let (salt_hex, hash_hex) = rest.split_once(':')?;
    if hash_hex.contains(':') {
        return None;
    }
    let salt = decode_hex(salt_hex)?;
    let expected = decode_hex(hash_hex)?;
    if salt.is_empty() || expected.is_empty() || expected.len() > LEGACY_MAX_KEY_LEN {
        return None;
    }
    Some((salt, expected))
}

/// Verify a legacy scrypt hash by recomputing the KDF with nest-auth's parameters
/// (`N = 2^15`, `r = 8`, `p = 1`) and comparing in constant time.
#[cfg(feature = "scrypt")]
pub(super) fn verify_legacy(password: &[u8], salt: &[u8], expected: &[u8]) -> bool {
    // Any failure along the way (a bad output length rejected by `Params::new`, or the
    // structurally-unreachable KDF error) maps to `None` and so fails verification —
    // fail-closed, never a panic and never a silently-discarded error.
    scrypt::Params::new(
        LEGACY_LOG_N,
        LEGACY_BLOCK_SIZE,
        LEGACY_PARALLELISM,
        expected.len(),
    )
    .ok()
    .and_then(|params| {
        // The derived key is secret material — held in a zeroizing buffer, wiped on drop.
        let mut out = zeroize::Zeroizing::new(vec![0u8; expected.len()]);
        scrypt::scrypt(password, salt, &params, &mut out)
            .ok()
            .map(|()| out)
    })
    .is_some_and(|out| crate::compare::constant_time_eq(&out, expected))
}

/// Decode a lower/upper-case hex string into bytes; `None` on odd length or a
/// non-hex character.
#[cfg(feature = "scrypt")]
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

/// Map one hex ASCII digit to its nibble value; `None` if not a hex digit.
#[cfg(feature = "scrypt")]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
