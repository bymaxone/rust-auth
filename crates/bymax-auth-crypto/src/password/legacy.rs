//! The pre-PHC nest-auth encoding: `scrypt:N:r:p:{salt_hex}:{derived_hex}`.
//!
//! Read-only, and always reported as needing a rehash — nothing here mints this shape.
//!
//! # Why this exists
//!
//! The two implementations share one user table and one brute-force counter. nest-auth wrote
//! this encoding before the pair agreed on PHC, and a hash this crate cannot read does not
//! surface as a parse failure: [`super::verify`] is total, so it collapses to `Ok(false)` and
//! the engine answers `auth.invalid_credentials` — indistinguishable from a wrong password.
//! Five of those trip the *shared* `lf:` lockout, so an account whose hash is in the legacy
//! shape is locked out of **both** backends by its owner's own correct attempts.
//!
//! The wire contract called the format "self-describing", which both encodings are. That is
//! precisely why the divergence survived a release: prose that each side satisfied separately
//! and neither could test against the other. `credentialFormats.passwordHash` now pins the
//! encoding with known-answer vectors, and `password::tests` verifies a vector nest-auth
//! actually produced.

#[cfg(feature = "scrypt")]
use scrypt::{Params, scrypt};
#[cfg(feature = "scrypt")]
use subtle::ConstantTimeEq;

/// The derived-key length nest-auth wrote under this encoding, in bytes.
#[cfg(feature = "scrypt")]
const LEGACY_KEY_LEN: usize = 64;

/// A parsed legacy hash: the cost it records, its salt and its derived key.
#[cfg(feature = "scrypt")]
struct LegacyHash {
    log_n: u8,
    r: u32,
    p: u32,
    salt: Vec<u8>,
    derived: Vec<u8>,
}

/// Decode an even-length lowercase-or-uppercase hex string.
///
/// Written by hand rather than pulled in as a dependency: this is the only hex in the crate,
/// and `from_str_radix` on two-byte windows keeps it allocation-light and panic-free.
#[cfg(feature = "scrypt")]
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        // `chunks_exact(2)` yields two-byte windows, and both are ASCII by the `is_ascii`
        // guard below, so `from_utf8` cannot fail — but it is handled rather than unwrapped,
        // because the workspace denies `unwrap`.
        let text = core::str::from_utf8(pair).ok()?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

/// Parse `scrypt:N:r:p:{salt_hex}:{derived_hex}`.
///
/// Returns `None` for anything else, including a PHC string (which contains no `:` before its
/// first `$`, so the two shapes never collide).
#[cfg(feature = "scrypt")]
fn parse(stored: &str) -> Option<LegacyHash> {
    let mut fields = stored.split(':');
    if fields.next()? != "scrypt" {
        return None;
    }
    let n: u64 = fields.next()?.parse().ok()?;
    let r: u32 = fields.next()?.parse().ok()?;
    let p: u32 = fields.next()?.parse().ok()?;
    let salt = decode_hex(fields.next()?)?;
    let derived = decode_hex(fields.next()?)?;
    // Exactly six fields: a trailing one means the value is not this encoding.
    if fields.next().is_some() {
        return None;
    }

    // `N` must be a power of two for scrypt, and the `Params` constructor takes log2(N) as a
    // `u8`. Rejecting a non-power-of-two here rather than rounding keeps a corrupt record from
    // verifying under a cost it never used.
    if !n.is_power_of_two() || n < 2 {
        return None;
    }
    let log_n = u8::try_from(n.trailing_zeros()).ok()?;
    if derived.len() != LEGACY_KEY_LEN || r == 0 || p == 0 {
        return None;
    }

    Some(LegacyHash {
        log_n,
        r,
        p,
        salt,
        derived,
    })
}

/// Verify `password` against a legacy-encoded hash, in constant time.
///
/// Returns `false` when `stored` is not in this encoding, so the caller can try it after PHC
/// without branching on which shape it holds.
#[cfg(feature = "scrypt")]
pub(super) fn verify_legacy(password: &[u8], stored: &str) -> bool {
    let Some(parsed) = parse(stored) else {
        return false;
    };
    // Derived under the parameters the hash RECORDS, never under whatever is configured today
    // — the property that makes the cost factor raisable at all.
    let Ok(params) = Params::new(parsed.log_n, parsed.r, parsed.p, parsed.derived.len()) else {
        return false;
    };
    let mut candidate = vec![0u8; parsed.derived.len()];
    if scrypt(password, &parsed.salt, &params, &mut candidate).is_err() {
        return false;
    }
    // Lengths are equal by construction (`candidate` is sized from `derived`), so `ct_eq`
    // compares the full buffers with no early exit.
    candidate.ct_eq(&parsed.derived).into()
}

/// Without the `scrypt` feature there is no verifier for this encoding, so a legacy hash is
/// simply unreadable — the same answer the crate gives for any algorithm it cannot compute.
#[cfg(not(feature = "scrypt"))]
pub(super) fn verify_legacy(_password: &[u8], _stored: &str) -> bool {
    false
}
