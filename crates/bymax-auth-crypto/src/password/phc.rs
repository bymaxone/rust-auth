//! PHC parsing, verification, and rehash detection.

use password_hash::{PasswordHash, PasswordVerifier};

#[cfg(feature = "argon2")]
use argon2::Argon2;
#[cfg(feature = "scrypt")]
use scrypt::Scrypt;

use super::{PasswordAlgorithm, PasswordParams};

/// Verify `password` against a PHC string, auto-selecting the verifier from the PHC
/// algorithm prefix. Returns `false` for a wrong password, a malformed string, or an
/// algorithm whose feature is not compiled in — never panics.
///
/// PHC is the only encoding either implementation reads. nest-auth writes it too, so a hash
/// from one backend verifies under the other, and there is no second shape to fall back to:
/// nothing in the credential path branches on which library wrote the record.
pub(super) fn verify_phc(password: &[u8], phc: &str) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else {
        return false;
    };
    if !cost_is_admissible(&hash) {
        return false;
    }
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

/// The largest working set a STORED record may ask the KDF for, in bytes.
///
/// 512 MiB — four times the shipped scrypt default (`N = 2^17, r = 8` is 128 MiB, the OWASP
/// recommendation), and the same figure nest-auth's parser enforces, so the two implementations
/// refuse exactly the same records out of the user table they share.
const MAX_KDF_BYTES_PER_DERIVATION: u64 = 512 * 1024 * 1024;

/// The largest `r` or `p` a stored scrypt record may carry. Both implementations write 8 and 1.
const MAX_SCRYPT_PARAMETER: u32 = 255;

/// Whether the cost recorded IN the hash is one this process is willing to derive under.
///
/// The verifiers take their parameters from the record, so without this the stored string
/// decides how much memory the process allocates. `$scrypt$ln=31,r=8,p=1$…` asks for 2 TiB:
/// that is not a failed login, it is an allocation that OOM-kills the host and takes every
/// in-flight connection with it — from an unauthenticated route, since the derivation runs
/// before the password is known to be right. The same applies to Argon2id's `m`.
///
/// A record written under a validated configuration is always admissible, because startup holds
/// the configured cost to the same ceiling. So nothing legitimate is refused: this only rejects
/// a record no deployment of either implementation could have produced, and refusing it reads
/// to the caller exactly like a wrong password.
pub(super) fn cost_is_admissible(hash: &PasswordHash) -> bool {
    match hash.algorithm.as_str() {
        "scrypt" => scrypt_cost_is_admissible(hash),
        "argon2id" => argon2_cost_is_admissible(hash),
        // An algorithm no verifier here handles is refused downstream anyway.
        _ => true,
    }
}

/// The scrypt half of [`cost_is_admissible`]: `128 * N * r` bytes, with `N = 2 ** ln`.
fn scrypt_cost_is_admissible(hash: &PasswordHash) -> bool {
    let (Some(ln), Some(r), Some(p)) = (
        decimal_param(hash, "ln"),
        decimal_param(hash, "r"),
        decimal_param(hash, "p"),
    ) else {
        return false;
    };
    if ln == 0
        || !(1..=MAX_SCRYPT_PARAMETER).contains(&r)
        || !(1..=MAX_SCRYPT_PARAMETER).contains(&p)
    {
        return false;
    }
    // Checked throughout: an `ln` of 64 or more has no `2 ** ln` in a u64 at all, and
    // `checked_shl` answers `None` rather than wrapping to a small, admissible-looking number.
    1u64.checked_shl(ln)
        .and_then(|n| n.checked_mul(u64::from(r)))
        .and_then(|nr| nr.checked_mul(128))
        .is_some_and(|bytes| bytes <= MAX_KDF_BYTES_PER_DERIVATION)
}

/// The Argon2id half of [`cost_is_admissible`]: `m` is the working set, in KiB.
fn argon2_cost_is_admissible(hash: &PasswordHash) -> bool {
    let Some(memory_kib) = decimal_param(hash, "m") else {
        return false;
    };
    u64::from(memory_kib)
        .checked_mul(1024)
        .is_some_and(|bytes| bytes <= MAX_KDF_BYTES_PER_DERIVATION)
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
