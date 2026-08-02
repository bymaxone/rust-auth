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
