//! Argon2id PHC hashing (the `argon2` feature).

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHasher, SaltString};
use rand::rngs::OsRng;

use super::Argon2Params;
use crate::CryptoError;

/// Derived-key length in bytes for new Argon2id hashes.
const OUTPUT_LEN: usize = 32;

/// Hash `password` with Argon2id and the given cost parameters, returning a PHC string.
///
/// The 16-byte random salt is drawn from the CSPRNG by `SaltString::generate`.
pub(super) fn hash(password: &[u8], params: &Argon2Params) -> Result<String, CryptoError> {
    params.validate()?;
    // The constructor enforces Argon2's internal relations (e.g. `memory >= 8 * lanes`),
    // rejecting an otherwise-above-floor but inconsistent parameter set.
    let inner = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(OUTPUT_LEN),
    )
    .map_err(|_| CryptoError::InvalidParams)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, inner);
    let salt = SaltString::generate(&mut OsRng);
    // With validated params and a freshly generated salt the KDF cannot fail; the
    // `.ok()...ok_or` form maps the unreachable error to `CryptoError::Hash` without an
    // untestable `?` error branch (the error value is constructed on every call).
    hasher
        .hash_password(password, &salt)
        .ok()
        .map(|phc| phc.to_string())
        .ok_or(CryptoError::Hash)
}
