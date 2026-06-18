//! scrypt PHC hashing (the `scrypt` feature).

use password_hash::{PasswordHasher, SaltString};
use rand::rngs::OsRng;
use scrypt::{Params, Scrypt};

use super::ScryptParams;
use crate::CryptoError;

/// Derived-key length in bytes for new scrypt hashes.
const OUTPUT_LEN: usize = 32;

/// Hash `password` with scrypt and the given cost parameters, returning a PHC string.
///
/// The 16-byte random salt is drawn from the CSPRNG by `SaltString::generate`.
pub(super) fn hash(password: &[u8], params: &ScryptParams) -> Result<String, CryptoError> {
    params.validate()?;
    // `cost_factor` is a validated power of two, so `trailing_zeros()` (in 14..=31)
    // is exactly `log2(N)` and fits in the `u8` the scrypt parameter expects.
    let log_n = params.cost_factor.trailing_zeros() as u8;
    // The constructor enforces the remaining bounds (e.g. `r`/`p` must be non-zero),
    // so a below-floor `block_size`/`parallelization` is rejected here.
    let inner = Params::new(log_n, params.block_size, params.parallelization, OUTPUT_LEN)
        .map_err(|_| CryptoError::InvalidParams)?;
    let salt = SaltString::generate(&mut OsRng);
    // With validated params and a freshly generated salt the KDF cannot fail; the
    // `.ok()...ok_or` form maps the unreachable error to `CryptoError::Hash` without an
    // untestable `?` error branch (the error value is constructed on every call).
    Scrypt
        .hash_password_customized(password, None, None, inner, &salt)
        .ok()
        .map(|phc| phc.to_string())
        .ok_or(CryptoError::Hash)
}
