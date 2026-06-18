//! Password hashing over RustCrypto: scrypt (default) and Argon2id (`argon2`
//! feature), producing self-describing PHC strings with constant-time verification,
//! rehash-on-verify detection, parameter-floor validation, and a compatibility
//! parser for the legacy `scrypt:hex:hex` corpus.
//!
//! Run [`hash`] and [`verify`] inside `tokio::task::spawn_blocking` (or equivalent);
//! both are synchronous, memory-hard CPU work (~100–200 ms) and would otherwise stall
//! an async runtime worker. This crate takes no runtime dependency, so dispatching to
//! a blocking pool is the **caller's** responsibility.
//!
//! # Storage format
//!
//! New hashes are written as standard PHC strings — `$scrypt$ln=15,r=8,p=1$…` or
//! `$argon2id$v=19$m=19456,t=2,p=1$…` — which self-describe their algorithm and
//! parameters. [`verify`] additionally accepts the legacy nest-auth
//! `scrypt:{salt_hex}:{hash_hex}` form (under the `scrypt` feature) and
//! [`needs_rehash`] always reports it as stale so it migrates to PHC on next login.

#[cfg(feature = "argon2")]
mod argon2;
mod phc;
#[cfg(feature = "scrypt")]
mod scrypt;

use crate::CryptoError;

/// The KDF used to hash a new password. Verification accepts any supported algorithm
/// regardless of which one is active here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// scrypt (RFC 7914) — the parity default with nest-auth's stored corpus. Always
    /// representable so this `#[default]` compiles even in an Argon2id-only build; but
    /// hashing with it requires the `scrypt` feature (otherwise [`hash`] returns
    /// [`CryptoError::InvalidParams`]).
    #[default]
    Scrypt,
    /// Argon2id (RFC 9106) — OWASP's first-choice memory-hard KDF, recommended for new
    /// deployments. Selectable only when the `argon2` feature is compiled in.
    #[cfg(feature = "argon2")]
    Argon2id,
}

/// scrypt cost parameters.
///
/// `cost_factor` is the CPU/memory cost `N`; it must be a power of two and at least
/// [`ScryptParams::MIN_COST_FACTOR`] (the security floor). `block_size` is `r` and
/// `parallelization` is `p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScryptParams {
    /// CPU/memory cost `N`. Power of two, `>= 2^14`. Default `2^15` (32768).
    pub cost_factor: u32,
    /// Block size `r`. Default 8.
    pub block_size: u32,
    /// Parallelization `p`. Default 1.
    pub parallelization: u32,
}

impl ScryptParams {
    /// Minimum accepted `cost_factor` (`2^14` = 16384) — the enforced security floor.
    pub const MIN_COST_FACTOR: u32 = 1 << 14;

    /// Validate `cost_factor` against the floor.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidParams`] when `cost_factor` is not a power of two
    /// or is below [`MIN_COST_FACTOR`](Self::MIN_COST_FACTOR). The `block_size` /
    /// `parallelization` sanity bounds are enforced by the KDF parameter constructor
    /// in [`hash`].
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.cost_factor < Self::MIN_COST_FACTOR || !self.cost_factor.is_power_of_two() {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            cost_factor: 1 << 15,
            block_size: 8,
            parallelization: 1,
        }
    }
}

/// Argon2id cost parameters (`argon2` feature).
///
/// Defaults and floors track the OWASP production baseline: `memory_kib >= 19456`,
/// `iterations >= 2`, `parallelism >= 1`.
#[cfg(feature = "argon2")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB. Default and floor 19456 (19 MiB, OWASP baseline).
    pub memory_kib: u32,
    /// Iterations (time cost). Default and floor 2.
    pub iterations: u32,
    /// Degree of parallelism (lanes). Default 1.
    pub parallelism: u32,
}

#[cfg(feature = "argon2")]
impl Argon2Params {
    /// Minimum accepted `memory_kib` (OWASP production floor).
    pub const MIN_MEMORY_KIB: u32 = 19456;
    /// Minimum accepted `iterations` (OWASP production floor).
    pub const MIN_ITERATIONS: u32 = 2;

    /// Validate the parameters against the OWASP floors.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidParams`] when `memory_kib`, `iterations`, or
    /// `parallelism` is below its floor.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.memory_kib < Self::MIN_MEMORY_KIB
            || self.iterations < Self::MIN_ITERATIONS
            || self.parallelism == 0
        {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }
}

#[cfg(feature = "argon2")]
impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: Self::MIN_MEMORY_KIB,
            iterations: Self::MIN_ITERATIONS,
            parallelism: 1,
        }
    }
}

/// The resolved hashing configuration: which algorithm to write with, and the cost
/// parameters for each supported algorithm.
#[derive(Clone, Copy, Debug, Default)]
pub struct PasswordParams {
    /// Algorithm used to hash NEW passwords.
    pub active: PasswordAlgorithm,
    /// scrypt cost parameters (used when `active` is [`PasswordAlgorithm::Scrypt`]).
    pub scrypt: ScryptParams,
    /// Argon2id cost parameters (used when `active` is [`PasswordAlgorithm::Argon2id`]).
    #[cfg(feature = "argon2")]
    pub argon2: Argon2Params,
}

/// Hash `password` with the active algorithm, returning a self-describing PHC string.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] when the active algorithm's parameters are
/// below the security floor (or the active algorithm's feature is not compiled in),
/// and [`CryptoError::Hash`] if the underlying KDF fails.
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::password::{hash, verify, PasswordParams};
///
/// // The default writer is scrypt; in an Argon2id-only build the default would
/// // instead return `Err(InvalidParams)`, so guard on the `Ok` to stay build-agnostic.
/// if let Ok(phc) = hash(b"correct horse battery staple", &PasswordParams::default()) {
///     assert!(phc.starts_with("$scrypt$"));
///     assert!(verify(b"correct horse battery staple", &phc).unwrap());
/// }
/// ```
pub fn hash(password: &[u8], params: &PasswordParams) -> Result<String, CryptoError> {
    match params.active {
        #[cfg(feature = "scrypt")]
        PasswordAlgorithm::Scrypt => scrypt::hash(password, &params.scrypt),
        // `Scrypt` is always representable but cannot be a writer without its feature.
        #[cfg(not(feature = "scrypt"))]
        PasswordAlgorithm::Scrypt => Err(CryptoError::InvalidParams),
        #[cfg(feature = "argon2")]
        PasswordAlgorithm::Argon2id => argon2::hash(password, &params.argon2),
    }
}

/// Verify `password` against a stored hash, in constant time.
///
/// This function is **total**: a wrong password, a malformed PHC string, or an
/// unknown algorithm all return `Ok(false)` — never `Err`, never a panic. The stored
/// algorithm is auto-detected from the PHC prefix (or the legacy `scrypt:hex:hex`
/// form), so hashes written under any supported scheme still verify, and the password
/// comparison itself is constant-time (via the `password-hash` verifier).
///
/// Timing: a *malformed* stored hash returns before the KDF runs, so it is not
/// time-equivalent to a wrong password (which runs the full KDF). This is not a login
/// oracle — the caller supplies the password while the stored hash is server-side (a
/// real PHC string or the startup sentinel), so the fast path is never reached with
/// attacker-controlled input. The anti-enumeration timing floor lives in the engine,
/// not here.
///
/// # Errors
///
/// Never returns `Err`; the `Result` exists for symmetry with [`hash`] and forward
/// compatibility.
pub fn verify(password: &[u8], phc: &str) -> Result<bool, CryptoError> {
    #[cfg(feature = "scrypt")]
    if let Some((salt, expected)) = phc::parse_legacy(phc) {
        return Ok(phc::verify_legacy(password, &salt, &expected));
    }
    Ok(phc::verify_phc(password, phc))
}

/// Return `true` when a stored hash should be re-hashed with the current config.
///
/// True when the stored hash uses a different algorithm than `current.active`, uses
/// weaker-than-current parameters, is unparseable, or is the legacy
/// `scrypt:hex:hex` format. Drives transparent rehash-on-verify: the caller re-hashes
/// the just-verified plaintext and persists it.
#[must_use]
pub fn needs_rehash(phc: &str, current: &PasswordParams) -> bool {
    #[cfg(feature = "scrypt")]
    if phc::is_legacy(phc) {
        return true;
    }
    phc::needs_rehash_phc(phc, current)
}

#[cfg(test)]
mod tests;
