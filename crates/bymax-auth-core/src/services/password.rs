//! The engine's password service: async hashing/verification that dispatches the
//! synchronous, memory-hard KDF to `tokio::task::spawn_blocking`, rehash-on-verify
//! detection against the active parameters, and a startup-loaded sentinel hash that keeps
//! login latency uniform for an absent user (anti-enumeration, §7.1.2 / §15.5).
//!
//! The crypto crate ([`bymax_auth_crypto::password`]) is synchronous and ~100–200 ms per
//! call; running it inline on an async worker would stall every other in-flight request,
//! so every hash/verify here — including the sentinel and the rehash — goes through the
//! blocking pool (§7.2). Construction is the one exception: the sentinel is computed once,
//! synchronously, while the engine is still being assembled.

use std::sync::Arc;

use bymax_auth_crypto::CryptoError;
use bymax_auth_crypto::password::{PasswordParams, hash, needs_rehash, verify};
use bymax_auth_types::{AuthError, FieldError};
use tokio::sync::Semaphore;
use tokio::task::JoinError;

use crate::ConfigError;
use crate::config::PasswordConfig;
use crate::services::internal_error;
#[cfg(test)]
use crate::traits::breach::AllowAllBreachChecker;
use crate::traits::breach::PasswordBreachChecker;

/// A fixed, non-secret plaintext hashed once at startup into the [`PasswordService`]
/// sentinel. Its only purpose is to give the absent-user login path a real PHC string to
/// run the full KDF against, so timing cannot distinguish a missing account from a wrong
/// password. The value is not a credential — it never authenticates anything.
const SENTINEL_PLAINTEXT: &[u8] = b"bymax-auth::anti-enumeration-sentinel::v1";

/// The lowest `password.min_length` a deployment may configure — the structural floor the
/// DTOs already enforce, below which the setting could not change any outcome.
const MIN_CONFIGURABLE_LENGTH: u32 = 8;

/// The highest `password.min_length` a deployment may configure — the longest password the
/// DTOs accept, above which no password could be set at all.
const MAX_CONFIGURABLE_LENGTH: u32 = 128;

/// The result of [`PasswordService::verify`]: whether the password matched the stored hash
/// and whether that stored hash is weaker than the active configuration (so the caller can
/// fire a rehash-on-verify upgrade).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// Whether the supplied password verified against the stored hash.
    pub matched: bool,
    /// Whether the stored hash should be re-hashed with the current scheme.
    pub needs_rehash: bool,
}

/// Hashes and verifies passwords with the configured memory-hard KDF, off the async
/// runtime. Holds the resolved crypto parameters, the `rehash_on_verify` toggle, and the
/// precomputed sentinel hash.
pub struct PasswordService {
    params: PasswordParams,
    rehash_on_verify: bool,
    min_length: u32,
    sentinel: String,
    breach_checker: Arc<dyn PasswordBreachChecker>,
    /// Bounds how many memory-hard derivations run at once. See [`kdf_permit_count`].
    kdf_permits: Arc<Semaphore>,
}

/// The resident-memory budget the concurrent KDF derivations are sized against, in MiB.
///
/// 512 MiB, which is what nest-auth admits by construction: Node's `crypto.scrypt` runs on the
/// libuv thread pool, four threads by default, at ~128 MiB of working set each. The two
/// libraries can back the same deployment, so their load shapes should not differ by an order
/// of magnitude on the one route an unauthenticated caller can drive.
///
/// **Sized against, not capped by.** [`kdf_permit_count`] floors at two permits, so a
/// configuration whose single derivation already exceeds 256 MiB admits 2 × that working set
/// and overshoots this figure. That is deliberate and it is the lesser of the two failures: one
/// permit makes every login on the deployment strictly sequential behind a memory-hard KDF,
/// which is a self-inflicted denial of service on the same unauthenticated route. A working set
/// that large is a configuration worth questioning on its own — the defaults are 128 MiB
/// (scrypt at `N = 2^17, r = 8`) and 19 MiB (Argon2id) — and the budget is what keeps the
/// ordinary case bounded rather than a guarantee for the extreme one.
const KDF_MEMORY_BUDGET_MIB: usize = 512;

/// The working set one derivation holds, in MiB, for the algorithm new hashes are made with.
///
/// scrypt's is `128 * N * r` bytes — at the default `N = 2^17, r = 8` that is **128 MiB**, not
/// the ~16 MiB this module used to claim. The figure was wrong by 8×, and it was the number the
/// concurrency ceiling was reasoned from, so the ceiling inherited the error.
fn kdf_working_set_mib(config: &crate::config::PasswordConfig) -> usize {
    match config.active_algorithm {
        crate::config::PasswordAlgorithm::Scrypt => {
            let n = config.scrypt.cost_factor as usize;
            let r = config.scrypt.block_size as usize;
            (128usize.saturating_mul(n).saturating_mul(r) / (1024 * 1024)).max(1)
        }
        // `Argon2id` is compile-gated behind the `argon2` feature — it is not merely unselectable
        // without it, the VARIANT does not exist — so the arm has to carry the same gate or a
        // build without the feature fails to compile on a pattern naming something absent.
        #[cfg(feature = "argon2")]
        crate::config::PasswordAlgorithm::Argon2id => {
            (config.argon2.memory_kib as usize / 1024).max(1)
        }
    }
}

/// How many KDF derivations may run concurrently.
///
/// `spawn_blocking` alone bounds nothing useful here. Tokio's blocking pool defaults to 512
/// threads, and every one of these tasks holds the KDF's working memory for its whole run.
/// Unbounded, a few hundred concurrent logins reach tens of gigabytes of resident memory — and
/// login is a route an unauthenticated caller can drive: the derivation runs before the password
/// is known to be right, and the absent-user path deliberately runs one too. The per-IP limiter
/// does not help against a distributed caller, and the per-account lockout does not fire on
/// distinct addresses.
///
/// The ceiling is sized from a MEMORY budget rather than a core count. One-per-core was the previous rule and it
/// scaled the wrong quantity: a 32-core host admitted 32 concurrent derivations, which at the
/// real 128 MiB working set is ~4 GiB resident on an unauthenticated route — while nest-auth,
/// pinned at four by the libuv pool, admitted ~512 MiB for the same traffic. Dividing a fixed
/// budget by the configured working set makes a heavier cost factor buy fewer slots rather than
/// more memory, which is the direction that stays safe when someone raises it.
///
/// Still capped by the core count on top, because the work is CPU- and memory-bound and
/// admitting more than that adds pressure without adding throughput. Never fewer than two, so a
/// deliberately huge cost factor cannot serialize the service into a deadlock-shaped queue.
/// Past the ceiling requests queue, which is the behaviour to want under load — and the wait is
/// identical for a real and an absent account, so the timing uniformity the sentinel exists for
/// survives it.
fn kdf_permit_count(config: &crate::config::PasswordConfig) -> usize {
    let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
    let by_memory = KDF_MEMORY_BUDGET_MIB / kdf_working_set_mib(config);
    by_memory.clamp(2, cores.max(2))
}

impl PasswordService {
    /// Build the service from `config`, computing the sentinel hash once (synchronously,
    /// during engine assembly).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::SentinelHashFailed`] if the KDF rejects the (already
    /// validated) parameters while hashing the sentinel — effectively unreachable once
    /// startup validation has accepted the configuration.
    pub(crate) fn new(
        config: &PasswordConfig,
        breach_checker: Arc<dyn PasswordBreachChecker>,
    ) -> Result<Self, ConfigError> {
        if !(MIN_CONFIGURABLE_LENGTH..=MAX_CONFIGURABLE_LENGTH).contains(&config.min_length) {
            return Err(ConfigError::PasswordMinLengthRange {
                got: config.min_length,
            });
        }
        let params = to_crypto_params(config);
        let sentinel =
            hash(SENTINEL_PLAINTEXT, &params).map_err(|_| ConfigError::SentinelHashFailed)?;
        Ok(Self {
            params,
            rehash_on_verify: config.rehash_on_verify,
            min_length: config.min_length,
            sentinel,
            breach_checker,
            kdf_permits: Arc::new(Semaphore::new(kdf_permit_count(config))),
        })
    }

    /// Take one of the KDF's concurrency permits, held for the whole derivation.
    ///
    /// # Errors
    ///
    /// Returns a generic [`AuthError::Internal`] if the semaphore has been closed, which this
    /// crate never does — it is owned by the service and lives as long as it.
    async fn acquire_kdf_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, AuthError> {
        // `let-else` rather than `map_err`: a closure is a function of its own to the coverage
        // instrumentation, and this one runs only if the semaphore is closed — which this crate
        // never does, since it owns it and it lives as long as the service. A branch nothing can
        // reach is a branch; a function nothing can reach fails a 100% function gate.
        let Ok(permit) = Arc::clone(&self.kdf_permits).acquire_owned().await else {
            return Err(internal_error("kdf concurrency limiter closed"));
        };
        Ok(permit)
    }

    /// Reject a password that appears in a known-breach corpus.
    ///
    /// Called wherever a password is being *set* — registration, reset, invitation acceptance —
    /// and never on login: refusing a breached password someone already has would lock them out
    /// of the account they need to get into in order to change it.
    ///
    /// The checker fails open by contract, so an unreachable corpus admits the password rather
    /// than blocking the credential path.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PasswordCompromised`] when the corpus knows the password.
    pub(crate) async fn assert_not_compromised(&self, password: &str) -> Result<(), AuthError> {
        if self.breach_checker.is_breached(password).await {
            return Err(AuthError::PasswordCompromised);
        }
        Ok(())
    }

    /// Reject a password shorter than the configured floor.
    ///
    /// The DTOs carry a structural `length(min = 8)` — the lowest NIST SP 800-63B-4 permits
    /// under any circumstance — and this is the deployment's policy on top of it. It lives here
    /// rather than in the DTO because a `garde` attribute is fixed when the type is compiled,
    /// before any configuration exists.
    ///
    /// It answers [`AuthError::Validation`] with the same `FieldError` shape the adapter's own
    /// validation failure produces for a short password, so the shared error catalog gains no
    /// entry and a client already handling that case sees no new shape. This is the same code
    /// and the same details nest-auth answers with.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Validation`] when the password is shorter than the floor.
    pub(crate) fn assert_long_enough(&self, password: &str, field: &str) -> Result<(), AuthError> {
        // Characters, not bytes: `len()` would make the floor depend on the alphabet, so the
        // same policy would admit a 15-character ASCII password and refuse a 15-character one
        // written in an accented or non-Latin script.
        if password.chars().count() >= self.min_length as usize {
            return Ok(());
        }
        Err(AuthError::Validation {
            details: vec![FieldError {
                field: field.to_owned(),
                message: format!("{field} must be at least {} characters", self.min_length),
            }],
        })
    }

    /// The whole password policy, applied wherever a password is being *set*.
    ///
    /// One entry point so the four call sites — registration, reset, authenticated change and
    /// invitation acceptance — cannot drift into applying different halves of it.
    ///
    /// Order matters: length first, because it is decided locally and for free, and the breach
    /// check may reach a network corpus. A password refused for being short should not cost a
    /// round trip, and should not be sent anywhere first.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Validation`] when it is too short, or
    /// [`AuthError::PasswordCompromised`] when the corpus knows it.
    pub(crate) async fn assert_acceptable(
        &self,
        password: &str,
        field: &str,
    ) -> Result<(), AuthError> {
        self.assert_long_enough(password, field)?;
        self.assert_not_compromised(password).await
    }

    /// Whether rehash-on-verify is enabled, so the caller upgrades a stale-but-valid hash.
    #[must_use]
    pub fn rehash_on_verify(&self) -> bool {
        self.rehash_on_verify
    }

    /// Hash `password` with the active algorithm, returning a self-describing PHC string.
    ///
    /// # Errors
    ///
    /// Returns a generic [`AuthError::Internal`] if the blocking task fails to join or the
    /// KDF errors — the failing step is never surfaced to the caller.
    pub async fn hash(&self, password: &str) -> Result<String, AuthError> {
        let params = self.params;
        let password = password.to_owned();
        let _permit = self.acquire_kdf_permit().await?;
        let joined = tokio::task::spawn_blocking(move || hash(password.as_bytes(), &params)).await;
        flatten_hash(joined)
    }

    /// Verify `password` against the stored `phc`, reporting both the match result and
    /// whether the stored hash needs rehashing under the active parameters. The crypto
    /// `verify` is total (a malformed hash yields `false`, never an error), so the only
    /// failure here is a blocking-pool join failure.
    ///
    /// # Errors
    ///
    /// Returns a generic [`AuthError::Internal`] if the blocking task fails to join.
    pub async fn verify(&self, password: &str, phc: &str) -> Result<VerifyOutcome, AuthError> {
        let params = self.params;
        let password = password.to_owned();
        let phc = phc.to_owned();
        let _permit = self.acquire_kdf_permit().await?;
        let joined = tokio::task::spawn_blocking(move || {
            // The crypto verifier never returns `Err`; collapse the `Result` to a bool so a
            // malformed stored hash is an authentication failure, not an error path.
            let matched = verify(password.as_bytes(), &phc).unwrap_or(false);
            let needs_rehash = needs_rehash(&phc, &params);
            VerifyOutcome {
                matched,
                needs_rehash,
            }
        })
        .await;
        joined.map_err(task_join_failed)
    }

    /// Run a throw-away verify against the startup sentinel so the absent-user login path
    /// performs the same memory-hard work as a real verify (uniform timing). The boolean
    /// result is intentionally discarded.
    ///
    /// # Errors
    ///
    /// Returns a generic [`AuthError::Internal`] if the blocking task fails to join.
    pub async fn verify_sentinel(&self, password: &str) -> Result<(), AuthError> {
        let _ = self.verify(password, &self.sentinel).await?;
        Ok(())
    }
}

/// Flatten the nested `Result` returned by awaiting the blocking hash task: a join failure
/// or a KDF failure both collapse to the opaque internal error.
fn flatten_hash(
    joined: Result<Result<String, CryptoError>, JoinError>,
) -> Result<String, AuthError> {
    joined.map_err(task_join_failed)?.map_err(hash_failed)
}

/// Map a blocking-pool join failure (a panicked or cancelled hashing task) to the opaque
/// internal error, so the failing step is never surfaced to the caller.
fn task_join_failed(_error: JoinError) -> AuthError {
    internal_error("password task failed to join")
}

/// Map a KDF failure to the opaque internal error.
fn hash_failed(_error: CryptoError) -> AuthError {
    internal_error("password hashing failed")
}

/// Translate the engine's [`PasswordConfig`] into the crypto crate's [`PasswordParams`].
/// The two `PasswordAlgorithm` enums are distinct types (one per crate), so the active
/// algorithm is mapped explicitly; the `Argon2id` arm exists only when the `argon2`
/// feature is compiled in (it is otherwise unrepresentable on both sides).
fn to_crypto_params(config: &PasswordConfig) -> PasswordParams {
    use crate::config::PasswordAlgorithm as CoreAlgorithm;
    use bymax_auth_crypto::password::{PasswordAlgorithm as CryptoAlgorithm, ScryptParams};

    let active = match config.active_algorithm {
        CoreAlgorithm::Scrypt => CryptoAlgorithm::Scrypt,
        #[cfg(feature = "argon2")]
        CoreAlgorithm::Argon2id => CryptoAlgorithm::Argon2id,
    };

    PasswordParams {
        active,
        scrypt: ScryptParams {
            cost_factor: config.scrypt.cost_factor,
            block_size: config.scrypt.block_size,
            parallelization: config.scrypt.parallelization,
        },
        #[cfg(feature = "argon2")]
        argon2: bymax_auth_crypto::password::Argon2Params {
            memory_kib: config.argon2.memory_kib,
            iterations: config.argon2.iterations,
            parallelism: config.argon2.parallelism,
        },
    }
}

#[cfg(test)]
mod tests;
