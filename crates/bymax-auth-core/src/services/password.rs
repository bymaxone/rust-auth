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

use bymax_auth_crypto::CryptoError;
use bymax_auth_crypto::password::{PasswordParams, hash, needs_rehash, verify};
use bymax_auth_types::AuthError;
use tokio::task::JoinError;

use crate::ConfigError;
use crate::config::PasswordConfig;
use crate::services::internal_error;

/// A fixed, non-secret plaintext hashed once at startup into the [`PasswordService`]
/// sentinel. Its only purpose is to give the absent-user login path a real PHC string to
/// run the full KDF against, so timing cannot distinguish a missing account from a wrong
/// password. The value is not a credential — it never authenticates anything.
const SENTINEL_PLAINTEXT: &[u8] = b"bymax-auth::anti-enumeration-sentinel::v1";

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
    sentinel: String,
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
    pub(crate) fn new(config: &PasswordConfig) -> Result<Self, ConfigError> {
        let params = to_crypto_params(config);
        let sentinel =
            hash(SENTINEL_PLAINTEXT, &params).map_err(|_| ConfigError::SentinelHashFailed)?;
        Ok(Self {
            params,
            rehash_on_verify: config.rehash_on_verify,
            sentinel,
        })
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
mod tests {
    use super::*;
    use crate::config::PasswordConfig;

    /// A password config whose active algorithm is whichever hasher is compiled in, so the
    /// sentinel computes under either feature matrix.
    fn config() -> PasswordConfig {
        #[cfg(not(feature = "scrypt"))]
        {
            PasswordConfig {
                active_algorithm: crate::config::PasswordAlgorithm::Argon2id,
                ..PasswordConfig::default()
            }
        }
        #[cfg(feature = "scrypt")]
        {
            PasswordConfig::default()
        }
    }

    /// Build the service for a valid fixture config. Returns `None` only if construction
    /// somehow failed (unreachable for the fixture), so callers stay panic-free with
    /// `let-else`.
    fn service() -> Option<PasswordService> {
        PasswordService::new(&config()).ok()
    }

    #[tokio::test]
    async fn hash_then_verify_round_trips_and_rejects_a_wrong_password() {
        // A freshly hashed password verifies; a different password does not — the core
        // hash/verify contract, exercised through the spawn_blocking dispatch.
        let Some(svc) = service() else { return };
        let result = svc.hash("correct horse battery staple").await;
        assert!(result.is_ok());
        let Ok(phc) = result else { return };
        assert!(phc.starts_with('$'));

        let good = svc.verify("correct horse battery staple", &phc).await;
        assert!(matches!(good, Ok(VerifyOutcome { matched: true, .. })));
        let bad = svc.verify("wrong password", &phc).await;
        assert!(matches!(bad, Ok(VerifyOutcome { matched: false, .. })));
    }

    #[tokio::test]
    async fn verify_reports_needs_rehash_for_a_legacy_or_weaker_hash() {
        // A fresh hash under the active params does not need rehashing; a legacy
        // non-PHC value (scrypt builds) always reports stale so it migrates on next login.
        let Some(svc) = service() else { return };
        let Ok(phc) = svc.hash("pw").await else { return };
        let outcome = svc.verify("pw", &phc).await;
        assert!(matches!(
            outcome,
            Ok(VerifyOutcome {
                needs_rehash: false,
                ..
            })
        ));

        #[cfg(feature = "scrypt")]
        {
            // The legacy `scrypt:salt:hash` corpus is always stale; the password need not
            // match for `needs_rehash` to fire (it parses the stored form, not the input).
            let legacy = "scrypt:0011:2233";
            let stale = svc.verify("anything", legacy).await;
            assert!(matches!(
                stale,
                Ok(VerifyOutcome {
                    needs_rehash: true,
                    matched: false
                })
            ));
        }
    }

    #[tokio::test]
    async fn verify_sentinel_runs_a_verify_without_revealing_a_result() {
        // The absent-user path runs the sentinel verify for uniform timing; it must succeed
        // (no error) regardless of the supplied password.
        let Some(svc) = service() else { return };
        assert!(
            svc.verify_sentinel("whatever the attacker tried")
                .await
                .is_ok()
        );
    }

    #[test]
    fn rehash_on_verify_reflects_the_config_toggle() {
        // The toggle is surfaced so the login flow can gate the fire-and-forget upgrade.
        let mut cfg = config();
        cfg.rehash_on_verify = false;
        let off = PasswordService::new(&cfg);
        assert!(matches!(off, Ok(s) if !s.rehash_on_verify()));
        let Some(on) = service() else { return };
        assert!(on.rehash_on_verify());
    }

    #[test]
    fn new_fails_when_the_sentinel_hash_cannot_be_computed() {
        // A config whose scrypt parameters are below the floor makes the startup sentinel
        // hash fail, so construction reports `SentinelHashFailed` rather than panicking.
        #[cfg(feature = "scrypt")]
        {
            let mut cfg = PasswordConfig {
                active_algorithm: crate::config::PasswordAlgorithm::Scrypt,
                ..PasswordConfig::default()
            };
            cfg.scrypt.cost_factor = 3; // not a power of two and below the floor
            assert!(matches!(
                PasswordService::new(&cfg),
                Err(ConfigError::SentinelHashFailed)
            ));
        }
    }

    #[tokio::test]
    async fn flatten_hash_collapses_join_and_kdf_failures_to_the_internal_error() {
        // A successful hash passes through; a KDF error and a real blocking-pool join
        // failure both collapse to the opaque internal error.
        assert!(matches!(
            flatten_hash(Ok(Ok("$scrypt$x".to_owned()))),
            Ok(phc) if phc == "$scrypt$x"
        ));
        assert!(matches!(
            flatten_hash(Ok(Err(CryptoError::Hash))),
            Err(AuthError::Internal(_))
        ));
        // A cancelled task yields a `JoinError` without panicking, exercising the
        // join-failure arm of both `flatten_hash` and `task_join_failed`.
        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let join_result = handle.await;
        let Err(join_error) = join_result else { return };
        assert!(matches!(
            flatten_hash(Err(join_error)),
            Err(AuthError::Internal(_))
        ));
    }

    #[cfg(feature = "argon2")]
    #[test]
    fn to_crypto_params_maps_the_argon2id_algorithm() {
        // The Argon2id arm of the algorithm mapping is selected when it is the active hasher.
        let cfg = PasswordConfig {
            active_algorithm: crate::config::PasswordAlgorithm::Argon2id,
            ..PasswordConfig::default()
        };
        let params = to_crypto_params(&cfg);
        assert!(matches!(
            params.active,
            bymax_auth_crypto::password::PasswordAlgorithm::Argon2id
        ));
    }
}
