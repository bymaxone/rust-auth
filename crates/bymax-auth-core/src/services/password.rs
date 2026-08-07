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
        PasswordService::new(&config(), Arc::new(AllowAllBreachChecker)).ok()
    }

    #[test]
    fn the_kdf_ceiling_is_a_memory_budget_rather_than_a_core_count() {
        // `spawn_blocking` bounds nothing useful on its own: Tokio's blocking pool defaults to
        // 512 threads, and each of these tasks holds the KDF's working memory for its whole run.
        // Login is a route an unauthenticated caller drives — the derivation runs before the
        // password is known to be right, and the absent-user path deliberately runs one too.
        //
        // The ceiling used to be one-per-core, reasoned from a working set this module stated as
        // "~16 MiB". scrypt's is `128 * N * r`, so at the default `N = 2^17, r = 8` it is
        // **128 MiB** — the figure was wrong by 8×, and a 32-core host therefore admitted ~4 GiB
        // resident where nest-auth, pinned at four by the libuv pool, admitted ~512 MiB.
        let defaults = crate::config::PasswordConfig::default();
        assert_eq!(
            kdf_working_set_mib(&defaults),
            128,
            "scrypt at N=2^17, r=8 holds 128 MiB, not the 16 MiB the old comment claimed"
        );

        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        assert_eq!(
            kdf_permit_count(&defaults),
            (512 / 128usize).clamp(2, cores.max(2)),
            "the budget divided by the working set, capped by the cores"
        );

        // The direction that matters: raising the cost factor must buy FEWER slots, not more
        // memory. The old rule was indifferent to it — the same 32 permits at any cost.
        let mut heavier = crate::config::PasswordConfig::default();
        heavier.scrypt.cost_factor = 1 << 19;
        assert!(
            kdf_permit_count(&heavier) <= kdf_permit_count(&defaults),
            "a heavier KDF must not admit more concurrency"
        );

        assert!(
            kdf_permit_count(&defaults) >= 2,
            "a single permit would serialize login"
        );
        // The floor takes precedence over the budget, and the case is pinned so the doc cannot
        // drift back into claiming otherwise: a working set past half the budget still admits
        // two, and therefore overshoots it. One permit would serialize every login on the
        // deployment behind a memory-hard KDF, which is a self-inflicted denial of service on
        // the same unauthenticated route the budget exists to protect.
        let enormous = crate::config::PasswordConfig {
            // 4 GiB working set at r = 8.
            scrypt: crate::config::ScryptParams {
                cost_factor: 1 << 22,
                ..crate::config::ScryptParams::default()
            },
            ..crate::config::PasswordConfig::default()
        };
        assert_eq!(
            kdf_permit_count(&enormous),
            2,
            "the floor wins over the budget, deliberately"
        );
        assert!(
            kdf_working_set_mib(&enormous) * kdf_permit_count(&enormous) > KDF_MEMORY_BUDGET_MIB,
            "and that is what overshooting the budget looks like — sized against, not capped by"
        );

        assert!(
            kdf_permit_count(&heavier) >= 2,
            "even a deliberately huge cost factor keeps two, so the queue cannot deadlock-shape"
        );
        assert!(
            kdf_permit_count(&defaults) < 512,
            "the point is to be below the blocking pool's default"
        );

        // Argon2id sizes from its own declared budget rather than scrypt's derived one, so the
        // ceiling tracks whichever algorithm actually hashes new passwords.
        #[cfg(feature = "argon2")]
        {
            let argon = crate::config::PasswordConfig {
                active_algorithm: crate::config::PasswordAlgorithm::Argon2id,
                ..crate::config::PasswordConfig::default()
            };
            assert_eq!(
                kdf_working_set_mib(&argon),
                usize::try_from(argon.argon2.memory_kib / 1024).unwrap_or(usize::MAX),
                "Argon2id's working set is the configured memory_kib, in MiB"
            );
            assert!(kdf_permit_count(&argon) >= 2);
        }
    }

    #[tokio::test]
    async fn a_closed_limiter_refuses_rather_than_deriving_unbounded() {
        // The semaphore is owned by the service and lives as long as it, so nothing in this
        // crate closes it — but "nothing closes it" is a property of today's code, not of the
        // type. Closing it here proves the refusal is a refusal: the derivation does not fall
        // through to running unbounded, which is the one outcome the limiter exists to prevent.
        let Some(svc) = service() else { return };
        svc.kdf_permits.close();

        assert!(matches!(
            svc.hash("correct horse battery staple").await,
            Err(AuthError::Internal(_))
        ));
        assert!(matches!(
            svc.verify("correct horse battery staple", "$scrypt$x")
                .await,
            Err(AuthError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn the_kdf_limiter_admits_no_more_than_its_permits_at_once() {
        // The permit is held for the whole derivation, not merely taken and dropped. Draining
        // the semaphore and watching a hash fail to make progress is what proves it: without
        // the acquire, the hash would complete while every permit is held elsewhere.
        let Some(svc) = service() else { return };
        let permits = u32::try_from(kdf_permit_count(&config())).unwrap_or(u32::MAX);
        let all = Arc::clone(&svc.kdf_permits)
            .acquire_many_owned(permits)
            .await;
        let Ok(held) = all else { return };

        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            svc.hash("correct horse battery staple"),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a derivation ran with no permit available"
        );

        // Released, it proceeds — the limiter queues work, it does not reject it.
        drop(held);
        assert!(svc.hash("correct horse battery staple").await.is_ok());
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
    async fn verify_reports_needs_rehash_for_an_unreadable_or_weaker_hash() {
        // A fresh hash under the active params does not need rehashing; a value that is not a
        // PHC string always reports stale so it migrates on the next login.
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
            // A stored value this library never writes is always stale; the password need not
            // match for `needs_rehash` to fire (it parses the stored form, not the input).
            let unreadable = "scrypt:0011:2233";
            let stale = svc.verify("anything", unreadable).await;
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

    #[tokio::test]
    async fn verify_sentinel_actually_spends_the_kdf_time() {
        // The sentinel exists only to spend the KDF's time, so the one thing that can prove it
        // ran is that it costs what a verify costs — an `Ok(())` in its place returns in
        // microseconds and silently removes the user-enumeration defence.
        //
        // Compared against a real verify measured in the same test, as a *lower* bound: a
        // loaded machine slows both, and can never make the sentinel finish faster than a
        // quarter of a real verify. The comparison cannot flake in the failing direction.
        let Some(svc) = service() else { return };
        let hashed = svc.hash("correct horse battery staple").await;
        let Ok(phc) = hashed else { return };

        let started = std::time::Instant::now();
        let _ = svc.verify("correct horse battery staple", &phc).await;
        let real = started.elapsed();

        let started = std::time::Instant::now();
        let _ = svc.verify_sentinel("whatever the attacker tried").await;
        let sentinel = started.elapsed();

        assert!(
            sentinel * 4 >= real,
            "sentinel took {sentinel:?} against a real verify's {real:?} — it did no work"
        );
    }

    #[test]
    fn rehash_on_verify_reflects_the_config_toggle() {
        // The toggle is surfaced so the login flow can gate the fire-and-forget upgrade.
        let mut cfg = config();
        cfg.rehash_on_verify = false;
        let off = PasswordService::new(&cfg, Arc::new(AllowAllBreachChecker));
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
                PasswordService::new(&cfg, Arc::new(AllowAllBreachChecker)),
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

    /// A checker that records whether it was consulted, so "the corpus is not reached" is
    /// assertable rather than assumed.
    struct RecordingChecker {
        consulted: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl PasswordBreachChecker for RecordingChecker {
        async fn is_breached(&self, _password: &str) -> bool {
            self.consulted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            false
        }
    }

    /// Build a service whose only difference from the fixture is the configured floor.
    fn service_with_floor(min_length: u32) -> Option<PasswordService> {
        PasswordService::new(
            &PasswordConfig {
                min_length,
                ..config()
            },
            Arc::new(AllowAllBreachChecker),
        )
        .ok()
    }

    #[test]
    fn the_default_floor_is_the_single_factor_requirement() {
        // NIST SP 800-63B-4 §3.1.1.1 allows 8 only for a password used as part of multi-factor
        // authentication and requires 15 for one used as a single factor. MFA here is opt-in per
        // user, so the default deployment IS single-factor. This is also the number nest-auth
        // defaults to: the two libraries back the same accounts, and a password one of them
        // accepts and the other refuses is a policy that exists only on paper.
        assert_eq!(PasswordConfig::default().min_length, 15);
    }

    #[test]
    fn a_floor_outside_the_window_is_refused_at_construction() {
        // Below 8 cannot describe a conformant deployment and is unreachable anyway — the DTOs
        // refuse the request first — so the setting would look applied and do nothing. Above 128
        // exceeds the longest password the DTOs accept, so no password could ever be set and the
        // failure would read as a user-input problem rather than a configuration one.
        for refused in [0, 7, 129, u32::MAX] {
            assert!(
                matches!(
                    PasswordService::new(
                        &PasswordConfig {
                            min_length: refused,
                            ..config()
                        },
                        Arc::new(AllowAllBreachChecker),
                    ),
                    Err(ConfigError::PasswordMinLengthRange { got }) if got == refused
                ),
                "expected {refused} to be refused"
            );
        }
        // Both ends of the window are accepted, so neither bound can be off by one.
        assert!(service_with_floor(8).is_some());
        assert!(service_with_floor(128).is_some());
    }

    #[test]
    fn a_password_below_the_floor_is_a_validation_failure_naming_its_field() {
        // The wire shape must not change: this answers the same code and the same
        // `{ field, message }` details the adapter's own length validation produces, so the
        // shared error catalog gains no entry and a client already handling a short password
        // sees nothing new. The field travels in so the error points at the input the caller
        // actually sent rather than at whatever this library calls it internally.
        let Some(svc) = service() else { return };

        let refused = svc.assert_long_enough(&"x".repeat(14), "newPassword");

        // Everything asserted through expressions rather than a destructuring block. The
        // workspace denies `panic!` even in tests, so the usual `let-else { panic! }` is out —
        // and an `if let` with no `else` leaves the not-taken arm as a line no run reaches,
        // which the 100% line gate then reports. `matches!` and a `Debug` render carry the same
        // facts with nothing unreachable behind them.
        assert!(
            matches!(&refused, Err(AuthError::Validation { details }) if details.len() == 1),
            "expected exactly one validation detail, got {refused:?}"
        );
        let rendered = format!("{refused:?}");
        assert!(rendered.contains(r#"field: "newPassword""#), "{rendered}");
        assert!(
            rendered.contains("newPassword must be at least 15 characters"),
            "{rendered}"
        );
    }

    #[test]
    fn the_floor_is_the_configured_value_and_its_boundary_is_inclusive() {
        // Exactly at the floor is admitted — the comparison is `>=`, and an off-by-one here
        // rejects a password the policy allows, on every registration. And the floor is the
        // CONFIGURED number: without the second half, a hardcoded 15 would satisfy every other
        // test in this module.
        let Some(default) = service() else { return };
        assert!(
            default
                .assert_long_enough(&"x".repeat(15), "password")
                .is_ok()
        );
        assert!(
            default
                .assert_long_enough(&"x".repeat(14), "password")
                .is_err()
        );

        // One line on purpose: a `let-else` whose body is on its own line leaves that line
        // unreachable, and the coverage gate is per line.
        let Some(raised) = service_with_floor(20) else { return };
        assert!(
            raised
                .assert_long_enough(&"x".repeat(20), "password")
                .is_ok()
        );
        assert!(
            raised
                .assert_long_enough(&"x".repeat(19), "password")
                .is_err()
        );
    }

    #[test]
    fn the_floor_counts_characters_rather_than_bytes() {
        // `len()` would make the policy depend on the alphabet: the same fifteen characters
        // written with accents are 20-odd bytes and written in a non-Latin script more still, so
        // a byte floor silently demands a shorter password from some users and a longer one from
        // others. Fifteen characters is fifteen characters.
        let Some(svc) = service() else { return };
        let accented = "ãéîõüçñáàâê"
            .chars()
            .chain("çãõü".chars())
            .collect::<String>();

        assert_eq!(accented.chars().count(), 15);
        assert!(accented.len() > 15, "the fixture must be multi-byte");
        assert!(svc.assert_long_enough(&accented, "password").is_ok());
    }

    #[tokio::test]
    async fn a_password_refused_locally_never_reaches_the_breach_corpus() {
        // Ordering is the point: the length is decided locally and for free, and the corpus may
        // be a network call. A password refused for being short should not cost a round trip,
        // and should not be sent anywhere first.
        let checker = Arc::new(RecordingChecker {
            consulted: std::sync::atomic::AtomicBool::new(false),
        });
        // Method syntax, not `Arc::clone(&checker)`: with the annotation on the binding, the
        // associated-function form resolves against `Arc<dyn …>` and then rejects a
        // `&Arc<RecordingChecker>`. `.clone()` resolves on the concrete type and coerces after.
        let breach: Arc<dyn PasswordBreachChecker> = checker.clone();
        let Ok(svc) = PasswordService::new(&config(), breach) else { return };

        assert!(svc.assert_acceptable("short", "password").await.is_err());
        assert!(
            !checker.consulted.load(std::sync::atomic::Ordering::SeqCst),
            "the corpus was consulted for a password refused on length"
        );

        // And a long-enough password DOES reach it — otherwise "never consulted" passes for a
        // service that simply never screens anything.
        assert!(
            svc.assert_acceptable(&"x".repeat(15), "password")
                .await
                .is_ok()
        );
        assert!(checker.consulted.load(std::sync::atomic::Ordering::SeqCst));
    }
}
