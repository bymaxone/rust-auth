//! Tests for the password module.
//!
//! Tests are grouped by the feature they need: scrypt-writing tests under
//! `scrypt_tests` (`scrypt`), Argon2id-writing tests under `argon2` (`argon2`), and
//! cross-algorithm tests under `cross` (both). This keeps every entry of the feature
//! matrix — including the Argon2id-only build — green and meaningful.

use super::*;

#[test]
fn default_params_are_scrypt_at_the_baseline() {
    // The default writer is scrypt at the nest-auth baseline (N=2^15, r=8, p=1) — the
    // drop-in parity posture the library promises out of the box.
    let params = PasswordParams::default();
    assert_eq!(params.active, PasswordAlgorithm::Scrypt);
    assert_eq!(params.scrypt.cost_factor, 1 << 15);
    assert_eq!(params.scrypt.block_size, 8);
    assert_eq!(params.scrypt.parallelization, 1);
}

#[test]
fn verify_is_total_on_malformed_and_unknown_input() {
    // verify never errors: garbage, an empty string, and an unknown-algorithm PHC all
    // return Ok(false) — the timing-uniform, no-oracle totality the spec mandates.
    assert!(matches!(verify(b"pw", "not a hash at all"), Ok(false)));
    assert!(matches!(verify(b"pw", ""), Ok(false)));
    assert!(matches!(
        verify(b"pw", "$pbkdf2$i=1000$c2FsdA$aGFzaA"),
        Ok(false)
    ));
}

#[test]
fn needs_rehash_is_true_for_unparseable_phc() {
    // Both a non-PHC string (rejected outright) and a scrypt-tagged hash missing its
    // cost parameters are treated as stale, so a corrupt record is replaced on next
    // login rather than persisting forever.
    assert!(needs_rehash(
        "not a phc string at all",
        &PasswordParams::default()
    ));
    assert!(needs_rehash(
        "$scrypt$totally-broken",
        &PasswordParams::default()
    ));
}

#[cfg(feature = "scrypt")]
mod scrypt_tests {
    use super::*;
    use proptest::prelude::*;

    /// A correct password and an independently computed legacy `scrypt:hex:hex` vector
    /// (Python `hashlib.scrypt`, N=2^15, r=8, p=1, 32-byte key) — an external KAT
    /// proving the legacy verifier reproduces nest-auth's stored format rather than
    /// just agreeing with itself.
    const LEGACY_PASSWORD: &[u8] = b"correct horse battery staple";
    const LEGACY_HASH: &str = "scrypt:6e6573742d617574682d6c6567616379:\
                               f07791588511498573e76f19c5ec479c2fdbd3340e2e1a9e1c817bb0aacbdadf";

    #[test]
    fn scrypt_hash_round_trips() {
        // A scrypt hash is a `$scrypt$` PHC string that verifies for the right password
        // and rejects a wrong one — the core hash/verify contract for the default writer.
        let phc = hash(b"s3cret-pw", &PasswordParams::default()).unwrap_or_default();
        assert!(
            phc.starts_with("$scrypt$"),
            "expected scrypt PHC, got {phc}"
        );
        assert!(matches!(verify(b"s3cret-pw", &phc), Ok(true)));
        assert!(matches!(verify(b"wrong-pw", &phc), Ok(false)));
    }

    #[test]
    fn distinct_salts_produce_distinct_hashes() {
        // Hashing the same password twice yields different PHC strings (fresh random
        // salt) yet both verify — guards against a missing/static salt.
        let a = hash(b"same", &PasswordParams::default()).unwrap_or_default();
        let b = hash(b"same", &PasswordParams::default()).unwrap_or_default();
        assert_ne!(a, b);
        assert!(matches!(verify(b"same", &a), Ok(true)));
        assert!(matches!(verify(b"same", &b), Ok(true)));
    }

    #[test]
    fn legacy_scrypt_hash_verifies_against_external_vector() {
        // The legacy `scrypt:hex:hex` corpus verifies (external KAT) for the right
        // password and rejects a wrong one — the migration-compatibility guarantee.
        assert!(matches!(verify(LEGACY_PASSWORD, LEGACY_HASH), Ok(true)));
        assert!(matches!(verify(b"wrong password", LEGACY_HASH), Ok(false)));
    }

    #[test]
    fn legacy_hash_is_always_stale() {
        // A legacy hash always reports needs_rehash → true so the next successful login
        // transparently upgrades it to a PHC string.
        assert!(needs_rehash(LEGACY_HASH, &PasswordParams::default()));
    }

    #[test]
    fn legacy_parser_rejects_malformed_hex_and_shapes() {
        // Malformed legacy strings (odd-length hex, non-hex chars, a too-short or
        // over-long derived key, extra/empty segments) must not verify — exercises the
        // hex decoder, the length cap, and the short-key KDF guard.
        assert!(matches!(verify(b"pw", "scrypt:abc:00"), Ok(false))); // odd-length salt hex
        assert!(matches!(verify(b"pw", "scrypt:zz:00"), Ok(false))); // first nibble non-hex
        assert!(matches!(verify(b"pw", "scrypt:az:00"), Ok(false))); // second nibble non-hex
        assert!(matches!(verify(b"pw", "scrypt:aa:00"), Ok(false))); // 1-byte key < KDF min
        assert!(matches!(verify(b"pw", "scrypt:aa:bb:cc"), Ok(false))); // extra segment
        assert!(matches!(verify(b"pw", "scrypt::00"), Ok(false))); // empty salt
        assert!(matches!(verify(b"pw", "scrypt:aa:"), Ok(false))); // empty hash
        assert!(matches!(verify(b"pw", "scrypt:aa:zz"), Ok(false))); // valid salt, non-hex hash
        assert!(matches!(verify(b"pw", "scrypt:no-second-colon"), Ok(false))); // single segment
        let over_long = format!("scrypt:aa:{}", "ab".repeat(65)); // 65-byte key > cap
        assert!(matches!(verify(b"pw", &over_long), Ok(false)));
        // Upper-case hex must decode (exercises the A–F branch of the nibble decoder);
        // the recomputed KDF then rejects the wrong password.
        let upper = format!("scrypt:AABBCCDD:{}", "AB".repeat(32));
        assert!(matches!(verify(b"pw", &upper), Ok(false)));
    }

    #[test]
    fn needs_rehash_is_false_for_a_current_scrypt_hash() {
        // A hash written with the current params is not stale — rehash-on-verify must
        // not fire pointlessly on an up-to-date hash.
        let phc = hash(b"pw", &PasswordParams::default()).unwrap_or_default();
        assert!(!needs_rehash(&phc, &PasswordParams::default()));
    }

    #[test]
    fn needs_rehash_is_true_when_stored_scrypt_is_weaker() {
        // A hash at the baseline cost is stale once the configured cost is raised — the
        // signal that drives a transparent cost-factor upgrade.
        let phc = hash(b"pw", &PasswordParams::default()).unwrap_or_default();
        let stronger = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1 << 16,
                ..ScryptParams::default()
            },
            ..PasswordParams::default()
        };
        assert!(needs_rehash(&phc, &stronger));
    }

    #[test]
    fn needs_rehash_detects_block_or_parallelization_downgrade() {
        // With an equal cost factor, a higher current `r` or `p` still marks the stored
        // hash stale — covers each operand of the scrypt staleness check independently,
        // not only the cost-factor path.
        let phc = hash(b"pw", &PasswordParams::default()).unwrap_or_default(); // ln=15, r=8, p=1
        let higher_r = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1 << 15,
                block_size: 16,
                parallelization: 1,
            },
            ..PasswordParams::default()
        };
        let higher_p = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1 << 15,
                block_size: 8,
                parallelization: 2,
            },
            ..PasswordParams::default()
        };
        assert!(needs_rehash(&phc, &higher_r));
        assert!(needs_rehash(&phc, &higher_p));
    }

    #[test]
    fn scrypt_param_floor_is_enforced() {
        // Below-floor and non-power-of-two cost factors are rejected with InvalidParams,
        // so a misconfiguration fails loudly instead of weakening every stored hash.
        assert!(
            ScryptParams {
                cost_factor: 1024,
                ..ScryptParams::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ScryptParams {
                cost_factor: 20000,
                ..ScryptParams::default()
            }
            .validate()
            .is_err()
        );
        assert!(ScryptParams::default().validate().is_ok());

        let weak = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1024,
                ..ScryptParams::default()
            },
            ..PasswordParams::default()
        };
        assert!(matches!(
            hash(b"pw", &weak),
            Err(CryptoError::InvalidParams)
        ));
    }

    #[test]
    fn scrypt_rejects_inconsistent_block_or_parallelization() {
        // A zero block size passes the cost-factor floor but is rejected by the KDF
        // parameter constructor — covers the InvalidParams path for `r`/`p` sanity.
        let bad = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1 << 15,
                block_size: 0,
                parallelization: 1,
            },
            ..PasswordParams::default()
        };
        assert!(matches!(hash(b"pw", &bad), Err(CryptoError::InvalidParams)));
    }

    proptest! {
        // Each case runs a memory-hard scrypt hash (~50 ms), so keep the count small —
        // enough to sample the input space without turning the suite into a benchmark.
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn scrypt_round_trip_for_arbitrary_passwords(pw in proptest::collection::vec(any::<u8>(), 0..40)) {
            // For any password the hash verifies and a single-byte-extended password
            // does not — the round-trip and rejection properties over the input space.
            let phc = hash(&pw, &PasswordParams::default()).unwrap_or_default();
            prop_assert!(matches!(verify(&pw, &phc), Ok(true)));
            let mut other = pw.clone();
            other.push(0xff);
            prop_assert!(matches!(verify(&other, &phc), Ok(false)));
        }
    }
}

#[cfg(feature = "argon2")]
mod argon2 {
    use super::*;

    /// Build a `PasswordParams` whose active writer is Argon2id at the default floor.
    fn argon2_params() -> PasswordParams {
        PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            ..PasswordParams::default()
        }
    }

    #[test]
    fn argon2_hash_round_trips() {
        // An Argon2id hash is an `$argon2id$` PHC string that verifies for the right
        // password and rejects a wrong one — the recommended-writer hash/verify path.
        let phc = hash(b"a-strong-pw", &argon2_params()).unwrap_or_default();
        assert!(
            phc.starts_with("$argon2id$"),
            "expected argon2id PHC, got {phc}"
        );
        assert!(matches!(verify(b"a-strong-pw", &phc), Ok(true)));
        assert!(matches!(verify(b"nope", &phc), Ok(false)));
    }

    #[test]
    fn argon2_needs_rehash_tracks_cost() {
        // A current Argon2id hash is not stale; raising the memory cost makes the
        // stored hash stale — the parameter-upgrade trigger for Argon2id.
        let phc = hash(b"pw", &argon2_params()).unwrap_or_default();
        assert!(!needs_rehash(&phc, &argon2_params()));
        let stronger = PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            argon2: Argon2Params {
                memory_kib: 1 << 16,
                ..Argon2Params::default()
            },
            ..PasswordParams::default()
        };
        assert!(needs_rehash(&phc, &stronger));
    }

    #[test]
    fn argon2_hash_missing_a_param_is_stale() {
        // An argon2id-tagged hash whose parameter set is incomplete (here `p` removed)
        // is treated as stale → rehash, rather than being read with a missing cost.
        let phc = hash(b"pw", &argon2_params()).unwrap_or_default();
        let stripped = phc.replacen(",p=1", "", 1);
        assert_ne!(stripped, phc, "expected the argon2 PHC to contain ',p=1'");
        assert!(needs_rehash(&stripped, &argon2_params()));
    }

    #[test]
    fn argon2_needs_rehash_detects_iteration_or_lane_downgrade() {
        // With equal memory, a higher current iteration or lane count still marks the
        // stored hash stale — covers the `t` and `p` operands of the Argon2id
        // staleness check beyond the memory path.
        let phc = hash(b"pw", &argon2_params()).unwrap_or_default(); // m=19456, t=2, p=1
        let higher_t = PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            argon2: Argon2Params {
                memory_kib: 19456,
                iterations: 3,
                parallelism: 1,
            },
            ..PasswordParams::default()
        };
        let higher_p = PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            argon2: Argon2Params {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 2,
            },
            ..PasswordParams::default()
        };
        assert!(needs_rehash(&phc, &higher_t));
        assert!(needs_rehash(&phc, &higher_p));
    }

    #[test]
    fn argon2_param_floor_is_enforced() {
        // Below-floor memory/iterations and an inconsistent (memory < 8*lanes)
        // parameter set are both rejected with InvalidParams.
        assert!(
            Argon2Params {
                memory_kib: 1024,
                ..Argon2Params::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                iterations: 1,
                ..Argon2Params::default()
            }
            .validate()
            .is_err()
        );
        assert!(Argon2Params::default().validate().is_ok());

        // A below-floor parameter set is rejected at hash time (the floor check fires
        // before the KDF runs), not only via the standalone `validate()`.
        let weak = PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            argon2: Argon2Params {
                memory_kib: 1024,
                iterations: 2,
                parallelism: 1,
            },
            ..PasswordParams::default()
        };
        assert!(matches!(
            hash(b"pw", &weak),
            Err(CryptoError::InvalidParams)
        ));

        let inconsistent = PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            argon2: Argon2Params {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 100_000,
            },
            ..PasswordParams::default()
        };
        assert!(matches!(
            hash(b"pw", &inconsistent),
            Err(CryptoError::InvalidParams)
        ));
    }
}

#[cfg(all(feature = "scrypt", feature = "argon2"))]
mod cross {
    use super::*;

    /// Build a `PasswordParams` whose active writer is Argon2id at the default floor.
    fn argon2_params() -> PasswordParams {
        PasswordParams {
            active: PasswordAlgorithm::Argon2id,
            ..PasswordParams::default()
        }
    }

    #[test]
    fn verify_auto_detects_algorithm_across_writers() {
        // A verifier picks the algorithm from the PHC prefix, so both a scrypt and an
        // Argon2id hash verify regardless of which is currently active — the
        // cross-algorithm verification the rehash-on-verify migration depends on.
        let scrypt_phc = hash(b"pw", &PasswordParams::default()).unwrap_or_default();
        let argon_phc = hash(b"pw", &argon2_params()).unwrap_or_default();
        assert!(matches!(verify(b"pw", &scrypt_phc), Ok(true)));
        assert!(matches!(verify(b"pw", &argon_phc), Ok(true)));
    }

    #[test]
    fn cross_algorithm_hash_is_stale() {
        // With Argon2id active, a stored scrypt hash is stale (and vice versa) — the
        // algorithm-migration trigger of rehash-on-verify.
        let scrypt_phc = hash(b"pw", &PasswordParams::default()).unwrap_or_default();
        assert!(needs_rehash(&scrypt_phc, &argon2_params()));

        let argon_phc = hash(b"pw", &argon2_params()).unwrap_or_default();
        assert!(needs_rehash(&argon_phc, &PasswordParams::default()));
    }
}
