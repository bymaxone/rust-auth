//! Tests for the password module.
//!
//! Tests are grouped by the feature they need: scrypt-writing tests under
//! `scrypt_tests` (`scrypt`), Argon2id-writing tests under `argon2` (`argon2`), and
//! cross-algorithm tests under `cross` (both). This keeps every entry of the feature
//! matrix — including the Argon2id-only build — green and meaningful.

use super::*;

#[test]
fn default_params_are_scrypt_at_the_baseline() {
    // The default writer is scrypt at OWASP's recommended minimum (N=2^17, r=8, p=1), which
    // nest-auth also defaults to — the drop-in parity posture the library promises out of the
    // box. Pinned to the literal: read back through `ScryptParams::default()` this would agree
    // with itself no matter what the number became.
    let params = PasswordParams::default();
    assert_eq!(params.active, PasswordAlgorithm::Scrypt);
    assert_eq!(params.scrypt.cost_factor, 1 << 17);
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
fn verify_refuses_a_record_asking_for_more_memory_than_the_ceiling() {
    // Scenario: a well-formed scrypt record whose recorded cost asks for a working set no
    // configuration could have been validated with. Expected: refused, and refused by
    // RETURNING — never by attempting the derivation. Why: the verifier takes its parameters
    // from the record, so without this bound the stored string decides how much memory the
    // process allocates. `ln=31, r=8` is `128 * 2^31 * 8` — 2 TiB. That is not a failed login;
    // it is an allocation that OOM-kills the host and takes every in-flight connection with it,
    // reachable from an unauthenticated route because the derivation runs before the password
    // is known to be right.
    //
    // These assertions must return promptly. If one hangs or the runner dies, the bound is gone
    // and the derivation is being attempted for real.
    let salt = "c2FsdHNhbHRzYWx0c2FsdA";
    let key = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    for params in [
        "ln=31,r=8,p=1",   // 2 TiB
        "ln=23,r=1,p=1",   // 1 GiB — the first power of two past the ceiling at the smallest r
        "ln=14,r=256,p=1", // r above the parameter ceiling, at a working set that would pass
    ] {
        let record = format!("$scrypt${params}${salt}${key}");
        assert!(
            matches!(verify(b"anything", &record), Ok(false)),
            "expected {params} to be refused"
        );
    }
}

#[test]
fn the_cost_ceiling_admits_its_own_boundary_and_nothing_past_it() {
    // The predicate directly, because `verify` cannot show this: an admitted record and a
    // refused one both answer `Ok(false)` for a password that does not match, and the only
    // other way to tell them apart is to let the admitted one actually derive — 512 MiB of
    // real work for one assertion.
    //
    // `128 * 2^22 * 1` is exactly 512 MiB and the bound is `<=`, so it is admitted; one more
    // power of two, or one more block, is not. Without the admitted side, the ceiling could be
    // tightened to nothing and every refusal test above would stay green while every legitimate
    // login stopped working.
    let salt = "c2FsdHNhbHRzYWx0c2FsdA";
    let key = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    let admissible = |params: &str| {
        let record = format!("$scrypt${params}${salt}${key}");
        password_hash::PasswordHash::new(&record).is_ok_and(|h| super::phc::cost_is_admissible(&h))
    };

    assert!(admissible("ln=22,r=1,p=1"), "exactly 512 MiB must be read");
    assert!(
        admissible("ln=17,r=8,p=1"),
        "the shipped default must be read"
    );
    assert!(!admissible("ln=23,r=1,p=1"), "one power of two past it");
    assert!(!admissible("ln=22,r=2,p=1"), "one block past it");
    // An `ln` with no `2 ** ln` in a u64 at all. It is refused by the `ln` guard, which is the
    // point of having one: the shift below it never runs on a value that would wrap, so there is
    // no overflow path to check and none to leave untested.
    assert!(!admissible("ln=64,r=1,p=1"), "no representable working set");
    assert!(!admissible("ln=0,r=8,p=1"), "N = 1 is not a cost");
    assert!(!admissible("ln=14,r=0,p=1"), "r = 0 is not a block size");
    assert!(!admissible("ln=14,r=8,p=0"), "p = 0 is not a lane count");
    assert!(
        !admissible("ln=14,r=8"),
        "a missing parameter is not a zero"
    );
}

#[test]
fn the_cost_ceiling_covers_argon2id_too() {
    // Argon2id has the identical hole and needs the identical bound: `m` is the working set in
    // KiB and the verifier takes it from the record, so a stored `m=4294967295` asks for 4 TiB.
    // The scrypt half is the one this pair ships with by default, which is exactly why the other
    // one is easy to leave open.
    let salt = "c2FsdHNhbHRzYWx0c2FsdA";
    let key = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
    let admissible = |params: &str| {
        let record = format!("$argon2id$v=19${params}${salt}${key}");
        password_hash::PasswordHash::new(&record).is_ok_and(|h| super::phc::cost_is_admissible(&h))
    };

    assert!(
        admissible("m=19456,t=2,p=1"),
        "the shipped default must be read"
    );
    assert!(
        admissible("m=524288,t=2,p=1"),
        "exactly 512 MiB must be read"
    );
    assert!(!admissible("m=524289,t=2,p=1"), "one KiB past the ceiling");
    assert!(!admissible("m=4294967295,t=2,p=1"), "4 TiB is not a cost");
    assert!(!admissible("t=2,p=1"), "a missing m is not a zero");
}

#[test]
fn the_cost_ceiling_has_no_opinion_on_an_algorithm_it_cannot_verify() {
    // A WELL-FORMED PHC string tagged with an algorithm this module has no verifier for. The
    // predicate answers `true` — it bounds a cost it understands, and it is not the place that
    // decides which algorithms are accepted; `verify_phc` refuses this record a line later,
    // because no verifier in its list claims the identifier.
    //
    // The existing totality test passes a `$pbkdf2$…` string too, but it never reaches here:
    // that one fails `PasswordHash::new` outright, so `verify` returns before the predicate
    // runs. This arm needs a record that actually parses.
    let record = format!(
        "$pbkdf2$i=1000${}${}",
        "c2FsdHNhbHRzYWx0c2FsdA", "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
    );
    let parsed = password_hash::PasswordHash::new(&record);

    assert!(
        parsed.is_ok(),
        "the fixture must parse, or it tests nothing"
    );
    assert!(parsed.is_ok_and(|h| super::phc::cost_is_admissible(&h)));
    // And the record is still refused, by the verifier list rather than by the ceiling.
    assert!(matches!(verify(b"anything", &record), Ok(false)));
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
                cost_factor: 1 << 18,
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
        // The floor is inclusive: 2^14 is the documented minimum, not the first rejected
        // value. Only a config sitting exactly on it separates `<` from `<=`, and refusing it
        // would reject the very parameters the constant advertises.
        assert!(
            ScryptParams {
                cost_factor: ScryptParams::MIN_COST_FACTOR,
                ..ScryptParams::default()
            }
            .validate()
            .is_ok()
        );
        assert_eq!(ScryptParams::MIN_COST_FACTOR, 16_384);

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

    // -----------------------------------------------------------------------
    // Cross-implementation conformance: `passwordHashFormat` in the wire contract
    // -----------------------------------------------------------------------

    /// Read `passwordHashFormat.vectors` from the shared cross-implementation wire contract.
    ///
    /// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
    /// backs the same user table over the same Redis. Reading it here rather than copying the
    /// strings in means a drift on either side turns that side red immediately.
    fn contract_vectors() -> Vec<serde_json::Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root.get("passwordHashFormat")
            .and_then(|s| s.get("vectors"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn every_contract_password_hash_vector_verifies_here() {
        // The vectors are real emitted output — one hash written by this crate and one written
        // by nest-auth. Each must verify here, must refuse a wrong password, and must report
        // the staleness the contract declares.
        //
        // This replaces an agreement that was prose: `credentialFormats.passwordHash` read
        // "self-describing: the parameters travel with the hash", which BOTH sides satisfied
        // while writing strings the other could not parse. Neither suite could fail, because
        // neither was testing against the other's output. And the failure did not look like a
        // parse error: `verify` is total, so an unreadable hash returns `Ok(false)` and the
        // engine answers `invalid_credentials` — five of which trip the SHARED `lf:` counter
        // and lock the account out of both backends using the owner's own correct password.
        // Evaluated with the deployment configured at exactly the cost the PHC vectors record,
        // which is what the contract's `needsRehash` field means. Against a HIGHER configured
        // cost every vector is stale, and the assertion would say nothing about the encoding.
        let at_vector_cost = PasswordParams {
            scrypt: ScryptParams {
                cost_factor: 1 << 14,
                block_size: 8,
                parallelization: 1,
            },
            ..PasswordParams::default()
        };
        let vectors = contract_vectors();
        assert_eq!(
            vectors.len(),
            2,
            "the contract must pin one vector per implementation — it declared {} \
             (did the file load?)",
            vectors.len()
        );

        for vector in &vectors {
            let password = vector
                .get("password")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let stored = vector
                .get("hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let written_by = vector
                .get("writtenBy")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let wants_rehash = vector
                .get("needsRehash")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or_default();

            assert!(
                matches!(verify(password.as_bytes(), stored), Ok(true)),
                "the vector written by {written_by} must verify here"
            );
            assert!(
                matches!(verify(b"definitely-not-the-password", stored), Ok(false)),
                "the vector written by {written_by} must refuse a wrong password"
            );
            assert_eq!(
                needs_rehash(stored, &at_vector_cost),
                wants_rehash,
                "the vector written by {written_by} must report the staleness the contract declares"
            );
        }
    }
}
