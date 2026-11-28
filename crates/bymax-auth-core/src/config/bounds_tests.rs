//! The numeric ceilings of the configuration (layer: config, tests).
//!
//! Each option is accepted at both edges of its range and refused one past the ceiling, so a
//! ceiling that silently moves or disappears fails here.

use std::collections::HashMap;
use std::time::Duration;

use secrecy::SecretString;

use super::{AuthConfig, Environment};
use crate::error::ConfigError;

/// The ten years Redis can still represent as an expiry in milliseconds.
const TTL_CEILING_SECS: u64 = 315_360_000;

/// A configuration that validates, so each case isolates one option.
fn valid() -> AuthConfig {
    let mut cfg = AuthConfig::default();
    #[cfg(not(feature = "scrypt"))]
    {
        cfg.password.active_algorithm = super::PasswordAlgorithm::Argon2id;
    }
    cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    cfg.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
        ("MEMBER".to_owned(), Vec::new()),
    ]);
    cfg
}

/// One bounded option: its path, the range it is accepted in, and how a value is written to it.
struct Bound {
    field: &'static str,
    min: u64,
    max: u64,
    set: fn(&mut AuthConfig, u64),
}

fn secs(cfg_value: &mut Duration, value: u64) {
    *cfg_value = Duration::from_secs(value);
}

/// Every option with a range in whole numbers of its own unit.
fn bounds() -> Vec<Bound> {
    vec![
        Bound {
            field: "sessions.default_max_sessions",
            min: 1,
            max: 1_000,
            set: |c, v| c.sessions.default_max_sessions = u32::try_from(v).unwrap_or(u32::MAX),
        },
        Bound {
            field: "jwt.refresh_expires_in_days",
            min: 1,
            max: 3_650,
            set: |c, v| c.jwt.refresh_expires_in_days = u32::try_from(v).unwrap_or(u32::MAX),
        },
        Bound {
            field: "jwt.absolute_session_lifetime_days",
            min: 1,
            max: 3_650,
            set: |c, v| c.jwt.absolute_session_lifetime_days = u32::try_from(v).unwrap_or(u32::MAX),
        },
        Bound {
            field: "jwt.access_cookie_max_age",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.jwt.access_cookie_max_age, v),
        },
        Bound {
            field: "brute_force.window",
            min: 1,
            max: 604_800,
            set: |c, v| secs(&mut c.brute_force.window, v),
        },
        Bound {
            field: "password_reset.token_ttl",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.password_reset.token_ttl, v),
        },
        Bound {
            field: "password_reset.otp_ttl",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.password_reset.otp_ttl, v),
        },
        Bound {
            field: "email_verification.otp_ttl",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.email_verification.otp_ttl, v),
        },
        Bound {
            field: "email_change.token_ttl",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.email_change.token_ttl, v),
        },
        Bound {
            field: "invitations.token_ttl",
            min: 1,
            max: TTL_CEILING_SECS,
            set: |c, v| secs(&mut c.invitations.token_ttl, v),
        },
    ]
}

#[test]
fn every_option_is_accepted_at_both_edges_of_its_range() {
    for bound in bounds() {
        for edge in [bound.min, bound.max] {
            let mut cfg = valid();
            (bound.set)(&mut cfg, edge);
            let outcome = cfg.validate(Environment::Production);
            assert!(
                outcome.is_ok(),
                "{} = {edge} must be accepted: {outcome:?}",
                bound.field
            );
        }
    }
}

#[test]
fn every_option_is_refused_one_past_its_ceiling_by_name() {
    for bound in bounds() {
        let mut cfg = valid();
        (bound.set)(&mut cfg, bound.max + 1);
        let outcome = cfg.validate(Environment::Production);
        assert!(
            matches!(
                outcome,
                Err(ConfigError::OutOfRange { field, got, min, max })
                    if field == bound.field && got == bound.max + 1 && min == bound.min && max == bound.max
            ),
            "{} one past its ceiling must be refused as out of range: {outcome:?}",
            bound.field
        );
    }
}

#[test]
fn every_option_is_refused_at_zero_except_the_absolute_lifetime() {
    // The store refuses `SET key value EX 0`, `Max-Age=0` deletes a cookie and a cap of no
    // sessions evicts each one as it is created. The absolute cap's `0` switches it off.
    for bound in bounds() {
        let mut cfg = valid();
        (bound.set)(&mut cfg, 0);
        let outcome = cfg.validate(Environment::Production);
        let accepted = bound.field == "jwt.absolute_session_lifetime_days";
        assert_eq!(
            outcome.is_ok(),
            accepted,
            "{} = 0: {outcome:?}",
            bound.field
        );
        // A zero refresh lifetime or counting window is refused by an earlier rule of its own.
        let earlier = ["jwt.refresh_expires_in_days", "brute_force.window"];
        if !accepted && !earlier.contains(&bound.field) {
            assert!(
                matches!(
                    outcome,
                    Err(ConfigError::OutOfRange { field, got: 0, min: 1, max })
                        if field == bound.field && max == bound.max
                ),
                "{} = 0 must be refused as out of range: {outcome:?}",
                bound.field
            );
        }
    }
}

#[test]
fn a_sub_second_lifetime_is_zero_seconds_and_is_refused() {
    let mut cfg = valid();
    cfg.invitations.token_ttl = Duration::from_millis(500);
    assert!(matches!(
        cfg.validate(Environment::Production),
        Err(ConfigError::OutOfRange {
            field: "invitations.token_ttl",
            got: 0,
            ..
        })
    ));
}

#[test]
fn the_user_status_cache_ttl_is_at_most_an_hour_and_zero_means_no_cache() {
    let mut cfg = valid();
    for (secs, accepted) in [(0, true), (60, true), (3_600, true), (3_601, false)] {
        cfg.user_status_cache_ttl = Duration::from_secs(secs);
        let outcome = cfg.validate(Environment::Production);
        assert_eq!(outcome.is_ok(), accepted, "{secs}s gave {outcome:?}");
        if !accepted {
            assert!(matches!(
                outcome,
                Err(ConfigError::UserStatusCacheTtlCeiling {
                    got: 3_601,
                    max: 3_600
                })
            ));
        }
    }
}

#[cfg(feature = "scrypt")]
#[test]
fn scrypt_parallelization_has_a_ceiling_of_sixteen() {
    let mut cfg = valid();
    cfg.password.scrypt.parallelization = 16;
    assert!(cfg.validate(Environment::Production).is_ok());
    cfg.password.scrypt.parallelization = 17;
    assert!(matches!(
        cfg.validate(Environment::Production),
        Err(ConfigError::OutOfRange {
            field: "password.scrypt.parallelization",
            got: 17,
            min: 1,
            max: 16
        })
    ));
}

#[cfg(feature = "argon2")]
#[test]
fn argon2_parallelism_has_a_ceiling_of_sixteen() {
    let mut cfg = valid();
    cfg.password.argon2.parallelism = 16;
    assert!(cfg.validate(Environment::Production).is_ok());
    cfg.password.argon2.parallelism = 17;
    assert!(matches!(
        cfg.validate(Environment::Production),
        Err(ConfigError::OutOfRange {
            field: "password.argon2.parallelism",
            got: 17,
            min: 1,
            max: 16
        })
    ));
}
