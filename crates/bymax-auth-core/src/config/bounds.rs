//! The numeric ceilings of the configuration (layer: config).
//!
//! A value the store cannot represent fails on every request that uses it (an expiry whose
//! milliseconds overflow 64 bits), and a value that is merely huge turns a security window into a
//! permanent one. The ranges follow the boot checks of `@bymax-one/nest-auth`; the Argon2id lane
//! ceiling is this library's own, since the same cost argument holds for it.

use super::AuthConfig;
use crate::ConfigError;

/// The longest accepted store lifetime, in seconds (ten years). A far larger value overflows the
/// 64-bit millisecond expiry Redis computes, and Redis refuses it.
const TTL_CEILING_SECS: u64 = 315_360_000;

/// The most concurrent sessions a default cap may name.
const MAX_SESSIONS_CEILING: u64 = 1_000;

/// The longest refresh or absolute session lifetime, in days (ten years).
const LIFETIME_CEILING_DAYS: u64 = 3_650;

/// The longest failure-counting window, in seconds (one week).
const BRUTE_FORCE_WINDOW_CEILING_SECS: u64 = 604_800;

/// The longest status-cache lifetime, in seconds (one hour): how long a suspended account can
/// still pass. `0` is no cache. `nest-auth` enforces the same ceiling.
const MAX_USER_STATUS_CACHE_TTL_SECS: u64 = 3_600;

/// The most lanes a password hasher may be asked for.
#[cfg(any(feature = "scrypt", feature = "argon2"))]
const PARALLELISM_CEILING: u64 = 16;

/// Refuses `got` outside `1..=max`, naming the option.
fn within(field: &'static str, got: u64, max: u64) -> Result<(), ConfigError> {
    if (1..=max).contains(&got) {
        return Ok(());
    }
    Err(ConfigError::OutOfRange {
        field,
        got,
        min: 1,
        max,
    })
}

impl AuthConfig {
    /// The ranges of the options that name a lifetime, a window, a cap or a lane count.
    pub(super) fn validate_ceilings(&self) -> Result<(), ConfigError> {
        self.validate_session_ceilings()?;
        self.validate_lifetime_ceilings()?;
        self.validate_status_cache_ceiling()?;
        self.validate_parallelism_ceilings()
    }

    /// The status-cache lifetime has a ceiling and no floor.
    fn validate_status_cache_ceiling(&self) -> Result<(), ConfigError> {
        let got = self.user_status_cache_ttl.as_secs();
        if got > MAX_USER_STATUS_CACHE_TTL_SECS {
            return Err(ConfigError::UserStatusCacheTtlCeiling {
                got,
                max: MAX_USER_STATUS_CACHE_TTL_SECS,
            });
        }
        Ok(())
    }

    /// The session cap, the session lifetimes and the failure-counting window.
    fn validate_session_ceilings(&self) -> Result<(), ConfigError> {
        within(
            "sessions.default_max_sessions",
            u64::from(self.sessions.default_max_sessions),
            MAX_SESSIONS_CEILING,
        )?;
        within(
            "jwt.refresh_expires_in_days",
            u64::from(self.jwt.refresh_expires_in_days),
            LIFETIME_CEILING_DAYS,
        )?;
        // `0` switches the absolute cap off; any other value is the cap in days.
        let absolute = u64::from(self.jwt.absolute_session_lifetime_days);
        if absolute != 0 {
            within(
                "jwt.absolute_session_lifetime_days",
                absolute,
                LIFETIME_CEILING_DAYS,
            )?;
        }
        within(
            "brute_force.window",
            self.brute_force.window.as_secs(),
            BRUTE_FORCE_WINDOW_CEILING_SECS,
        )
    }

    /// The access cookie and the five store lifetimes, in whole seconds: a sub-second part is
    /// dropped, as the store drops it.
    fn validate_lifetime_ceilings(&self) -> Result<(), ConfigError> {
        let lifetimes = [
            ("jwt.access_cookie_max_age", self.jwt.access_cookie_max_age),
            ("password_reset.token_ttl", self.password_reset.token_ttl),
            ("password_reset.otp_ttl", self.password_reset.otp_ttl),
            (
                "email_verification.otp_ttl",
                self.email_verification.otp_ttl,
            ),
            ("email_change.token_ttl", self.email_change.token_ttl),
            ("invitations.token_ttl", self.invitations.token_ttl),
        ];
        for (field, lifetime) in lifetimes {
            within(field, lifetime.as_secs(), TTL_CEILING_SECS)?;
        }
        Ok(())
    }

    /// The lane count of each compiled-in password hasher.
    fn validate_parallelism_ceilings(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "scrypt")]
        within(
            "password.scrypt.parallelization",
            u64::from(self.password.scrypt.parallelization),
            PARALLELISM_CEILING,
        )?;
        #[cfg(feature = "argon2")]
        within(
            "password.argon2.parallelism",
            u64::from(self.password.argon2.parallelism),
            PARALLELISM_CEILING,
        )?;
        Ok(())
    }
}
