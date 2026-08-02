//! [`OtpStore`] over Redis: the OTP record, the attempt-bounded verify script, and the
//! resend cooldown (section 12.5.4). The Lua compare only decides the attempts bump; the
//! authoritative comparison is re-done here in constant time via `subtle`.

use async_trait::async_trait;
use bymax_auth_core::traits::{OtpPurpose, OtpStore};
use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

/// The `otp_verify` reply tag for an absent record (TTL elapsed).
const TAG_EXPIRED: &str = "EXPIRED";
/// The `otp_verify` reply tag when the attempt ceiling was already reached.
const TAG_MAX: &str = "MAX";
/// The `otp_verify` reply tag when the record is present and under the ceiling.
const TAG_PRESENT: &str = "PRESENT";

/// Compose the `{purpose}:{identifier}` segment shared by the OTP and resend keys. The
/// `identifier` is already an HMAC of `tenant:email`, so no raw email enters the key.
fn purpose_segment(purpose: OtpPurpose, identifier: &str) -> String {
    format!("{}:{}", purpose.as_str(), identifier)
}

/// Map the `otp_verify` reply (`{ tag, storedCode }`) onto a typed outcome. On the `PRESENT`
/// tag the authoritative decision is the constant-time comparison of the submitted code
/// against the stored code (the Lua plain compare only drove the atomic attempts bump).
fn interpret_otp(tag: &str, stored: &str, submitted: &str) -> Result<(), AuthError> {
    match tag {
        TAG_EXPIRED => Err(AuthError::OtpExpired),
        TAG_MAX => Err(AuthError::OtpMaxAttempts),
        TAG_PRESENT => {
            if constant_time_eq(submitted.as_bytes(), stored.as_bytes()) {
                Ok(())
            } else {
                Err(AuthError::OtpInvalid)
            }
        }
        // The script only ever returns the three tags above; any other reply is a contract
        // breach, surfaced fail-closed as an opaque internal error rather than a silent pass.
        _ => Err(AuthError::Internal("unexpected otp_verify reply".into())),
    }
}

impl RedisStores {
    /// Store an OTP record with a zeroed attempt counter and the configured TTL.
    async fn put_inner(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self
            .keys()
            .key(Prefix::Otp, &purpose_segment(purpose, identifier));
        // A HASH of `code` + `attempts`, not a JSON string: the verify script bumps the
        // counter with `HINCRBY`, which is what lets "check the ceiling, compare, bump or
        // consume" be one atomic step without decoding anything — and leaves the TTL alone, so
        // a wrong guess cannot extend the OTP's lifetime. Written in a transaction so the
        // record never exists without its expiry.
        let mut conn = self.connection().await?;
        redis::pipe()
            .atomic()
            .hset(&key, "code", code)
            .ignore()
            .hset(&key, "attempts", 0)
            .ignore()
            .expire(&key, i64::try_from(ttl_secs).unwrap_or(i64::MAX))
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Run the attempt-bounded verify script, returning its `(tag, storedCode)` reply.
    async fn verify_inner(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        max_attempts: u32,
    ) -> Result<(String, String), RedisStoreError> {
        let key = self
            .keys()
            .key(Prefix::Otp, &purpose_segment(purpose, identifier));
        let mut conn = self.connection().await?;
        let reply: (String, String) = script::OTP_VERIFY
            .prepare()
            .key(&key)
            .arg(code)
            .arg(max_attempts)
            .invoke_async(&mut conn)
            .await?;
        Ok(reply)
    }

    /// Begin a resend if the cooldown window is free (`SET … EX NX`).
    async fn try_begin_resend_inner(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        cooldown_secs: u64,
    ) -> Result<bool, RedisStoreError> {
        let key = self
            .keys()
            .key(Prefix::Resend, &purpose_segment(purpose, identifier));
        let mut conn = self.connection().await?;
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(cooldown_secs)
            .arg("NX")
            .query_async(&mut conn)
            .await?;
        Ok(set.is_some())
    }
}

#[async_trait]
impl OtpStore for RedisStores {
    async fn put(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_inner(purpose, identifier, code, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn verify(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        max_attempts: u32,
    ) -> Result<(), AuthError> {
        let (tag, stored) = self
            .verify_inner(purpose, identifier, code, max_attempts)
            .await
            .map_err(AuthError::from)?;
        interpret_otp(&tag, &stored, code)
    }

    async fn try_begin_resend(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        cooldown_secs: u64,
    ) -> Result<bool, AuthError> {
        self.try_begin_resend_inner(purpose, identifier, cooldown_secs)
            .await
            .map_err(AuthError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_segment_joins_purpose_and_identifier() {
        // The segment is `{purpose}:{hmac}`; both OTP purposes render their stable wire form.
        assert_eq!(
            purpose_segment(OtpPurpose::PasswordReset, "deadbeef"),
            "password_reset:deadbeef"
        );
        assert_eq!(
            purpose_segment(OtpPurpose::EmailVerification, "deadbeef"),
            "email_verification:deadbeef"
        );
    }

    #[test]
    fn interpret_otp_covers_every_reply_tag() {
        // The four real outcomes plus the fail-closed catch-all for an out-of-contract reply.
        assert!(matches!(
            interpret_otp("EXPIRED", "", "123456"),
            Err(AuthError::OtpExpired)
        ));
        assert!(matches!(
            interpret_otp("MAX", "", "123456"),
            Err(AuthError::OtpMaxAttempts)
        ));
        assert!(interpret_otp("PRESENT", "123456", "123456").is_ok());
        assert!(matches!(
            interpret_otp("PRESENT", "123456", "000000"),
            Err(AuthError::OtpInvalid)
        ));
        assert!(matches!(
            interpret_otp("BOGUS", "123456", "123456"),
            Err(AuthError::Internal(_))
        ));
    }

    #[test]
    fn the_verify_script_bumps_in_place_and_never_extends_the_ttl() {
        // Static guard on the shared script. The bump must be an in-place `HINCRBY`: computing
        // it in the caller is the race the HASH form exists to close (N concurrent guesses each
        // read the same counter and each write back 1, so the ceiling is exceeded by simply
        // submitting in parallel), and re-writing the record would reset the TTL, letting a
        // wrong guess buy extra OTP lifetime. The ceiling is checked BEFORE the comparison so
        // an exhausted record cannot be probed further.
        let source = include_str!("../lua/otp_verify.lua");
        assert!(source.contains("redis.call('HINCRBY', KEYS[1], 'attempts', 1)"));
        // No `cjson` in the executable body — the comment block explains why it left, and the
        // in-memory Redis the nest-auth end-to-end tier runs against does not provide it.
        let body: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!body.contains("cjson"));
        let ceiling = source.find("attempts >= tonumber(ARGV[2])");
        let compare = source.find("code == ARGV[1]");
        assert!(matches!((ceiling, compare), (Some(c), Some(k)) if c < k));
        // A match consumes the record, so a correct code is single-use.
        assert!(source.contains("redis.call('DEL', KEYS[1])"));
    }
}
