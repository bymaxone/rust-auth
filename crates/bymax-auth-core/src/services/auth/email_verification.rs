//! The email-verification flows (§7.1.6): `verify_email`, `resend_verification_email`, and
//! the private `send_verification_otp`. All paths are anti-enumerating — the resend returns
//! a uniform response with a normalized timing floor whether or not the account exists, and
//! a vanished account on verify collapses to `OtpInvalid` rather than a distinct error.

use std::collections::BTreeMap;
use std::time::Instant;

use bymax_auth_types::{AuthError, SafeAuthUser};

use crate::engine::AuthEngine;
use crate::services::auth::detached::{run_after_email_verified, run_send_verification_email};
use crate::services::auth::{map_repository_error, normalize_anti_enum, spawn_guarded};
use crate::traits::{HookContext, OtpPurpose};

/// The resend cooldown window, in seconds (§7.1.6).
const RESEND_COOLDOWN_SECS: u64 = 60;

/// The fixed verification-OTP length, in digits (§7.1.6).
const VERIFICATION_OTP_LENGTH: u8 = 6;

impl AuthEngine {
    /// Verify an email by consuming its OTP, then mark the account verified. The user is
    /// identified server-side from `(tenant_id, email)`, so a valid OTP can never verify a
    /// different account.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::OtpInvalid`]/[`AuthError::OtpExpired`]/[`AuthError::OtpMaxAttempts`]
    /// from the OTP check, [`AuthError::OtpInvalid`] when no such account exists (no
    /// post-OTP enumeration oracle), or a store [`AuthError`].
    pub async fn verify_email(
        &self,
        tenant_id: &str,
        email: &str,
        otp: &str,
    ) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(tenant_id, email);
        self.otp()
            .verify(OtpPurpose::EmailVerification, &identifier, otp)
            .await?;

        // An unknown account post-OTP collapses to OtpInvalid (no distinct "not found").
        let user = match self
            .user_repository()
            .find_by_email(email, tenant_id)
            .await
            .map_err(map_repository_error)?
        {
            Some(user) => user,
            None => return Err(AuthError::OtpInvalid),
        };

        self.user_repository()
            .update_email_verified(&user.id, true)
            .await
            .map_err(map_repository_error)?;

        let hook_ctx = verification_context(&user.id, &user.email, tenant_id);
        let safe = SafeAuthUser::from(user);
        spawn_guarded(run_after_email_verified(
            self.hooks().clone(),
            safe,
            hook_ctx,
        ));
        Ok(())
    }

    /// Re-issue a verification OTP, throttled by an atomic cooldown and uniformly
    /// anti-enumerating: the response and its timing floor are identical whether or not the
    /// account exists or still needs verification.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only on an infrastructure failure; account state never
    /// changes the (always `Ok`) outcome.
    pub async fn resend_verification_email(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<(), AuthError> {
        let started = Instant::now();
        let identifier = self.hashed_identifier(tenant_id, email);

        // Atomic cooldown gate — a second resend inside the window is a silent success.
        if !self
            .otp()
            .try_begin_resend(
                OtpPurpose::EmailVerification,
                &identifier,
                RESEND_COOLDOWN_SECS,
            )
            .await?
        {
            normalize_anti_enum(started).await;
            return Ok(());
        }

        let found = self
            .user_repository()
            .find_by_email(email, tenant_id)
            .await
            .map_err(map_repository_error)?;
        if let Some(user) = found
            && !user.email_verified
        {
            // Best-effort: a dispatch failure must not change the uniform response.
            let _ = self.send_verification_otp(tenant_id, email, &user.id).await;
        }

        normalize_anti_enum(started).await;
        Ok(())
    }

    /// Generate, store, and dispatch a verification OTP for an account. Best-effort: a store
    /// failure is reported to the caller (which ignores it), and the email send is
    /// fire-and-forget so its round-trip never perturbs the normalized timing.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] if the OTP cannot be persisted.
    pub(crate) async fn send_verification_otp(
        &self,
        tenant_id: &str,
        email: &str,
        _user_id: &str,
    ) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(tenant_id, email);
        let otp = self.otp().generate(VERIFICATION_OTP_LENGTH);
        let ttl = self.config().config().email_verification.otp_ttl.as_secs();
        self.otp()
            .store(OtpPurpose::EmailVerification, &identifier, &otp, ttl)
            .await?;

        spawn_guarded(run_send_verification_email(
            self.email_provider().clone(),
            email.to_owned(),
            otp,
        ));
        Ok(())
    }
}

/// A [`HookContext`] carrying only the verified identity, for the verification hook (which
/// has no originating request context).
fn verification_context(user_id: &str, email: &str, tenant_id: &str) -> HookContext {
    HookContext {
        user_id: Some(user_id.to_owned()),
        email: Some(email.to_owned()),
        tenant_id: Some(tenant_id.to_owned()),
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, harness};
    use crate::traits::UserRepository;
    use std::time::Duration;

    fn harness_with_verification() -> Option<Harness> {
        let mut cfg = base_config();
        cfg.email_verification.required = true;
        harness(cfg, None)
    }

    #[tokio::test]
    async fn verify_email_consumes_the_otp_and_marks_verified() {
        // A correct OTP marks the account verified; the OTP is single-use afterwards.
        let Some(h) = harness_with_verification() else { return };
        let id = h
            .seed(SeedUser {
                email: "v@example.com".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        // Send an OTP, then read it back from the in-memory store to submit it.
        assert!(
            h.engine
                .send_verification_otp("t1", "v@example.com", &id)
                .await
                .is_ok()
        );
        let identifier = h.engine.hashed_identifier("t1", "v@example.com");
        let stored = h
            .stores
            .peek_otp(OtpPurpose::EmailVerification, &identifier);
        let Some(code) = stored else { return };
        assert!(
            h.engine
                .verify_email("t1", "v@example.com", &code)
                .await
                .is_ok()
        );
        let stored = h.users.find_by_id(&id, None).await;
        assert!(matches!(stored, Ok(Some(u)) if u.email_verified));
        // The OTP is consumed: a second submission is now expired.
        assert!(matches!(
            h.engine.verify_email("t1", "v@example.com", &code).await,
            Err(AuthError::OtpExpired)
        ));
    }

    #[tokio::test]
    async fn verify_email_rejects_a_wrong_code_and_an_unknown_account() {
        // A wrong OTP is OtpInvalid; a valid OTP for a vanished account collapses to
        // OtpInvalid (no post-OTP enumeration).
        let Some(h) = harness_with_verification() else { return };
        let _ = h
            .seed(SeedUser {
                email: "w@example.com".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        assert!(
            h.engine
                .send_verification_otp("t1", "w@example.com", "x")
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine.verify_email("t1", "w@example.com", "000000").await,
            Err(AuthError::OtpInvalid)
        ));
        // An OTP stored for an email with no backing user collapses to OtpInvalid on success.
        assert!(
            h.engine
                .send_verification_otp("t1", "ghost@example.com", "g")
                .await
                .is_ok()
        );
        let identifier = h.engine.hashed_identifier("t1", "ghost@example.com");
        let stored = h
            .stores
            .peek_otp(OtpPurpose::EmailVerification, &identifier);
        let Some(code) = stored else { return };
        assert!(matches!(
            h.engine
                .verify_email("t1", "ghost@example.com", &code)
                .await,
            Err(AuthError::OtpInvalid)
        ));
    }

    #[tokio::test]
    async fn resend_is_anti_enumerating_and_cooldown_throttled() {
        // The first resend is allowed; a second within the window is a silent success; both
        // an existing-unverified, an existing-verified, and an absent account return Ok with
        // the timing floor honored.
        let Some(h) = harness_with_verification() else { return };
        let _ = h
            .seed(SeedUser {
                email: "r@example.com".to_owned(),
                password: "pw".to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: false,
                mfa_enabled: false,
            })
            .await;
        let started = Instant::now();
        assert!(
            h.engine
                .resend_verification_email("t1", "r@example.com")
                .await
                .is_ok()
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        // Second resend within the cooldown is the silent-success branch.
        assert!(
            h.engine
                .resend_verification_email("t1", "r@example.com")
                .await
                .is_ok()
        );
        // An absent account is indistinguishable (uniform Ok).
        assert!(
            h.engine
                .resend_verification_email("t1", "absent@example.com")
                .await
                .is_ok()
        );
        // An already-verified account: resend short-circuits the send but still returns Ok.
        let _ = h.seed(SeedUser::active("done@example.com", "pw")).await;
        assert!(
            h.engine
                .resend_verification_email("t1", "done@example.com")
                .await
                .is_ok()
        );
    }
}
