//! The body shared by the two reset-request entry points, `initiate_reset` and
//! `resend_reset_otp`, which draw on one resend cooldown under one key.
//!
//! Layer: an engine service helper; the entry points and their timing floor live in
//! `password_reset.rs`.
//!
//! A failure BEFORE the account is known (the cooldown gate, the account lookup) is the same for
//! every address, so it is surfaced and the caller answers `500` after the floor. A failure AFTER
//! it is known (issuing or storing the proof, sending it) happens only for a registered address,
//! so a `5xx` there would answer the enumeration question: it is logged and the uniform `Ok(())`
//! stands. The cooldown a request took is released on any failure, so the retry a failure invites
//! is not refused for the rest of the window.

use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_types::{AuthError, AuthUser};

use super::password_reset::{RESEND_COOLDOWN_SECS, RESET_TOKEN_BYTES, password_fingerprint};
use crate::config::ResetMethod;
use crate::engine::AuthEngine;
use crate::services::auth::detached::run_send_reset_otp_email;
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::traits::{OtpPurpose, ResetContext};

impl AuthEngine {
    /// Take the cooldown, look the account up and issue its proof by `method`.
    ///
    /// Takes the RESOLVED tenant and the normalized email as plain arguments rather than the
    /// input struct: the struct's `tenant_id` is what the caller asked for, and a resolver may
    /// have overruled it. Keeping only the resolved value in scope is what makes reading the
    /// wrong one impossible rather than merely unlikely.
    ///
    /// # Errors
    ///
    /// Returns the store error of the cooldown gate or the account lookup; every later failure
    /// is logged and the outcome stays `Ok(())`.
    pub(super) async fn begin_reset_request(
        &self,
        tenant_id: &str,
        email: &str,
        method: ResetMethod,
    ) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(tenant_id, email);
        // A cooldown hit is a silent success, and the caller's anti-enumeration floor still
        // applies, so the throttle does not itself answer whether the account exists. Every
        // issuance rewrites the OTP record with `attempts: 0`, so an untimed entry point would
        // turn the 5-attempt ceiling into 5 attempts per call.
        if !self
            .otp()
            .try_begin_resend(OtpPurpose::PasswordReset, &identifier, RESEND_COOLDOWN_SECS)
            .await?
        {
            return Ok(());
        }

        let found = self
            .user_repository()
            .find_by_email(email, tenant_id)
            .await
            .map_err(map_repository_error);
        let user = match found {
            Ok(user) => crate::services::auth::tenant_scoped(user, tenant_id),
            Err(error) => {
                self.release_reset_cooldown(&identifier).await;
                return Err(error);
            }
        };
        // An unknown email or a blocked account takes no visible branch.
        let Some(user) = user.filter(|user| self.assert_user_not_blocked(&user.status).is_ok())
        else {
            return Ok(());
        };
        let issued = match method {
            ResetMethod::Otp => self.send_reset_otp(tenant_id, email, &identifier).await,
            ResetMethod::Token => self.send_reset_token(&user, email, tenant_id).await,
        };
        if let Err(error) = issued {
            // No account, address or tenant in the line: it must read the same whichever
            // account the failure belonged to.
            let cause = crate::services::error_chain(&error);
            tracing::warn!(%cause, "password reset: the proof could not be issued");
            self.release_reset_cooldown(&identifier).await;
        }
        Ok(())
    }

    /// Release the cooldown a failed request took. A release that fails is logged and nothing
    /// more: the cooldown then runs out by itself.
    async fn release_reset_cooldown(&self, identifier: &str) {
        let released = self
            .otp()
            .release_resend(OtpPurpose::PasswordReset, identifier)
            .await;
        if let Err(error) = released {
            let cause = crate::services::error_chain(&error);
            tracing::warn!(%cause, "password reset: the resend cooldown could not be released");
        }
    }

    /// Generate, store, and dispatch a reset OTP. The store write is reported to the caller; the
    /// email send is fire-and-forget so its round-trip never perturbs the normalized timing, and
    /// a send that fails releases the cooldown from the detached task.
    async fn send_reset_otp(
        &self,
        tenant_id: &str,
        email: &str,
        identifier: &str,
    ) -> Result<(), AuthError> {
        let length = self.config().config().password_reset.otp_length;
        let otp = self.otp().generate(length);
        let ttl = self.config().config().password_reset.otp_ttl.as_secs();
        self.otp()
            .store(OtpPurpose::PasswordReset, identifier, &otp, ttl)
            .await?;
        let provider = self.email_provider().clone();
        let store = self.otp().store_handle();
        let (tenant_id, email, identifier) = (
            tenant_id.to_owned(),
            email.to_owned(),
            identifier.to_owned(),
        );
        spawn_guarded(async move {
            let sent = run_send_reset_otp_email(provider, tenant_id, email, otp).await;
            if sent.is_err() {
                // Best effort: a failed release leaves the cooldown to run out.
                let _ = store
                    .release_resend(OtpPurpose::PasswordReset, &identifier)
                    .await;
            }
            sent
        });
        Ok(())
    }

    /// Generate, store, and dispatch a reset link token. On a send failure the stored token is
    /// deleted so an undeliverable token does not linger in a Redis snapshot, and the failure is
    /// returned so the caller logs it and releases the cooldown. The send is blocking here (not
    /// fire-and-forget) precisely so its failure can drive that cleanup.
    async fn send_reset_token(
        &self,
        user: &AuthUser,
        email: &str,
        tenant_id: &str,
    ) -> Result<(), AuthError> {
        let Some(store) = self.password_reset_store() else {
            // A misconfiguration: the token method is selected but no `pw_reset:` store is wired.
            // Surfaced to the caller, whose log line carries it, so a deployment running the
            // token method without its store is observable without a second line here.
            return Err(crate::services::internal_error(
                "password reset store not configured",
            ));
        };
        let raw = generate_secure_token(RESET_TOKEN_BYTES);
        let ttl = self.config().config().password_reset.token_ttl.as_secs();
        let context = ResetContext {
            user_id: user.id.clone(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            password_fingerprint: password_fingerprint(user),
        };
        store.put_token(&raw, &context, ttl).await?;

        let sent = self
            .email_provider()
            .send_password_reset_token(tenant_id, email, &raw, None)
            .await;
        if sent.is_err() {
            if let Err(error) = store.delete_token(&raw).await {
                // The rollback is what keeps an undeliverable token from lingering in a Redis
                // snapshot for its whole TTL; the caller's line reports the delivery failure.
                tracing::error!(%error, "password reset: rollback of the stored token failed");
            }
            return Err(crate::services::internal_error(
                "password reset token delivery failed",
            ));
        }
        Ok(())
    }
}
