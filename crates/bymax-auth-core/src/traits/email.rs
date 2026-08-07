//! The transactional-email contract. The engine sends no mail itself: it names auth
//! events through the object-safe [`EmailProvider`] trait and the host supplies an
//! adapter for its provider (Resend, SES, SMTP, …). The contract describes *what* to
//! send, never *how* to render it — template, layout, and localization are the
//! adapter's concern.
//!
//! Every method takes an optional BCP-47 `locale`; the adapter falls back to a default
//! when it is `None`. Implementations must never log email bodies, tokens, OTPs, or
//! recovery codes. Delivery is fire-and-forget from the engine's perspective: a returned
//! `Err` is logged and dropped, except where a flow is explicitly gated on delivery.

use async_trait::async_trait;

use crate::normalize::mask_email;
use time::OffsetDateTime;

/// The transactional-email contract, held on the engine as `Arc<dyn EmailProvider>`.
///
/// # Errors
///
/// Every method returns [`EmailError::Delivery`] wrapping the underlying transport
/// failure (network, auth, provider 5xx). For fire-and-forget sends the engine logs and
/// continues.
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send a password-reset link token for the user to embed in a time-limited URL.
    /// Never log `token`.
    async fn send_password_reset_token(
        &self,
        email: &str,
        token: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError>;

    /// Send a short-lived numeric password-reset OTP. Never log `otp`.
    async fn send_password_reset_otp(
        &self,
        email: &str,
        otp: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError>;

    /// Send the email-verification OTP after registration or on resend. Never log `otp`.
    async fn send_email_verification_otp(
        &self,
        email: &str,
        otp: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError>;

    /// Security alert: the account password changed — after an authenticated change, and
    /// after a completed reset.
    ///
    /// NIST SP 800-63B §4.6 requires the subscriber to be notified through a channel
    /// independent of the transaction that bound the new credential. The classic takeover
    /// starts with a compromised mailbox: the attacker triggers a reset, completes it, and
    /// deletes the mail. This notice is what turns "the victim finds out days later, at a
    /// failed login" into "the victim finds out now" — and it was the one credential change
    /// this trait stayed silent about while announcing every MFA change unprompted.
    ///
    /// Defaulted to a no-op so an existing provider keeps compiling; a deployment that wants
    /// the notice implements it.
    async fn send_password_changed(
        &self,
        email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        let _ = (email, locale);
        Ok(())
    }

    /// Deliver the address-change verification token to the **new** address.
    ///
    /// The token goes here and nowhere else: receiving it is what proves the requester
    /// controls the address before it becomes the account's. The provider builds the
    /// confirmation URL from it.
    ///
    /// **Required, unlike the notices below.** A defaulted no-op would swallow the token and
    /// leave the flow minting `ec:` keys nobody ever receives — a failure that looks like
    /// success from every side, and that a user experiences as a verification email that
    /// simply never arrives. Every other trait method that carries a token is required for
    /// the same reason; making this one optional would be the exception, not the rule.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError`] when delivery fails. The engine surfaces it: a change whose
    /// verification could not be sent has not started.
    async fn send_email_change_verification(
        &self,
        new_email: &str,
        token: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError>;

    /// Notify the **old** address that the account's address has changed.
    ///
    /// NIST SP 800-63B §4.6 asks for notification of a credential change, and the address is
    /// the recovery credential: someone who moves it can then drive a password reset to a
    /// mailbox the owner does not read. This message is what puts that in front of the owner
    /// while they still control the address it arrives at.
    ///
    /// Defaulted to a no-op so an existing provider keeps compiling, exactly like
    /// [`Self::send_password_changed`] — it is the same kind of notice, and it carries no
    /// token whose loss would break the flow.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError`] when delivery fails. The engine logs and drops it: a change the
    /// user asked for and proved is not rolled back because a mail server was down.
    async fn send_email_changed_notification(
        &self,
        old_email: &str,
        new_email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        let _ = (old_email, new_email, locale);
        Ok(())
    }

    /// Security alert: MFA was enabled on the account.
    async fn send_mfa_enabled(&self, email: &str, locale: Option<&str>) -> Result<(), EmailError>;

    /// Security alert: MFA was disabled on the account.
    async fn send_mfa_disabled(&self, email: &str, locale: Option<&str>) -> Result<(), EmailError>;

    /// Security alert about a newly established session. The body should show the device, IP,
    /// and session hash.
    ///
    /// **This library never calls it**, which is why it has a default: it is a typed signature
    /// for the host to call from the `on_new_session` hook — which the library DOES fire, on
    /// every session it creates, with the same [`SessionInfo`] this takes.
    ///
    /// The alert deliberately does not live inside the library, because the library cannot send
    /// it well. Without device recognition it fires on *every* login, and an alert that arrives
    /// on every login is one the user learns to dismiss — at which point the control has stopped
    /// existing while still appearing to be in place. Recognizing a device means keeping a
    /// per-user device history, and the host already has one (or can key it to its own user
    /// record); the library would have to invent that state in the Redis keyspace it shares with
    /// nest-auth, which is a contract change to solve a problem the caller is better placed to
    /// solve.
    ///
    /// So: decide in `on_new_session` whether the session is worth alerting about, and call this
    /// when it is.
    async fn send_new_session_alert(
        &self,
        email: &str,
        session: &SessionInfo,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        let _ = (email, session, locale);
        Ok(())
    }

    /// Tenant invitation: the body should show the inviter, the tenant, the accept URL
    /// (built from `invite.invite_token`), and the expiry. Never log `invite.invite_token`.
    async fn send_invitation(
        &self,
        email: &str,
        invite: &InviteData,
        locale: Option<&str>,
    ) -> Result<(), EmailError>;
}

/// Details of a new session, shared by [`EmailProvider::send_new_session_alert`] and the
/// `on_new_session` hook.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    /// Human-readable device/browser, e.g. `"Chrome on macOS"`.
    pub device: String,
    /// Originating IP. May be personal data — consider masking before passing it to a
    /// third party. Must come from a trusted-proxy configuration, never raw
    /// `X-Forwarded-For`.
    pub ip: String,
    /// Display-only session identifier — a short hash (e.g. the first 8 hex chars of the
    /// SHA-256 of the refresh token). Never the raw token.
    pub session_hash: String,
}

/// Data required to render a tenant-invitation email. The `Debug` impl redacts
/// `invite_token` (a live single-use credential) so it cannot leak into a log.
#[derive(Clone)]
pub struct InviteData {
    /// Display name of the inviter.
    pub inviter_name: String,
    /// Name of the tenant/workspace the invitee is joining.
    pub tenant_name: String,
    /// Raw invitation token (64 hex chars). The adapter builds the full accept URL.
    pub invite_token: String,
    /// UTC instant after which the invitation is no longer valid.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for InviteData {
    /// Redacts `invite_token`; the inviter/tenant/expiry fields are display-safe.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteData")
            .field("inviter_name", &self.inviter_name)
            .field("tenant_name", &self.tenant_name)
            .field("invite_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A transactional-email failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmailError {
    /// Any failure in the underlying transport/provider (network, auth, 5xx). The engine
    /// logs this and continues for fire-and-forget sends.
    #[error("email delivery failed")]
    Delivery(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The default email provider installed when the host supplies none. Every method
/// returns `Ok(())` without sending anything, emitting a `tracing` debug line that
/// records the event and a MASKED recipient, and redacts tokens and OTPs — keeping local
/// development and tests running without an email backend.
///
/// The address is masked for the same reason every other log line in the engine masks it: a
/// debug level is not a private one. Whoever ships these logs to an aggregator is not
/// necessarily the operator, and a provider that only runs when none is configured is exactly
/// the one likeliest to be running with verbose logging turned on.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpEmailProvider;

#[async_trait]
impl EmailProvider for NoOpEmailProvider {
    async fn send_email_change_verification(
        &self,
        new_email: &str,
        token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        let _ = token;
        tracing::debug!(
            event = "email_change_verification",
            email = %mask_email(new_email),
            "noop email: token redacted"
        );
        Ok(())
    }

    async fn send_password_reset_token(
        &self,
        email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        tracing::debug!(event = "password_reset_token", email = %mask_email(email), "noop email: token redacted");
        Ok(())
    }
    async fn send_password_reset_otp(
        &self,
        email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        tracing::debug!(event = "password_reset_otp", email = %mask_email(email), "noop email: otp redacted");
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        tracing::debug!(event = "email_verification_otp", email = %mask_email(email), "noop email: otp redacted");
        Ok(())
    }
    async fn send_mfa_enabled(&self, email: &str, _locale: Option<&str>) -> Result<(), EmailError> {
        tracing::debug!(event = "mfa_enabled", email = %mask_email(email), "noop email");
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        tracing::debug!(event = "mfa_disabled", email = %mask_email(email), "noop email");
        Ok(())
    }
    // `send_new_session_alert` is deliberately NOT overridden here. It is the one method with a
    // default, because the library never calls it — so the log line the other no-ops write
    // ("this is what would have been sent") could never fire for this one from library code, and
    // inheriting the default is what keeps the no-op honest about that.
    async fn send_invitation(
        &self,
        email: &str,
        _invite: &InviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        tracing::debug!(event = "invitation", email = %mask_email(email), "noop email: token redacted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn session() -> SessionInfo {
        SessionInfo {
            device: "Chrome on macOS".into(),
            ip: "203.0.113.4".into(),
            session_hash: "deadbeef".into(),
        }
    }

    fn invite() -> InviteData {
        InviteData {
            inviter_name: "Owner".into(),
            tenant_name: "Acme".into(),
            invite_token: "0".repeat(64),
            expires_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn invite_data_debug_redacts_the_token() {
        // The single-use invitation token must never appear in a `{:?}` of the invite data.
        let rendered = format!("{:?}", invite());
        assert!(!rendered.contains(&"0".repeat(64)));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("Acme"));
    }

    #[tokio::test]
    async fn noop_provider_is_object_safe_and_returns_ok() {
        // Behind `Arc<dyn EmailProvider>` the trait must be object-safe; every method of
        // the NoOp default must succeed without a backend, covering all eight sends.
        let email: Arc<dyn EmailProvider> = Arc::new(NoOpEmailProvider);
        assert!(
            email
                .send_password_reset_token("e@x.io", "tok", Some("en"))
                .await
                .is_ok()
        );
        assert!(
            email
                .send_password_reset_otp("e@x.io", "123456", None)
                .await
                .is_ok()
        );
        assert!(
            email
                .send_email_verification_otp("e@x.io", "123456", Some("pt-BR"))
                .await
                .is_ok()
        );
        assert!(email.send_mfa_enabled("e@x.io", None).await.is_ok());
        assert!(email.send_mfa_disabled("e@x.io", None).await.is_ok());
        assert!(
            email
                .send_new_session_alert("e@x.io", &session(), None)
                .await
                .is_ok()
        );
        assert!(
            email
                .send_invitation("e@x.io", &invite(), None)
                .await
                .is_ok()
        );
    }
}
