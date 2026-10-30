//! The copy of every message the port can send: the [`AuthEmailCatalogue`] of pure renderers, the
//! [`AuthEmailContext`] each one is handed, and the built-in [`DefaultAuthEmailCatalogue`].
//!
//! Layer: wording only. Delivery, escaping and the failure policy live in the parent module,
//! which fills the context and calls the renderers.

use super::super::email::{InviteData, SessionInfo};
use super::{AuthEmailMessage, render_utc_instant};

/// How long a verification or reset code stays valid, stated in the message that carries it.
const CODE_VALIDITY_TEXT: &str = "It expires shortly, so use it soon.";

/// Closing line on every message announcing a change the recipient may not have made.
pub(super) const UNEXPECTED_CHANGE_TEXT: &str = "If this was not you, secure your account immediately: change your password and sign out of every session.";

/// What every renderer is told about the message it is rendering, besides its own fields.
///
/// A renderer is a pure function, and a product's copy often needs more than the code it
/// carries: a link under a tenant-specific host needs the tenant, and a greeting needs the
/// address. `tenant_id` and `email` are the ones the provider already holds when it delivers, so
/// the renderer gets exactly what the channel gets.
///
/// `email` is the **delivery address**, which is not always the account's current one: for
/// [`AuthEmailCatalogue::email_change_verification`] it is the NEW address (the one being proven),
/// and for [`AuthEmailCatalogue::email_changed`] it is the PREVIOUS one (the notice goes where the
/// owner still reads), with both addresses also passed as that renderer's own fields.
#[derive(Debug, Clone, Copy)]
pub struct AuthEmailContext<'a> {
    /// The tenant the message is attributed to.
    pub tenant_id: &'a str,
    /// The address the message is delivered to.
    pub email: &'a str,
    /// BCP 47 locale tag the message is rendered in, when the caller supplied one.
    pub locale: Option<&'a str>,
}

/// The copy for every message the port can send, as pure renderers keyed by event.
///
/// Every method has a default, so an override implements only the events whose wording it
/// wants to change and the rest keep the secure default. A catalogue chooses words, never
/// behaviour: the subject sanitization and the delivery-error policy apply to an override
/// exactly as they do to the default.
///
/// **Escaping is the one exception, and it is a security boundary worth reading twice.** The
/// provider escapes what it renders — a message that leaves `html` unset has its `text` turned
/// into escaped paragraphs. A renderer that RETURNS `html` has that value used verbatim, and
/// owns the escaping of every dynamic value it interpolates: an inviter's display name, a
/// tenant's name, the address an account moved to. That is deliberate, because the escaped-text
/// default cannot carry a real `<a>` link — but it means an override that trusts the provider
/// to escape its markup is trusting a protection that is not there.
///
/// Each renderer is a pure function of its inputs, which is what makes an override a drop-in
/// replacement and keeps the copy testable without a provider around it.
pub trait AuthEmailCatalogue: Send + Sync {
    /// Password-reset link carrying a signed token.
    fn password_reset_token(&self, ctx: &AuthEmailContext<'_>, token: &str) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Reset your password",
            format!(
                "Use this token to reset your password: {token}\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change."
            ),
        )
    }

    /// One-time code for the password-reset flow.
    fn password_reset_otp(&self, ctx: &AuthEmailContext<'_>, otp: &str) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Your password reset code",
            format!(
                "Your password reset code is {otp}.\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change."
            ),
        )
    }

    /// One-time code that activates a newly registered account.
    fn email_verification_otp(&self, ctx: &AuthEmailContext<'_>, otp: &str) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Verify your email address",
            format!(
                "Your verification code is {otp}.\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not create an account, ignore this message."
            ),
        )
    }

    /// Notice that the account password changed (NIST SP 800-63B §4.6).
    fn password_changed(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Your password was changed",
            format!("The password on your account was changed.\n\n{UNEXPECTED_CHANGE_TEXT}"),
        )
    }

    /// Code confirming ownership of an address the user is moving to.
    fn email_change_verification(
        &self,
        ctx: &AuthEmailContext<'_>,
        token: &str,
    ) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Confirm your new email address",
            format!(
                "Your confirmation code is {token}.\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not ask to change your email address, ignore this message."
            ),
        )
    }

    /// Notice to the previous address that the account's email moved.
    fn email_changed(
        &self,
        ctx: &AuthEmailContext<'_>,
        old_email: &str,
        new_email: &str,
    ) -> AuthEmailMessage {
        let _ = (ctx, old_email);
        AuthEmailMessage::plain(
            "Your email address was changed",
            format!(
                "The email address on your account was changed to {new_email}, and this address no longer signs in to it.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Notice that a second factor was added.
    fn mfa_enabled(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Two-factor authentication is on",
            format!(
                "Two-factor authentication was enabled on your account.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Notice that a second factor was removed.
    fn mfa_disabled(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "Two-factor authentication is off",
            format!(
                "Two-factor authentication was disabled on your account.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Security alert about a newly established session.
    fn new_session_alert(
        &self,
        ctx: &AuthEmailContext<'_>,
        session: &SessionInfo,
    ) -> AuthEmailMessage {
        let _ = ctx;
        AuthEmailMessage::plain(
            "New sign-in to your account",
            format!(
                "A new session was started on your account.\n\nDevice: {}\nIP: {}\nSession: {}\n\n{UNEXPECTED_CHANGE_TEXT}",
                session.device, session.ip, session.session_hash
            ),
        )
    }

    /// Invitation to join a tenant.
    fn invitation(&self, ctx: &AuthEmailContext<'_>, invite: &InviteData) -> AuthEmailMessage {
        let _ = ctx;
        let expires = render_utc_instant(invite.expires_at);
        AuthEmailMessage::plain(
            format!(
                "{} invited you to {}",
                invite.inviter_name, invite.tenant_name
            ),
            format!(
                "{} invited you to join {}.\n\nUse this token to accept: {}\n\nIt expires on {expires}.\n\nIf you were not expecting this invitation, ignore this message.",
                invite.inviter_name, invite.tenant_name, invite.invite_token
            ),
        )
    }
}

/// The built-in copy: [`AuthEmailCatalogue`] with every method left at its default.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAuthEmailCatalogue;

impl AuthEmailCatalogue for DefaultAuthEmailCatalogue {}
