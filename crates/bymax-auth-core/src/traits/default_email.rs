//! The overridable default implementation of [`EmailProvider`].
//!
//! Ships the security-notification policy every host would otherwise hand-write to bridge this
//! library's email port onto a delivery channel: HTML escaping on a message path that carries
//! caller-chosen text, CR/LF stripping on the subject header so a name cannot inject one, the
//! NIST SP 800-63B notification catalogue (a password-changed notice, MFA enable/disable
//! notices, an email-changed notice to the *previous* address), and a swallow-and-log failure
//! policy so a down channel never turns "enable MFA" into a failed request.
//!
//! It sends through [`AuthEmailSink`], a port narrow enough that this module depends on no
//! concrete mailer — one method, one struct of already-rendered fields. The tenant the email
//! port now carries is passed straight through to the sink, so a multi-tenant channel can
//! attribute and route each message.
//!
//! The copy is deliberately plain and entirely replaceable: implement [`AuthEmailCatalogue`]
//! and override any subset of its methods with a product's own wording, returning `html` for
//! real links, layout and branding. What must survive a rewrite is the security shape — a code
//! is stated once, a notice of a change the user may not have made tells them how to react, and
//! nothing the catalogue produced is ever logged. A delivery failure records a library-owned
//! event name and the channel's own error — never a subject, a body, an address or a code —
//! because the catalogue is the host's and a subject carrying the code is an ordinary product
//! decision, not a misuse.
//!
//! Mirrors nest-auth's `DefaultAuthEmailProvider` so the two libraries send the same messages
//! from the same events.

use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use time::{OffsetDateTime, UtcOffset};

use super::email::{EmailError, EmailProvider, InviteData, SessionInfo};

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// One rendered message on its way to the channel, tenant and recipient attached.
///
/// Borrowed rather than owned: every field is already rendered by the time the sink sees it,
/// and the provider holds them alive across the single `send` call.
///
/// The `Debug` impl is hand-written and redacts both bodies; see the impl below.
///
/// Deliberately NOT `#[non_exhaustive]`, even though the host only ever receives one. Sealing it
/// would buy the freedom to add a field without a major bump, at the cost of making the host's
/// own sink untestable: they could not construct one to drive `send` in a unit test, and the
/// sink is the piece this library asks them to write. A field added later is a breaking change
/// worth taking over an adapter nobody can test.
#[derive(Clone, Copy)]
pub struct OutgoingEmail<'a> {
    /// Tenant the message is attributed to, for the channel's audit log and routing.
    pub tenant_id: &'a str,
    /// Recipient address.
    pub to: &'a str,
    /// Subject line, already stripped of CR/LF.
    pub subject: &'a str,
    /// HTML body.
    pub html: &'a str,
    /// Plain-text body.
    pub text: &'a str,
}

impl std::fmt::Debug for OutgoingEmail<'_> {
    /// Redacts both bodies and masks the recipient.
    ///
    /// A rendered body is where the reset token, the verification OTP and the invitation token
    /// actually are — this is the one type in the module that holds a live credential in the
    /// clear, and a sink that logs its input at debug would otherwise put every one of them in
    /// a log pipeline. The address is masked for the same reason every other log line in the
    /// engine masks it, and the subject is kept because it is the only field that names which
    /// message this was, which is what makes the line useful at all.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingEmail")
            .field("tenant_id", &crate::normalize::log_safe(self.tenant_id))
            .field("to", &crate::normalize::mask_email(self.to))
            .field("subject", &self.subject)
            .field("html", &"[REDACTED]")
            .field("text", &"[REDACTED]")
            .finish()
    }
}

/// The delivery channel [`DefaultAuthEmailProvider`] sends through.
///
/// Narrow by design: it names only the one call the provider makes, so the provider couples to
/// no concrete mailer. Any adapter over SES, Resend, SMTP or an internal notification service
/// satisfies it in a few lines.
#[async_trait]
pub trait AuthEmailSink: Send + Sync {
    /// Deliver one rendered message.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::Delivery`] when the channel refuses or fails to accept the
    /// message. What the provider does with that is [`DeliveryErrorPolicy`]'s decision, not the
    /// sink's.
    async fn send(&self, message: OutgoingEmail<'_>) -> Result<(), EmailError>;
}

// ---------------------------------------------------------------------------
// Copy
// ---------------------------------------------------------------------------

/// One rendered message, before the tenant and recipient are attached to it.
///
/// The `Debug` impl is hand-written and redacts both bodies, for the reason
/// [`OutgoingEmail`]'s does: a rendered body is where the token or code actually is.
#[derive(Clone)]
pub struct AuthEmailMessage {
    /// Subject line. Plain text — never rendered as HTML, so it needs no escaping. The
    /// provider strips CR/LF from it before it reaches the channel or a log line.
    pub subject: String,
    /// Body as plain text. Rendered to minimal, escaped HTML by the provider when `html` is
    /// `None`.
    pub text: String,
    /// Body as HTML, used verbatim when present. The provider does **not** escape it — an
    /// override that sets this owns its own escaping, which is the point: it is the seam for a
    /// product's real `<a>` links, layout and branding, none of which the escaped-text default
    /// can carry. Leave it `None` to have the provider render [`Self::text`] into safe, escaped
    /// paragraphs.
    pub html: Option<String>,
}

impl std::fmt::Debug for AuthEmailMessage {
    /// Redacts both bodies; the subject names the message and carries no secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthEmailMessage")
            .field("subject", &self.subject)
            .field("text", &"[REDACTED]")
            .field("html", &self.html.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl AuthEmailMessage {
    /// A message whose HTML the provider renders from the plain text.
    #[must_use]
    pub fn plain(subject: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            text: text.into(),
            html: None,
        }
    }
}

/// How long a verification or reset code stays valid, stated in the message that carries it.
const CODE_VALIDITY_TEXT: &str = "It expires shortly, so use it soon.";

/// Closing line on every message announcing a change the recipient may not have made.
const UNEXPECTED_CHANGE_TEXT: &str = "If this was not you, secure your account immediately: change your password and sign out of every session.";

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
    fn password_reset_token(&self, token: &str, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Reset your password",
            format!(
                "Use this token to reset your password: {token}\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change."
            ),
        )
    }

    /// One-time code for the password-reset flow.
    fn password_reset_otp(&self, otp: &str, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Your password reset code",
            format!(
                "Your password reset code is {otp}.\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change."
            ),
        )
    }

    /// One-time code that activates a newly registered account.
    fn email_verification_otp(&self, otp: &str, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Verify your email address",
            format!(
                "Your verification code is {otp}.\n\n{CODE_VALIDITY_TEXT}\n\nIf you did not create an account, ignore this message."
            ),
        )
    }

    /// Notice that the account password changed (NIST SP 800-63B §4.6).
    fn password_changed(&self, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Your password was changed",
            format!("The password on your account was changed.\n\n{UNEXPECTED_CHANGE_TEXT}"),
        )
    }

    /// Code confirming ownership of an address the user is moving to.
    fn email_change_verification(&self, token: &str, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
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
        old_email: &str,
        new_email: &str,
        locale: Option<&str>,
    ) -> AuthEmailMessage {
        let _ = (old_email, locale);
        AuthEmailMessage::plain(
            "Your email address was changed",
            format!(
                "The email address on your account was changed to {new_email}, and this address no longer signs in to it.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Notice that a second factor was added.
    fn mfa_enabled(&self, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Two-factor authentication is on",
            format!(
                "Two-factor authentication was enabled on your account.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Notice that a second factor was removed.
    fn mfa_disabled(&self, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "Two-factor authentication is off",
            format!(
                "Two-factor authentication was disabled on your account.\n\n{UNEXPECTED_CHANGE_TEXT}"
            ),
        )
    }

    /// Security alert about a newly established session.
    fn new_session_alert(&self, session: &SessionInfo, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
        AuthEmailMessage::plain(
            "New sign-in to your account",
            format!(
                "A new session was started on your account.\n\nDevice: {}\nIP: {}\nSession: {}\n\n{UNEXPECTED_CHANGE_TEXT}",
                session.device, session.ip, session.session_hash
            ),
        )
    }

    /// Invitation to join a tenant.
    fn invitation(&self, invite: &InviteData, locale: Option<&str>) -> AuthEmailMessage {
        let _ = locale;
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

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Render an instant as a UTC ISO-8601 timestamp for display in a message body.
///
/// Built from the components rather than through a format description because this must not be
/// able to fail: a formatter returns a `Result`, and the only honest thing to do with an error
/// on this path would be to invent a date or drop the line — in a message whose whole job is to
/// tell the invitee when their link stops working.
fn render_utc_instant(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// Escape the five characters that can change the structure of an HTML document.
///
/// Not optional: some bodies carry values the sender chose — an inviter's display name, a
/// tenant's name, the address an account moved to — and an unescaped `<` turns a message into
/// markup a mail client renders: a fake link, a hidden block, or a rewritten instruction next to
/// a real code.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Render a plain-text body as the minimal HTML the channel also wants: one escaped paragraph
/// per blank-line-separated block, with a single newline inside a block becoming a `<br>`.
///
/// Without the `<br>`, HTML's whitespace collapsing would fold a body like the new-session alert
/// — where device, IP and session sit on their own lines — back onto one line, so the HTML would
/// say something the plain-text body did not. Deliberately not a template engine: a product that
/// needs real layout returns `html` from its override instead.
fn to_html(text: &str) -> String {
    text.split("\n\n")
        .map(|paragraph| format!("<p>{}</p>", escape_html(paragraph).replace('\n', "<br>")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip CR and LF from a subject line.
///
/// A subject is a single email header, and a header ends at the first newline. Caller-chosen
/// text reaches the subject — an inviter's name, a tenant's name — so a `\r` or `\n` smuggled
/// into one would otherwise let a channel that builds headers by concatenation read the rest of
/// the value as additional headers (a hidden `Bcc:`), or reject the message outright. Newlines
/// carry no meaning in a subject, so they are removed rather than escaped. The provider applies
/// this to every subject, default or overridden, because the sink is a generic port that makes
/// no such promise itself.
fn sanitize_subject(subject: &str) -> String {
    let mut out = String::with_capacity(subject.len());
    let mut in_break = false;
    for ch in subject.chars() {
        if ch == '\r' || ch == '\n' {
            // A run of CR/LF collapses to one space, so `\r\n` does not become two.
            if !in_break {
                out.push(' ');
                in_break = true;
            }
        } else {
            out.push(ch);
            in_break = false;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// What the provider does when the channel rejects a send.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryErrorPolicy {
    /// Log the failure and report success, so a down channel never turns a notification into a
    /// failed user request. The default.
    #[default]
    Swallow,
    /// Log the failure and return it, restoring the error for the two flows that react to one:
    /// the reset path deletes an undelivered token early instead of leaving it to its TTL, and
    /// the email-change path lets a failed verification send surface rather than recording
    /// "sent".
    ///
    /// It does NOT turn a channel outage into a failed user operation elsewhere. Every other
    /// send is already handled by its caller — the MFA and password-changed notices are
    /// detached through `spawn_guarded`, and the invitation flow catches the error and leaves
    /// the invitation standing. So the choice is narrower than it looks: `Rethrow` buys the
    /// cleanup on those two flows, and costs nothing on the rest.
    Rethrow,
}

/// The default [`EmailProvider`] over an [`AuthEmailSink`] delivery channel.
///
/// ```no_run
/// use std::sync::Arc;
/// use bymax_auth_core::traits::{
///     AuthEmailSink, DefaultAuthEmailProvider, EmailError, OutgoingEmail,
/// };
///
/// struct MySink;
///
/// #[async_trait::async_trait]
/// impl AuthEmailSink for MySink {
///     async fn send(&self, message: OutgoingEmail<'_>) -> Result<(), EmailError> {
///         println!("to {} for tenant {}", message.to, message.tenant_id);
///         Ok(())
///     }
/// }
///
/// let provider = DefaultAuthEmailProvider::new(Arc::new(MySink));
/// ```
///
/// No method fails on a delivery failure by default — the engine awaits some of these calls
/// (sending an invitation, confirming an address change), so a channel that is down would turn
/// each into a failed request over a message that is a notification rather than the operation
/// itself. The failure is logged and the flow continues.
///
/// That choice has a cost worth stating, because two flows react to an `Err` from the port. A
/// reset-token send that fails lets the reset flow delete the stored token early rather than
/// leave it to its TTL; and the email-change flow surfaces a failed verification send instead of
/// recording "verification sent". Under the default both degrade gracefully rather than break:
/// the reset token still expires at its TTL and was never delivered to anyone, and the change
/// still requires the verification the recipient never got, so it cannot complete. A deployment
/// that wants the error back on those two flows builds the provider with
/// [`DeliveryErrorPolicy::Rethrow`]. That does not make an outage fail anything else: the other
/// sends are already detached or caught by their callers.
pub struct DefaultAuthEmailProvider {
    /// The channel every message goes out through.
    sink: Arc<dyn AuthEmailSink>,
    /// The copy in effect — the built-in catalogue unless one was supplied.
    messages: Arc<dyn AuthEmailCatalogue>,
    /// What a rejected send does after it is logged.
    on_delivery_error: DeliveryErrorPolicy,
}

impl std::fmt::Debug for DefaultAuthEmailProvider {
    /// Names the type and the delivery policy; the sink and catalogue are host-supplied trait
    /// objects with no `Debug` bound and nothing display-safe to add.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultAuthEmailProvider")
            .field("on_delivery_error", &self.on_delivery_error)
            .finish_non_exhaustive()
    }
}

impl DefaultAuthEmailProvider {
    /// Build the provider over `sink` with the built-in copy and the swallow-and-log policy.
    #[must_use]
    pub fn new(sink: Arc<dyn AuthEmailSink>) -> Self {
        Self {
            sink,
            messages: Arc::new(DefaultAuthEmailCatalogue),
            on_delivery_error: DeliveryErrorPolicy::Swallow,
        }
    }

    /// Replace the copy with a product's own catalogue.
    #[must_use]
    pub fn with_catalogue(mut self, messages: Arc<dyn AuthEmailCatalogue>) -> Self {
        self.messages = messages;
        self
    }

    /// Choose what a rejected send does after it is logged.
    #[must_use]
    pub fn with_delivery_error_policy(mut self, policy: DeliveryErrorPolicy) -> Self {
        self.on_delivery_error = policy;
        self
    }

    /// Render the body to HTML (unless the message carries its own), hand the message to the
    /// channel, and apply the configured failure policy.
    ///
    /// `event` is a library-owned constant naming which message this was — never anything the
    /// catalogue produced. It is the only identifying thing that reaches a log line here; see
    /// the failure arm for why.
    async fn deliver(
        &self,
        event: &'static str,
        tenant_id: &str,
        to: &str,
        message: AuthEmailMessage,
    ) -> Result<(), EmailError> {
        // Stripped once, then used for both the header and the log line: a subject is a single
        // header, and a smuggled CR/LF must reach neither the channel (header injection) nor
        // the logger.
        let subject = sanitize_subject(&message.subject);
        // Borrowed when the renderer supplied its own HTML, owned only when one has to be
        // built: a body is the largest thing on this path and there is no reason to copy one.
        let html: Cow<'_, str> = message
            .html
            .as_deref()
            .map_or_else(|| Cow::Owned(to_html(&message.text)), Cow::Borrowed);
        let outcome = self
            .sink
            .send(OutgoingEmail {
                tenant_id,
                to,
                subject: &subject,
                html: &html,
                text: &message.text,
            })
            .await;
        match outcome {
            Ok(()) => Ok(()),
            Err(error) => {
                // A library-owned event name, never the rendered subject.
                //
                // The subject is catalogue-produced, and the catalogue is the host's. Putting the
                // code in the subject is an ordinary product decision — "123456 is your
                // verification code" is what shows in a phone's notification preview, and plenty
                // of products write it that way — so a host doing something entirely reasonable
                // would have had this line copy their OTP into a log pipeline. That the port's
                // contract forbids logging codes does not help: the code that writes the line is
                // this one, not theirs, and a rule nobody can see being broken is not a control.
                //
                // The constant is also the better field for the reader. It is stable across a
                // reworded subject and across locales, so an alert keys off it once, where
                // matching on product copy silently stops firing the day marketing edits it.
                //
                // The address stays out for its own reason: a log line reaches a wider audience
                // than the inbox it was going to. The error is the channel's, not the body.
                tracing::error!(%error, event, "auth email: delivery failed");
                // Log first, then honour the configured policy: a deployment on `Rethrow` wants
                // the failure to reach the caller that reacts to it, not to be absorbed here.
                match self.on_delivery_error {
                    DeliveryErrorPolicy::Swallow => Ok(()),
                    DeliveryErrorPolicy::Rethrow => Err(error),
                }
            }
        }
    }
}

#[async_trait]
impl EmailProvider for DefaultAuthEmailProvider {
    async fn send_password_reset_token(
        &self,
        tenant_id: &str,
        email: &str,
        token: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "password_reset_token",
            tenant_id,
            email,
            self.messages.password_reset_token(token, locale),
        )
        .await
    }

    async fn send_password_reset_otp(
        &self,
        tenant_id: &str,
        email: &str,
        otp: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "password_reset_otp",
            tenant_id,
            email,
            self.messages.password_reset_otp(otp, locale),
        )
        .await
    }

    async fn send_email_verification_otp(
        &self,
        tenant_id: &str,
        email: &str,
        otp: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "email_verification_otp",
            tenant_id,
            email,
            self.messages.email_verification_otp(otp, locale),
        )
        .await
    }

    async fn send_password_changed(
        &self,
        tenant_id: &str,
        email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "password_changed",
            tenant_id,
            email,
            self.messages.password_changed(locale),
        )
        .await
    }

    async fn send_email_change_verification(
        &self,
        tenant_id: &str,
        new_email: &str,
        token: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "email_change_verification",
            tenant_id,
            new_email,
            self.messages.email_change_verification(token, locale),
        )
        .await
    }

    async fn send_email_changed_notification(
        &self,
        tenant_id: &str,
        old_email: &str,
        new_email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        // Addressed to the OLD address: it is the one the owner still reads if someone else
        // moved the account's, and telling the new address that it is the new address warns
        // nobody.
        self.deliver(
            "email_changed",
            tenant_id,
            old_email,
            self.messages.email_changed(old_email, new_email, locale),
        )
        .await
    }

    async fn send_mfa_enabled(
        &self,
        tenant_id: &str,
        email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "mfa_enabled",
            tenant_id,
            email,
            self.messages.mfa_enabled(locale),
        )
        .await
    }

    async fn send_mfa_disabled(
        &self,
        tenant_id: &str,
        email: &str,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "mfa_disabled",
            tenant_id,
            email,
            self.messages.mfa_disabled(locale),
        )
        .await
    }

    async fn send_new_session_alert(
        &self,
        tenant_id: &str,
        email: &str,
        session: &SessionInfo,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "new_session_alert",
            tenant_id,
            email,
            self.messages.new_session_alert(session, locale),
        )
        .await
    }

    async fn send_invitation(
        &self,
        tenant_id: &str,
        email: &str,
        invite: &InviteData,
        locale: Option<&str>,
    ) -> Result<(), EmailError> {
        self.deliver(
            "invitation",
            tenant_id,
            email,
            self.messages.invitation(invite, locale),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    /// One message as the sink saw it — an owned copy of [`OutgoingEmail`], since the borrowed
    /// original does not outlive the call.
    #[derive(Clone, Default)]
    struct Recorded {
        tenant_id: String,
        to: String,
        subject: String,
        html: String,
        text: String,
    }

    /// A sink that records every message it was handed, or fails every send.
    struct RecordingSink {
        sent: Mutex<Vec<Recorded>>,
        fail: bool,
    }

    impl RecordingSink {
        fn new(fail: bool) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                fail,
            }
        }

        /// The recorded messages; a poisoned lock (test-only) reads as none rather than panics.
        fn sent(&self) -> Vec<Recorded> {
            self.sent.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }

    #[async_trait]
    impl AuthEmailSink for RecordingSink {
        async fn send(&self, message: OutgoingEmail<'_>) -> Result<(), EmailError> {
            if self.fail {
                return Err(EmailError::Delivery("channel down".into()));
            }
            if let Ok(mut guard) = self.sent.lock() {
                guard.push(Recorded {
                    tenant_id: message.tenant_id.to_owned(),
                    to: message.to.to_owned(),
                    subject: message.subject.to_owned(),
                    html: message.html.to_owned(),
                    text: message.text.to_owned(),
                });
            }
            Ok(())
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

    fn session() -> SessionInfo {
        SessionInfo {
            device: "Chrome on macOS".into(),
            ip: "203.0.113.4".into(),
            session_hash: "deadbeef".into(),
        }
    }

    #[tokio::test]
    async fn every_send_reaches_the_sink_with_the_tenant_and_recipient() {
        // The whole point of the port carrying a tenant is that the channel receives it. All ten
        // methods are exercised so a new one cannot be added without a recipient or an
        // attribution.
        let sink = Arc::new(RecordingSink::new(false));
        let provider = DefaultAuthEmailProvider::new(sink.clone());
        assert!(
            provider
                .send_password_reset_token("t1", "a@x.io", "tok", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_password_reset_otp("t1", "a@x.io", "123456", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_verification_otp("t1", "a@x.io", "123456", Some("pt-BR"))
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_password_changed("t1", "a@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_change_verification("t1", "new@x.io", "tok", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_changed_notification("t1", "old@x.io", "new@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_mfa_enabled("t1", "a@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_mfa_disabled("t1", "a@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_new_session_alert("t1", "a@x.io", &session(), None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_invitation("t1", "a@x.io", &invite(), None)
                .await
                .is_ok()
        );

        let sent = sink.sent();
        assert_eq!(sent.len(), 10, "every method must reach the sink once");
        assert!(sent.iter().all(|m| m.tenant_id == "t1"));
        // The change notice goes to the address being left, not the one being moved to.
        let changed = sent.get(5).cloned().unwrap_or_default();
        assert_eq!(changed.to, "old@x.io");
        assert!(changed.text.contains("new@x.io"));
    }

    #[tokio::test]
    async fn a_delivery_failure_logs_the_event_and_never_the_catalogue_subject() {
        // The subject is the host's, through their catalogue, and putting the code in it is an
        // ordinary product decision — "123456 is your verification code" is what shows in a
        // phone's notification preview. If the failure line logged the subject, a host doing
        // something entirely reasonable would have this library copy their OTP into a log
        // pipeline. The port's no-log contract does not cover it either, because the code
        // writing the line is this library's, not theirs.
        struct CodeInSubject;
        impl AuthEmailCatalogue for CodeInSubject {
            fn email_verification_otp(&self, otp: &str, _locale: Option<&str>) -> AuthEmailMessage {
                AuthEmailMessage::plain(format!("{otp} is your verification code"), "…")
            }
        }

        let provider = DefaultAuthEmailProvider::new(Arc::new(RecordingSink::new(true)))
            .with_catalogue(Arc::new(CodeInSubject));
        // Captured so the event's fields are actually rendered: with no subscriber installed the
        // formatting never runs, which leaves this unfalsifiable from a test.
        let (events, capture) = crate::log_capture::capture_events();
        assert!(
            provider
                .send_email_verification_otp("t1", "user@example.com", "123456", None)
                .await
                .is_ok()
        );
        drop(capture);

        assert!(
            events.contains_at(tracing::Level::ERROR, "auth email: delivery failed"),
            "the delivery failure was not reported at all"
        );
        assert!(
            events.contains("event=email_verification_otp"),
            "the failure line does not name which message failed"
        );
        assert!(
            !events.contains("123456"),
            "the OTP reached a log line through the catalogue's subject"
        );
        assert!(
            !events.contains("user@example.com"),
            "the recipient reached a log line"
        );
    }

    #[tokio::test]
    async fn a_delivery_failure_is_swallowed_by_default_and_returned_on_rethrow() {
        // The default keeps a down channel from failing the user's action; `Rethrow` restores
        // the error for the two flows that clean up when a send fails.
        let sink = Arc::new(RecordingSink::new(true));
        let swallowing = DefaultAuthEmailProvider::new(sink.clone());
        assert!(
            swallowing
                .send_mfa_enabled("t1", "a@x.io", None)
                .await
                .is_ok()
        );

        let rethrowing = DefaultAuthEmailProvider::new(sink)
            .with_delivery_error_policy(DeliveryErrorPolicy::Rethrow);
        assert!(
            rethrowing
                .send_mfa_enabled("t1", "a@x.io", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn caller_chosen_text_cannot_inject_markup_or_a_header() {
        // An inviter's display name and a tenant's name are caller-chosen and reach both the
        // subject (a single header) and the HTML body. Neither may carry their structure.
        let sink = Arc::new(RecordingSink::new(false));
        let provider = DefaultAuthEmailProvider::new(sink.clone());
        let hostile = InviteData {
            inviter_name: "Eve\r\nBcc: attacker@evil.io".into(),
            tenant_name: "<script>alert(1)</script>".into(),
            invite_token: "0".repeat(64),
            expires_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(
            provider
                .send_invitation("t1", "a@x.io", &hostile, None)
                .await
                .is_ok()
        );

        let sent = sink.sent();
        let Recorded { subject, html, .. } = sent.first().cloned().unwrap_or_default();
        assert!(
            !subject.contains('\r') && !subject.contains('\n'),
            "a CR/LF survived into the subject header: {subject:?}"
        );
        assert!(
            !html.contains("<script>"),
            "unescaped markup survived into the HTML body: {html:?}"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_html_renderer_preserves_the_shape_of_the_plain_text() {
        // A blank line separates paragraphs and a single newline is a line break — without the
        // `<br>` the new-session alert's device/IP/session lines would collapse into one, so the
        // HTML would say something the text did not.
        let rendered = to_html("one\ntwo\n\nthree");
        assert_eq!(rendered, "<p>one<br>two</p>\n<p>three</p>");
        assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(sanitize_subject("a\r\nb\nc"), "a b c");
    }

    #[tokio::test]
    async fn an_override_replaces_only_the_copy_it_names() {
        // A catalogue chooses words, never behaviour: the override's own HTML is used verbatim
        // while every unset event keeps the built-in default.
        struct BrandedCatalogue;
        impl AuthEmailCatalogue for BrandedCatalogue {
            fn mfa_enabled(&self, _locale: Option<&str>) -> AuthEmailMessage {
                AuthEmailMessage {
                    subject: "2FA on".into(),
                    text: "Two-factor is on.".into(),
                    html: Some("<a href=\"https://acme.test\">Manage</a>".into()),
                }
            }
        }

        let sink = Arc::new(RecordingSink::new(false));
        let provider =
            DefaultAuthEmailProvider::new(sink.clone()).with_catalogue(Arc::new(BrandedCatalogue));
        assert!(
            provider
                .send_mfa_enabled("t1", "a@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_mfa_disabled("t1", "a@x.io", None)
                .await
                .is_ok()
        );

        let sent = sink.sent();
        let enabled = sent.first().cloned().unwrap_or_default();
        assert_eq!(enabled.subject, "2FA on");
        assert_eq!(enabled.html, "<a href=\"https://acme.test\">Manage</a>");
        let disabled = sent.get(1).cloned().unwrap_or_default();
        assert_eq!(disabled.subject, "Two-factor authentication is off");
    }

    #[test]
    fn a_debug_of_a_message_never_carries_the_body_it_rendered() {
        // A rendered body is where the reset token, the verification OTP and the invitation
        // token actually are — these are the only two types in the module that hold a live
        // credential in the clear. A sink that logs its input at debug, which is exactly what a
        // new adapter does while it is being wired up, must not put those in a log pipeline.
        let token = "9".repeat(64);
        let message = AuthEmailMessage {
            subject: "Reset your password".to_owned(),
            text: format!("Use this token: {token}"),
            html: Some(format!("<p>{token}</p>")),
        };
        let rendered = format!("{message:?}");
        assert!(!rendered.contains(&token), "{rendered}");
        assert!(rendered.contains("[REDACTED]") && rendered.contains("Reset your password"));

        let outgoing = format!(
            "{:?}",
            OutgoingEmail {
                tenant_id: "t1",
                to: "victim@example.com",
                subject: "Reset your password",
                html: &message.text,
                text: &message.text,
            }
        );
        assert!(!outgoing.contains(&token), "{outgoing}");
        assert!(
            !outgoing.contains("victim@example.com"),
            "the recipient reached a log line unmasked: {outgoing}"
        );
        assert!(outgoing.contains("Reset your password"));
    }

    #[test]
    fn an_expiry_is_rendered_in_utc_whatever_offset_it_carries() {
        // The invitee reads one instant, and it has to be the one the token actually expires
        // at. An offset carried through unconverted would state a wall-clock time hours away
        // from when the link stops working — and every component is pinned here, because a
        // month or minute rendered from the wrong field is a plausible message that lies.
        let at = OffsetDateTime::UNIX_EPOCH
            .replace_date(
                time::Date::from_calendar_date(2026, time::Month::November, 3)
                    .unwrap_or(time::Date::MIN),
            )
            .replace_time(time::Time::from_hms(4, 5, 6).unwrap_or(time::Time::MIDNIGHT))
            .to_offset(UtcOffset::from_hms(-3, 0, 0).unwrap_or(UtcOffset::UTC));
        assert_eq!(render_utc_instant(at), "2026-11-03T04:05:06Z");
    }

    #[test]
    fn the_provider_debug_names_the_policy_and_nothing_host_supplied() {
        // A `{:?}` reaches logs, and the sink is the host's own type; the policy is the only
        // field worth printing.
        let rendered = format!(
            "{:?}",
            DefaultAuthEmailProvider::new(Arc::new(RecordingSink::new(false)))
                .with_delivery_error_policy(DeliveryErrorPolicy::Rethrow)
        );
        assert!(rendered.contains("Rethrow"), "{rendered}");
        assert_eq!(DeliveryErrorPolicy::default(), DeliveryErrorPolicy::Swallow);
    }

    #[test]
    fn the_built_in_catalogue_states_every_code_and_warns_on_every_change() {
        // The security shape of the copy, asserted rather than assumed: a message that carries a
        // code states it, and a message announcing a change the user may not have made tells
        // them how to react.
        let c = DefaultAuthEmailCatalogue;
        assert!(c.password_reset_token("TOK", None).text.contains("TOK"));
        assert!(c.password_reset_otp("123456", None).text.contains("123456"));
        assert!(
            c.email_verification_otp("654321", None)
                .text
                .contains("654321")
        );
        assert!(
            c.email_change_verification("TOK", None)
                .text
                .contains("TOK")
        );
        for changed in [
            c.password_changed(None),
            c.mfa_enabled(None),
            c.mfa_disabled(None),
            c.email_changed("old@x.io", "new@x.io", None),
            c.new_session_alert(&session(), None),
        ] {
            assert!(
                changed.text.contains(UNEXPECTED_CHANGE_TEXT),
                "a change notice without the what-to-do line: {:?}",
                changed.subject
            );
        }
        let invitation = c.invitation(&invite(), None);
        assert!(invitation.text.contains(&"0".repeat(64)));
        assert!(invitation.text.contains("1970-01-01T00:00:00Z"));
        assert!(invitation.subject.contains("Acme"));
        // The alert repeats the session facts the recipient needs to recognize it as theirs.
        let alert = c.new_session_alert(&session(), None);
        assert!(alert.text.contains("Chrome on macOS") && alert.text.contains("203.0.113.4"));
    }
}
