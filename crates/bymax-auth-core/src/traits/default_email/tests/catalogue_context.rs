//! Every renderer of the catalogue is told the tenant, the delivery address and the locale, together
//! with its own fields. `email` is the delivery address: the NEW address for the address-change
//! code, the PREVIOUS one for the "your address changed" notice.
//!
//! Layer: unit tests of `DefaultAuthEmailProvider` with a catalogue that records what each of its
//! renderers was handed, sharing the fixtures of the parent test module.

use super::*;

/// What a renderer was handed: its name, the context, and its own fields rendered as text.
type Seen = (String, String, String, Option<String>, String);

/// A catalogue that overrides all ten renderers and records the context each one received.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn note(&self, name: &str, ctx: &AuthEmailContext<'_>, own: String) -> AuthEmailMessage {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((
                name.to_owned(),
                ctx.tenant_id.to_owned(),
                ctx.email.to_owned(),
                ctx.locale.map(str::to_owned),
                own,
            ));
        }
        AuthEmailMessage::plain(name, "body")
    }

    fn only(&self) -> Option<Seen> {
        let seen = self.seen.lock().map(|g| g.clone()).unwrap_or_default();
        (seen.len() == 1).then(|| seen[0].clone())
    }
}

impl AuthEmailCatalogue for Recorder {
    fn password_reset_token(&self, ctx: &AuthEmailContext<'_>, token: &str) -> AuthEmailMessage {
        self.note("password_reset_token", ctx, token.to_owned())
    }
    fn password_reset_otp(&self, ctx: &AuthEmailContext<'_>, otp: &str) -> AuthEmailMessage {
        self.note("password_reset_otp", ctx, otp.to_owned())
    }
    fn email_verification_otp(&self, ctx: &AuthEmailContext<'_>, otp: &str) -> AuthEmailMessage {
        self.note("email_verification_otp", ctx, otp.to_owned())
    }
    fn password_changed(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        self.note("password_changed", ctx, String::new())
    }
    fn email_change_verification(
        &self,
        ctx: &AuthEmailContext<'_>,
        token: &str,
    ) -> AuthEmailMessage {
        self.note("email_change_verification", ctx, token.to_owned())
    }
    fn email_changed(
        &self,
        ctx: &AuthEmailContext<'_>,
        old_email: &str,
        new_email: &str,
    ) -> AuthEmailMessage {
        self.note("email_changed", ctx, format!("{old_email}>{new_email}"))
    }
    fn mfa_enabled(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        self.note("mfa_enabled", ctx, String::new())
    }
    fn mfa_disabled(&self, ctx: &AuthEmailContext<'_>) -> AuthEmailMessage {
        self.note("mfa_disabled", ctx, String::new())
    }
    fn new_session_alert(
        &self,
        ctx: &AuthEmailContext<'_>,
        session: &SessionInfo,
    ) -> AuthEmailMessage {
        self.note("new_session_alert", ctx, session.session_hash.clone())
    }
    fn invitation(&self, ctx: &AuthEmailContext<'_>, invite: &InviteData) -> AuthEmailMessage {
        self.note("invitation", ctx, invite.invite_token.clone())
    }
}

/// A provider over a recording sink, with the recording catalogue installed.
fn provider() -> (DefaultAuthEmailProvider, Arc<Recorder>, Arc<RecordingSink>) {
    let recorder = Arc::new(Recorder::default());
    let sink = Arc::new(RecordingSink::new(false));
    let provider = DefaultAuthEmailProvider::new(sink.clone()).with_catalogue(recorder.clone());
    (provider, recorder, sink)
}

const TENANT: &str = "tenant-9";
const LOCALE: Option<&str> = Some("pt-BR");

/// The one record a send produced, or `None` when it produced none or several.
fn expect(recorder: &Recorder, name: &str, email: &str, own: &str) -> bool {
    recorder.only()
        == Some((
            name.to_owned(),
            TENANT.to_owned(),
            email.to_owned(),
            LOCALE.map(str::to_owned),
            own.to_owned(),
        ))
}

#[tokio::test]
async fn the_password_reset_token_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(
        p.send_password_reset_token(TENANT, "a@x.io", "TOK", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "password_reset_token", "a@x.io", "TOK"));
}

#[tokio::test]
async fn the_password_reset_otp_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(
        p.send_password_reset_otp(TENANT, "a@x.io", "123456", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "password_reset_otp", "a@x.io", "123456"));
}

#[tokio::test]
async fn the_email_verification_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(
        p.send_email_verification_otp(TENANT, "a@x.io", "654321", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "email_verification_otp", "a@x.io", "654321"));
}

#[tokio::test]
async fn the_password_changed_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(
        p.send_password_changed(TENANT, "a@x.io", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "password_changed", "a@x.io", ""));
}

#[tokio::test]
async fn the_address_change_code_is_rendered_for_the_new_address() {
    let (p, r, sink) = provider();
    assert!(
        p.send_email_change_verification(TENANT, "new@x.io", "TOK", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "email_change_verification", "new@x.io", "TOK"));
    assert_eq!(
        sink.sent().first().map(|m| m.to.clone()),
        Some("new@x.io".to_owned())
    );
}

#[tokio::test]
async fn the_address_changed_notice_is_rendered_for_the_previous_address() {
    // The context's `email` is where the notice goes (the previous address); both addresses are
    // also the renderer's own fields.
    let (p, r, sink) = provider();
    assert!(
        p.send_email_changed_notification(TENANT, "old@x.io", "new@x.io", LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "email_changed", "old@x.io", "old@x.io>new@x.io"));
    assert_eq!(
        sink.sent().first().map(|m| m.to.clone()),
        Some("old@x.io".to_owned())
    );
}

#[tokio::test]
async fn the_mfa_enabled_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(p.send_mfa_enabled(TENANT, "a@x.io", LOCALE).await.is_ok());
    assert!(expect(&r, "mfa_enabled", "a@x.io", ""));
}

#[tokio::test]
async fn the_mfa_disabled_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    assert!(p.send_mfa_disabled(TENANT, "a@x.io", LOCALE).await.is_ok());
    assert!(expect(&r, "mfa_disabled", "a@x.io", ""));
}

#[tokio::test]
async fn the_new_session_alert_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    let info = session();
    assert!(
        p.send_new_session_alert(TENANT, "a@x.io", &info, LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(
        &r,
        "new_session_alert",
        "a@x.io",
        &info.session_hash
    ));
}

#[tokio::test]
async fn the_invitation_renderer_gets_the_tenant_and_the_recipient() {
    let (p, r, _) = provider();
    let invite = invite();
    assert!(
        p.send_invitation(TENANT, "a@x.io", &invite, LOCALE)
            .await
            .is_ok()
    );
    assert!(expect(&r, "invitation", "a@x.io", &invite.invite_token));
}

#[tokio::test]
async fn an_absent_locale_reaches_the_renderer_as_none() {
    let (p, r, _) = provider();
    assert!(p.send_mfa_enabled(TENANT, "a@x.io", None).await.is_ok());
    let seen = r.only();
    assert!(matches!(seen, Some((_, _, _, None, _))));
}
