//! A failed invitation send: the caller is told, the stored invitation stays, and nothing the
//! mail channel wrote reaches the error or the log, because a relay can quote the body it
//! rejected and that body carries the raw invitation token.

use std::sync::Mutex;

use super::*;
use crate::traits::email::{InviteData, SessionInfo};
use crate::traits::{EmailError, EmailProvider};

const INVITEE: &str = "unreachable@example.com";

/// A mail channel whose invitation send fails with an error that QUOTES the raw token, the way a
/// relay quoting the rejected body would, and remembers every token it was handed.
#[derive(Default)]
struct RelayDown {
    tokens: Mutex<Vec<String>>,
}

impl RelayDown {
    fn tokens(&self) -> Vec<String> {
        self.tokens
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl EmailProvider for RelayDown {
    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _to: &str,
        data: &InviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        if let Ok(mut seen) = self.tokens.lock() {
            seen.push(data.invite_token.clone());
        }
        let quoted = format!("relay rejected the body: token={}", data.invite_token);
        Err(EmailError::Delivery(Box::new(std::io::Error::other(
            quoted,
        ))))
    }

    async fn send_password_reset_token(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_password_reset_otp(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_email_verification_otp(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_email_change_verification(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_enabled(&self, _: &str, _: &str, _: Option<&str>) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_disabled(&self, _: &str, _: &str, _: Option<&str>) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_new_session_alert(
        &self,
        _: &str,
        _: &str,
        _: &SessionInfo,
        _: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
}

/// An engine over a channel that is down, with one `ADMIN` inviter.
async fn down() -> Option<(AuthEngine, Arc<RelayDown>, String)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let mailer = Arc::new(RelayDown::default());
    let engine = AuthEngine::builder()
        .config(invite_config())
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(Arc::new(InMemoryStores::new()))
        .email_provider(mailer.clone())
        .build()
        .ok()?;
    let admin = seed_admin(&users, "sender@example.com", "ADMIN").await;
    Some((engine, mailer, admin))
}

/// Accept `token`, returning whether the invitation was redeemed.
async fn redeemed(engine: &AuthEngine, token: &str) -> bool {
    let input = AcceptInvitationInput {
        token: token.to_owned(),
        name: "New Member".to_owned(),
        password: "a-strong-password".to_owned(),
    };
    engine
        .accept_invitation(input, "203.0.113.4", "agent/1.0", BTreeMap::new())
        .await
        .is_ok()
}

#[tokio::test]
async fn a_failed_send_is_a_fixed_internal_error_that_quotes_nothing_the_channel_wrote() {
    let Some((engine, mailer, admin)) = down().await else { return };

    let (events, capture) = crate::log_capture::capture_events();
    let outcome = engine.invite(&admin, INVITEE, "MEMBER", "t1", None).await;
    drop(capture);

    let Err(error) = outcome else {
        assert!(outcome.is_err(), "a failed send must be reported");
        return;
    };
    assert!(matches!(error, AuthError::Internal(_)), "{error:?}");
    let tokens = mailer.tokens();
    assert_eq!(tokens.len(), 1, "one send was attempted");
    let token = &tokens[0];
    let chain = crate::services::error_chain(&error);
    assert!(
        !chain.contains(token.as_str()),
        "the error chain quotes the token: {chain}"
    );
    assert!(
        !format!("{error:?}").contains(token.as_str()),
        "the debug form quotes it"
    );
    assert!(
        !events.contains(token.as_str()),
        "a log line quotes the token"
    );
    assert!(
        !events.contains("relay rejected"),
        "a log line carries the channel's text"
    );
    let reported = events
        .iter()
        .into_iter()
        .filter(|event| event.rendered.contains("invitation: delivery failed"))
        .count();
    assert_eq!(reported, 1, "one fixed line for one failure");
}

#[tokio::test]
async fn the_invitation_survives_a_failed_send_and_a_retry_supersedes_it() {
    let Some((engine, mailer, admin)) = down().await else { return };

    let first = engine.invite(&admin, INVITEE, "MEMBER", "t1", None).await;
    let second = engine.invite(&admin, INVITEE, "MEMBER", "t1", None).await;

    assert!(first.is_err() && second.is_err());
    let tokens = mailer.tokens();
    assert_eq!(tokens.len(), 2, "each attempt sent once");
    // The record was kept (the email may have been delivered despite the error), and the retry
    // replaced it, so exactly the latest token is redeemable.
    assert!(
        !redeemed(&engine, &tokens[0]).await,
        "the superseded token must be dead"
    );
    assert!(
        redeemed(&engine, &tokens[1]).await,
        "the latest invitation must stand"
    );
}

#[tokio::test]
async fn the_relay_double_succeeds_at_every_send_but_the_invitation() {
    // The double exists to fail ONE send; its other methods are what make it a valid provider,
    // and a method nothing calls is a method nothing proves.
    let relay = RelayDown::default();
    let session = SessionInfo {
        device: "Chrome".to_owned(),
        ip: "1.2.3.4".to_owned(),
        session_hash: "abcd1234".to_owned(),
    };
    assert!(
        relay
            .send_password_reset_token("t1", "e", "t", None)
            .await
            .is_ok()
    );
    assert!(
        relay
            .send_password_reset_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(
        relay
            .send_email_verification_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(
        relay
            .send_email_change_verification("t1", "e", "t", None)
            .await
            .is_ok()
    );
    assert!(relay.send_mfa_enabled("t1", "e", None).await.is_ok());
    assert!(relay.send_mfa_disabled("t1", "e", None).await.is_ok());
    assert!(
        relay
            .send_new_session_alert("t1", "e", &session, None)
            .await
            .is_ok()
    );
}
