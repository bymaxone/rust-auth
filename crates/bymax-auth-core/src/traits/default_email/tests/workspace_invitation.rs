//! The built-in workspace-invitation message: who sent it, what it offers, and the one sentence
//! that tells an existing account from a new one, in the words nest-auth's default provider uses.
//!
//! Layer: unit tests of `DefaultAuthEmailProvider`, sharing the fixtures of the parent test module.

use super::*;
use crate::traits::email::{WorkspaceInviteData, WorkspaceInviteKind};

fn data(kind: WorkspaceInviteKind, inviter: &str, account_exists: bool) -> WorkspaceInviteData {
    WorkspaceInviteData::new(
        inviter.into(),
        "Acme".into(),
        "admin".into(),
        "a".repeat(64),
        OffsetDateTime::UNIX_EPOCH,
        account_exists,
        kind,
    )
}

/// The one message the sink received for `invite`.
async fn sent_for(invite: &WorkspaceInviteData) -> Recorded {
    let sink = Arc::new(RecordingSink::new(false));
    let provider = DefaultAuthEmailProvider::new(sink.clone());
    let result = provider
        .send_workspace_invitation("t1", "new@x.io", invite, None)
        .await;
    assert!(result.is_ok(), "{result:?}");
    let sent = sink.sent();
    assert_eq!(sent.len(), 1);
    sent.first().cloned().unwrap_or_default()
}

#[tokio::test]
async fn a_member_invitation_names_the_inviter_the_workspace_and_the_role() {
    let message = sent_for(&data(WorkspaceInviteKind::Member, "Owner", false)).await;
    assert_eq!(message.tenant_id, "t1");
    assert_eq!(message.to, "new@x.io");
    assert_eq!(message.subject, "Owner invited you to Acme");
    assert_eq!(
        message.text,
        format!(
            "Owner invited you to the workspace Acme as admin.\n\nCreate your account and use this token to accept: {}\n\nIt expires on 1970-01-01T00:00:00.000Z.\n\nIf you were not expecting this invitation, ignore this message.",
            "a".repeat(64)
        )
    );
}

#[tokio::test]
async fn an_existing_account_is_told_to_sign_in() {
    let message = sent_for(&data(WorkspaceInviteKind::Member, "Owner", true)).await;
    assert!(
        message
            .text
            .contains("Sign in and use this token to accept:")
    );
    assert!(!message.text.contains("Create your account"));
}

#[tokio::test]
async fn a_bootstrap_invitation_offers_ownership_and_names_no_blank_inviter() {
    let named = sent_for(&data(WorkspaceInviteKind::Bootstrap, "Ada", false)).await;
    assert_eq!(named.subject, "Ada invited you to set up Acme");
    assert!(
        named
            .text
            .starts_with("Ada invited you to set up the workspace Acme as its owner.")
    );

    let unnamed = sent_for(&data(WorkspaceInviteKind::Bootstrap, "  ", false)).await;
    assert_eq!(unnamed.subject, "You have been invited to set up Acme");
    assert!(
        unnamed
            .text
            .starts_with("You have been invited to set up the workspace Acme as its owner.")
    );
}

#[tokio::test]
async fn markup_in_a_name_reaches_the_html_part_escaped() {
    let message = sent_for(&data(WorkspaceInviteKind::Member, "<b>Eve</b>", false)).await;
    assert!(
        message.html.contains("&lt;b&gt;Eve&lt;/b&gt;"),
        "{}",
        message.html
    );
    assert!(!message.html.contains("<b>"), "{}", message.html);
}

#[tokio::test]
async fn the_catalogue_is_handed_the_tenant_the_address_and_the_locale() {
    struct Seen(Mutex<Vec<(String, String, Option<String>)>>);
    impl AuthEmailCatalogue for Seen {
        fn workspace_invitation(
            &self,
            ctx: &AuthEmailContext<'_>,
            _invite: &WorkspaceInviteData,
        ) -> AuthEmailMessage {
            if let Ok(mut seen) = self.0.lock() {
                seen.push((
                    ctx.tenant_id.to_owned(),
                    ctx.email.to_owned(),
                    ctx.locale.map(str::to_owned),
                ));
            }
            AuthEmailMessage::plain("s", "b")
        }
    }
    let seen = Arc::new(Seen(Mutex::new(Vec::new())));
    let provider = DefaultAuthEmailProvider::new(Arc::new(RecordingSink::new(false)))
        .with_catalogue(seen.clone());
    let invite = data(WorkspaceInviteKind::Member, "Owner", false);
    let result = provider
        .send_workspace_invitation("t9", "x@y.io", &invite, Some("pt-BR"))
        .await;
    assert!(result.is_ok());
    let recorded = seen.0.lock().map(|g| g.clone()).unwrap_or_default();
    assert_eq!(
        recorded,
        vec![(
            "t9".to_owned(),
            "x@y.io".to_owned(),
            Some("pt-BR".to_owned())
        )]
    );
}

#[tokio::test]
async fn a_blank_inviter_is_what_the_shared_whitespace_rule_calls_blank() {
    // U+FEFF is whitespace to JavaScript and U+0085 is not, so the same name picks the same
    // sentence as the nest-auth message.
    let blank = sent_for(&data(WorkspaceInviteKind::Bootstrap, "\u{feff}", false)).await;
    assert_eq!(blank.subject, "You have been invited to set up Acme");

    let next_line = sent_for(&data(WorkspaceInviteKind::Bootstrap, "\u{85}", false)).await;
    assert_eq!(next_line.subject, "\u{85} invited you to set up Acme");
}
