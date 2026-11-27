//! A fixture for the workspace invitation tests: an engine with the workspace layer and an
//! invitation store on, one workspace with an owner, an admin and a member, and a mailer that
//! records what it is asked to send (layer: service, test support).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::workspace_support_tests::{
    Fixture, RecordingHooks, acting_member, active, membership, seed_account, workspace,
};
use crate::config::{AuthConfig, Environment};
use crate::engine::{AuthEngine, AuthEngineBuilder};
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaceInvitations,
    InMemoryWorkspaces,
};
use crate::traits::{
    EmailError, EmailProvider, InvitationPlace, InviteData, Publication, PublishOutcome,
    WorkspaceInvitationStore, WorkspaceInviteData,
};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::domain::WorkspaceStatus;
use crate::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use crate::workspace::keys::{invitation_index_id, invitation_record_id, invitation_set_id};

/// What the mailer does with a workspace invitation.
#[derive(Clone, Copy)]
pub(super) enum Mode {
    /// Records it.
    Deliver,
    /// Fails with an error whose text quotes the token, as a relay can.
    RelayQuotesTheToken,
    /// Answers that the provider does not implement the message.
    Unsupported,
}

/// A mailer that records the workspace invitations it is asked to send.
pub(super) struct Mailer {
    sent: Mutex<Vec<(String, String, WorkspaceInviteData)>>,
    mode: Mutex<Mode>,
}

impl Mailer {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            mode: Mutex::new(Mode::Deliver),
        }
    }

    /// Changes what the mailer does from now on.
    pub(super) fn act(&self, mode: Mode) {
        if let Ok(mut slot) = self.mode.lock() {
            *slot = mode;
        }
    }

    /// The messages sent so far: the tenant, the address and what it carried.
    pub(super) fn sent(&self) -> Vec<(String, String, WorkspaceInviteData)> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl EmailProvider for Mailer {
    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _email: &str,
        _invite: &InviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_password_changed(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
    async fn send_email_changed_notification(
        &self,
        _tenant_id: &str,
        _email: &str,
        _new_email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_workspace_invitation(
        &self,
        tenant_id: &str,
        email: &str,
        invite: &WorkspaceInviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        let mode = self.mode.lock().map(|mode| *mode).unwrap_or(Mode::Deliver);
        match mode {
            Mode::Deliver => {
                if let Ok(mut sent) = self.sent.lock() {
                    sent.push((tenant_id.to_owned(), email.to_owned(), invite.clone()));
                }
                Ok(())
            }
            Mode::RelayQuotesTheToken => Err(EmailError::Delivery(
                format!("relay rejected the body: {}", invite.invite_token).into(),
            )),
            Mode::Unsupported => Err(EmailError::Unsupported),
        }
    }
}

/// The engine, its doubles and the three members of `w1` of `t1`.
pub(super) struct Inv {
    pub(super) f: Fixture,
    pub(super) store: Arc<InMemoryWorkspaceInvitations>,
    pub(super) mail: Arc<Mailer>,
    pub(super) owner: WorkspaceMember,
    pub(super) admin: WorkspaceMember,
    pub(super) member: WorkspaceMember,
}

/// The engine over `config`, with or without an invitation store.
fn engine(
    config: AuthConfig,
    store: Option<Arc<dyn WorkspaceInvitationStore>>,
    customize: impl FnOnce(AuthEngineBuilder) -> AuthEngineBuilder,
) -> Option<(Fixture, Arc<Mailer>)> {
    let repo = Arc::new(InMemoryWorkspaces::new());
    let cache = Arc::new(InMemoryMembershipCache::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let hooks = Arc::new(RecordingHooks::default());
    let mail = Arc::new(Mailer::new());
    let mut builder = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(Arc::new(InMemoryStores::new()))
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(cache.clone())
        .email_provider(mail.clone())
        .hooks(hooks.clone());
    if let Some(store) = store {
        builder = builder.workspace_invitation_store(store);
    }
    let engine = customize(builder).build().ok()?;
    let fixture = Fixture {
        engine,
        repo,
        cache,
        users,
        hooks,
    };
    Some((fixture, mail))
}

/// A fixture over `config`: `w1` of `t1` is active, with an owner, an admin and a member.
pub(super) async fn setup(config: AuthConfig) -> Option<Inv> {
    setup_over(config, |store| store).await
}

/// A fixture whose engine reaches the store through `wrap`, which gets the in-memory store the
/// fixture itself reads and seeds, so a test can interpose on what the engine does with it.
pub(super) async fn setup_over(
    config: AuthConfig,
    wrap: impl FnOnce(Arc<InMemoryWorkspaceInvitations>) -> Arc<dyn WorkspaceInvitationStore>,
) -> Option<Inv> {
    setup_customized(config, wrap, |builder| builder).await
}

/// [`setup_over`] with `customize` applied to the engine's builder last, so a test can replace a
/// collaborator the fixture wired.
pub(super) async fn setup_customized(
    config: AuthConfig,
    wrap: impl FnOnce(Arc<InMemoryWorkspaceInvitations>) -> Arc<dyn WorkspaceInvitationStore>,
    customize: impl FnOnce(AuthEngineBuilder) -> AuthEngineBuilder,
) -> Option<Inv> {
    let store = Arc::new(InMemoryWorkspaceInvitations::new());
    let (f, mail) = engine(config, Some(wrap(store.clone())), customize)?;
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    let mut seated = Vec::new();
    for (tick, (email, role)) in (2..).zip([
        ("owner@x.io", "owner"),
        ("admin@x.io", "admin"),
        ("member@x.io", "member"),
    ]) {
        let id = seed_account(&f, "t1", email, false).await;
        f.repo
            .seed_membership(membership(&active("t1", "w1", &id, role), tick));
        seated.push(acting_member("t1", "w1", &id, role));
    }
    let mut seated = seated.into_iter();
    let (owner, admin, member) = (seated.next()?, seated.next()?, seated.next()?);
    Some(Inv {
        f,
        store,
        mail,
        owner,
        admin,
        member,
    })
}

/// A fixture whose engine was given no invitation store.
pub(super) fn without_a_store(config: AuthConfig) -> Option<Fixture> {
    engine(config, None, |builder| builder).map(|(fixture, _)| fixture)
}

/// The place of `email`'s invitation in `t1`'s `w1`.
pub(super) fn place(inv: &Inv, email: &str) -> InvitationPlace {
    let key = inv
        .f
        .engine
        .workspaces()
        .map(|runtime| *runtime.identifier_key)
        .unwrap_or([0; 64]);
    InvitationPlace {
        index_id: invitation_index_id(&key, "t1", "w1", email).unwrap_or_default(),
        set_id: invitation_set_id(&key, "t1", "w1").unwrap_or_default(),
    }
}

/// The record key a token is stored under.
pub(super) fn key_of(token: &str) -> String {
    record_key(&invitation_record_id(token))
}

/// An invitation to seed straight into the store.
pub(super) struct Seeded<'a> {
    pub(super) email: &'a str,
    pub(super) role: &'a str,
    pub(super) inviter: &'a str,
    pub(super) created_at: &'a str,
    pub(super) resends: u64,
}

/// Publishes `seed` under the token `token` and answers the record key.
pub(super) async fn seed(inv: &Inv, token: &str, seed: &Seeded<'_>) -> String {
    let record = InvitationRecord::Member {
        base: InvitationBase {
            email: seed.email.to_owned(),
            role: seed.role.to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: seed.created_at.to_owned(),
            resend_count: seed.resends,
        },
        inviter_user_id: seed.inviter.to_owned(),
    };
    let key = key_of(token);
    let place = place(inv, seed.email);
    let outcome = inv
        .store
        .publish(Publication {
            place: &place,
            record_key: &key,
            record: &record,
            ttl: std::num::NonZeroU64::new(600).unwrap_or(std::num::NonZeroU64::MIN),
            pending_limit: 0,
            expected_key: None,
        })
        .await;
    assert!(
        matches!(outcome, Ok(PublishOutcome::Published)),
        "seeding failed: {outcome:?}"
    );
    key
}

/// Whether `result` is `auth.too_many_requests`.
pub(super) fn is_limited<T>(result: &Result<T, AuthError>) -> bool {
    matches!(result, Err(AuthError::TooManyRequests { .. }))
}

/// Publishes a bootstrap invitation to `email` for the workspace `workspace_id`, which need not
/// exist, under the token `token`; answers the record key.
pub(super) async fn seed_bootstrap(
    inv: &Inv,
    token: &str,
    (email, workspace_id, role): (&str, &str, &str),
) -> String {
    let record = InvitationRecord::Bootstrap {
        base: InvitationBase {
            email: email.to_owned(),
            role: role.to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: workspace_id.to_owned(),
            created_at: "2026-01-01T00:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        workspace_name: "Acme Inc".to_owned(),
    };
    let key = key_of(token);
    let place = place(inv, email);
    let outcome = inv
        .store
        .publish(Publication {
            place: &place,
            record_key: &key,
            record: &record,
            ttl: std::num::NonZeroU64::new(600).unwrap_or(std::num::NonZeroU64::MIN),
            pending_limit: 0,
            expected_key: None,
        })
        .await;
    assert!(
        matches!(outcome, Ok(PublishOutcome::Published)),
        "seeding failed: {outcome:?}"
    );
    key
}
