//! Bootstrap invitations: what issuing and withdrawing one writes, and what accepting one
//! creates or refuses with the token unspent (layer: service, tests).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bymax_auth_types::{AuthError, SafeAuthUser};

use super::PlatformWorkspaceInvitation;
use crate::config::AuthConfig;
use crate::services::auth::test_support::ctx;
use crate::services::workspace_invitations::{
    AcceptedWorkspaceInvitation, WorkspaceSignup, WorkspaceSignupInput,
};
use crate::services::workspace_invitations_support_tests::{
    Inv, Mode, Seeded, key_of, place, place_in, seed, seed_bootstrap, setup, setup_customized,
    setup_over, without_a_store,
};
use crate::services::workspace_support_tests::{
    active, config, membership, seed_account, workspace,
};
use crate::testing::InMemoryWorkspaceInvitations;
use crate::traits::workspace_invitation_store::{IndexedInvitation, PendingInvitation, Removal};
use crate::traits::{
    AuthHooks, BeforeWorkspaceCreateResult, HookContext, HookError, HookPlane, InvitationPlace,
    Publication, PublishOutcome, WorkspaceInvitationStore, WorkspaceInviteKind,
    WorkspaceRepository,
};
use crate::workspace::audit::AuditKind;
use crate::workspace::domain::{
    MembershipRef, MembershipStatus, Workspace, WorkspaceRef, WorkspaceStatus,
};
use crate::workspace::invitation::InvitationRecord;

const TOKEN: &str = "bootstrap-token";
const JOE: &str = "joe@x.io";
const GOOD_PASSWORD: &str = "marmaladeorbit77";
/// The id the seeded bootstrap record reserves.
const NEW: &str = "w9";

/// The context a host hands a platform call.
fn host_ctx() -> HookContext {
    HookContext::from_request(
        HookPlane::Platform,
        &ctx(),
        None,
        None,
        Some("t1".to_owned()),
    )
}

fn platform_input(email: &str, name: &str) -> PlatformWorkspaceInvitation {
    PlatformWorkspaceInvitation {
        tenant_id: "t1".to_owned(),
        email: email.to_owned(),
        workspace_name: name.to_owned(),
        inviter_name: "The Platform".to_owned(),
    }
}

async fn issue(inv: &Inv, email: &str, name: &str) -> Result<String, AuthError> {
    let input = platform_input(email, name);
    inv.f
        .engine
        .invite_workspace_as_platform(input, &host_ctx())
        .await
}

async fn withdraw(inv: &Inv, workspace_id: &str, email: &str) -> Result<(), AuthError> {
    let workspace = WorkspaceRef {
        tenant_id: "t1",
        workspace_id,
    };
    inv.f
        .engine
        .revoke_workspace_invitation_as_platform(workspace, email, &host_ctx())
        .await
}

/// The token of the `index`-th message mailed.
fn mailed_token(inv: &Inv, index: usize) -> String {
    let sent = inv.mail.sent();
    sent.get(index)
        .map(|(_, _, data)| data.invite_token.clone())
        .unwrap_or_default()
}

async fn accept(inv: &Inv, user: &str) -> Result<AcceptedWorkspaceInvitation, AuthError> {
    inv.f
        .engine
        .accept_workspace_invitation("t1", user, TOKEN, &ctx())
        .await
}

async fn signup(inv: &Inv) -> Result<WorkspaceSignup, AuthError> {
    let input = WorkspaceSignupInput {
        token: TOKEN.to_owned(),
        name: "Joe Doe".to_owned(),
        password: GOOD_PASSWORD.to_owned(),
    };
    inv.f
        .engine
        .accept_workspace_invitation_signup(input, "203.0.113.4", "agent/1.0", BTreeMap::new())
        .await
}

/// A fixture with a verified account of [`JOE`] holding a bootstrap invitation under [`TOKEN`].
async fn invited(config: AuthConfig) -> (Inv, String) {
    let Some(inv) = setup(config).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    seed_bootstrap(&inv, TOKEN, (JOE, NEW, "owner")).await;
    (inv, joe)
}

async fn unspent(inv: &Inv) -> bool {
    let record = inv.store.read_record(&key_of(TOKEN)).await;
    let index = inv.store.read_index(&place_in(inv, NEW, JOE)).await;
    matches!((record, index), (Ok(Some(_)), Ok(Some(_))))
}

async fn found(inv: &Inv, workspace_id: &str) -> Option<Workspace> {
    let workspace = WorkspaceRef {
        tenant_id: "t1",
        workspace_id,
    };
    inv.f.repo.find_by_id(workspace).await.ok().flatten()
}

fn seat(inv: &Inv, workspace_id: &str, user: &str) -> Option<(String, MembershipStatus)> {
    let member = MembershipRef {
        tenant_id: "t1",
        workspace_id,
        user_id: user,
    };
    inv.f.repo.membership(member).map(|m| (m.role, m.status))
}

fn owner_of_the_new_workspace() -> AcceptedWorkspaceInvitation {
    AcceptedWorkspaceInvitation {
        workspace_id: NEW.to_owned(),
        role: "owner".to_owned(),
    }
}

#[tokio::test]
async fn issuing_publishes_a_bootstrap_record_mails_the_token_and_reports_it() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };

    let Ok(id) = issue(&inv, " Joe@X.io ", "  Acme Inc  ").await else {
        unreachable!("the invitation is issued");
    };

    assert_eq!(id.len(), 36, "{id}");
    assert!(found(&inv, &id).await.is_none(), "nothing is created yet");
    let sent = inv.mail.sent();
    let Some((tenant, to, data)) = sent.first() else {
        unreachable!("one message is mailed");
    };
    assert_eq!((tenant.as_str(), to.as_str()), ("t1", JOE));
    assert_eq!(data.kind, WorkspaceInviteKind::Bootstrap);
    assert_eq!((data.role.as_str(), data.account_exists), ("owner", false));
    assert_eq!(data.workspace_name, "Acme Inc");
    assert_eq!(data.inviter_name, "The Platform");
    let record = inv.store.read_record(&key_of(&data.invite_token)).await;
    let Ok(Some(InvitationRecord::Bootstrap {
        base,
        workspace_name,
    })) = record
    else {
        unreachable!("a bootstrap record is published: {record:?}");
    };
    assert_eq!(workspace_name, "Acme Inc");
    assert_eq!((base.email.as_str(), base.role.as_str()), (JOE, "owner"));
    assert_eq!(
        (base.workspace_id.as_str(), base.resend_count),
        (id.as_str(), 0)
    );
    let events = inv.f.hooks.events(1).await;
    let expected = AuditKind::MemberInvited {
        email: JOE.to_owned(),
        role: "owner".to_owned(),
    };
    let first = events.first();
    assert_eq!(first.map(|e| &e.kind), Some(&expected));
    assert_eq!(first.map(|e| e.actor_user_id.clone()), Some(None));
    assert_eq!(first.map(|e| e.workspace_id.clone()), Some(id));
    assert_eq!(first.map(|e| e.at.clone()), Some(base.created_at));
}

#[tokio::test]
async fn each_issue_is_its_own_invitation_and_says_whether_the_address_has_an_account() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let first = issue(&inv, JOE, "Acme").await;
    seed_account(&inv.f, "t1", JOE, false).await;
    let second = issue(&inv, JOE, "Acme").await;

    let (Ok(first), Ok(second)) = (first, second) else {
        unreachable!("both are issued");
    };
    assert_ne!(first, second);
    for index in [0, 1] {
        let key = key_of(&mailed_token(&inv, index));
        let record = inv.store.read_record(&key).await;
        assert!(matches!(record, Ok(Some(_))), "{index}");
    }
    let known: Vec<bool> = inv.mail.sent().iter().map(|s| s.2.account_exists).collect();
    assert_eq!(known, [false, true]);
}

#[tokio::test]
async fn an_unusable_workspace_name_is_refused_before_anything_is_mailed() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    for name in ["   ", "line\nbreak"] {
        let refused = issue(&inv, JOE, name).await;
        assert!(
            matches!(refused, Err(AuthError::Validation { .. })),
            "{refused:?}"
        );
    }
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn a_failed_delivery_fails_the_issue_without_quoting_the_relay() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    inv.mail.act(Mode::RelayQuotesTheToken);
    let failed = issue(&inv, JOE, "Acme").await;
    assert!(matches!(failed, Err(AuthError::Internal(_))), "{failed:?}");
    assert!(inv.f.hooks.events(0).await.is_empty());
}

#[tokio::test]
async fn withdrawing_removes_the_bootstrap_invitation_and_reports_it_once() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let Ok(id) = issue(&inv, JOE, "Acme").await else {
        unreachable!("the invitation is issued");
    };
    let key = key_of(&mailed_token(&inv, 0));

    assert!(withdraw(&inv, &id, " Joe@X.io ").await.is_ok());

    assert!(matches!(inv.store.read_record(&key).await, Ok(None)));
    let place = place_in(&inv, &id, JOE);
    assert!(matches!(inv.store.read_index(&place).await, Ok(None)));
    let events = inv.f.hooks.events(2).await;
    let expected = AuditKind::InvitationRevoked {
        email: JOE.to_owned(),
        role: "owner".to_owned(),
    };
    let revoked = events.iter().find(|e| e.kind == expected);
    assert_eq!(revoked.map(|e| e.actor_user_id.clone()), Some(None));
    assert!(withdraw(&inv, &id, JOE).await.is_ok());
    assert_eq!(inv.f.hooks.events(0).await.len(), 2);
}

#[tokio::test]
async fn withdrawing_leaves_a_member_invitation_alone() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let seeded = Seeded {
        email: JOE,
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: "2026-01-01T00:00:00.000Z",
        resends: 0,
    };
    let key = seed(&inv, TOKEN, &seeded).await;

    assert!(withdraw(&inv, "w1", JOE).await.is_ok());

    assert!(matches!(inv.store.read_record(&key).await, Ok(Some(_))));
    let index = inv.store.read_index(&place(&inv, JOE)).await;
    assert!(matches!(index, Ok(Some(_))));
    assert!(inv.f.hooks.events(0).await.is_empty());
}

/// The in-memory store, answering that every removal found the index moved, and, unless
/// `publishes`, that every publication did too.
struct Contended {
    store: Arc<InMemoryWorkspaceInvitations>,
    publishes: bool,
}

#[async_trait]
impl WorkspaceInvitationStore for Contended {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        self.store.read_record(record_key).await
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        self.store.read_index(place).await
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        if !self.publishes {
            return Ok(PublishOutcome::Lost);
        }
        self.store.publish(publication).await
    }

    async fn remove(
        &self,
        _place: &InvitationPlace,
        _record_key: &str,
        _removal: Removal,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        self.store.pending(place).await
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        self.store.count_inviter(rate_id).await
    }
}

#[tokio::test]
async fn a_publication_that_does_not_land_mails_nothing() {
    let wrap = |store| -> Arc<dyn WorkspaceInvitationStore> {
        Arc::new(Contended {
            store,
            publishes: false,
        })
    };
    let Some(inv) = setup_over(config(), wrap).await else {
        unreachable!("the fixture builds");
    };

    let refused = issue(&inv, JOE, "Acme").await;

    assert!(
        matches!(refused, Err(AuthError::TooManyRequests { .. })),
        "{refused:?}"
    );
    assert!(inv.mail.sent().is_empty());
    assert!(inv.f.hooks.events(0).await.is_empty());
}

#[tokio::test]
async fn a_withdrawal_that_keeps_losing_the_index_asks_for_a_retry() {
    let wrap = |store| -> Arc<dyn WorkspaceInvitationStore> {
        Arc::new(Contended {
            store,
            publishes: true,
        })
    };
    let Some(inv) = setup_over(config(), wrap).await else {
        unreachable!("the fixture builds");
    };
    let Ok(id) = issue(&inv, JOE, "Acme").await else {
        unreachable!("the invitation is issued");
    };
    let refused = withdraw(&inv, &id, JOE).await;
    assert!(
        matches!(refused, Err(AuthError::TooManyRequests { .. })),
        "{refused:?}"
    );
}

#[tokio::test]
async fn accepting_creates_the_workspace_with_the_caller_as_its_owner() {
    let mut config = config();
    config.workspaces.allow_create = false;
    let (inv, joe) = invited(config).await;

    let accepted = accept(&inv, &joe).await;

    assert_eq!(accepted.ok(), Some(owner_of_the_new_workspace()));
    let created = found(&inv, NEW).await.map(|w| (w.name, w.status));
    let expected = ("Acme Inc".to_owned(), WorkspaceStatus::Active);
    assert_eq!(created, Some(expected));
    let active_owner = ("owner".to_owned(), MembershipStatus::Active);
    assert_eq!(seat(&inv, NEW, &joe), Some(active_owner));
    assert!(!unspent(&inv).await);
    let events = inv.f.hooks.events(1).await;
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.type_name()).collect();
    assert_eq!(kinds, ["invitation.accepted"]);
}

/// Hooks that refuse every workspace with the reason they hold, and count the sign-ups they were
/// told about.
struct Refusing(Option<String>);

#[async_trait]
impl AuthHooks for Refusing {
    async fn before_workspace_create(
        &self,
        _user: &SafeAuthUser,
        _name: &str,
        _ctx: &HookContext,
    ) -> Result<BeforeWorkspaceCreateResult, HookError> {
        Ok(BeforeWorkspaceCreateResult::Reject {
            reason: self.0.clone(),
        })
    }
}

/// [`invited`] over an engine whose host refuses every workspace with `reason`.
async fn invited_refusing(reason: Option<String>) -> (Inv, String) {
    let customize =
        |builder: crate::engine::AuthEngineBuilder| builder.hooks(Arc::new(Refusing(reason)));
    let Some(inv) = setup_customized(config(), |store| store, customize).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    seed_bootstrap(&inv, TOKEN, (JOE, NEW, "owner")).await;
    (inv, joe)
}

#[tokio::test]
async fn a_host_refusal_creates_nothing_and_leaves_the_token_unspent() {
    for (reason, shown) in [
        (Some("over quota".to_owned()), "over quota"),
        (None, "Workspace creation was refused"),
    ] {
        let (inv, joe) = invited_refusing(reason).await;
        let refused = accept(&inv, &joe).await;
        let Err(AuthError::ForbiddenWithDetails(details)) = refused else {
            unreachable!("the host refused: {refused:?}");
        };
        let detail = details
            .first()
            .map(|d| (d.field.as_str(), d.message.as_str()));
        assert_eq!(detail, Some(("name", shown)));
        assert!(found(&inv, NEW).await.is_none());
        assert!(unspent(&inv).await);
    }
}

#[tokio::test]
async fn a_signup_refused_at_creation_keeps_the_account_and_the_token() {
    let customize =
        |builder: crate::engine::AuthEngineBuilder| builder.hooks(Arc::new(Refusing(None)));
    let Some(inv) = setup_customized(config(), |store| store, customize).await else {
        unreachable!("the fixture builds");
    };
    seed_bootstrap(&inv, TOKEN, (JOE, NEW, "owner")).await;

    let refused = signup(&inv).await;

    assert!(
        matches!(refused, Err(AuthError::ForbiddenWithDetails(_))),
        "{:?}",
        refused.err()
    );
    let account = inv.f.engine.find_account("t1", JOE).await;
    assert!(matches!(account, Ok(Some(_))));
    assert!(found(&inv, NEW).await.is_none());
    assert!(unspent(&inv).await);
}

/// Seats `joe` as the owner of `w2`.
fn owning_w2(inv: &Inv, joe: &str) {
    inv.f
        .repo
        .seed_workspace(workspace("t1", "w2", WorkspaceStatus::Active, 3));
    inv.f
        .repo
        .seed_membership(membership(&active("t1", "w2", joe, "owner"), 4));
}

#[tokio::test]
async fn the_owner_cap_refuses_the_acceptance_with_the_token_unspent() {
    let mut config = config();
    config.workspaces.max_workspaces_per_user = 1;
    let (inv, joe) = invited(config).await;
    owning_w2(&inv, &joe);

    let refused = accept(&inv, &joe).await;

    assert!(
        matches!(refused, Err(AuthError::WorkspaceLimitReached)),
        "{refused:?}"
    );
    assert!(found(&inv, NEW).await.is_none());
    assert!(unspent(&inv).await);
}

/// Seeds the reserved workspace in `status` with `user` seated as `role`.
fn already_created(inv: &Inv, status: WorkspaceStatus, user: &str, role: &str) {
    inv.f.repo.seed_workspace(workspace("t1", NEW, status, 5));
    inv.f
        .repo
        .seed_membership(membership(&active("t1", NEW, user, role), 6));
}

#[tokio::test]
async fn a_retry_that_finds_its_own_workspace_succeeds_without_the_cap() {
    let mut config = config();
    config.workspaces.max_workspaces_per_user = 1;
    let (inv, joe) = invited(config).await;
    already_created(&inv, WorkspaceStatus::Active, &joe, "owner");

    let accepted = accept(&inv, &joe).await;

    assert_eq!(accepted.ok(), Some(owner_of_the_new_workspace()));
    assert!(!unspent(&inv).await);
}

/// How one case arranges the repository before the acceptance.
type Prepare<'a> = &'a dyn Fn(&Inv, &str);

#[tokio::test]
async fn an_existing_workspace_the_caller_does_not_actively_own_is_not_joined() {
    let other = |inv: &Inv, _: &str| {
        let owner = inv.owner.user_id.clone();
        already_created(inv, WorkspaceStatus::Active, &owner, "owner");
    };
    let lesser = |inv: &Inv, joe: &str| already_created(inv, WorkspaceStatus::Active, joe, "admin");
    let suspended = |inv: &Inv, joe: &str| {
        already_created(inv, WorkspaceStatus::Active, joe, "owner");
        let mut held = membership(&active("t1", NEW, joe, "owner"), 6);
        held.status = MembershipStatus::Suspended;
        inv.f.repo.seed_membership(held);
    };
    let deleting = |inv: &Inv, joe: &str| {
        already_created(inv, WorkspaceStatus::PendingDeletion, joe, "owner");
    };
    let cases: [Prepare<'_>; 4] = [&other, &lesser, &suspended, &deleting];
    for (index, prepare) in cases.into_iter().enumerate() {
        let (inv, joe) = invited(config()).await;
        prepare(&inv, &joe);
        let refused = accept(&inv, &joe).await;
        assert!(
            matches!(refused, Err(AuthError::InvalidInvitationToken)),
            "{index}: {refused:?}"
        );
        assert!(unspent(&inv).await, "{index}");
    }
}

#[tokio::test]
async fn a_bootstrap_record_granting_another_role_is_an_invalid_token() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    seed_bootstrap(&inv, TOKEN, (JOE, NEW, "admin")).await;
    let refused = accept(&inv, &joe).await;
    assert!(matches!(refused, Err(AuthError::InvalidInvitationToken)));
    assert!(found(&inv, NEW).await.is_none());
    assert!(unspent(&inv).await);
}

#[tokio::test]
async fn a_signup_creates_the_account_and_the_workspace_it_owns() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    seed_bootstrap(&inv, TOKEN, (JOE, NEW, "owner")).await;

    let Ok(done) = signup(&inv).await else {
        unreachable!("the signup is accepted");
    };

    assert_eq!(done.accepted, owner_of_the_new_workspace());
    let active_owner = ("owner".to_owned(), MembershipStatus::Active);
    assert_eq!(seat(&inv, NEW, &done.result.user.id), Some(active_owner));
    assert!(!unspent(&inv).await);
}

#[tokio::test]
async fn platform_invitations_need_the_invitation_store() {
    let Some(f) = without_a_store(config()) else {
        unreachable!("the fixture builds");
    };
    let issued = f
        .engine
        .invite_workspace_as_platform(platform_input(JOE, "Acme"), &host_ctx())
        .await;
    assert!(matches!(issued, Err(AuthError::Internal(_))));
    let workspace = WorkspaceRef {
        tenant_id: "t1",
        workspace_id: NEW,
    };
    let withdrawn = f
        .engine
        .revoke_workspace_invitation_as_platform(workspace, JOE, &host_ctx())
        .await;
    assert!(matches!(withdrawn, Err(AuthError::Internal(_))));
}
