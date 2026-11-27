//! Acceptance of a workspace invitation: what refuses it with the token unspent, what is written
//! and in which order, and what a signup creates (layer: service, tests).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bymax_auth_types::{AuthError, SafeAuthUser};

use super::{AcceptedWorkspaceInvitation, WorkspaceSignup, WorkspaceSignupInput, create_failure};
use crate::config::AuthConfig;
use crate::services::auth::test_support::ctx;
use crate::services::workspace_invitations_support_tests::{
    Inv, Seeded, key_of, place, seed, seed_bootstrap, setup, setup_customized, setup_over,
    without_a_store,
};
use crate::services::workspace_support_tests::{
    active, authorize, config, membership, seed_account,
};
use crate::testing::InMemoryWorkspaceInvitations;
use crate::traits::workspace_invitation_store::{IndexedInvitation, PendingInvitation, Removal};
use crate::traits::{
    AuthHooks, HookContext, HookError, InvitationPlace, PasswordBreachChecker, Publication,
    PublishOutcome, UserRepository, WorkspaceInvitationStore,
};
use crate::workspace::access::AcceptedRoles;
use crate::workspace::audit::AuditKind;
use crate::workspace::domain::{MembershipRef, MembershipStatus, WorkspaceStatus};
use crate::workspace::invitation::InvitationRecord;

const TOKEN: &str = "acceptance-token";
const JOE: &str = "joe@x.io";
const GOOD_PASSWORD: &str = "marmaladeorbit77";
const BREACHED: &str = "breached-passphrase";

/// A live member invitation of `email` to `role`, issued by `inviter`, under [`TOKEN`].
async fn invite(inv: &Inv, email: &str, role: &str, inviter: &str) {
    let seeded = Seeded {
        email,
        role,
        inviter,
        created_at: "2026-01-01T00:00:00.000Z",
        resends: 0,
    };
    seed(inv, TOKEN, &seeded).await;
}

/// A fixture with a verified account of [`JOE`] invited as `member` by the owner.
async fn invited(config: AuthConfig) -> (Inv, String) {
    let Some(inv) = setup(config).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    invite(&inv, JOE, "member", &inv.owner.user_id).await;
    (inv, joe)
}

async fn accept(inv: &Inv, user: &str) -> Result<AcceptedWorkspaceInvitation, AuthError> {
    inv.f
        .engine
        .accept_workspace_invitation("t1", user, TOKEN, &ctx())
        .await
}

async fn signup(inv: &Inv, token: &str, password: &str) -> Result<WorkspaceSignup, AuthError> {
    let input = WorkspaceSignupInput {
        token: token.to_owned(),
        name: "Joe Doe".to_owned(),
        password: password.to_owned(),
    };
    inv.f
        .engine
        .accept_workspace_invitation_signup(input, "203.0.113.4", "agent/1.0", BTreeMap::new())
        .await
}

/// Whether the record under [`TOKEN`] and the address's index are both still there.
async fn unspent(inv: &Inv, email: &str) -> bool {
    let record = inv.store.read_record(&key_of(TOKEN)).await;
    let index = inv.store.read_index(&place(inv, email)).await;
    matches!((record, index), (Ok(Some(_)), Ok(Some(_))))
}

/// Whether neither the record nor the index is there.
async fn spent(inv: &Inv, email: &str) -> bool {
    let record = inv.store.read_record(&key_of(TOKEN)).await;
    let index = inv.store.read_index(&place(inv, email)).await;
    matches!((record, index), (Ok(None), Ok(None)))
}

fn in_w1(user: &str) -> MembershipRef<'_> {
    MembershipRef {
        tenant_id: "t1",
        workspace_id: "w1",
        user_id: user,
    }
}

fn role_in_w1(inv: &Inv, user: &str) -> Option<String> {
    inv.f.repo.membership(in_w1(user)).map(|m| m.role)
}

fn accepted_as(role: &str) -> AcceptedWorkspaceInvitation {
    AcceptedWorkspaceInvitation {
        workspace_id: "w1".to_owned(),
        role: role.to_owned(),
    }
}

#[tokio::test]
async fn accepting_writes_the_membership_spends_the_token_and_reports_it() {
    let (inv, joe) = invited(config()).await;
    let any = AcceptedRoles::AnyMember;
    let before = authorize(&inv.f, ("t1", &joe, "w1"), &any, false).await;
    assert!(before.is_err(), "{before:?}");

    assert_eq!(accept(&inv, &joe).await.ok(), Some(accepted_as("member")));

    let written = inv.f.repo.membership(in_w1(&joe));
    assert_eq!(
        written.and_then(|m| m.invited_by_user_id),
        Some(inv.owner.user_id.clone())
    );
    assert!(spent(&inv, JOE).await);
    let after = authorize(&inv.f, ("t1", &joe, "w1"), &any, false).await;
    assert!(after.is_ok(), "the new member is authorized: {after:?}");
    let operations = inv.f.cache.operations();
    assert!(operations.contains(&"bump_membership"), "{operations:?}");
    let events = inv.f.hooks.events(1).await;
    let expected = AuditKind::InvitationAccepted {
        email: JOE.to_owned(),
        role: "member".to_owned(),
        user_id: joe.clone(),
        lost_consume_race: false,
    };
    assert_eq!(events.first().map(|e| &e.kind), Some(&expected));
    assert_eq!(
        events.first().and_then(|e| e.actor_user_id.clone()),
        Some(joe)
    );
}

#[tokio::test]
async fn a_token_cannot_be_accepted_twice() {
    let (inv, joe) = invited(config()).await;
    assert!(accept(&inv, &joe).await.is_ok());
    let again = accept(&inv, &joe).await;
    assert!(matches!(again, Err(AuthError::InvalidInvitationToken)));
}

#[tokio::test]
async fn the_address_is_compared_in_its_normalized_form() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", "Joe@X.io", false).await;
    invite(&inv, JOE, "member", &inv.owner.user_id).await;
    assert!(accept(&inv, &joe).await.is_ok());
}

#[tokio::test]
async fn a_caller_that_is_not_the_invited_verified_account_is_refused_with_the_token_unspent() {
    let (inv, joe) = invited(config()).await;
    let ann = seed_account(&inv.f, "t1", "ann@x.io", false).await;
    let stranger = seed_account(&inv.f, "t2", JOE, false).await;

    let other_address = accept(&inv, &ann).await;
    assert!(matches!(
        other_address,
        Err(AuthError::InvitationEmailMismatch)
    ));
    let gone = accept(&inv, "nobody").await;
    assert!(matches!(gone, Err(AuthError::TokenInvalid)));
    let other_tenant = inv
        .f
        .engine
        .accept_workspace_invitation("t2", &stranger, TOKEN, &ctx())
        .await;
    assert!(matches!(
        other_tenant,
        Err(AuthError::InvalidInvitationToken)
    ));
    let unverified = inv.f.users.update_email_verified(&joe, "t1", false).await;
    assert!(unverified.is_ok());
    let refused = accept(&inv, &joe).await;
    assert!(matches!(refused, Err(AuthError::EmailNotVerified)));
    assert!(unspent(&inv, JOE).await);
    assert_eq!(role_in_w1(&inv, &ann), None);
    assert_eq!(role_in_w1(&inv, &joe), None);
}

#[tokio::test]
async fn the_address_is_judged_before_verification_and_both_before_the_inviter() {
    let (inv, joe) = invited(config()).await;
    let owner = &inv.owner.user_id;
    let blocked = inv.f.users.update_status(owner, "t1", "BANNED").await;
    assert!(blocked.is_ok());
    let ann = seed_account(&inv.f, "t1", "ann@x.io", false).await;
    assert!(
        inv.f
            .users
            .update_email_verified(&ann, "t1", false)
            .await
            .is_ok()
    );
    let mismatch = accept(&inv, &ann).await;
    assert!(matches!(mismatch, Err(AuthError::InvitationEmailMismatch)));
    assert!(
        inv.f
            .users
            .update_email_verified(&joe, "t1", false)
            .await
            .is_ok()
    );
    let unverified = accept(&inv, &joe).await;
    assert!(matches!(unverified, Err(AuthError::EmailNotVerified)));
    assert!(
        inv.f
            .users
            .update_email_verified(&joe, "t1", true)
            .await
            .is_ok()
    );
    let unbacked = accept(&inv, &joe).await;
    assert!(matches!(unbacked, Err(AuthError::InvalidInvitationToken)));
}

/// What can stop standing behind a member invitation.
#[derive(Debug, Clone, Copy)]
enum Lapse {
    WorkspaceNotActive,
    InviterGone,
    InviterBlocked,
    InviterNotAMember,
    InviterSuspended,
    InviterNoLongerOutranks,
}

/// Seeds an invitation to `admin` whose authority has lapsed as `lapse` says.
async fn lapsed(lapse: Lapse) -> (Inv, String) {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    let mut inviter = inv.owner.user_id.clone();
    match lapse {
        Lapse::WorkspaceNotActive => {
            let row = crate::services::workspace_support_tests::workspace(
                "t1",
                "w1",
                WorkspaceStatus::PendingDeletion,
                1,
            );
            inv.f.repo.seed_workspace(row);
        }
        Lapse::InviterGone => inviter = "nobody".to_owned(),
        Lapse::InviterBlocked => {
            let blocked = inv.f.users.update_status(&inviter, "t1", "BANNED").await;
            assert!(blocked.is_ok());
        }
        Lapse::InviterNotAMember => {
            inviter = seed_account(&inv.f, "t1", "out@x.io", false).await;
        }
        Lapse::InviterSuspended => {
            let mut seat = membership(&active("t1", "w1", &inviter, "owner"), 9);
            seat.status = MembershipStatus::Suspended;
            inv.f.repo.seed_membership(seat);
        }
        // An admin may not grant their own role.
        Lapse::InviterNoLongerOutranks => inviter = inv.admin.user_id.clone(),
    }
    invite(&inv, JOE, "admin", &inviter).await;
    (inv, joe)
}

#[tokio::test]
async fn an_invitation_nobody_stands_behind_answers_as_an_invalid_token_and_stays() {
    for lapse in [
        Lapse::WorkspaceNotActive,
        Lapse::InviterGone,
        Lapse::InviterBlocked,
        Lapse::InviterNotAMember,
        Lapse::InviterSuspended,
        Lapse::InviterNoLongerOutranks,
    ] {
        let (inv, joe) = lapsed(lapse).await;
        let signed_in = accept(&inv, &joe).await;
        assert!(
            matches!(signed_in, Err(AuthError::InvalidInvitationToken)),
            "{lapse:?}: {signed_in:?}"
        );
        let by_signup = signup(&inv, TOKEN, GOOD_PASSWORD).await;
        assert!(
            matches!(by_signup, Err(AuthError::InvalidInvitationToken)),
            "{lapse:?}: signup is judged before the existing account"
        );
        assert!(unspent(&inv, JOE).await, "{lapse:?}");
        assert_eq!(role_in_w1(&inv, &joe), None, "{lapse:?}");
    }
}

#[tokio::test]
async fn a_token_that_names_nothing_usable_is_invalid() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    let unknown = accept(&inv, &joe).await;
    assert!(matches!(unknown, Err(AuthError::InvalidInvitationToken)));
    let by_signup = signup(&inv, TOKEN, GOOD_PASSWORD).await;
    assert!(matches!(by_signup, Err(AuthError::InvalidInvitationToken)));

    invite(&inv, JOE, "superuser", &inv.owner.user_id).await;
    let unknown_role = accept(&inv, &joe).await;
    assert!(matches!(
        unknown_role,
        Err(AuthError::InvalidInvitationToken)
    ));
    assert!(unspent(&inv, JOE).await);
}

#[tokio::test]
async fn a_bootstrap_record_is_not_accepted_and_stays() {
    let Some(inv) = setup(config()).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    seed_bootstrap(&inv, TOKEN, (JOE, "w9", "owner")).await;
    let refused = accept(&inv, &joe).await;
    assert!(matches!(refused, Err(AuthError::InvalidInvitationToken)));
    assert!(unspent(&inv, JOE).await);
}

#[tokio::test]
async fn an_active_member_keeps_their_role_and_the_token_is_spent() {
    let (inv, joe) = invited(config()).await;
    inv.f
        .repo
        .seed_membership(membership(&active("t1", "w1", &joe, "admin"), 9));
    assert_eq!(accept(&inv, &joe).await.ok(), Some(accepted_as("admin")));
    assert_eq!(role_in_w1(&inv, &joe).as_deref(), Some("admin"));
    assert!(spent(&inv, JOE).await);
    let events = inv.f.hooks.events(1).await;
    let role = events.first().and_then(|e| match &e.kind {
        AuditKind::InvitationAccepted { role, .. } => Some(role.clone()),
        _ => None,
    });
    assert_eq!(role.as_deref(), Some("admin"));
}

#[tokio::test]
async fn a_suspended_member_is_not_reinstated_and_the_token_is_unspent() {
    let (inv, joe) = invited(config()).await;
    let mut seat = membership(&active("t1", "w1", &joe, "member"), 9);
    seat.status = MembershipStatus::Suspended;
    inv.f.repo.seed_membership(seat);
    let refused = accept(&inv, &joe).await;
    assert!(matches!(refused, Err(AuthError::InvalidInvitationToken)));
    let kept = inv.f.repo.membership(in_w1(&joe)).map(|m| m.status);
    assert_eq!(kept, Some(MembershipStatus::Suspended));
    assert!(unspent(&inv, JOE).await);
}

/// What the store does when the token is spent.
#[derive(Clone, Copy)]
enum Spend {
    /// Removes, then answers that the index no longer named the record.
    Lost,
    /// Fails the first time, having removed nothing.
    FailsOnce,
}

/// The in-memory store with [`Spend`] applied to its removals.
struct Spending {
    inner: Arc<InMemoryWorkspaceInvitations>,
    spend: Spend,
    calls: AtomicUsize,
}

#[async_trait]
impl WorkspaceInvitationStore for Spending {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        self.inner.read_record(record_key).await
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        self.inner.read_index(place).await
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        self.inner.publish(publication).await
    }

    async fn remove(
        &self,
        place: &InvitationPlace,
        record_key: &str,
        removal: Removal,
    ) -> Result<bool, AuthError> {
        assert_eq!(removal, Removal::Spend);
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.spend {
            Spend::FailsOnce if call == 0 => Err(AuthError::Internal("store down".into())),
            Spend::FailsOnce => self.inner.remove(place, record_key, removal).await,
            Spend::Lost => {
                self.inner.remove(place, record_key, removal).await?;
                Ok(false)
            }
        }
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        self.inner.pending(place).await
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        self.inner.count_inviter(rate_id).await
    }
}

/// [`invited`] over a store that spends as `spend` says.
async fn invited_spending(spend: Spend) -> (Inv, String) {
    let wrap = |inner| -> Arc<dyn WorkspaceInvitationStore> {
        Arc::new(Spending {
            inner,
            spend,
            calls: AtomicUsize::new(0),
        })
    };
    let Some(inv) = setup_over(config(), wrap).await else {
        unreachable!("the fixture builds");
    };
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    invite(&inv, JOE, "member", &inv.owner.user_id).await;
    (inv, joe)
}

#[tokio::test]
async fn a_spend_that_lost_the_index_still_accepts_and_the_hook_event_says_so() {
    let (inv, joe) = invited_spending(Spend::Lost).await;
    assert_eq!(accept(&inv, &joe).await.ok(), Some(accepted_as("member")));
    let events = inv.f.hooks.events(1).await;
    assert!(matches!(
        events.first().map(|e| &e.kind),
        Some(AuditKind::InvitationAccepted {
            lost_consume_race: true,
            ..
        })
    ));
}

#[tokio::test]
async fn the_membership_is_written_before_the_spend_and_a_retry_completes_it() {
    let (inv, joe) = invited_spending(Spend::FailsOnce).await;
    let failed = accept(&inv, &joe).await;
    assert!(matches!(failed, Err(AuthError::Internal(_))));
    assert_eq!(role_in_w1(&inv, &joe).as_deref(), Some("member"));
    assert!(unspent(&inv, JOE).await);

    assert_eq!(accept(&inv, &joe).await.ok(), Some(accepted_as("member")));
    assert!(spent(&inv, JOE).await);
}

#[tokio::test]
async fn acceptance_needs_the_invitation_store() {
    let Some(f) = without_a_store(config()) else {
        unreachable!("the fixture builds");
    };
    let refused = f
        .engine
        .accept_workspace_invitation("t1", "u", TOKEN, &ctx())
        .await;
    assert!(matches!(refused, Err(AuthError::Internal(_))));
}

/// Hooks that record who `after_invitation_accepted` was called for.
#[derive(Default)]
struct Accepted {
    calls: Mutex<Vec<(SafeAuthUser, HookContext)>>,
}

impl Accepted {
    /// The calls so far, after the detached deliveries have had time to land.
    async fn calls(&self) -> Vec<(SafeAuthUser, HookContext)> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl AuthHooks for Accepted {
    async fn after_invitation_accepted(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((user.clone(), ctx.clone()));
        }
        Ok(())
    }
}

/// A breach screen that refuses [`BREACHED`].
struct Screen;

#[async_trait]
impl PasswordBreachChecker for Screen {
    async fn is_breached(&self, password: &str) -> bool {
        password == BREACHED
    }
}

/// An owner's invitation of [`JOE`], who has no account, over an engine with `hooks` and the
/// screen, and sessions tracked.
async fn awaiting_signup(hooks: Arc<Accepted>) -> Inv {
    let mut config = config();
    config.sessions.enabled = true;
    let customize = |builder: crate::engine::AuthEngineBuilder| {
        builder.hooks(hooks).breach_checker(Arc::new(Screen))
    };
    let Some(inv) = setup_customized(config, |store| store, customize).await else {
        unreachable!("the fixture builds");
    };
    invite(&inv, JOE, "member", &inv.owner.user_id).await;
    inv
}

#[tokio::test]
async fn a_signup_creates_a_verified_account_that_joins_and_is_signed_in() {
    let hooks = Arc::new(Accepted::default());
    let inv = awaiting_signup(hooks.clone()).await;

    let Ok(done) = signup(&inv, TOKEN, GOOD_PASSWORD).await else {
        unreachable!("the signup is accepted");
    };

    let printed = format!("{done:?}");
    for secret in [&done.result.refresh_token, &done.result.access_token] {
        assert!(!printed.contains(secret.as_str()), "{printed}");
    }
    assert!(!printed.contains(JOE), "{printed}");
    let user = done.result.user;
    assert_eq!(done.accepted, accepted_as("member"));
    assert_eq!((user.email.as_str(), user.name.as_str()), (JOE, "Joe Doe"));
    assert_eq!((user.tenant_id.as_str(), user.email_verified), ("t1", true));
    assert!(!done.result.access_token.is_empty() && !done.result.refresh_token.is_empty());
    assert_eq!(role_in_w1(&inv, &user.id).as_deref(), Some("member"));
    assert!(spent(&inv, JOE).await);
    let calls = hooks.calls().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls.first().map(|(u, c)| (u.id.clone(), c.ip.clone())),
        Some((user.id, "203.0.113.4".to_owned()))
    );
}

#[tokio::test]
async fn a_signed_in_acceptance_fires_no_after_hook() {
    let hooks = Arc::new(Accepted::default());
    let inv = awaiting_signup(hooks.clone()).await;
    let joe = seed_account(&inv.f, "t1", JOE, false).await;
    assert!(accept(&inv, &joe).await.is_ok());
    assert!(hooks.calls().await.is_empty());
}

#[tokio::test]
async fn a_signup_for_an_address_with_an_account_is_refused_with_the_token_unspent() {
    let inv = awaiting_signup(Arc::new(Accepted::default())).await;
    seed_account(&inv.f, "t1", JOE, false).await;
    let refused = signup(&inv, TOKEN, GOOD_PASSWORD).await;
    assert!(matches!(refused, Err(AuthError::EmailAlreadyExists)));
    assert!(unspent(&inv, JOE).await);
}

#[tokio::test]
async fn a_refused_password_creates_nothing_and_spends_nothing() {
    let inv = awaiting_signup(Arc::new(Accepted::default())).await;
    for password in ["short", BREACHED] {
        let refused = signup(&inv, TOKEN, password).await;
        assert!(refused.is_err(), "{password}");
        let account = inv.f.users.find_by_email(JOE, "t1").await;
        assert!(matches!(account, Ok(None)), "{password}");
        assert!(unspent(&inv, JOE).await, "{password}");
    }
}

/// A breach screen that creates [`JOE`]'s account while the password is being judged, as a
/// registration landing between the account check and the creation does.
struct Registers(Arc<crate::testing::InMemoryUserRepository>);

#[async_trait]
impl PasswordBreachChecker for Registers {
    async fn is_breached(&self, _password: &str) -> bool {
        let data = bymax_auth_types::CreateUserData {
            email: JOE.to_owned(),
            name: "Joe".to_owned(),
            password_hash: None,
            role: None,
            status: None,
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        };
        let created = self.0.create(data).await;
        assert!(created.is_ok());
        false
    }
}

#[tokio::test]
async fn a_registration_that_wins_the_creation_answers_as_an_existing_account() {
    let users = Arc::new(Mutex::new(None));
    let wired = users.clone();
    let customize = move |builder: crate::engine::AuthEngineBuilder| {
        let repository = Arc::new(crate::testing::InMemoryUserRepository::new());
        if let Ok(mut slot) = wired.lock() {
            *slot = Some(repository.clone());
        }
        builder
            .user_repository(repository.clone())
            .breach_checker(Arc::new(Registers(repository)))
    };
    let Some(inv) = setup_customized(config(), |store| store, customize).await else {
        unreachable!("the fixture builds");
    };
    let Some(users) = users.lock().ok().and_then(|slot| slot.clone()) else {
        unreachable!("the repository was wired");
    };
    // The fixture seeded its seats into the repository the engine no longer reads.
    let owner = bymax_auth_types::CreateUserData {
        email: "owner@x.io".to_owned(),
        name: "Owner".to_owned(),
        password_hash: None,
        role: None,
        status: Some("active".to_owned()),
        tenant_id: "t1".to_owned(),
        email_verified: Some(true),
    };
    let Ok(owner) = users.create(owner).await else {
        unreachable!("the owner is created");
    };
    inv.f
        .repo
        .seed_membership(membership(&active("t1", "w1", &owner.id, "owner"), 8));
    invite(&inv, JOE, "member", &owner.id).await;

    let refused = signup(&inv, TOKEN, GOOD_PASSWORD).await;

    assert!(matches!(refused, Err(AuthError::EmailAlreadyExists)));
    assert!(unspent(&inv, JOE).await);
}

#[tokio::test]
async fn a_workspace_gone_at_the_membership_write_is_an_invalid_token_and_stays() {
    // A membership repository that holds the inviter's seat and no workspace row: what a
    // workspace removed between the checks and the write looks like to the write.
    let memberships = Arc::new(crate::testing::InMemoryWorkspaces::new());
    let seats = memberships.clone();
    let repo = Arc::new(Mutex::new(None));
    let wired = repo.clone();
    let customize = move |builder: crate::engine::AuthEngineBuilder| {
        let workspaces = Arc::new(crate::testing::InMemoryWorkspaces::new());
        if let Ok(mut slot) = wired.lock() {
            *slot = Some(workspaces.clone());
        }
        builder.workspace_repositories(workspaces, seats)
    };
    let Some(inv) = setup_customized(config(), |store| store, customize).await else {
        unreachable!("the fixture builds");
    };
    let Some(workspaces) = repo.lock().ok().and_then(|slot| slot.clone()) else {
        unreachable!("the repository was wired");
    };
    let row =
        crate::services::workspace_support_tests::workspace("t1", "w1", WorkspaceStatus::Active, 1);
    workspaces.seed_workspace(row);
    let owner = inv.owner.user_id.clone();
    memberships.seed_membership(membership(&active("t1", "w1", &owner, "owner"), 8));
    invite(&inv, JOE, "member", &owner).await;
    let joe = seed_account(&inv.f, "t1", JOE, false).await;

    let refused = accept(&inv, &joe).await;

    assert!(matches!(refused, Err(AuthError::InvalidInvitationToken)));
    assert!(unspent(&inv, JOE).await);
}

#[test]
fn a_create_that_failed_because_the_address_was_taken_says_so() {
    let down = || crate::RepositoryError::Backend("down".into());
    assert!(matches!(
        create_failure(down(), true),
        AuthError::EmailAlreadyExists
    ));
    assert!(matches!(
        create_failure(down(), false),
        AuthError::Internal(_)
    ));
}

#[test]
fn the_signup_input_never_prints_the_token_or_the_password() {
    let input = WorkspaceSignupInput {
        token: "secret-token".to_owned(),
        name: "Joe".to_owned(),
        password: "secret-password".to_owned(),
    };
    let printed = format!("{input:?}");
    assert!(printed.contains("Joe") && !printed.contains("secret"));
}
