//! An OAuth sign-in that carries a workspace invitation, and what `registration` closes (layer:
//! service, tests).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use async_trait::async_trait;
use bymax_auth_types::{AuthError, CreateWithOAuthData, SafeAuthUser, UpdateMfaData};

use crate::config::{AuthConfig, Environment, RegistrationMode};
use crate::engine::{AuthEngine, AuthEngineBuilder};
use crate::services::auth::RegisterInput;
use crate::services::auth::test_support::{base_config, ctx};
use crate::services::oauth::OAuthOutcome;
use crate::services::workspace_invitations_support_tests::{
    Inv, Seeded, key_of, seed, seed_bootstrap, setup_customized,
};
use crate::services::workspace_support_tests::{config, workspace};
use crate::testing::{InMemoryUserRepository, InMemoryWorkspaces};
use crate::traits::{
    AuthHooks, HookContext, HookError, OAuthLoginResult, OAuthProfile, OAuthProvider,
    OAuthProviderError, OAuthStateStore, OAuthTokens, UserRepository, WorkspaceInvitationStore,
};
use crate::workspace::domain::{MembershipRef, WorkspaceStatus};
use crate::workspace::keys::invitation_record_id;

mod closed_sessions;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const INVITEE: &str = "joe@x.io";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A provider that answers every exchange and reports the profile a test chose.
struct Provider {
    profile: Mutex<(String, bool)>,
}

#[async_trait]
impl OAuthProvider for Provider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorize_url(&self, state: &str, _code_challenge: Option<&str>) -> String {
        format!("https://provider.test/authorize?state={state}")
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<OAuthTokens, OAuthProviderError> {
        Ok(OAuthTokens {
            access_token: "at".to_owned(),
            token_type: "bearer".to_owned(),
            expires_in: None,
            scope: None,
            id_token: None,
            refresh_token: None,
        })
    }

    async fn fetch_profile(&self, _token: &str) -> Result<OAuthProfile, OAuthProviderError> {
        let (email, email_verified) = lock(&self.profile).clone();
        Ok(OAuthProfile {
            provider: "google".to_owned(),
            provider_id: "google-user-1".to_owned(),
            email,
            email_verified,
            name: None,
            avatar: None,
        })
    }
}

/// A state store that keeps what was put, so a test can read the record.
#[derive(Default)]
struct States(Mutex<HashMap<String, String>>);

#[async_trait]
impl OAuthStateStore for States {
    async fn put_state(&self, hash: &str, payload: &str, _ttl: u64) -> Result<(), AuthError> {
        lock(&self.0).insert(hash.to_owned(), payload.to_owned());
        Ok(())
    }

    async fn take_state(&self, hash: &str) -> Result<Option<String>, AuthError> {
        Ok(lock(&self.0).remove(hash))
    }
}

/// A hook with a fixed sign-in decision that counts what it hears, and can close the workspace
/// while the host is deciding.
struct Hooks {
    decision: Mutex<OAuthLoginResult>,
    asked: AtomicUsize,
    accepted: AtomicUsize,
    closes: OnceLock<Arc<InMemoryWorkspaces>>,
}

#[async_trait]
impl AuthHooks for Hooks {
    async fn on_oauth_login(
        &self,
        _profile: &OAuthProfile,
        _existing: Option<&SafeAuthUser>,
        _ctx: &HookContext,
    ) -> Result<OAuthLoginResult, HookError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if let Some(repo) = self.closes.get() {
            repo.seed_workspace(workspace("t1", "w1", WorkspaceStatus::Suspended, 1));
        }
        Ok(lock(&self.decision).clone())
    }

    async fn after_invitation_accepted(
        &self,
        _user: &SafeAuthUser,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.accepted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The invitation fixture with OAuth wired, and the doubles that drive it.
struct Rig {
    inv: Inv,
    hooks: Arc<Hooks>,
    provider: Arc<Provider>,
    states: Arc<States>,
}

async fn rig_with(config: AuthConfig, decision: OAuthLoginResult) -> Option<Rig> {
    rig_over(config, decision, |builder| builder).await
}

/// As [`rig_with`], with `wire` applied to the builder after the fixture's own doubles.
async fn rig_over(
    config: AuthConfig,
    decision: OAuthLoginResult,
    wire: impl FnOnce(AuthEngineBuilder) -> AuthEngineBuilder,
) -> Option<Rig> {
    let hooks = Arc::new(Hooks {
        decision: Mutex::new(decision),
        asked: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        closes: OnceLock::new(),
    });
    let provider = Arc::new(Provider {
        profile: Mutex::new((INVITEE.to_owned(), true)),
    });
    let states = Arc::new(States::default());
    let (h, p, s) = (hooks.clone(), provider.clone(), states.clone());
    let inv = setup_customized(
        config,
        |store| store as Arc<dyn WorkspaceInvitationStore>,
        move |builder| wire(builder.hooks(h).oauth_provider(p).oauth_state_store(s)),
    )
    .await?;
    Some(Rig {
        inv,
        hooks,
        provider,
        states,
    })
}

fn oauth_config() -> AuthConfig {
    let mut config = config();
    config.controllers.oauth = true;
    config.controllers.workspaces = true;
    config
}

fn closed_config() -> AuthConfig {
    let mut config = oauth_config();
    config.registration = RegistrationMode::InvitationOnly;
    config
}

/// A rig whose member invitation to [`INVITEE`] is published under [`TOKEN`].
async fn invited(config: AuthConfig, decision: OAuthLoginResult) -> Option<Rig> {
    let rig = rig_with(config, decision).await?;
    seed_member(&rig).await;
    Some(rig)
}

/// Publishes a member invitation to [`INVITEE`] under [`TOKEN`].
async fn seed_member(rig: &Rig) {
    let member = Seeded {
        email: INVITEE,
        role: "member",
        inviter: &rig.inv.owner.user_id,
        created_at: "2026-01-01T00:00:00.000Z",
        resends: 0,
    };
    seed(&rig.inv, TOKEN, &member).await;
}

/// Starts a flow with `invitation` and completes its callback.
async fn flow(rig: &Rig, invitation: Option<&str>) -> Result<OAuthOutcome, AuthError> {
    let engine = &rig.inv.f.engine;
    let started = engine
        .oauth_initiate_with_invitation("google", Some("t1"), invitation, &ctx())
        .await?;
    let state = started.state.as_str();
    engine
        .oauth_callback("google", "code", state, Some(state), &ctx())
        .await
}

async fn account(rig: &Rig, email: &str) -> Option<String> {
    let found = rig.inv.f.users.find_by_email(email, "t1").await;
    found.ok().flatten().map(|user| user.id)
}

fn member_of(rig: &Rig, workspace_id: &str, user_id: &str) -> Option<String> {
    let reference = MembershipRef {
        tenant_id: "t1",
        workspace_id,
        user_id,
    };
    rig.inv.f.repo.membership(reference).map(|row| row.role)
}

async fn unspent(rig: &Rig) -> bool {
    let record = rig.inv.store.read_record(&key_of(TOKEN)).await;
    matches!(record, Ok(Some(_)))
}

/// An account for `email` already bound to the provider identity.
async fn bound_account(users: &InMemoryUserRepository, email: &str) -> Option<String> {
    let created = users
        .create_with_oauth(CreateWithOAuthData {
            email: email.to_owned(),
            name: "Bound".to_owned(),
            role: None,
            status: Some("active".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
            oauth_provider: "google".to_owned(),
            oauth_provider_id: "google-user-1".to_owned(),
        })
        .await;
    created.ok().map(|user| user.id)
}

/// Waits for the detached after-acceptance hook to have had its chance, then reads the count.
async fn accepted_calls(rig: &Rig) -> usize {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    rig.hooks.accepted.load(Ordering::SeqCst)
}

#[tokio::test]
async fn the_state_record_carries_the_token_digest_and_never_the_token() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Create).await else { unreachable!() };
    let started = rig
        .inv
        .f
        .engine
        .oauth_initiate_with_invitation("google", Some("t1"), Some(TOKEN), &ctx())
        .await;
    assert!(started.is_ok());
    let records: Vec<String> = lock(&rig.states.0).values().cloned().collect();
    let digest = format!(
        "\"workspaceInvitation\":\"{}\"",
        invitation_record_id(TOKEN)
    );
    assert!(matches!(records.as_slice(), [only] if only.contains(&digest)));
    assert!(records.iter().all(|record| !record.contains(TOKEN)));
}

#[tokio::test]
async fn a_token_is_refused_at_the_start_while_the_workspace_layer_is_off() {
    let states = Arc::new(States::default());
    let provider = Arc::new(Provider {
        profile: Mutex::new((INVITEE.to_owned(), true)),
    });
    let mut cfg = base_config();
    cfg.controllers.oauth = true;
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(crate::testing::InMemoryStores::new()))
        .oauth_provider(provider)
        .oauth_state_store(states.clone())
        .build();
    let Ok(engine) = built else { unreachable!() };
    let started = engine
        .oauth_initiate_with_invitation("google", Some("t1"), Some(TOKEN), &ctx())
        .await;
    assert!(matches!(started, Err(AuthError::InvalidInvitationToken)));
    assert!(lock(&states.0).is_empty());
}

#[tokio::test]
async fn a_new_account_joins_the_workspace_and_is_signed_in() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Create).await else { unreachable!() };
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Ok(OAuthOutcome::Authenticated(_))));
    let Some(joe) = account(&rig, INVITEE).await else { unreachable!() };
    assert_eq!(member_of(&rig, "w1", &joe).as_deref(), Some("member"));
    assert!(!unspent(&rig).await);
    assert_eq!(accepted_calls(&rig).await, 1);
}

#[tokio::test]
async fn a_session_that_cannot_be_written_keeps_the_membership_and_runs_no_hook() {
    let store = Arc::new(closed_sessions::ClosedSessions::default());
    let wired = rig_over(oauth_config(), OAuthLoginResult::Create, move |builder| {
        builder.session_store(store)
    });
    let Some(rig) = wired.await else { unreachable!() };
    seed_member(&rig).await;
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Err(AuthError::ServiceUnavailable(_))));
    let Some(joe) = account(&rig, INVITEE).await else { unreachable!() };
    assert_eq!(member_of(&rig, "w1", &joe).as_deref(), Some("member"));
    assert!(!unspent(&rig).await);
    assert_eq!(accepted_calls(&rig).await, 0);
}

#[tokio::test]
async fn a_linked_account_joins_without_the_after_acceptance_hook() {
    let Some(rig) = invited(closed_config(), OAuthLoginResult::Link).await else { unreachable!() };
    let Some(joe) = bound_account(&rig.inv.f.users, INVITEE).await else { unreachable!() };
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Ok(OAuthOutcome::Authenticated(_))));
    assert_eq!(member_of(&rig, "w1", &joe).as_deref(), Some("member"));
    assert_eq!(accepted_calls(&rig).await, 0);
}

#[cfg(feature = "mfa")]
#[tokio::test]
async fn an_account_with_a_second_factor_is_challenged_and_the_invitation_stays_unspent() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Link).await else { unreachable!() };
    let Some(joe) = bound_account(&rig.inv.f.users, INVITEE).await else { unreachable!() };
    let enrolled = UpdateMfaData {
        mfa_enabled: true,
        mfa_secret: Some("enc".to_owned()),
        mfa_recovery_codes: None,
    };
    assert!(
        rig.inv
            .f
            .users
            .update_mfa(&joe, "t1", enrolled)
            .await
            .is_ok()
    );
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Ok(OAuthOutcome::MfaChallenge(_))));
    assert_eq!(member_of(&rig, "w1", &joe), None);
    assert!(unspent(&rig).await);
}

#[tokio::test]
async fn a_profile_the_invitation_does_not_fit_is_refused_before_the_hook_is_asked() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Create).await else { unreachable!() };
    *lock(&rig.provider.profile) = ("eve@x.io".to_owned(), false);
    let other = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(other, Err(AuthError::InvitationEmailMismatch)));
    *lock(&rig.provider.profile) = (INVITEE.to_owned(), false);
    let unverified = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(unverified, Err(AuthError::EmailNotVerified)));
    let unknown = flow(&rig, Some(&"f".repeat(64))).await;
    assert!(matches!(unknown, Err(AuthError::InvalidInvitationToken)));
    assert_eq!(rig.hooks.asked.load(Ordering::SeqCst), 0);
    assert!(unspent(&rig).await);
}

#[tokio::test]
async fn an_invitation_of_another_tenant_is_refused() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Create).await else { unreachable!() };
    let engine = &rig.inv.f.engine;
    let started = engine
        .oauth_initiate_with_invitation("google", Some("t2"), Some(TOKEN), &ctx())
        .await;
    let Ok(started) = started else { unreachable!() };
    let state = started.state.as_str();
    let outcome = engine
        .oauth_callback("google", "code", state, Some(state), &ctx())
        .await;
    assert!(matches!(outcome, Err(AuthError::InvalidInvitationToken)));
    assert_eq!(rig.hooks.asked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_workspace_closed_while_the_host_decides_refuses_the_write_and_keeps_the_account() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Create).await else { unreachable!() };
    assert!(rig.hooks.closes.set(rig.inv.f.repo.clone()).is_ok());
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Err(AuthError::InvalidInvitationToken)));
    let Some(joe) = account(&rig, INVITEE).await else { unreachable!() };
    assert_eq!(member_of(&rig, "w1", &joe), None);
    assert!(unspent(&rig).await);
    assert_eq!(accepted_calls(&rig).await, 0);
}

#[tokio::test]
async fn the_account_signed_in_has_to_hold_the_invited_address() {
    let Some(rig) = invited(oauth_config(), OAuthLoginResult::Link).await else { unreachable!() };
    let Some(other) = bound_account(&rig.inv.f.users, "other@x.io").await else { unreachable!() };
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Err(AuthError::InvitationEmailMismatch)));
    assert_eq!(member_of(&rig, "w1", &other), None);
    assert!(unspent(&rig).await);
}

#[tokio::test]
async fn a_bootstrap_invitation_creates_the_workspace_for_the_new_account() {
    let Some(rig) = rig_with(closed_config(), OAuthLoginResult::Create).await else {
        unreachable!()
    };
    seed_bootstrap(&rig.inv, TOKEN, (INVITEE, "w9", "owner")).await;
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Ok(OAuthOutcome::Authenticated(_))));
    let Some(joe) = account(&rig, INVITEE).await else { unreachable!() };
    assert_eq!(member_of(&rig, "w9", &joe).as_deref(), Some("owner"));
}

#[tokio::test]
async fn invitation_only_creates_no_account_for_a_flow_without_an_invitation() {
    let Some(rig) = invited(closed_config(), OAuthLoginResult::Create).await else {
        unreachable!()
    };
    let outcome = flow(&rig, None).await;
    assert!(matches!(outcome, Err(AuthError::RegistrationClosed)));
    assert_eq!(account(&rig, INVITEE).await, None);
}

#[tokio::test]
async fn invitation_only_creates_the_account_of_a_flow_with_an_invitation() {
    let Some(rig) = invited(closed_config(), OAuthLoginResult::Create).await else {
        unreachable!()
    };
    let outcome = flow(&rig, Some(TOKEN)).await;
    assert!(matches!(outcome, Ok(OAuthOutcome::Authenticated(_))));
    assert!(account(&rig, INVITEE).await.is_some());
}

#[tokio::test]
async fn invitation_only_closes_the_password_sign_up_before_the_tenant_is_read() {
    let Some(rig) = rig_with(closed_config(), OAuthLoginResult::Create).await else {
        unreachable!()
    };
    let input = RegisterInput {
        email: INVITEE.to_owned(),
        name: "Joe Doe".to_owned(),
        password: "a sufficiently long password".to_owned(),
        tenant_id: None,
    };
    let outcome = rig.inv.f.engine.register(input, &ctx()).await;
    assert!(matches!(outcome, Err(AuthError::RegistrationClosed)));
    assert_eq!(account(&rig, INVITEE).await, None);
}
