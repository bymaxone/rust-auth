//! A later invite, a redemption or a failing withdrawal landing inside a revoke or an acceptance.

use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;

use super::*;
use crate::traits::{InvitationStore, InvitationWithdrawal};

const EMAIL: &str = "bob@example.com";
const FIRST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PASSWORD: &str = "correct-horse-battery-staple";

/// The token of the `n`th replacement.
fn replacement(n: usize) -> String {
    format!("{n}").repeat(64)
}

fn record(role: &str, inviter: &str) -> StoredInvitation {
    StoredInvitation {
        email: EMAIL.to_owned(),
        role: role.to_owned(),
        tenant_id: "t1".to_owned(),
        inviter_user_id: inviter.to_owned(),
        created_at: OffsetDateTime::now_utc(),
    }
}

/// What happens under the caller, and how often.
#[derive(Default)]
struct Script {
    /// Later invites that land right after the pending record is read for judging.
    after_judging: usize,
    /// Later invites that land right before the index is released.
    before_release: usize,
    /// How many have landed.
    landed: usize,
    fail_withdraw: bool,
    /// The invitation under [`FIRST`] is redeemed right after it is read for judging.
    spent_after_judging: bool,
    /// The record reads as text that is not an invitation.
    garbled: bool,
}

struct Raced {
    inner: Arc<InMemoryStores>,
    script: Mutex<Script>,
    replacement: StoredInvitation,
    invitee: OnceLock<String>,
}

const GARBLED: &str = "{";

impl Raced {
    fn script<T>(&self, read: impl FnOnce(&mut Script) -> T) -> Option<T> {
        self.script.lock().ok().map(|mut script| read(&mut script))
    }

    /// The derived invitee identifier, known once the engine is built.
    fn invitee(&self) -> String {
        self.invitee.get().cloned().unwrap_or_default()
    }

    /// A later invite for the address.
    async fn reinvite(&self, tenant: &str, invitee: &str) -> Result<(), AuthError> {
        let n = self
            .script(|s| {
                s.landed += 1;
                s.landed + 1
            })
            .unwrap_or_default();
        let old = self.inner.read_invitation_index(tenant, invitee).await?;
        self.inner
            .publish_invitation(
                tenant,
                invitee,
                &token_hash(&replacement(n)),
                &self.replacement,
                600,
                old.as_deref(),
            )
            .await
            .map(|_| ())
    }
}

#[async_trait]
impl InvitationStore for Raced {
    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        self.inner.consume_invitation(token).await
    }
    async fn publish_invitation(
        &self,
        tenant: &str,
        invitee: &str,
        hash: &str,
        invitation: &StoredInvitation,
        ttl: u64,
        superseded: Option<&str>,
    ) -> Result<bool, AuthError> {
        self.inner
            .publish_invitation(tenant, invitee, hash, invitation, ttl, superseded)
            .await
    }
    async fn withdraw_invitation(
        &self,
        tenant: &str,
        invitee: &str,
        hash: &str,
        judged: Option<&str>,
    ) -> Result<InvitationWithdrawal, AuthError> {
        if self
            .script(|s| std::mem::take(&mut s.fail_withdraw))
            .unwrap_or_default()
        {
            return Err(crate::services::internal_error("withdraw failed"));
        }
        // The garbled text stands for what the store holds, so compare against that instead.
        let held = self.inner.read_invitation_record(hash).await?;
        let judged = match judged {
            Some(GARBLED) => held.as_deref(),
            other => other,
        };
        self.inner
            .withdraw_invitation(tenant, invitee, hash, judged)
            .await
    }
    async fn read_invitation_index(
        &self,
        tenant: &str,
        invitee: &str,
    ) -> Result<Option<String>, AuthError> {
        self.inner.read_invitation_index(tenant, invitee).await
    }
    async fn release_invitation_index(
        &self,
        tenant: &str,
        invitee: &str,
        expected: &str,
    ) -> Result<bool, AuthError> {
        let land = self
            .script(|s| {
                let land = s.before_release > 0;
                s.before_release = s.before_release.saturating_sub(1);
                land
            })
            .unwrap_or_default();
        if land {
            self.reinvite(tenant, invitee).await?;
        }
        self.inner
            .release_invitation_index(tenant, invitee, expected)
            .await
    }
    async fn read_invitation_record(&self, hash: &str) -> Result<Option<String>, AuthError> {
        let read = self.inner.read_invitation_record(hash).await?;
        let (land, spent, garbled) = self
            .script(|s| {
                let land = s.after_judging > 0;
                s.after_judging = s.after_judging.saturating_sub(1);
                (land, std::mem::take(&mut s.spent_after_judging), s.garbled)
            })
            .unwrap_or_default();
        if land {
            let invitee = self.invitee();
            self.reinvite("t1", &invitee).await?;
        }
        if spent {
            self.inner.consume_invitation(FIRST).await?;
        }
        Ok(if garbled {
            Some(GARBLED.to_owned())
        } else {
            read
        })
    }
}

struct Race {
    s: Setup,
    admin: String,
    member: String,
}

/// An engine over a store that runs `script`, with a `MEMBER` invitation pending under [`FIRST`]
/// and later invites granting `later_role`.
async fn race(script: Script, later_role: &str) -> Option<Race> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let admin = seed_admin(&users, "admin@example.com", "ADMIN").await;
    let member = seed_admin(&users, "member@example.com", "MEMBER").await;
    let double = Arc::new(Raced {
        inner: stores.clone(),
        script: Mutex::new(script),
        replacement: record(later_role, &admin),
        invitee: OnceLock::new(),
    });
    let engine = AuthEngine::builder()
        .config(invite_config())
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .invitation_store(double.clone())
        .build()
        .ok()?;
    let id = engine.invitee_identifier(EMAIL);
    double.invitee.set(id.clone()).ok()?;
    stores
        .publish_invitation(
            "t1",
            &id,
            &token_hash(FIRST),
            &record("MEMBER", &admin),
            600,
            None,
        )
        .await
        .ok()?;
    let s = Setup {
        engine,
        users,
        stores,
    };
    Some(Race { s, admin, member })
}

async fn revoke(race: &Race, who: &str) -> Result<bool, AuthError> {
    race.s.engine.revoke_invitation(who, EMAIL, "t1").await
}

async fn live(race: &Race, token: &str) -> bool {
    let hash = token_hash(token);
    let read = race.s.stores.read_invitation_record(&hash).await;
    matches!(read, Ok(Some(_)))
}

async fn accept(race: &Race, token: &str) -> Result<AuthResult, AuthError> {
    let input = AcceptInvitationInput {
        token: token.to_owned(),
        name: "Bob".to_owned(),
        password: PASSWORD.to_owned(),
    };
    race.s
        .engine
        .accept_invitation(input, "1.2.3.4", "agent", BTreeMap::new())
        .await
}

fn judged(times: usize) -> Script {
    Script {
        after_judging: times,
        ..Script::default()
    }
}

#[tokio::test]
async fn a_revoke_removes_the_invitation_that_replaced_the_one_it_judged() {
    for times in [1, 2] {
        let Some(r) = race(judged(times), "MEMBER").await else { unreachable!() };
        assert!(matches!(revoke(&r, &r.admin).await, Ok(true)), "{times}");
        assert_eq!(indexed(&r.s, EMAIL).await, None, "{times}");
        assert!(!live(&r, &replacement(times + 1)).await, "{times}");
    }
}

#[tokio::test]
async fn a_revoke_replaced_under_all_three_attempts_leaves_the_last_invitation_revocable() {
    let Some(r) = race(judged(3), "MEMBER").await else { unreachable!() };
    assert!(matches!(
        revoke(&r, &r.admin).await,
        Err(AuthError::TooManyRequests { .. })
    ));
    let last = replacement(4);
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(&last)));
    assert!(live(&r, &last).await);
    assert!(matches!(revoke(&r, &r.admin).await, Ok(true)));
    assert!(!live(&r, &last).await);
}

#[tokio::test]
async fn an_outranked_revoker_leaves_a_higher_replacement_indexed() {
    let Some(r) = race(judged(1), "ADMIN").await else { unreachable!() };
    assert!(matches!(revoke(&r, &r.member).await, Ok(false)));
    let later = replacement(2);
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(&later)));
    assert!(live(&r, &later).await);
}

#[tokio::test]
async fn an_acceptance_keeps_the_index_of_a_later_invite() {
    let script = Script {
        before_release: 1,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { unreachable!() };
    assert!(accept(&r, FIRST).await.is_ok());
    assert_eq!(
        indexed(&r.s, EMAIL).await,
        Some(token_hash(&replacement(2)))
    );
}

#[tokio::test]
async fn a_refused_acceptance_keeps_the_index_of_a_later_invite() {
    let script = Script {
        before_release: 1,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { unreachable!() };
    // The inviter is gone, so the acceptance is refused after the token is consumed.
    let gone = record("MEMBER", "nobody");
    assert!(put_record(&r.s.stores, FIRST, &gone).await.is_ok());
    assert!(matches!(
        accept(&r, FIRST).await,
        Err(AuthError::InvalidInvitationToken)
    ));
    assert_eq!(
        indexed(&r.s, EMAIL).await,
        Some(token_hash(&replacement(2)))
    );
}

#[tokio::test]
async fn a_revoke_whose_withdrawal_fails_leaves_both_and_can_be_retried() {
    let script = Script {
        fail_withdraw: true,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { unreachable!() };
    assert!(revoke(&r, &r.admin).await.is_err());
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(FIRST)));
    assert!(live(&r, FIRST).await);
    assert!(matches!(revoke(&r, &r.admin).await, Ok(true)));
    assert!(!live(&r, FIRST).await);
}

#[tokio::test]
async fn a_revoke_of_an_invitation_redeemed_while_judged_answers_false_and_drops_the_index() {
    let script = Script {
        spent_after_judging: true,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { unreachable!() };
    assert!(matches!(revoke(&r, &r.admin).await, Ok(false)));
    assert_eq!(indexed(&r.s, EMAIL).await, None);
}

#[tokio::test]
async fn a_record_that_is_not_an_invitation_is_withdrawn_without_a_rank_check() {
    let script = Script {
        garbled: true,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { unreachable!() };
    assert!(matches!(revoke(&r, &r.member).await, Ok(true)));
    assert_eq!(indexed(&r.s, EMAIL).await, None);
    assert!(!live(&r, FIRST).await);
}
