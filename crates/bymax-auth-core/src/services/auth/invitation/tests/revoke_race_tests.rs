//! A later invite, or a failing delete, landing inside a revoke or an acceptance.

use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;

use super::*;
use crate::traits::InvitationStore;

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
    fail_delete: bool,
    /// The invite in flight under [`FIRST`] writes its record and confirms right after the first
    /// delete.
    written_after_delete: bool,
    /// The same, right before the first release instead.
    written_before_release: bool,
    /// What that confirmation answered.
    confirmed: Option<bool>,
    /// Another revoke releases the index right before this one does.
    released_elsewhere: bool,
}

struct Raced {
    inner: Arc<InMemoryStores>,
    script: Mutex<Script>,
    replacement: StoredInvitation,
    invitee: OnceLock<String>,
}

impl Raced {
    fn script<T>(&self, read: impl FnOnce(&mut Script) -> T) -> Option<T> {
        self.script.lock().ok().map(|mut script| read(&mut script))
    }

    /// The derived invitee identifier, known once the engine is built.
    fn invitee(&self) -> String {
        self.invitee.get().cloned().unwrap_or_default()
    }

    /// The rest of the invite that claimed [`FIRST`]: write, confirm, withdraw when refused.
    async fn finish_invite(&self) -> Result<(), AuthError> {
        let hash = token_hash(FIRST);
        self.inner
            .put_invitation(FIRST, &self.replacement, 600)
            .await?;
        let confirmed = self
            .inner
            .claim_invitation_index("t1", &self.invitee(), &hash, 600, Some(&hash))
            .await?;
        self.script(|s| s.confirmed = Some(confirmed));
        if !confirmed {
            self.inner.delete_invitation_by_hash(&hash).await?;
        }
        Ok(())
    }

    /// A later invite, in the order `invite` writes: claim, delete the superseded record, write.
    async fn reinvite(&self, tenant: &str, invitee: &str) -> Result<(), AuthError> {
        let n = self
            .script(|s| {
                s.landed += 1;
                s.landed + 1
            })
            .unwrap_or_default();
        let token = replacement(n);
        let old = self.inner.read_invitation_index(tenant, invitee).await?;
        let new = token_hash(&token);
        self.inner
            .claim_invitation_index(tenant, invitee, &new, 600, old.as_deref())
            .await?;
        if let Some(old) = old {
            self.inner.delete_invitation_by_hash(&old).await?;
        }
        self.inner
            .put_invitation(&token, &self.replacement, 600)
            .await
    }
}

#[async_trait]
impl InvitationStore for Raced {
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &StoredInvitation,
        ttl: u64,
    ) -> Result<(), AuthError> {
        self.inner.put_invitation(token, invitation, ttl).await
    }
    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        self.inner.consume_invitation(token).await
    }
    async fn put_invitation_index(
        &self,
        tenant: &str,
        invitee: &str,
        hash: &str,
        ttl: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .put_invitation_index(tenant, invitee, hash, ttl)
            .await
    }
    async fn claim_invitation_index(
        &self,
        tenant: &str,
        invitee: &str,
        hash: &str,
        ttl: u64,
        expected: Option<&str>,
    ) -> Result<bool, AuthError> {
        self.inner
            .claim_invitation_index(tenant, invitee, hash, ttl, expected)
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
        let (land, elsewhere) = self
            .script(|s| {
                let land = s.before_release > 0;
                s.before_release = s.before_release.saturating_sub(1);
                (land, std::mem::take(&mut s.released_elsewhere))
            })
            .unwrap_or_default();
        if land {
            self.reinvite(tenant, invitee).await?;
        }
        if self
            .script(|s| std::mem::take(&mut s.written_before_release))
            .unwrap_or_default()
        {
            self.finish_invite().await?;
        }
        if elsewhere {
            self.inner
                .release_invitation_index(tenant, invitee, expected)
                .await?;
        }
        self.inner
            .release_invitation_index(tenant, invitee, expected)
            .await
    }
    async fn read_invitation_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<StoredInvitation>, AuthError> {
        let read = self.inner.read_invitation_by_hash(hash).await?;
        let land = self
            .script(|s| {
                let land = s.after_judging > 0;
                s.after_judging = s.after_judging.saturating_sub(1);
                land
            })
            .unwrap_or_default();
        if land {
            let invitee = self.invitee();
            self.reinvite("t1", &invitee).await?;
        }
        Ok(read)
    }
    async fn delete_invitation_by_hash(&self, hash: &str) -> Result<bool, AuthError> {
        if self
            .script(|s| std::mem::take(&mut s.fail_delete))
            .unwrap_or_default()
        {
            return Err(crate::services::internal_error("delete failed"));
        }
        let removed = self.inner.delete_invitation_by_hash(hash).await?;
        if self
            .script(|s| std::mem::take(&mut s.written_after_delete))
            .unwrap_or_default()
        {
            self.finish_invite().await?;
        }
        Ok(removed)
    }
}

struct Race {
    double: Arc<Raced>,
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
        .put_invitation(FIRST, &record("MEMBER", &admin), 600)
        .await
        .ok()?;
    stores
        .put_invitation_index("t1", &id, &token_hash(FIRST), 600)
        .await
        .ok()?;
    let s = Setup {
        engine,
        users,
        stores,
    };
    Some(Race {
        double,
        s,
        admin,
        member,
    })
}

async fn revoke(race: &Race, who: &str) -> Result<bool, AuthError> {
    race.s.engine.revoke_invitation(who, EMAIL, "t1").await
}

async fn live(race: &Race, token: &str) -> bool {
    let hash = token_hash(token);
    let read = race.s.stores.read_invitation_by_hash(&hash).await;
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
        let Some(r) = race(judged(times), "MEMBER").await else { return };
        assert!(matches!(revoke(&r, &r.admin).await, Ok(true)), "{times}");
        assert_eq!(indexed(&r.s, EMAIL).await, None, "{times}");
        assert!(!live(&r, &replacement(times + 1)).await, "{times}");
    }
}

#[tokio::test]
async fn a_revoke_replaced_under_all_three_attempts_leaves_the_last_invitation_revocable() {
    let Some(r) = race(judged(3), "MEMBER").await else { return };
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
    let Some(r) = race(judged(1), "ADMIN").await else { return };
    assert!(matches!(revoke(&r, &r.member).await, Ok(false)));
    let later = replacement(2);
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(&later)));
    assert!(live(&r, &later).await);
}

#[tokio::test]
async fn a_revoke_keeps_the_index_a_later_invite_claimed_before_the_release() {
    // The pending record is already deleted; the later invitation is above the revoker.
    let script = Script {
        before_release: 1,
        ..Script::default()
    };
    let Some(r) = race(script, "ADMIN").await else { return };
    assert!(matches!(revoke(&r, &r.member).await, Ok(true)));
    assert_eq!(
        indexed(&r.s, EMAIL).await,
        Some(token_hash(&replacement(2)))
    );
}

#[tokio::test]
async fn a_revoke_reports_its_removal_when_another_caller_released_the_index() {
    let script = Script {
        released_elsewhere: true,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { return };
    assert!(matches!(revoke(&r, &r.admin).await, Ok(true)));
    assert!(!live(&r, FIRST).await);
}

#[tokio::test]
async fn an_acceptance_keeps_the_index_of_a_later_invite() {
    let script = Script {
        before_release: 1,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { return };
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
    let Some(r) = race(script, "MEMBER").await else { return };
    // The inviter is gone, so the acceptance is refused after the token is consumed.
    let gone = record("MEMBER", "nobody");
    assert!(r.s.stores.put_invitation(FIRST, &gone, 600).await.is_ok());
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
async fn a_revoke_whose_record_delete_fails_can_be_retried() {
    let script = Script {
        fail_delete: true,
        ..Script::default()
    };
    let Some(r) = race(script, "MEMBER").await else { return };
    assert!(revoke(&r, &r.admin).await.is_err());
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(FIRST)));
    assert!(matches!(revoke(&r, &r.admin).await, Ok(true)));
    assert!(!live(&r, FIRST).await);
}

#[tokio::test]
async fn an_invite_in_flight_cannot_confirm_after_the_revoke_has_deleted() {
    let script = Script {
        written_after_delete: true,
        ..Script::default()
    };
    let Some((r, answer)) = revoke_in_flight(script, "MEMBER").await else { return };
    assert!(matches!(answer, Ok(false)));
    assert_eq!(r.double.script(|s| s.confirmed), Some(Some(false)));
    assert_eq!(indexed(&r.s, EMAIL).await, None);
    assert!(!live(&r, FIRST).await);
}

/// A revoke while the invite under [`FIRST`] holds the index and has written no record.
async fn revoke_in_flight(
    script: Script,
    later_role: &str,
) -> Option<(Race, Result<bool, AuthError>)> {
    let r = race(script, later_role).await?;
    let pending = token_hash(FIRST);
    r.s.stores.delete_invitation_by_hash(&pending).await.ok()?;
    let answer = revoke(&r, &r.member).await;
    Some((r, answer))
}

#[tokio::test]
async fn a_revoke_removes_the_record_an_invite_in_flight_confirmed_before_the_release() {
    let script = Script {
        written_before_release: true,
        ..Script::default()
    };
    let Some((r, answer)) = revoke_in_flight(script, "MEMBER").await else { return };
    assert!(matches!(answer, Ok(true)));
    assert_eq!(r.double.script(|s| s.confirmed), Some(Some(true)));
    assert!(!live(&r, FIRST).await);
}

#[tokio::test]
async fn a_revoke_of_an_invite_in_flight_judges_the_invitation_that_replaced_it() {
    let replaced = || Script {
        before_release: 1,
        ..Script::default()
    };
    let later = replacement(2);
    let Some((r, answer)) = revoke_in_flight(replaced(), "MEMBER").await else { return };
    assert!(matches!(answer, Ok(true)));
    assert!(!live(&r, &later).await);
    let Some((r, answer)) = revoke_in_flight(replaced(), "ADMIN").await else { return };
    assert!(matches!(answer, Ok(false)));
    assert_eq!(indexed(&r.s, EMAIL).await, Some(token_hash(&later)));
    assert!(live(&r, &later).await);
}
