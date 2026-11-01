//! Re-inviting an address: the caller must outrank the pending invitation they would destroy,
//! and the claim is a compare-and-swap against the invitation that rank check approved.

use std::sync::Mutex;

use async_trait::async_trait;

use super::*;
use crate::traits::InvitationStore;

const PENDING_EMAIL: &str = "bob@example.com";

/// The invitee-index token hash currently naming the address, if any.
async fn indexed(s: &Setup) -> Option<String> {
    let engine_hash = s.engine.invitee_identifier(PENDING_EMAIL);
    s.stores
        .read_invitation_index("t1", &engine_hash)
        .await
        .unwrap_or_default()
}

/// Whether a record still exists under the hash.
async fn record_exists(s: &Setup, hash: &str) -> bool {
    s.stores
        .read_invitation_by_hash(hash)
        .await
        .map(|found| found.is_some())
        .unwrap_or(false)
}

/// Seed one `ADMIN` and one `MEMBER` inviter and return their ids.
async fn seed_inviters(s: &Setup) -> (String, String) {
    let admin = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
    let member = seed_admin(&s.users, "member@example.com", "MEMBER").await;
    (admin, member)
}

#[tokio::test]
async fn a_member_cannot_replace_a_pending_admin_invitation() {
    // `invite` authorises the role being REQUESTED. Without a check on the pending record, a
    // member could post a MEMBER invitation for an address and destroy a pending ADMIN one — a
    // withdrawal the revoke route refuses them.
    let Some(s) = setup(invite_config()) else { return };
    let (admin, member) = seed_inviters(&s).await;
    assert!(
        s.engine
            .invite(&admin, PENDING_EMAIL, "ADMIN", "t1", None)
            .await
            .is_ok()
    );
    let pending = indexed(&s).await;
    assert!(pending.is_some());
    let Some(pending) = pending else { return };

    let refused = s
        .engine
        .invite(&member, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );

    // The ADMIN invitation is untouched: still indexed, still a record.
    assert_eq!(indexed(&s).await.as_deref(), Some(pending.as_str()));
    assert!(record_exists(&s, &pending).await);
}

#[tokio::test]
async fn an_inviter_who_outranks_the_pending_invitation_replaces_it() {
    let Some(s) = setup(invite_config()) else { return };
    let (admin, member) = seed_inviters(&s).await;
    assert!(
        s.engine
            .invite(&member, PENDING_EMAIL, "MEMBER", "t1", None)
            .await
            .is_ok()
    );
    let first = indexed(&s).await;
    let Some(first) = first else { return };

    // An ADMIN re-inviting the address supersedes the member's invitation.
    assert!(
        s.engine
            .invite(&admin, PENDING_EMAIL, "MEMBER", "t1", None)
            .await
            .is_ok()
    );
    let second = indexed(&s).await;
    assert!(matches!(&second, Some(h) if *h != first), "{second:?}");
    assert!(
        !record_exists(&s, &first).await,
        "the superseded record must be gone"
    );
    let Some(second) = second else { return };
    assert!(record_exists(&s, &second).await);
}

/// A store that runs `moves` against the shared index immediately before each claim, standing in
/// for another inviter writing between the rank check and the claim.
struct Racing {
    inner: Arc<InMemoryStores>,
    tenant: String,
    invitee: String,
    moves: Mutex<Vec<String>>,
}

#[async_trait]
impl InvitationStore for Racing {
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &StoredInvitation,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner.put_invitation(token, invitation, ttl_secs).await
    }
    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        self.inner.consume_invitation(token).await
    }
    async fn put_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .put_invitation_index(tenant_id, invitee_hash, token_hash, ttl_secs)
            .await
    }
    async fn claim_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        ttl_secs: u64,
        expected: Option<&str>,
    ) -> Result<bool, AuthError> {
        let next = self
            .moves
            .lock()
            .ok()
            .and_then(|mut m| (!m.is_empty()).then(|| m.remove(0)));
        if let Some(next) = next {
            self.inner
                .put_invitation_index(&self.tenant, &self.invitee, &next, ttl_secs)
                .await?;
        }
        self.inner
            .claim_invitation_index(tenant_id, invitee_hash, token_hash, ttl_secs, expected)
            .await
    }
    async fn read_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, AuthError> {
        self.inner
            .read_invitation_index(tenant_id, invitee_hash)
            .await
    }
    async fn take_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, AuthError> {
        self.inner
            .take_invitation_index(tenant_id, invitee_hash)
            .await
    }
    async fn read_invitation_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredInvitation>, AuthError> {
        self.inner.read_invitation_by_hash(token_hash).await
    }
    async fn delete_invitation_by_hash(&self, token_hash: &str) -> Result<bool, AuthError> {
        self.inner.delete_invitation_by_hash(token_hash).await
    }
}

/// An engine whose invitation store races the claim with the given index values.
fn racing_setup(moves: Vec<String>) -> Option<(Setup, Arc<Racing>)> {
    let s = setup(invite_config())?;
    let racing = Arc::new(Racing {
        inner: s.stores.clone(),
        tenant: "t1".to_owned(),
        invitee: s.engine.invitee_identifier(PENDING_EMAIL),
        moves: Mutex::new(moves),
    });
    let engine = AuthEngine::builder()
        .config(invite_config())
        .environment(Environment::Test)
        .user_repository(s.users.clone())
        .redis_stores(s.stores.clone())
        .invitation_store(racing.clone())
        .build()
        .ok()?;
    Some((Setup { engine, ..s }, racing))
}

#[tokio::test]
async fn an_invitation_that_appears_between_the_check_and_the_claim_is_not_displaced_by_an_outranked_caller()
 {
    // The member's first rank check sees an empty index and approves "nothing pending". An
    // ADMIN invitation lands before the claim, so the claim must fail rather than overwrite it,
    // and the retry must re-derive the approval against the ADMIN record and refuse.
    let Some((s, racing)) = racing_setup(Vec::new()) else { return };
    let (admin, member) = seed_inviters(&s).await;
    // An ADMIN invitation for another address, whose index entry the race will copy onto the
    // contested address.
    assert!(
        s.engine
            .invite(&admin, "other@example.com", "ADMIN", "t1", None)
            .await
            .is_ok()
    );
    let admin_hash = s
        .stores
        .read_invitation_index("t1", &s.engine.invitee_identifier("other@example.com"))
        .await
        .unwrap_or_default();
    let Some(admin_hash) = admin_hash else { return };
    if let Ok(mut moves) = racing.moves.lock() {
        moves.push(admin_hash.clone());
    }
    let member_id = member;

    let refused = s
        .engine
        .invite(&member_id, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );
    assert_eq!(indexed(&s).await.as_deref(), Some(admin_hash.as_str()));
    assert!(record_exists(&s, &admin_hash).await);
}

#[tokio::test]
async fn an_index_that_keeps_moving_exhausts_the_retries_and_is_refused() {
    // Three claims, three concurrent writes: the caller was never shown to be allowed to destroy
    // whatever is there now, so the answer is a refusal, not an unbounded loop.
    let hashes: Vec<String> = (0..3).map(|n| format!("{n:064x}")).collect();
    let Some((s, _racing)) = racing_setup(hashes) else { return };
    let admin = seed_admin(&s.users, "admin3@example.com", "ADMIN").await;

    let refused = s
        .engine
        .invite(&admin, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );
}
