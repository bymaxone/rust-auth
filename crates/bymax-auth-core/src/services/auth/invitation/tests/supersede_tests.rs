//! Re-inviting an address: the caller must outrank the pending invitation they would destroy,
//! and the publication is a compare-and-swap against the invitation that rank check approved.

use std::sync::Mutex;

use async_trait::async_trait;

use super::*;
use crate::traits::{InvitationStore, InvitationWithdrawal};

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
        .read_invitation_record(hash)
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

    let (events, capture) = crate::log_capture::capture_events();
    let refused = s
        .engine
        .invite(&member, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    drop(capture);
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );
    // The refusal is recorded where an operator can see it and the caller cannot.
    assert!(events.contains_at(tracing::Level::WARN, "outranked by the pending invitation"));

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
    // Exactly one live record: the member's was replaced, not joined. This also shows the count
    // helper counts, so the "none left" assertion in the mid-invite test is not vacuous.
    assert_eq!(s.stores.invitation_record_count(), 1);
}

/// A pending invitation granting `role`.
fn pending_record(role: &str) -> StoredInvitation {
    StoredInvitation {
        email: PENDING_EMAIL.to_owned(),
        role: role.to_owned(),
        tenant_id: "t1".to_owned(),
        inviter_user_id: "someone".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A store that publishes the next of `moves` over the address immediately before each of the
/// caller's publications, standing in for another inviter writing between the rank check and the
/// write.
struct Racing {
    inner: Arc<InMemoryStores>,
    moves: Mutex<Vec<(String, StoredInvitation)>>,
    fail_publish: bool,
}

#[async_trait]
impl InvitationStore for Racing {
    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        self.inner.consume_invitation(token).await
    }
    async fn publish_invitation(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        invitation: &StoredInvitation,
        ttl_secs: u64,
        superseded: Option<&str>,
    ) -> Result<bool, AuthError> {
        if self.fail_publish {
            return Err(crate::services::internal_error("publish failed"));
        }
        let next = self
            .moves
            .lock()
            .ok()
            .and_then(|mut m| (!m.is_empty()).then(|| m.remove(0)));
        if let Some((hash, record)) = next {
            let held = self
                .inner
                .read_invitation_index(tenant_id, invitee_hash)
                .await?;
            self.inner
                .publish_invitation(
                    tenant_id,
                    invitee_hash,
                    &hash,
                    &record,
                    ttl_secs,
                    held.as_deref(),
                )
                .await?;
        }
        self.inner
            .publish_invitation(
                tenant_id,
                invitee_hash,
                token_hash,
                invitation,
                ttl_secs,
                superseded,
            )
            .await
    }
    async fn withdraw_invitation(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        judged: Option<&str>,
    ) -> Result<InvitationWithdrawal, AuthError> {
        self.inner
            .withdraw_invitation(tenant_id, invitee_hash, token_hash, judged)
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
    async fn release_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        expected: &str,
    ) -> Result<bool, AuthError> {
        self.inner
            .release_invitation_index(tenant_id, invitee_hash, expected)
            .await
    }
    async fn read_invitation_record(&self, token_hash: &str) -> Result<Option<String>, AuthError> {
        self.inner.read_invitation_record(token_hash).await
    }
}

/// An engine whose invitation store races or fails the publication.
fn racing_setup(moves: Vec<(String, StoredInvitation)>, fail_publish: bool) -> Option<Setup> {
    let s = setup(invite_config())?;
    let racing = Arc::new(Racing {
        inner: s.stores.clone(),
        moves: Mutex::new(moves),
        fail_publish,
    });
    let engine = AuthEngine::builder()
        .config(invite_config())
        .environment(Environment::Test)
        .user_repository(s.users.clone())
        .redis_stores(s.stores.clone())
        .invitation_store(racing)
        .build()
        .ok()?;
    Some(Setup { engine, ..s })
}

#[tokio::test]
async fn an_invitation_that_appears_between_the_check_and_the_write_is_not_displaced_by_an_outranked_caller()
 {
    // The member's first rank check sees an empty index and approves "nothing pending". An
    // ADMIN invitation lands before the publication, so it must be refused by the store, and the
    // retry must re-derive the approval against the ADMIN record and refuse.
    let admin_hash = "a".repeat(64);
    let moves = vec![(admin_hash.clone(), pending_record("ADMIN"))];
    let Some(s) = racing_setup(moves, false) else { return };
    let member = seed_admin(&s.users, "member@example.com", "MEMBER").await;

    let refused = s
        .engine
        .invite(&member, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );
    assert_eq!(indexed(&s).await.as_deref(), Some(admin_hash.as_str()));
    assert!(record_exists(&s, &admin_hash).await);
    assert_eq!(s.stores.invitation_record_count(), 1);
}

#[tokio::test]
async fn an_index_that_keeps_moving_exhausts_the_retries_and_is_refused() {
    // Three publications, three concurrent writes: the caller was never shown to be allowed to
    // destroy whatever is there now, so the answer is a refusal, not an unbounded loop.
    let moves = (0..3)
        .map(|n| (format!("{n:064x}"), pending_record("MEMBER")))
        .collect();
    let Some(s) = racing_setup(moves, false) else { return };
    let admin = seed_admin(&s.users, "admin3@example.com", "ADMIN").await;

    let (events, capture) = crate::log_capture::capture_events();
    let refused = s
        .engine
        .invite(&admin, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    drop(capture);
    assert!(
        matches!(refused, Err(AuthError::InsufficientRole)),
        "{refused:?}"
    );
    assert!(events.contains_at(tracing::Level::WARN, "kept changing under the rank check"));
    // Only the last concurrent invitation is left.
    assert_eq!(indexed(&s).await, Some(format!("{:064x}", 2)));
    assert_eq!(s.stores.invitation_record_count(), 1);
}

#[tokio::test]
async fn a_store_error_while_publishing_is_surfaced_and_leaves_nothing_behind() {
    let Some(s) = racing_setup(Vec::new(), true) else { return };
    let admin = seed_admin(&s.users, "admin5@example.com", "ADMIN").await;

    let outcome = s
        .engine
        .invite(&admin, PENDING_EMAIL, "MEMBER", "t1", None)
        .await;
    assert!(
        matches!(outcome, Err(AuthError::Internal(_))),
        "{outcome:?}"
    );
    assert_eq!(indexed(&s).await, None);
    assert_eq!(s.stores.invitation_record_count(), 0);
}
