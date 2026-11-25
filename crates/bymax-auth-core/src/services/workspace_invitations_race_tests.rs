//! The invitation services against a store that is written by someone else between two of their
//! calls: a revoke or an invitation that reads an address, and a replacement that lands before the
//! write (layer: service, tests).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::workspace_invitations_support_tests::{
    Inv, Seeded, is_limited, key_of, place, seed, setup_over,
};
use super::workspace_support_tests::config;
use crate::services::auth::test_support::ctx;
use crate::testing::InMemoryWorkspaceInvitations;
use crate::traits::workspace_invitation_store::{IndexedInvitation, PendingInvitation, Removal};
use crate::traits::{InvitationPlace, Publication, PublishOutcome, WorkspaceInvitationStore};
use crate::workspace::audit::AuditKind;
use crate::workspace::invitation::{InvitationBase, InvitationRecord};

const LONG_AGO: &str = "2026-01-01T00:00:00.000Z";

/// A store that, after answering a read of an address's index, publishes a replacement invitation
/// for that address under a new token, so the reader holds what is already stale. It does so for
/// the first `rounds` reads.
struct Racing {
    inner: Arc<InMemoryWorkspaceInvitations>,
    rounds: AtomicUsize,
    role: &'static str,
}

impl Racing {
    fn over(
        inner: Arc<InMemoryWorkspaceInvitations>,
        rounds: usize,
        role: &'static str,
    ) -> Arc<dyn WorkspaceInvitationStore> {
        Arc::new(Self {
            inner,
            rounds: AtomicUsize::new(rounds),
            role,
        })
    }

    /// Publishes the replacement for `place` over what the index held.
    async fn replace(&self, place: &InvitationPlace, held: Option<&str>, email: &str) {
        let round = self.rounds.load(Ordering::SeqCst);
        let key = key_of(&format!("raced-token-{round}"));
        let record = InvitationRecord::Member {
            base: InvitationBase {
                email: email.to_owned(),
                role: self.role.to_owned(),
                tenant_id: "t1".to_owned(),
                workspace_id: "w1".to_owned(),
                created_at: LONG_AGO.to_owned(),
                resend_count: 0,
            },
            inviter_user_id: "someone-else".to_owned(),
        };
        let ttl = std::num::NonZeroU64::new(600).unwrap_or(std::num::NonZeroU64::MIN);
        let outcome = self
            .inner
            .publish(Publication {
                place,
                record_key: &key,
                record: &record,
                ttl,
                pending_limit: 0,
                expected_key: held,
            })
            .await;
        assert!(
            matches!(outcome, Ok(PublishOutcome::Published)),
            "the racing writer must win: {outcome:?}"
        );
    }
}

#[async_trait]
impl WorkspaceInvitationStore for Racing {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        self.inner.read_record(record_key).await
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        let read = self.inner.read_index(place).await?;
        let left = self.rounds.load(Ordering::SeqCst);
        if left > 0 {
            let held = read.as_ref().map(|indexed| indexed.record_key.clone());
            self.replace(place, held.as_deref(), "race@x.io").await;
            self.rounds.store(left - 1, Ordering::SeqCst);
        }
        Ok(read)
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
        self.inner.remove(place, record_key, removal).await
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        self.inner.pending(place).await
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        self.inner.count_inviter(rate_id).await
    }
}

/// A fixture over a racing store, with `race@x.io` invited to `role` by the owner.
async fn racing(rounds: usize, replacement_role: &'static str, role: &str) -> Option<Inv> {
    let inv = setup_over(config(), |store| {
        Racing::over(store, rounds, replacement_role)
    })
    .await?;
    let first = Seeded {
        email: "race@x.io",
        role,
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "first-token", &first).await;
    Some(inv)
}

async fn held(inv: &Inv) -> Option<IndexedInvitation> {
    inv.store
        .read_index(&place(inv, "race@x.io"))
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn a_revoke_that_lost_the_index_once_removes_the_replacement_and_reports_what_it_removed() {
    // Seeding reads nothing, so the first read of the revoke is the racing one. Armed after.
    // The roles differ, so an event that named the invitation first read would be caught.
    let Some(inv) = racing(1, "admin", "member").await else { return };
    let revoked = inv
        .f
        .engine
        .revoke_workspace_invitation(&inv.owner, "race@x.io", &ctx())
        .await;
    assert!(revoked.is_ok(), "{revoked:?}");
    assert!(
        held(&inv).await.is_none(),
        "the replacement must be gone too"
    );
    let events = inv.f.hooks.events(1).await;
    assert_eq!(events.len(), 1, "one revoke, one event: {events:?}");
    assert!(matches!(
        events.first().map(|event| &event.kind),
        Some(AuditKind::InvitationRevoked { email, role }) if email == "race@x.io" && role == "admin"
    ));
}

#[tokio::test]
async fn a_revoke_that_keeps_losing_the_index_answers_too_many_requests_and_reports_nothing() {
    let Some(inv) = racing(10, "member", "member").await else { return };
    let revoked = inv
        .f
        .engine
        .revoke_workspace_invitation(&inv.owner, "race@x.io", &ctx())
        .await;
    assert!(is_limited(&revoked), "{revoked:?}");
    let events = inv.f.hooks.events(0).await;
    assert!(events.is_empty(), "nothing was removed: {events:?}");
}

#[tokio::test]
async fn a_replacement_above_the_actor_is_not_removed_by_the_retry_of_a_lost_revoke() {
    // The admin may revoke a member invitation; the one that replaced it is an admin's, which the
    // admin may not act on, so it reads as absent and survives.
    let Some(inv) = racing(1, "admin", "member").await else { return };
    let revoked = inv
        .f
        .engine
        .revoke_workspace_invitation(&inv.admin, "race@x.io", &ctx())
        .await;
    assert!(revoked.is_ok(), "{revoked:?}");
    let still = held(&inv).await;
    assert!(
        still.is_some_and(|indexed| indexed.record.is_some_and(|r| r.base().role == "admin")),
        "the invitation above the actor must survive"
    );
    let events = inv.f.hooks.events(0).await;
    assert!(events.is_empty(), "nothing was removed: {events:?}");
}

#[tokio::test]
async fn an_invitation_whose_index_moved_before_the_write_answers_too_many_requests() {
    // A first invitation: the index is empty when read and held by a stranger when written.
    let Some(inv) = setup_over(config(), |s| Racing::over(s, 1, "member")).await else { return };
    let invited = inv
        .f
        .engine
        .invite_workspace_member(&inv.owner, "race@x.io", "member", &ctx())
        .await;
    assert!(is_limited(&invited), "{invited:?}");
    assert!(inv.mail.sent().is_empty(), "a lost write mails nothing");
}
