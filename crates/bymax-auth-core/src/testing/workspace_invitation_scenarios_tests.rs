//! The invitation scenarios run against the in-memory store, and refuse a store that breaks any
//! one rule (layer: test support, tests).
//!
//! A runner that passes every store proves nothing about the stores it passes. Each case wraps the
//! in-memory store to misbehave in exactly one way and requires the run to fail.

use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::InMemoryWorkspaceInvitations;
use super::workspace_invitation_scenarios::{InvitationStoreProbe, run_invitation_store_scenarios};
use crate::traits::{
    IndexedInvitation, InvitationPlace, PendingInvitation, Publication, PublishOutcome,
    WorkspaceInvitationStore,
};
use crate::workspace::invitation::InvitationRecord;

#[tokio::test]
async fn the_in_memory_store_passes_every_scenario() {
    let store = InMemoryWorkspaceInvitations::new();
    store.freeze_clock();
    run_invitation_store_scenarios(&store).await;
}

/// The one way a [`Broken`] store misbehaves.
#[derive(Clone, Copy)]
enum Fault {
    /// A publication does not compare the index with what the writer read.
    IgnoresTheIndexComparison,
    /// A publication never refuses a full workspace.
    IgnoresTheCap,
    /// A publication refuses a full workspace even when it replaces a record.
    CapsAReplacement,
    /// A publication leaves the record it replaces in place.
    KeepsTheReplacedRecord,
    /// A removal deletes the index even when it names another record.
    RemovesAnotherRecordsIndex,
    /// A removal leaves the record in place.
    KeepsTheRemovedRecord,
    /// A listing keeps a member whose record is gone.
    ListsDeadMembers,
    /// A count answers one whatever came before.
    ForgetsTheCount,
}

struct Broken {
    inner: InMemoryWorkspaceInvitations,
    fault: Fault,
}

impl Broken {
    fn new(fault: Fault) -> Self {
        let inner = InMemoryWorkspaceInvitations::new();
        inner.freeze_clock();
        Self { inner, fault }
    }
}

#[async_trait]
impl WorkspaceInvitationStore for Broken {
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
        let mut changed = publication;
        match self.fault {
            Fault::IgnoresTheIndexComparison => {
                // Reads the index first and then claims to have expected what it found.
                let found = self.inner.read_index(publication.place).await?;
                changed.expected_key = found.as_ref().map(|i| i.record_key.as_str());
                let outcome = self.inner.publish(changed).await?;
                // The record it was meant to replace (expected) is the one it kept.
                return Ok(outcome);
            }
            Fault::IgnoresTheCap => changed.pending_limit = 0,
            Fault::CapsAReplacement => {
                if publication.expected_key.is_some() {
                    changed.pending_limit = 1;
                }
            }
            Fault::KeepsTheReplacedRecord => {
                let outcome = self.inner.publish(publication).await?;
                if let (PublishOutcome::Published, Some(old)) = (outcome, publication.expected_key)
                {
                    self.inner
                        .plant_raw_record(
                            old,
                            &publication.record.to_json(),
                            Duration::from_secs(600),
                        )
                        .await;
                }
                return Ok(outcome);
            }
            _ => {}
        }
        self.inner.publish(changed).await
    }

    async fn remove(&self, place: &InvitationPlace, record_key: &str) -> Result<bool, AuthError> {
        match self.fault {
            Fault::RemovesAnotherRecordsIndex => {
                let named = self.inner.read_index(place).await?;
                let removed = self.inner.remove(place, record_key).await?;
                if let Some(named) = named
                    && !removed
                {
                    self.inner.remove(place, &named.record_key).await?;
                }
                Ok(removed)
            }
            Fault::KeepsTheRemovedRecord => {
                let removed = self.inner.remove(place, record_key).await?;
                self.inner
                    .plant_raw_record(record_key, &record_json(), Duration::from_secs(600))
                    .await;
                Ok(removed)
            }
            _ => self.inner.remove(place, record_key).await,
        }
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        let mut listed = self.inner.pending(place).await?;
        if matches!(self.fault, Fault::ListsDeadMembers)
            && let Some(first) = listed.first().cloned()
        {
            listed.push(PendingInvitation {
                record_key: "winv:ghost".to_owned(),
                ..first
            });
        }
        Ok(listed)
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        let count = self.inner.count_inviter(rate_id).await?;
        Ok(if matches!(self.fault, Fault::ForgetsTheCount) {
            1
        } else {
            count
        })
    }
}

#[async_trait]
impl InvitationStoreProbe for Broken {
    async fn pass_time(&self, by: Duration) {
        self.inner.pass_time(by).await;
    }
    async fn plant_raw_record(&self, record_key: &str, raw: &str, ttl: Duration) {
        self.inner.plant_raw_record(record_key, raw, ttl).await;
    }
    async fn point_index(&self, place: &InvitationPlace, record_key: &str, ttl: Duration) {
        self.inner.point_index(place, record_key, ttl).await;
    }
    async fn delete_record(&self, record_key: &str) {
        self.inner.delete_record(record_key).await;
    }
    async fn set_members(&self, place: &InvitationPlace) -> Vec<String> {
        self.inner.set_members(place).await
    }
    async fn record_ttl(&self, record_key: &str) -> Option<u64> {
        self.inner.record_ttl(record_key).await
    }
    async fn index_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        self.inner.index_ttl(place).await
    }
    async fn set_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        self.inner.set_ttl(place).await
    }
    async fn rate_ttl(&self, rate_id: &str) -> Option<u64> {
        self.inner.rate_ttl(rate_id).await
    }
}

/// A record any scenario can read back.
fn record_json() -> String {
    InvitationRecord::Member {
        base: crate::workspace::invitation::InvitationBase {
            email: "a@x".to_owned(),
            role: "member".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: "2026-11-20T10:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        inviter_user_id: "u1".to_owned(),
    }
    .to_json()
}

/// Whether the run panics on a store with `fault`: a failed assertion in a task ends it with an
/// error, which is how the run reports the rule that was broken.
async fn run_fails(fault: Fault) -> bool {
    tokio::spawn(async move {
        let store = Broken::new(fault);
        run_invitation_store_scenarios(&store).await;
    })
    .await
    .is_err()
}

#[tokio::test]
async fn a_store_that_breaks_one_rule_fails_the_run() {
    for (name, fault) in [
        (
            "ignores the index comparison",
            Fault::IgnoresTheIndexComparison,
        ),
        ("ignores the cap", Fault::IgnoresTheCap),
        ("caps a replacement", Fault::CapsAReplacement),
        ("keeps the replaced record", Fault::KeepsTheReplacedRecord),
        (
            "removes another record's index",
            Fault::RemovesAnotherRecordsIndex,
        ),
        ("keeps the removed record", Fault::KeepsTheRemovedRecord),
        ("lists dead members", Fault::ListsDeadMembers),
        ("forgets the count", Fault::ForgetsTheCount),
    ] {
        assert!(run_fails(fault).await, "a store that {name} passed the run");
    }
}
