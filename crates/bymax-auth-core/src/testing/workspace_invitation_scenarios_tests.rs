//! The invitation scenarios run against the in-memory store, and refuse a store that breaks any
//! one rule (layer: test support, tests).
//!
//! A runner that passes every store proves nothing about the stores it passes. Each case wraps the
//! in-memory store to misbehave in exactly one way and requires the run to fail.

use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::InMemoryWorkspaceInvitations;
use super::workspace_invitation_scenarios::{
    self as scenarios, InvitationStoreProbe, run_invitation_store_scenarios,
};
use crate::traits::{
    IndexedInvitation, InvitationPlace, PendingInvitation, Publication, PublishOutcome,
    WorkspaceInvitationStore,
};
use crate::workspace::invitation::InvitationRecord;
use crate::workspace::limits::INVITER_WINDOW_SECONDS;

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
    /// A publication leaves every lifetime shorter than the one it was given.
    ShortensTheLifetimes,
    /// A publication leaves the index living far longer than the record.
    StretchesTheLifetimes,
    /// A publication counts the members whose record is gone.
    CountsGoneRecords,
    /// A record key that holds no record reads as a record.
    InventsARecord,
    /// A bootstrap record reads as absent.
    DropsBootstrapRecords,
    /// A publication with no cap still prunes the set.
    PrunesWhenUncapped,
    /// Every increment starts the counter's hour over.
    ResetsTheWindow,
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

impl Broken {
    /// Publishes, then leaves the index living for a different time than the one it was given.
    async fn moves_the_index_lifetime(
        &self,
        publication: Publication<'_>,
    ) -> Result<PublishOutcome, AuthError> {
        let outcome = self.inner.publish(publication).await?;
        let seconds = if matches!(self.fault, Fault::ShortensTheLifetimes) {
            60
        } else {
            6_000
        };
        let ttl = Duration::from_secs(seconds);
        self.inner
            .point_index(publication.place, publication.record_key, ttl)
            .await;
        Ok(outcome)
    }

    /// The faults that act before the publication reaches the store: an answer of their own, or a
    /// prune the store would not have made.
    async fn before_publishing(
        &self,
        publication: &Publication<'_>,
    ) -> Result<Option<PublishOutcome>, AuthError> {
        let uncapped = publication.pending_limit == 0;
        if matches!(self.fault, Fault::PrunesWhenUncapped) && uncapped {
            self.inner.pending(publication.place).await?;
        }
        if matches!(self.fault, Fault::CountsGoneRecords) && !uncapped {
            let held = self.inner.set_members(publication.place).await.len();
            let limit = usize::try_from(publication.pending_limit).unwrap_or(usize::MAX);
            if publication.expected_key.is_none() && held >= limit {
                return Ok(Some(PublishOutcome::Full));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl WorkspaceInvitationStore for Broken {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        let read = self.inner.read_record(record_key).await?;
        Ok(match (self.fault, read) {
            (Fault::InventsARecord, None) => InvitationRecord::parse(&record_json()),
            (Fault::DropsBootstrapRecords, Some(InvitationRecord::Bootstrap { .. })) => None,
            (_, read) => read,
        })
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        self.inner.read_index(place).await
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        if let Some(outcome) = self.before_publishing(&publication).await? {
            return Ok(outcome);
        }
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
            Fault::ShortensTheLifetimes | Fault::StretchesTheLifetimes => {
                return self.moves_the_index_lifetime(publication).await;
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
        let left = self.inner.rate_ttl(rate_id).await;
        if matches!(self.fault, Fault::ResetsTheWindow) {
            return left.map(|_| INVITER_WINDOW_SECONDS);
        }
        left
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

#[tokio::test]
async fn an_unavailable_store_fails_every_call_and_recovers_when_it_is_back() {
    let store = InMemoryWorkspaceInvitations::new();
    let place = InvitationPlace {
        index_id: "index".to_owned(),
        set_id: "set".to_owned(),
    };
    store.set_unavailable(true);
    assert!(store.read_record("winv:k").await.is_err());
    assert!(store.read_index(&place).await.is_err());
    let raw = r#"{"email":"a@example.com","role":"member","tenantId":"t1","workspaceId":"w1","createdAt":"2026-11-20T10:00:00.000Z","resendCount":0,"kind":"member","inviterUserId":"u1"}"#;
    let record = InvitationRecord::parse(raw);
    assert!(record.is_some(), "the fixture record must parse");
    if let Some(record) = record {
        let publication = Publication {
            place: &place,
            record_key: "winv:k",
            record: &record,
            ttl: std::num::NonZeroU64::MIN,
            pending_limit: 0,
            expected_key: None,
        };
        assert!(store.publish(publication).await.is_err());
    }
    assert!(store.remove(&place, "winv:k").await.is_err());
    assert!(store.pending(&place).await.is_err());
    assert!(store.count_inviter("rate").await.is_err());
    store.set_unavailable(false);
    assert!(matches!(store.count_inviter("rate").await, Ok(1)));
    assert!(matches!(store.read_record("winv:k").await, Ok(None)));
    assert!(matches!(store.read_index(&place).await, Ok(None)));
}

/// Whether one scenario, played alone, panics on a store with `fault`.
async fn alone_fails<F, Fut>(fault: Fault, play: F) -> bool
where
    F: FnOnce(std::sync::Arc<Broken>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move { play(std::sync::Arc::new(Broken::new(fault))).await })
        .await
        .is_err()
}

#[tokio::test]
async fn a_scenario_written_for_a_fault_fails_alone_on_a_store_with_that_fault() {
    let cases = [
        alone_fails(Fault::ShortensTheLifetimes, |s| async move {
            scenarios::a_first_publication_writes_all_three_structures_with_one_lifetime(&*s).await;
        })
        .await,
        alone_fails(Fault::StretchesTheLifetimes, |s| async move {
            scenarios::a_first_publication_writes_all_three_structures_with_one_lifetime(&*s).await;
        })
        .await,
        alone_fails(Fault::IgnoresTheCap, |s| async move {
            scenarios::the_cap_refuses_a_first_invitation_and_a_replacement_skips_it(&*s).await;
        })
        .await,
        alone_fails(Fault::CountsGoneRecords, |s| async move {
            scenarios::a_gone_record_is_dropped_before_the_cap_is_counted(&*s).await;
        })
        .await,
        alone_fails(Fault::InventsARecord, |s| async move {
            scenarios::a_foreign_value_under_a_record_key_reads_as_absent(&*s).await;
        })
        .await,
        alone_fails(Fault::StretchesTheLifetimes, |s| async move {
            scenarios::everything_expires_together_and_an_expired_index_is_replaced_like_any_other(
                &*s,
            )
            .await;
        })
        .await,
        alone_fails(Fault::DropsBootstrapRecords, |s| async move {
            scenarios::a_bootstrap_record_reads_back_as_written(&*s).await;
        })
        .await,
        alone_fails(Fault::PrunesWhenUncapped, |s| async move {
            scenarios::an_uncapped_publication_leaves_a_dead_member_alone(&*s).await;
        })
        .await,
        alone_fails(Fault::ResetsTheWindow, |s| async move {
            scenarios::the_inviter_counter_starts_its_hour_at_the_first_increment(&*s).await;
        })
        .await,
    ];
    assert_eq!(
        cases, [true; 9],
        "a scenario that passed on its broken store"
    );
}

#[tokio::test]
async fn a_record_is_readable_strictly_before_the_instant_it_expires() {
    let store = InMemoryWorkspaceInvitations::new();
    store.freeze_clock();
    store
        .plant_raw_record("winv:k", &record_json(), Duration::from_secs(10))
        .await;
    store.advance_clock(Duration::from_secs(9));
    assert!(matches!(store.read_record("winv:k").await, Ok(Some(_))));
    store.advance_clock(Duration::from_secs(1));
    assert!(matches!(store.read_record("winv:k").await, Ok(None)));
}

#[tokio::test]
async fn a_frozen_clock_stays_where_it_was_stopped() {
    let store = InMemoryWorkspaceInvitations::new();
    store.freeze_clock();
    store
        .plant_raw_record("winv:k", &record_json(), Duration::from_secs(600))
        .await;
    std::thread::sleep(Duration::from_millis(1_200));
    assert_eq!(store.record_ttl("winv:k").await, Some(600));
}
