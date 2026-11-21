//! The scenarios of the workspace invitation store, shared by every implementation (layer: test
//! support).
//!
//! `workspaceInvitations` in the shared wire contract states what the three structures must do
//! together: one atomic publication that a stale writer loses, a cap counted after dead members
//! are dropped, a replacement that skips the cap, a record that expires with its index and set,
//! and a counter whose lifetime starts at its first increment. The scenarios play those rules
//! against any [`InvitationStoreProbe`], so the in-memory store and the Redis store run the same
//! steps and cannot drift. Each scenario uses ids of its own, so they can share one backing store.

use std::num::NonZeroU64;
use std::time::Duration;

use async_trait::async_trait;

use crate::traits::{
    InvitationPlace, PendingInvitation, Publication, PublishOutcome, WorkspaceInvitationStore,
};
use crate::workspace::invitation::{InvitationBase, InvitationRecord};
use crate::workspace::limits::INVITER_WINDOW_SECONDS;

/// Direct access to a store's keyspace, which the scenarios need to plant a value, delete a
/// record under a live index, let time pass and read a remaining lifetime.
#[async_trait]
pub trait InvitationStoreProbe: WorkspaceInvitationStore {
    /// Lets `by` pass: the in-memory store advances its clock, a real store waits.
    async fn pass_time(&self, by: Duration);
    /// Writes `raw` under `record_key` with a lifetime of `ttl`, whatever it is.
    async fn plant_raw_record(&self, record_key: &str, raw: &str, ttl: Duration);
    /// Points the address's index at `record_key` with a lifetime of `ttl`.
    async fn point_index(&self, place: &InvitationPlace, record_key: &str, ttl: Duration);
    /// Deletes a record and nothing else, as its expiry would.
    async fn delete_record(&self, record_key: &str);
    /// The raw members of the place's pending set, sorted.
    async fn set_members(&self, place: &InvitationPlace) -> Vec<String>;
    /// Seconds the record has left, or `None` when there is none.
    async fn record_ttl(&self, record_key: &str) -> Option<u64>;
    /// Seconds the index has left, or `None` when there is none.
    async fn index_ttl(&self, place: &InvitationPlace) -> Option<u64>;
    /// Seconds the pending set has left, or `None` when there is none.
    async fn set_ttl(&self, place: &InvitationPlace) -> Option<u64>;
    /// Seconds the inviter counter has left, or `None` when there is none.
    async fn rate_ttl(&self, rate_id: &str) -> Option<u64>;
}

/// The lifetime most scenarios publish with.
const TTL: u64 = 600;

fn ttl(seconds: u64) -> NonZeroU64 {
    NonZeroU64::new(seconds).unwrap_or(NonZeroU64::MIN)
}

/// One scenario's ids.
struct Fixture {
    place: InvitationPlace,
    name: &'static str,
}

impl Fixture {
    fn new(name: &'static str) -> Self {
        Self {
            place: InvitationPlace {
                index_id: format!("{name}-index"),
                set_id: format!("{name}-set"),
            },
            name,
        }
    }

    /// Another address in the same workspace: its own index, the same set.
    fn neighbour(&self, address: &str) -> InvitationPlace {
        InvitationPlace {
            index_id: format!("{}-index-{address}", self.name),
            set_id: self.place.set_id.clone(),
        }
    }

    fn key(&self, suffix: &str) -> String {
        format!("winv:{}-{suffix}", self.name)
    }
}

fn record(email: &str) -> InvitationRecord {
    InvitationRecord::Member {
        base: InvitationBase {
            email: email.to_owned(),
            role: "member".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: "2026-11-20T10:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        inviter_user_id: "u1".to_owned(),
    }
}

async fn publish<S: WorkspaceInvitationStore + ?Sized>(
    store: &S,
    place: &InvitationPlace,
    key: &str,
    email: &str,
    limit: u32,
    expected: Option<&str>,
    seconds: u64,
) -> PublishOutcome {
    let outcome = store
        .publish(Publication {
            place,
            record_key: key,
            record: &record(email),
            ttl: ttl(seconds),
            pending_limit: limit,
            expected_key: expected,
        })
        .await;
    assert!(outcome.is_ok(), "publish failed: {outcome:?}");
    outcome.unwrap_or(PublishOutcome::Lost)
}

async fn pending<S: WorkspaceInvitationStore + ?Sized>(
    store: &S,
    place: &InvitationPlace,
) -> Vec<PendingInvitation> {
    let listed = store.pending(place).await;
    assert!(listed.is_ok(), "pending failed: {listed:?}");
    listed.unwrap_or_default()
}

fn within(left: Option<u64>, seconds: u64) -> bool {
    left.is_some_and(|left| left <= seconds && left + 10 >= seconds)
}

/// Plays every scenario against `store`.
///
/// # Panics
///
/// On the first rule the store breaks, naming it.
pub async fn run_invitation_store_scenarios<S: InvitationStoreProbe + ?Sized>(store: &S) {
    a_first_publication_writes_all_three_structures_with_one_lifetime(store).await;
    a_replacement_retires_the_record_it_replaces(store).await;
    a_writer_that_read_a_stale_index_writes_nothing(store).await;
    the_cap_refuses_a_first_invitation_and_a_replacement_skips_it(store).await;
    a_gone_record_is_dropped_before_the_cap_is_counted(store).await;
    a_removal_spends_the_record_the_index_and_the_set_member(store).await;
    a_removal_keeps_an_index_that_names_another_record(store).await;
    the_listing_drops_what_is_gone_and_shows_the_time_left(store).await;
    a_foreign_value_under_a_record_key_reads_as_absent(store).await;
    everything_expires_together_and_an_expired_index_is_replaced_like_any_other(store).await;
    the_inviter_counter_starts_its_hour_at_the_first_increment(store).await;
    a_bootstrap_record_reads_back_as_written(store).await;
    an_uncapped_publication_leaves_a_dead_member_alone(store).await;
}

pub(super) async fn a_first_publication_writes_all_three_structures_with_one_lifetime<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("first");
    let key = f.key("a");
    let outcome = publish(store, &f.place, &key, "a@x", 0, None, TTL).await;
    assert_eq!(outcome, PublishOutcome::Published, "first publication");
    assert_eq!(
        store.read_record(&key).await.ok().flatten(),
        Some(record("a@x"))
    );
    let indexed = store.read_index(&f.place).await.ok().flatten();
    assert_eq!(
        indexed.as_ref().map(|i| i.record_key.as_str()),
        Some(key.as_str())
    );
    assert_eq!(indexed.and_then(|i| i.record), Some(record("a@x")));
    assert_eq!(store.set_members(&f.place).await, vec![key.clone()]);
    assert!(within(store.record_ttl(&key).await, TTL), "record lifetime");
    assert!(
        within(store.index_ttl(&f.place).await, TTL),
        "index lifetime"
    );
    assert!(within(store.set_ttl(&f.place).await, TTL), "set lifetime");
}

async fn a_replacement_retires_the_record_it_replaces<S: InvitationStoreProbe + ?Sized>(store: &S) {
    let f = Fixture::new("replace");
    let (old, new) = (f.key("old"), f.key("new"));
    publish(store, &f.place, &old, "a@x", 0, None, TTL).await;
    let outcome = publish(store, &f.place, &new, "a@x", 0, Some(&old), TTL).await;
    assert_eq!(outcome, PublishOutcome::Published, "replacement");
    assert_eq!(
        store.read_record(&old).await.ok().flatten(),
        None,
        "old record"
    );
    assert_eq!(
        store.read_record(&new).await.ok().flatten(),
        Some(record("a@x"))
    );
    let indexed = store.read_index(&f.place).await.ok().flatten();
    assert_eq!(indexed.map(|i| i.record_key), Some(new.clone()), "index");
    assert_eq!(store.set_members(&f.place).await, vec![new], "set");
}

async fn a_writer_that_read_a_stale_index_writes_nothing<S: InvitationStoreProbe + ?Sized>(
    store: &S,
) {
    let f = Fixture::new("race");
    let (first, second, third) = (f.key("first"), f.key("second"), f.key("third"));
    publish(store, &f.place, &first, "a@x", 0, None, TTL).await;
    // A writer that read "no index" while another published the first invitation.
    let lost = publish(store, &f.place, &second, "a@x", 0, None, TTL).await;
    assert_eq!(lost, PublishOutcome::Lost, "expected no index, found one");
    // A writer that read the first record while another replaced it.
    publish(store, &f.place, &second, "a@x", 0, Some(&first), TTL).await;
    let stale = publish(store, &f.place, &third, "a@x", 0, Some(&first), TTL).await;
    assert_eq!(
        stale,
        PublishOutcome::Lost,
        "expected a record that was replaced"
    );
    assert_eq!(
        store.read_record(&third).await.ok().flatten(),
        None,
        "nothing written"
    );
    let indexed = store.read_index(&f.place).await.ok().flatten();
    assert_eq!(
        indexed.map(|i| i.record_key),
        Some(second.clone()),
        "index untouched"
    );
    assert_eq!(
        store.set_members(&f.place).await,
        vec![second],
        "exactly one record"
    );
}

pub(super) async fn the_cap_refuses_a_first_invitation_and_a_replacement_skips_it<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    // Cap 1 with one live invitation to a@x: a@x again succeeds, a first one to b@x does not.
    let f = Fixture::new("cap");
    let (a, a2, b) = (f.key("a"), f.key("a2"), f.key("b"));
    publish(store, &f.place, &a, "a@x", 1, None, TTL).await;
    let other = f.neighbour("b");
    let full = publish(store, &other, &b, "b@x", 1, None, TTL).await;
    assert_eq!(full, PublishOutcome::Full, "a first invitation at the cap");
    assert_eq!(
        store.read_record(&b).await.ok().flatten(),
        None,
        "nothing written"
    );
    assert_eq!(
        store.read_index(&other).await.ok().flatten(),
        None,
        "no index written"
    );
    let again = publish(store, &f.place, &a2, "a@x", 0, Some(&a), TTL).await;
    assert_eq!(
        again,
        PublishOutcome::Published,
        "a replacement skips the cap"
    );
    assert_eq!(
        store.set_members(&f.place).await,
        vec![a2],
        "the set did not grow"
    );
}

pub(super) async fn a_gone_record_is_dropped_before_the_cap_is_counted<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("dead");
    let (dead, fresh, replaced) = (f.key("dead"), f.key("fresh"), f.key("replaced"));
    publish(store, &f.place, &dead, "a@x", 1, None, TTL).await;
    store.delete_record(&dead).await;
    // The dead member still sits in the set; a first invitation to b@x at the cap succeeds.
    let other = f.neighbour("b");
    let outcome = publish(store, &other, &fresh, "b@x", 1, None, TTL).await;
    assert_eq!(
        outcome,
        PublishOutcome::Published,
        "the dead member is not counted"
    );
    assert_eq!(
        store.set_members(&f.place).await,
        vec![fresh],
        "the dead member is gone"
    );
    // An index that names a gone record is replaced like any other.
    let again = publish(store, &f.place, &replaced, "a@x", 0, Some(&dead), TTL).await;
    assert_eq!(
        again,
        PublishOutcome::Published,
        "a gone record's index is replaced"
    );
}

async fn a_removal_spends_the_record_the_index_and_the_set_member<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("remove");
    let old = f.key("old");
    publish(store, &f.place, &old, "a@x", 0, None, TTL).await;
    assert_eq!(
        store.remove(&f.place, &old).await.ok(),
        Some(true),
        "index named it"
    );
    assert_eq!(
        store.read_record(&old).await.ok().flatten(),
        None,
        "record gone"
    );
    assert_eq!(
        store.read_index(&f.place).await.ok().flatten(),
        None,
        "index gone"
    );
    assert!(
        store.set_members(&f.place).await.is_empty(),
        "set member gone"
    );
}

async fn a_removal_keeps_an_index_that_names_another_record<S: InvitationStoreProbe + ?Sized>(
    store: &S,
) {
    let f = Fixture::new("remove-other");
    let (old, new) = (f.key("old"), f.key("new"));
    // A resend landed between the write and the spend: the index names the new record.
    publish(store, &f.place, &old, "a@x", 0, None, TTL).await;
    publish(store, &f.place, &new, "a@x", 0, Some(&old), TTL).await;
    store
        .plant_raw_record(&old, &record("a@x").to_json(), Duration::from_secs(TTL))
        .await;
    assert_eq!(
        store.remove(&f.place, &old).await.ok(),
        Some(false),
        "index named another"
    );
    assert_eq!(
        store.read_record(&old).await.ok().flatten(),
        None,
        "own record still gone"
    );
    let indexed = store.read_index(&f.place).await.ok().flatten();
    assert_eq!(
        indexed.map(|i| i.record_key),
        Some(new.clone()),
        "index kept"
    );
    assert_eq!(
        store.set_members(&f.place).await,
        vec![new],
        "set entry kept"
    );
}

async fn the_listing_drops_what_is_gone_and_shows_the_time_left<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("listing");
    let (live, dead) = (f.key("live"), f.key("dead"));
    publish(store, &f.place, &live, "a@x", 0, None, TTL).await;
    publish(store, &f.neighbour("b"), &dead, "b@x", 0, None, TTL).await;
    store.delete_record(&dead).await;
    let listed = pending(store, &f.place).await;
    assert_eq!(listed.len(), 1, "only the live record is listed");
    assert_eq!(listed[0].record_key, live);
    assert_eq!(listed[0].record, record("a@x"));
    assert!(
        listed[0].ttl_seconds <= TTL && listed[0].ttl_seconds + 10 >= TTL,
        "time left"
    );
    assert_eq!(
        store.set_members(&f.place).await,
        vec![live],
        "the dead member is dropped"
    );
}

pub(super) async fn a_foreign_value_under_a_record_key_reads_as_absent<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("foreign");
    let key = f.key("x");
    store
        .plant_raw_record(&key, "not a record", Duration::from_secs(TTL))
        .await;
    assert_eq!(
        store.read_record(&key).await.ok().flatten(),
        None,
        "read as absent"
    );
    store
        .point_index(&f.place, &key, Duration::from_secs(TTL))
        .await;
    let indexed = store.read_index(&f.place).await.ok().flatten();
    assert_eq!(
        indexed.as_ref().map(|i| i.record_key.as_str()),
        Some(key.as_str())
    );
    assert_eq!(
        indexed.and_then(|i| i.record),
        None,
        "a live index over no record"
    );
}

pub(super) async fn everything_expires_together_and_an_expired_index_is_replaced_like_any_other<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("expiry");
    let (short, next) = (f.key("short"), f.key("next"));
    publish(store, &f.place, &short, "a@x", 1, None, 1).await;
    store.pass_time(Duration::from_millis(2_200)).await;
    assert_eq!(
        store.read_record(&short).await.ok().flatten(),
        None,
        "record expired"
    );
    assert_eq!(
        store.read_index(&f.place).await.ok().flatten(),
        None,
        "index expired"
    );
    assert!(
        pending(store, &f.place).await.is_empty(),
        "nothing is pending"
    );
    assert!(
        store.set_members(&f.place).await.is_empty(),
        "the set expired"
    );
    // The expired invitation leaves room for a first one at the cap, with no cooldown to honour.
    let outcome = publish(store, &f.place, &next, "a@x", 1, None, TTL).await;
    assert_eq!(
        outcome,
        PublishOutcome::Published,
        "published over an expired index"
    );
}

async fn the_inviter_counter_starts_its_hour_at_the_first_increment<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let rate = "rate-scenario";
    let counts = [
        store.count_inviter(rate).await.ok(),
        store.count_inviter(rate).await.ok(),
        store.count_inviter(rate).await.ok(),
    ];
    assert_eq!(counts, [Some(1), Some(2), Some(3)], "counts");
    let first = store.rate_ttl(rate).await;
    assert!(
        within(first, INVITER_WINDOW_SECONDS),
        "an hour from the first"
    );
    store.pass_time(Duration::from_secs(2)).await;
    store.count_inviter(rate).await.ok();
    let later = store.rate_ttl(rate).await;
    assert!(later <= first, "a later increment never extends the hour");
}

pub(super) async fn a_bootstrap_record_reads_back_as_written<S: InvitationStoreProbe + ?Sized>(
    store: &S,
) {
    let fixture = Fixture::new("bootstrap-roundtrip");
    let key = fixture.key("record");
    let written = InvitationRecord::Bootstrap {
        base: InvitationBase {
            email: "owner@example.com".to_owned(),
            role: "owner".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: "2026-11-20T10:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        workspace_name: "Acme".to_owned(),
    };
    let outcome = store
        .publish(Publication {
            place: &fixture.place,
            record_key: &key,
            record: &written,
            ttl: ttl(TTL),
            pending_limit: 0,
            expected_key: None,
        })
        .await;
    assert!(
        matches!(outcome, Ok(PublishOutcome::Published)),
        "a bootstrap record was not published: {outcome:?}"
    );
    let read = store.read_record(&key).await;
    assert!(
        matches!(&read, Ok(Some(found)) if *found == written),
        "a bootstrap record did not read back as written: {read:?}"
    );
}

/// With no cap there is nothing to count, so the set is not pruned.
pub(super) async fn an_uncapped_publication_leaves_a_dead_member_alone<
    S: InvitationStoreProbe + ?Sized,
>(
    store: &S,
) {
    let f = Fixture::new("uncapped");
    let (dead, fresh) = (f.key("dead"), f.key("fresh"));
    publish(store, &f.place, &dead, "a@x", 0, None, TTL).await;
    store.delete_record(&dead).await;
    let other = f.neighbour("b");
    publish(store, &other, &fresh, "b@x", 0, None, TTL).await;
    let mut expected = vec![dead, fresh];
    expected.sort();
    assert_eq!(
        store.set_members(&f.place).await,
        expected,
        "an uncapped publication does not prune the set"
    );
}
