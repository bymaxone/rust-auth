//! The in-memory membership cache against the contract's scenarios and its own rules (layer: test
//! double, tests).
//!
//! The scenarios are the shared table the Redis store also plays (see
//! `crates/bymax-auth-redis/tests/membership_cache_e2e.rs`); the rest pins what a scenario does not
//! observe: the retention every bump and fill leaves on a counter, the lifetime of an entry, and
//! that a read creates nothing.

use std::num::NonZeroU64;
use std::time::Duration;

use serde_json::Value;

use super::InMemoryMembershipCache;
use super::membership_cache_scenarios::{MembershipCacheProbe, run_membership_cache_scenarios};
use crate::traits::{FillOutcome, MembershipCacheStore};
use crate::workspace::limits::VERSION_RETENTION_SECONDS;
use crate::workspace::membership_cache::{
    MembershipCacheIds, MembershipVersions, VersionCounter, entry_value,
};

/// The `workspaceMembershipCache` section of the shared contract.
fn section() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str::<Value>(raw.as_str())
        .map_or(Value::Null, |root| root["workspaceMembershipCache"].clone())
}

/// The identifiers of an arbitrary member: any 64-character text names one counter of each kind.
fn ids() -> MembershipCacheIds {
    MembershipCacheIds {
        workspace: "a".repeat(64),
        membership: "b".repeat(64),
    }
}

/// An entry lifetime of `seconds`.
fn ttl(seconds: u64) -> NonZeroU64 {
    NonZeroU64::new(seconds).unwrap_or(NonZeroU64::MIN)
}

/// The retention, less a margin for the time a test takes.
fn near_retention(left: Option<Duration>) -> bool {
    let retention = Duration::from_secs(VERSION_RETENTION_SECONDS);
    left.is_some_and(|left| left <= retention && left + Duration::from_secs(5) >= retention)
}

#[tokio::test]
async fn the_contract_scenarios_pass_against_the_in_memory_store() {
    let key = [7_u8; 64];
    let played = run_membership_cache_scenarios(&section()["scenarios"], &key, || async {
        Some(InMemoryMembershipCache::new())
    })
    .await;
    assert!(matches!(played, Ok(steps) if steps > 10), "{played:?}");
}

#[tokio::test]
async fn a_scenario_table_the_runner_cannot_read_fails_the_run() {
    let fresh = || async { Some(InMemoryMembershipCache::new()) };
    let mut unknown = section()["scenarios"].clone();
    unknown["steps"][0]["unmodelled"] = Value::from(1);
    assert!(
        run_membership_cache_scenarios(&unknown, &[7; 64], fresh)
            .await
            .is_err()
    );
    let mut wrong = section()["scenarios"].clone();
    wrong["steps"][0]["expect"]["answer"] = Value::from("nobody");
    let failed = run_membership_cache_scenarios(&wrong, &[7; 64], fresh).await;
    assert!(failed.is_err_and(|error| error.contains("step 0")));
    let scenarios = section()["scenarios"].clone();
    let none = run_membership_cache_scenarios(&scenarios, &[7; 64], || async {
        None::<InMemoryMembershipCache>
    });
    assert!(none.await.is_err());
}

#[tokio::test]
async fn a_read_of_absent_counters_reads_zero_and_creates_nothing() {
    let cache = InMemoryMembershipCache::new();
    let read = cache.read(&ids()).await;
    assert!(matches!(&read, Ok(read) if read.versions == MembershipVersions::default()));
    assert!(matches!(&read, Ok(read) if read.entry.is_none()));
    for counter in [VersionCounter::Workspace, VersionCounter::Membership] {
        assert_eq!(cache.counter(counter, ids().counter(counter)).await, None);
    }
}

#[tokio::test]
async fn every_bump_increments_and_restores_the_retention() {
    let cache = InMemoryMembershipCache::new();
    let short = Duration::from_secs(10);
    cache.seed_counter(VersionCounter::Membership, &ids().membership, 4, short);
    assert!(matches!(
        cache.bump_membership(&ids().membership).await,
        Ok(5)
    ));
    assert!(near_retention(
        cache.counter_ttl(VersionCounter::Membership, &ids().membership)
    ));
    assert!(matches!(
        cache.bump_workspace(&ids().workspace).await,
        Ok(1)
    ));
    assert!(matches!(
        cache.bump_workspace(&ids().workspace).await,
        Ok(2)
    ));
    assert!(near_retention(
        cache.counter_ttl(VersionCounter::Workspace, &ids().workspace)
    ));
}

#[tokio::test]
async fn a_fill_extends_the_counters_that_exist_and_creates_none() {
    // entryRefreshesCounters: the compare, the write and the retention are one step.
    let rule = section()["entryRefreshesCounters"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(rule.contains("absent counts as 0") && rule.contains("extends every existing"));
    let cache = InMemoryMembershipCache::new();
    let short = Duration::from_secs(10);
    cache.seed_counter(VersionCounter::Workspace, &ids().workspace, 3, short);
    let versions = MembershipVersions {
        workspace: 3,
        membership: 0,
    };
    let filled = cache.fill(&ids(), versions, "editor", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Written)));
    assert!(near_retention(
        cache.counter_ttl(VersionCounter::Workspace, &ids().workspace)
    ));
    assert_eq!(
        cache.counter_ttl(VersionCounter::Membership, &ids().membership),
        None
    );
    let entry = ids().entry(versions);
    assert_eq!(cache.entry(&entry).await, Some(entry_value("editor")));
    let left = cache.entry_ttl(&entry);
    assert!(left.is_some_and(|left| left <= Duration::from_secs(60) && left.as_secs() >= 55));
}

#[tokio::test]
async fn a_fill_that_finds_a_counter_moved_writes_nothing() {
    let cache = InMemoryMembershipCache::new();
    let short = Duration::from_secs(10);
    cache.seed_counter(VersionCounter::Membership, &ids().membership, 2, short);
    let stale = MembershipVersions {
        workspace: 0,
        membership: 1,
    };
    let filled = cache.fill(&ids(), stale, "owner", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Moved)));
    assert_eq!(cache.entry(&ids().entry(stale)).await, None);
    let current = MembershipVersions {
        workspace: 0,
        membership: 2,
    };
    assert_eq!(cache.entry(&ids().entry(current)).await, None);
    // The moved fill refreshed nothing either.
    let left = cache.counter_ttl(VersionCounter::Membership, &ids().membership);
    assert!(left.is_some_and(|left| left <= short));
    // An expired counter reads 0, so a fill read before it expired no longer matches.
    cache.seed_counter(
        VersionCounter::Workspace,
        &ids().workspace,
        1,
        Duration::ZERO,
    );
    let before_expiry = MembershipVersions {
        workspace: 1,
        membership: 2,
    };
    let filled = cache.fill(&ids(), before_expiry, "owner", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Moved)));
}

#[tokio::test]
async fn an_unavailable_store_fails_every_call_and_records_it() {
    let cache = InMemoryMembershipCache::new();
    cache.set_unavailable(true);
    assert!(cache.read(&ids()).await.is_err());
    let versions = MembershipVersions::default();
    assert!(
        cache
            .fill(&ids(), versions, "owner", ttl(60))
            .await
            .is_err()
    );
    assert!(cache.bump_workspace(&ids().workspace).await.is_err());
    assert!(cache.bump_membership(&ids().membership).await.is_err());
    assert_eq!(
        cache.operations(),
        ["read", "fill", "bump_workspace", "bump_membership"]
    );
    cache.set_unavailable(false);
    assert_eq!(cache.entry(&ids().entry(versions)).await, None);
    assert_eq!(
        cache
            .counter(VersionCounter::Workspace, &ids().workspace)
            .await,
        None
    );
}

#[tokio::test]
async fn the_probe_plants_reads_and_drops_what_the_scenarios_need() {
    let cache = InMemoryMembershipCache::new();
    let entry = ids().entry(MembershipVersions::default());
    cache.seed_entry(&entry, "{}").await;
    assert_eq!(cache.entry(&entry).await.as_deref(), Some("{}"));
    assert!(cache.entry_ttl(&entry).is_some());
    let read = cache.read(&ids()).await;
    assert!(matches!(read, Ok(read) if read.entry.as_deref() == Some("{}")));
    assert!(cache.bump_membership(&ids().membership).await.is_ok());
    assert_eq!(
        cache
            .counter(VersionCounter::Membership, &ids().membership)
            .await,
        Some(1)
    );
    cache
        .drop_counter(VersionCounter::Membership, &ids().membership)
        .await;
    assert_eq!(
        cache
            .counter(VersionCounter::Membership, &ids().membership)
            .await,
        None
    );
    assert_eq!(
        cache.counter_ttl(VersionCounter::Membership, &ids().membership),
        None
    );
    assert_eq!(cache.entry_ttl("absent"), None);
}
