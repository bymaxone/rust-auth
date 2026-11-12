//! The scenario runner refuses what the contract does not allow (layer: test support, tests).
//!
//! A runner that passes every store proves nothing about the stores it passes. Each case here runs
//! the contract's table against the in-memory store wrapped to misbehave in exactly ONE way, or
//! runs a copy of the table edited in one place, and requires the run to fail naming the step and
//! the check that caught it.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::AuthError;
use serde_json::Value;

use super::InMemoryMembershipCache;
use super::membership_cache_scenarios::{MembershipCacheProbe, run_membership_cache_scenarios};
use crate::traits::{FillOutcome, MembershipCacheRead, MembershipCacheStore};
use crate::workspace::membership_cache::{
    MembershipCacheIds, MembershipVersions, VersionCounter, entry_value,
};

const KEY: [u8; 64] = [5; 64];

/// The one way a [`Broken`] store misbehaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// None: the wrapper behaves as the in-memory store does.
    Sound,
    /// A fill caches a role other than the one it was given.
    FillsWrongRole,
    /// A fill reports a write and writes nothing.
    FillWritesNothing,
    /// A fill writes under the versions it was given without comparing them with the counters.
    FillSkipsCompare,
    /// A fill writes under the versions the counters hold NOW, not the ones read.
    FillWritesUnderCurrent,
    /// A fill creates a counter that does not exist.
    FillCreatesCounters,
    /// A bump answers a new value and stores nothing.
    BumpStoresNothing,
    /// The first bump fails.
    FirstBumpFails,
}

/// The in-memory store with one [`Fault`].
struct Broken {
    inner: InMemoryMembershipCache,
    fault: Fault,
    bumps: AtomicUsize,
}

impl Broken {
    /// Fails the first bump under [`Fault::FirstBumpFails`].
    fn before_bump(&self) -> Result<(), AuthError> {
        let first = self.bumps.fetch_add(1, Ordering::SeqCst) == 0;
        if first && self.fault == Fault::FirstBumpFails {
            return Err(AuthError::Internal("bump refused".into()));
        }
        Ok(())
    }

    /// Answers a bump under [`Fault::BumpStoresNothing`]: the value after the current one.
    async fn unstored_bump(&self, counter: VersionCounter, id: &str) -> u64 {
        self.inner.counter(counter, id).await.unwrap_or(0) + 1
    }

    /// Plants `role`'s entry under `versions` without any check.
    async fn plant(&self, ids: &MembershipCacheIds, versions: MembershipVersions, role: &str) {
        self.inner
            .seed_entry(&ids.entry(versions), &entry_value(role))
            .await;
    }

    /// Creates each absent counter at 0, so the versions read do not change.
    async fn create_counters(&self, ids: &MembershipCacheIds) {
        for counter in [VersionCounter::Workspace, VersionCounter::Membership] {
            let id = ids.counter(counter);
            if self.inner.counter(counter, id).await.is_none() {
                self.inner
                    .seed_counter(counter, id, 0, Duration::from_secs(60));
            }
        }
    }
}

#[async_trait]
impl MembershipCacheStore for Broken {
    async fn read(&self, ids: &MembershipCacheIds) -> Result<MembershipCacheRead, AuthError> {
        self.inner.read(ids).await
    }

    async fn fill(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, AuthError> {
        match self.fault {
            Fault::FillsWrongRole => return self.inner.fill(ids, versions, "intruder", ttl).await,
            Fault::FillWritesNothing => return Ok(FillOutcome::Written),
            Fault::FillSkipsCompare => self.plant(ids, versions, role).await,
            Fault::FillWritesUnderCurrent => {
                let current = self.inner.read(ids).await?.versions;
                self.plant(ids, current, role).await;
            }
            Fault::FillCreatesCounters => self.create_counters(ids).await,
            Fault::Sound | Fault::BumpStoresNothing | Fault::FirstBumpFails => {}
        }
        self.inner.fill(ids, versions, role, ttl).await
    }

    async fn bump_workspace(&self, id: &str) -> Result<u64, AuthError> {
        self.before_bump()?;
        if self.fault == Fault::BumpStoresNothing {
            return Ok(self.unstored_bump(VersionCounter::Workspace, id).await);
        }
        self.inner.bump_workspace(id).await
    }

    async fn bump_membership(&self, id: &str) -> Result<u64, AuthError> {
        self.before_bump()?;
        if self.fault == Fault::BumpStoresNothing {
            return Ok(self.unstored_bump(VersionCounter::Membership, id).await);
        }
        self.inner.bump_membership(id).await
    }
}

#[async_trait]
impl MembershipCacheProbe for Broken {
    async fn seed_entry(&self, entry_id: &str, raw: &str) {
        self.inner.seed_entry(entry_id, raw).await;
    }

    async fn entry(&self, entry_id: &str) -> Option<String> {
        self.inner.entry(entry_id).await
    }

    async fn counter(&self, counter: VersionCounter, id: &str) -> Option<u64> {
        self.inner.counter(counter, id).await
    }

    async fn drop_counter(&self, counter: VersionCounter, id: &str) {
        self.inner.drop_counter(counter, id).await;
    }
}

/// The contract's `scenarios` table.
fn scenarios() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str::<Value>(raw.as_str()).map_or(Value::Null, |root| {
        root["workspaceMembershipCache"]["scenarios"].clone()
    })
}

/// Plays `table` against fresh stores with `fault`.
async fn run(table: &Value, fault: Fault) -> Result<usize, String> {
    run_membership_cache_scenarios(table, &KEY, || async move {
        Some(Broken {
            inner: InMemoryMembershipCache::new(),
            fault,
            bumps: AtomicUsize::new(0),
        })
    })
    .await
}

/// Whether `outcome` is a failure whose description contains every one of `needles`.
fn fails_with(outcome: &Result<usize, String>, needles: &[&str]) -> bool {
    matches!(outcome, Err(error) if needles.iter().all(|needle| error.contains(needle)))
}

#[tokio::test]
async fn the_wrapper_without_a_fault_passes_the_table() {
    let played = run(&scenarios(), Fault::Sound).await;
    assert!(matches!(played, Ok(steps) if steps > 10), "{played:?}");
}

#[tokio::test]
async fn a_store_that_caches_the_wrong_role_fails_at_the_first_fill() {
    let outcome = run(&scenarios(), Fault::FillsWrongRole).await;
    let named = ["steps: step 0", "entry under 0:0 is Some(\"intruder\")"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_store_whose_fill_writes_nothing_fails_at_the_first_fill() {
    let outcome = run(&scenarios(), Fault::FillWritesNothing).await;
    assert!(
        fails_with(&outcome, &["steps: step 0", "entry under 0:0 is None"]),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_fill_that_skips_the_compare_leaves_an_entry_under_the_versions_read() {
    let outcome = run(&scenarios(), Fault::FillSkipsCompare).await;
    let named = ["counterLoss: step 1", "an entry exists under 0:1"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_fill_under_the_moved_versions_is_readable_and_caught() {
    let outcome = run(&scenarios(), Fault::FillWritesUnderCurrent).await;
    let named = [
        "counterLoss: step 1",
        "an entry is readable under the current 0:2",
    ];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_fill_that_creates_counters_is_caught() {
    let outcome = run(&scenarios(), Fault::FillCreatesCounters).await;
    let named = ["counterLoss: step 3", "counter exists"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_bump_that_stores_nothing_reports_the_wrong_versions() {
    let outcome = run(&scenarios(), Fault::BumpStoresNothing).await;
    let named = ["steps: step 2", "versions 0:0, expected 0:1"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_failed_bump_fails_the_step_that_bumped() {
    let outcome = run(&scenarios(), Fault::FirstBumpFails).await;
    let named = ["steps: step 2", "bump failed"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
    // A concurrent bump that fails surfaces through the resolution it interrupted.
    let mut table = scenarios();
    table["steps"] = Value::Array(vec![table["counterLoss"]["steps"][1].clone()]);
    let outcome = run(&table, Fault::FirstBumpFails).await;
    let named = ["steps: step 0", "resolve failed"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

/// The step of `steps` at `index` whose action is `action`, so an edit lands where it is meant to.
fn step_index(table: &Value, sequence: &str, action: &str) -> usize {
    let steps = match sequence {
        "counterLoss" => &table["counterLoss"]["steps"],
        _ => &table["steps"],
    };
    let index = steps
        .as_array()
        .and_then(|steps| steps.iter().position(|step| step["do"] == action));
    assert!(index.is_some(), "{sequence} has no {action} step");
    index.unwrap_or_default()
}

#[tokio::test]
async fn an_expectation_the_store_does_not_meet_fails_the_step() {
    let mut table = scenarios();
    table["steps"][0]["expect"]["source"] = Value::from("cache");
    let outcome = run(&table, Fault::Sound).await;
    let named = ["steps: step 0", "source repository, expected cache"];
    assert!(fails_with(&outcome, &named), "{outcome:?}");

    let mut table = scenarios();
    let drop = step_index(&table, "counterLoss", "dropCounter");
    table["counterLoss"]["steps"][drop]["counter"] = Value::from("workspace");
    let outcome = run(&table, Fault::Sound).await;
    let named = [
        format!("counterLoss: step {drop}"),
        "versions 0:2, expected 0:0".to_owned(),
    ];
    let named: Vec<&str> = named.iter().map(String::as_str).collect();
    assert!(fails_with(&outcome, &named), "{outcome:?}");
}

#[tokio::test]
async fn a_table_the_runner_cannot_read_names_what_it_cannot_read() {
    let edits: [(&str, &str, Value, &str); 4] = [
        (
            "expect",
            "cachedUnder",
            Value::from(5),
            "neither null nor text",
        ),
        (
            "repository",
            "workspace",
            Value::from("archived"),
            "unknown workspace status",
        ),
        (
            "repository",
            "membership",
            Value::from("left"),
            "unknown membership status",
        ),
        (
            "expect",
            "versions",
            Value::from("one:two"),
            "not two whole numbers",
        ),
    ];
    for (object, field, value, message) in edits {
        let mut table = scenarios();
        table["steps"][0][object][field] = value;
        let outcome = run(&table, Fault::Sound).await;
        assert!(
            fails_with(&outcome, &["steps: step 0", message]),
            "{field}: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn a_step_missing_what_its_action_needs_fails() {
    let mut table = scenarios();
    let seed = step_index(&table, "steps", "seedEntry");
    if let Some(step) = table["steps"][seed].as_object_mut() {
        step.remove("entry");
    }
    let outcome = run(&table, Fault::Sound).await;
    assert!(
        fails_with(&outcome, &["seedEntry names no entry"]),
        "{outcome:?}"
    );

    let mut table = scenarios();
    let drop = step_index(&table, "counterLoss", "dropCounter");
    if let Some(step) = table["counterLoss"]["steps"][drop].as_object_mut() {
        step.remove("counter");
    }
    let outcome = run(&table, Fault::Sound).await;
    assert!(
        fails_with(&outcome, &["dropCounter names no counter"]),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_empty_sequence_fails_rather_than_passing_over_nothing() {
    for (pointer, name) in [("/steps", "steps"), ("/counterLoss/steps", "counterLoss")] {
        let mut table = scenarios();
        if let Some(slot) = table.pointer_mut(pointer) {
            *slot = Value::Array(Vec::new());
        }
        let outcome = run(&table, Fault::Sound).await;
        let message = format!("{name} has no steps");
        assert!(fails_with(&outcome, &[message.as_str()]), "{outcome:?}");
    }
}
