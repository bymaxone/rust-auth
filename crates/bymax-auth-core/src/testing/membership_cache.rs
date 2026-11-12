//! The in-memory [`MembershipCacheStore`] (layer: test double).
//!
//! Counters and entries expire on the wall clock like the Redis keys they stand in for, and every
//! operation runs under one lock, so a fill's compare, write and retention refresh are one step as
//! the Redis script makes them. A switch makes every call fail, for the advisory paths, and the
//! probe methods of [`MembershipCacheProbe`] reach the keyspace directly for the contract
//! scenarios.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::lock;
use super::membership_cache_scenarios::MembershipCacheProbe;
use crate::traits::{FillOutcome, MembershipCacheRead, MembershipCacheStore};
use crate::workspace::limits::VERSION_RETENTION_SECONDS;
use crate::workspace::membership_cache::{
    MembershipCacheIds, MembershipVersions, VersionCounter, entry_value,
};

/// A value and the instant it stops being readable.
type Slot<T> = (T, Instant);

#[derive(Default)]
struct State {
    counters: HashMap<(VersionCounter, String), Slot<u64>>,
    entries: HashMap<String, Slot<String>>,
    operations: Vec<&'static str>,
}

impl State {
    /// The live value of a counter, dropping it when its retention has run out.
    fn counter(&mut self, counter: VersionCounter, id: &str) -> Option<u64> {
        let key = (counter, id.to_owned());
        match self.counters.get(&key) {
            Some((value, expires)) if *expires > Instant::now() => Some(*value),
            Some(_) => {
                self.counters.remove(&key);
                None
            }
            None => None,
        }
    }

    /// The live entry `id`, dropping it when its lifetime has run out.
    fn entry(&mut self, id: &str) -> Option<String> {
        match self.entries.get(id) {
            Some((value, expires)) if *expires > Instant::now() => Some(value.clone()),
            Some(_) => {
                self.entries.remove(id);
                None
            }
            None => None,
        }
    }

    /// `INCR` then `EXPIRE` to the retention.
    fn bump(&mut self, counter: VersionCounter, id: &str) -> u64 {
        let next = self.counter(counter, id).unwrap_or(0).saturating_add(1);
        self.counters
            .insert((counter, id.to_owned()), (next, retention()));
        next
    }

    /// Extends a counter that exists to the retention; an absent one stays absent.
    fn refresh(&mut self, counter: VersionCounter, id: &str) {
        if self.counter(counter, id).is_some()
            && let Some(slot) = self.counters.get_mut(&(counter, id.to_owned()))
        {
            slot.1 = retention();
        }
    }
}

/// The instant a counter bumped or refreshed now stops being readable.
fn retention() -> Instant {
    Instant::now() + Duration::from_secs(VERSION_RETENTION_SECONDS)
}

/// The in-memory membership cache.
#[derive(Default)]
pub struct InMemoryMembershipCache {
    state: Mutex<State>,
    unavailable: AtomicBool,
}

impl InMemoryMembershipCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every store call fail while `down` is set, as an unreachable Redis would.
    pub fn set_unavailable(&self, down: bool) {
        self.unavailable.store(down, Ordering::SeqCst);
    }

    /// The store calls made so far, oldest first: `read`, `fill`, `bump_workspace` and
    /// `bump_membership`, a failed one included.
    #[must_use]
    pub fn operations(&self) -> Vec<&'static str> {
        lock(&self.state).operations.clone()
    }

    /// Plants a counter at `value` that expires in `ttl`, for a test of what a fill refreshes.
    pub fn seed_counter(&self, counter: VersionCounter, id: &str, value: u64, ttl: Duration) {
        lock(&self.state)
            .counters
            .insert((counter, id.to_owned()), (value, Instant::now() + ttl));
    }

    /// How long a counter has left, or `None` when it does not exist.
    #[must_use]
    pub fn counter_ttl(&self, counter: VersionCounter, id: &str) -> Option<Duration> {
        let mut state = lock(&self.state);
        state.counter(counter, id)?;
        let (_, expires) = state.counters.get(&(counter, id.to_owned()))?;
        Some(expires.saturating_duration_since(Instant::now()))
    }

    /// How long entry `id` has left, or `None` when it does not exist.
    #[must_use]
    pub fn entry_ttl(&self, id: &str) -> Option<Duration> {
        let mut state = lock(&self.state);
        state.entry(id)?;
        let (_, expires) = state.entries.get(id)?;
        Some(expires.saturating_duration_since(Instant::now()))
    }

    /// Records `operation` and fails it while the cache is unavailable.
    fn begin(
        &self,
        operation: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, State>, AuthError> {
        let mut state = lock(&self.state);
        state.operations.push(operation);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(AuthError::Internal("membership cache unavailable".into()));
        }
        Ok(state)
    }
}

#[async_trait]
impl MembershipCacheStore for InMemoryMembershipCache {
    async fn read(&self, ids: &MembershipCacheIds) -> Result<MembershipCacheRead, AuthError> {
        let mut state = self.begin("read")?;
        let versions = MembershipVersions {
            workspace: state
                .counter(VersionCounter::Workspace, &ids.workspace)
                .unwrap_or(0),
            membership: state
                .counter(VersionCounter::Membership, &ids.membership)
                .unwrap_or(0),
        };
        let entry = state.entry(&ids.entry(versions));
        Ok(MembershipCacheRead { versions, entry })
    }

    async fn fill(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, AuthError> {
        let mut state = self.begin("fill")?;
        let workspace = state
            .counter(VersionCounter::Workspace, &ids.workspace)
            .unwrap_or(0);
        let membership = state
            .counter(VersionCounter::Membership, &ids.membership)
            .unwrap_or(0);
        if (workspace, membership) != (versions.workspace, versions.membership) {
            return Ok(FillOutcome::Moved);
        }
        state.refresh(VersionCounter::Workspace, &ids.workspace);
        state.refresh(VersionCounter::Membership, &ids.membership);
        let expires = Instant::now() + Duration::from_secs(ttl.get());
        state
            .entries
            .insert(ids.entry(versions), (entry_value(role), expires));
        Ok(FillOutcome::Written)
    }

    async fn bump_workspace(&self, workspace_id: &str) -> Result<u64, AuthError> {
        let mut state = self.begin("bump_workspace")?;
        Ok(state.bump(VersionCounter::Workspace, workspace_id))
    }

    async fn bump_membership(&self, membership_id: &str) -> Result<u64, AuthError> {
        let mut state = self.begin("bump_membership")?;
        Ok(state.bump(VersionCounter::Membership, membership_id))
    }
}

#[async_trait]
impl MembershipCacheProbe for InMemoryMembershipCache {
    async fn seed_entry(&self, entry_id: &str, raw: &str) {
        let expires = Instant::now() + Duration::from_secs(VERSION_RETENTION_SECONDS);
        lock(&self.state)
            .entries
            .insert(entry_id.to_owned(), (raw.to_owned(), expires));
    }

    async fn entry(&self, entry_id: &str) -> Option<String> {
        lock(&self.state).entry(entry_id)
    }

    async fn counter(&self, counter: VersionCounter, id: &str) -> Option<u64> {
        lock(&self.state).counter(counter, id)
    }

    async fn drop_counter(&self, counter: VersionCounter, id: &str) {
        lock(&self.state).counters.remove(&(counter, id.to_owned()));
    }
}
