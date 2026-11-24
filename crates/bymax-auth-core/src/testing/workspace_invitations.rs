//! The in-memory [`WorkspaceInvitationStore`] (layer: test double).
//!
//! Records, indexes, sets and the inviter counter expire like the Redis keys they stand in for,
//! on the wall clock or on a clock a test freezes and advances by hand: a key is readable strictly
//! before the instant it expires, as Redis reads it. Every operation runs under one lock, so a
//! publication's compare, cap check and writes are one step as the Redis script makes them. The
//! probe methods of [`InvitationStoreProbe`] reach the keyspace directly for the scenarios the
//! store runs against both implementations.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::lock;
use super::workspace_invitation_scenarios::InvitationStoreProbe;
use crate::traits::{
    IndexedInvitation, InvitationPlace, PendingInvitation, Publication, PublishOutcome, Removal,
    WorkspaceInvitationStore,
};
use crate::workspace::invitation::InvitationRecord;
use crate::workspace::limits::INVITER_WINDOW_SECONDS;

/// A value and the instant it stops being readable.
type Slot<T> = (T, Instant);

#[derive(Default)]
struct State {
    /// Raw records by record key.
    records: HashMap<String, Slot<String>>,
    /// The record key each index names, by index id.
    indexes: HashMap<String, Slot<String>>,
    /// The record keys of each set, by set id.
    sets: HashMap<String, Slot<HashSet<String>>>,
    /// The inviter counters, by rate id.
    counters: HashMap<String, Slot<u64>>,
    /// The instant a frozen clock stands at; `None` follows the wall clock.
    frozen: Option<Instant>,
}

impl State {
    fn now(&self) -> Instant {
        self.frozen.unwrap_or_else(Instant::now)
    }

    fn live<T: Clone>(map: &mut HashMap<String, Slot<T>>, key: &str, now: Instant) -> Option<T> {
        match map.get(key) {
            Some((value, expires)) if *expires > now => Some(value.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    fn record(&mut self, key: &str) -> Option<String> {
        let now = self.now();
        Self::live(&mut self.records, key, now)
    }

    fn index(&mut self, id: &str) -> Option<String> {
        let now = self.now();
        Self::live(&mut self.indexes, id, now)
    }

    fn set(&mut self, id: &str) -> HashSet<String> {
        let now = self.now();
        Self::live(&mut self.sets, id, now).unwrap_or_default()
    }

    /// Drops the members of a set whose record is gone, as the dead-member prune does.
    fn prune(&mut self, id: &str) {
        let members = self.set(id);
        let dead: Vec<String> = members
            .iter()
            .filter(|member| self.record(member).is_none())
            .cloned()
            .collect();
        if let Some((set, _)) = self.sets.get_mut(id) {
            for member in dead {
                set.remove(&member);
            }
        }
    }

    fn left(&self, expires: Instant) -> u64 {
        expires.saturating_duration_since(self.now()).as_secs()
    }
}

/// The in-memory workspace invitation store.
#[derive(Default)]
pub struct InMemoryWorkspaceInvitations {
    state: Mutex<State>,
    unavailable: AtomicBool,
}

impl InMemoryWorkspaceInvitations {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every store call fail while `down` is set, as an unreachable Redis would.
    pub fn set_unavailable(&self, down: bool) {
        self.unavailable.store(down, Ordering::SeqCst);
    }

    /// Stops the clock at the current instant; until then it follows the wall clock.
    pub fn freeze_clock(&self) {
        let mut state = lock(&self.state);
        state.frozen = Some(state.now());
    }

    /// Moves the clock forward by `by`, freezing it first if it follows the wall clock.
    pub fn advance_clock(&self, by: Duration) {
        let mut state = lock(&self.state);
        state.frozen = Some(state.now() + by);
    }

    fn begin(&self) -> Result<std::sync::MutexGuard<'_, State>, AuthError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(AuthError::Internal("invitation store unavailable".into()));
        }
        Ok(lock(&self.state))
    }
}

#[async_trait]
impl WorkspaceInvitationStore for InMemoryWorkspaceInvitations {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        let mut state = self.begin()?;
        Ok(state
            .record(record_key)
            .and_then(|raw| InvitationRecord::parse(&raw)))
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        let mut state = self.begin()?;
        Ok(state.index(&place.index_id).map(|record_key| {
            let raw = state.record(&record_key);
            let record = raw.as_deref().and_then(InvitationRecord::parse);
            let unreadable = raw.is_some() && record.is_none();
            IndexedInvitation {
                record_key,
                record,
                unreadable,
            }
        }))
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        let mut state = self.begin()?;
        let Publication {
            place,
            record_key,
            record,
            ttl,
            pending_limit,
            expected_key,
        } = publication;
        if pending_limit > 0 {
            state.prune(&place.set_id);
        }
        if state.index(&place.index_id).as_deref() != expected_key {
            return Ok(PublishOutcome::Lost);
        }
        let limit = usize::try_from(pending_limit).unwrap_or(usize::MAX);
        if pending_limit > 0 && state.set(&place.set_id).len() >= limit {
            return Ok(PublishOutcome::Full);
        }
        let expires = state.now() + Duration::from_secs(ttl.get());
        state
            .records
            .insert(record_key.to_owned(), (record.to_json(), expires));
        state
            .indexes
            .insert(place.index_id.clone(), (record_key.to_owned(), expires));
        let mut members = state.set(&place.set_id);
        members.insert(record_key.to_owned());
        if let Some(old) = expected_key {
            state.records.remove(old);
            members.remove(old);
        }
        state.sets.insert(place.set_id.clone(), (members, expires));
        Ok(PublishOutcome::Published)
    }

    async fn remove(
        &self,
        place: &InvitationPlace,
        record_key: &str,
        removal: Removal,
    ) -> Result<bool, AuthError> {
        let mut state = self.begin()?;
        let in_set = state.set(&place.set_id).contains(record_key);
        let owned = in_set || state.index(&place.index_id).as_deref() == Some(record_key);
        if removal == Removal::Owned && !owned {
            return Ok(false);
        }
        state.records.remove(record_key);
        if let Some((members, _)) = state.sets.get_mut(&place.set_id) {
            members.remove(record_key);
        }
        if state.index(&place.index_id).as_deref() == Some(record_key) {
            state.indexes.remove(&place.index_id);
            return Ok(true);
        }
        Ok(false)
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        let mut state = self.begin()?;
        let mut live = Vec::new();
        for record_key in state.set(&place.set_id) {
            let Some(raw) = state.record(&record_key) else {
                continue;
            };
            let Some(record) = InvitationRecord::parse(&raw) else {
                continue;
            };
            let ttl_seconds = state
                .records
                .get(&record_key)
                .map_or(0, |(_, expires)| state.left(*expires));
            live.push(PendingInvitation {
                record_key,
                record,
                ttl_seconds,
            });
        }
        state.prune(&place.set_id);
        Ok(live)
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        let mut state = self.begin()?;
        let now = state.now();
        let live = State::live(&mut state.counters, rate_id, now);
        let (count, expires) = match live {
            Some(count) => {
                let expires = state.counters.get(rate_id).map_or(now, |(_, e)| *e);
                (count + 1, expires)
            }
            None => (1, now + Duration::from_secs(INVITER_WINDOW_SECONDS)),
        };
        state.counters.insert(rate_id.to_owned(), (count, expires));
        Ok(count)
    }
}

#[async_trait]
impl InvitationStoreProbe for InMemoryWorkspaceInvitations {
    async fn pass_time(&self, by: Duration) {
        self.advance_clock(by);
    }

    async fn plant_raw_record(&self, record_key: &str, raw: &str, ttl: Duration) {
        let mut state = lock(&self.state);
        let expires = state.now() + ttl;
        state
            .records
            .insert(record_key.to_owned(), (raw.to_owned(), expires));
    }

    async fn point_index(&self, place: &InvitationPlace, record_key: &str, ttl: Duration) {
        let mut state = lock(&self.state);
        let expires = state.now() + ttl;
        state
            .indexes
            .insert(place.index_id.clone(), (record_key.to_owned(), expires));
    }

    async fn delete_record(&self, record_key: &str) {
        lock(&self.state).records.remove(record_key);
    }

    async fn set_members(&self, place: &InvitationPlace) -> Vec<String> {
        let mut members: Vec<String> = lock(&self.state).set(&place.set_id).into_iter().collect();
        members.sort();
        members
    }

    async fn record_ttl(&self, record_key: &str) -> Option<u64> {
        let mut state = lock(&self.state);
        state.record(record_key)?;
        let (_, expires) = state.records.get(record_key)?;
        Some(state.left(*expires))
    }

    async fn index_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        let mut state = lock(&self.state);
        state.index(&place.index_id)?;
        let (_, expires) = state.indexes.get(&place.index_id)?;
        Some(state.left(*expires))
    }

    async fn set_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        let mut state = lock(&self.state);
        if state.set(&place.set_id).is_empty() {
            return None;
        }
        let (_, expires) = state.sets.get(&place.set_id)?;
        Some(state.left(*expires))
    }

    async fn rate_ttl(&self, rate_id: &str) -> Option<u64> {
        let mut state = lock(&self.state);
        let now = state.now();
        State::live(&mut state.counters, rate_id, now)?;
        let (_, expires) = state.counters.get(rate_id)?;
        Some(state.left(*expires))
    }
}
