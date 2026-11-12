//! The runner of the contract's membership-cache scenarios, shared by every store implementation
//! (layer: test support).
//!
//! `workspaceMembershipCache.scenarios` in the shared wire contract is a table of steps that both
//! libraries play against a store and two repositories. The runner takes the table as parsed JSON,
//! so the steps are always the contract's, and plays it against any [`MembershipCacheProbe`]: the
//! in-memory store and the Redis store run the same table and cannot drift. A step or a field the
//! runner does not know fails the run rather than being passed over.

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;
use time::OffsetDateTime;

use super::lock;
use crate::RepositoryError;
use crate::services::membership_cache::{
    MembershipCache, MembershipRows, MembershipRowsRead, Resolution, ResolutionSource,
    bump_membership, bump_workspace, resolve_membership,
};
use crate::traits::MembershipCacheStore;
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceStatus,
};
use crate::workspace::membership_cache::{
    MembershipCacheIds, MembershipCacheTtl, MembershipVersions, VersionCounter, entry_role,
};

/// Direct access to a store's keyspace, which the scenarios need to plant an entry, drop a
/// counter, and inspect what a step left behind.
#[async_trait]
pub trait MembershipCacheProbe: MembershipCacheStore {
    /// Writes `raw` as entry `entry_id` (a [`MembershipCacheIds::entry`]), with a lifetime longer
    /// than the scenario.
    async fn seed_entry(&self, entry_id: &str, raw: &str);
    /// The raw entry `entry_id`, or `None` when there is none.
    async fn entry(&self, entry_id: &str) -> Option<String>;
    /// The value of a counter, or `None` when it does not exist.
    async fn counter(&self, counter: VersionCounter, id: &str) -> Option<u64>;
    /// Removes a counter, as its expiry would.
    async fn drop_counter(&self, counter: VersionCounter, id: &str);
}

/// The member every scenario resolves.
const MEMBER: MembershipRef<'static> = MembershipRef {
    tenant_id: "t1",
    workspace_id: "w1",
    user_id: "u1",
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    #[serde(rename = "$comment")]
    _comment: IgnoredAny,
    steps: Vec<Step>,
    #[serde(rename = "counterLoss")]
    counter_loss: Sequence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sequence {
    #[serde(rename = "$comment")]
    _comment: IgnoredAny,
    steps: Vec<Step>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
enum Action {
    Resolve,
    BumpMembership,
    BumpWorkspace,
    SeedEntry,
    DropCounter,
}

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
enum CounterName {
    Workspace,
    Membership,
}

impl From<CounterName> for VersionCounter {
    fn from(name: CounterName) -> Self {
        match name {
            CounterName::Workspace => Self::Workspace,
            CounterName::Membership => Self::Membership,
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RowsState {
    workspace: String,
    membership: String,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    #[serde(rename = "do")]
    action: Action,
    repository: RowsState,
    entry: Option<String>,
    under: Option<String>,
    counter: Option<CounterName>,
    #[serde(rename = "concurrentBump")]
    concurrent_bump: Option<CounterName>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Expect {
    #[serde(default, deserialize_with = "present")]
    answer: Option<Value>,
    source: Option<String>,
    #[serde(default, deserialize_with = "present")]
    cached_under: Option<Value>,
    #[serde(default)]
    absent_under: Vec<String>,
    versions: Option<String>,
    #[serde(default)]
    counters_absent: bool,
}

/// `Some` for a field that is present, `null` included; an absent field is `None` by default.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// `"{workspace}:{membership}"` as versions.
fn parse_versions(text: &str) -> Result<MembershipVersions, String> {
    let parsed = text
        .split_once(':')
        .and_then(|(w, m)| Some((w.parse().ok()?, m.parse().ok()?)));
    parsed
        .map(|(workspace, membership)| MembershipVersions {
            workspace,
            membership,
        })
        .ok_or_else(|| format!("versions {text:?} are not two whole numbers"))
}

/// The workspace status named `name`.
fn workspace_status(name: &str) -> Result<WorkspaceStatus, String> {
    [
        WorkspaceStatus::Active,
        WorkspaceStatus::PendingDeletion,
        WorkspaceStatus::Suspended,
        WorkspaceStatus::Deleted,
    ]
    .into_iter()
    .find(|status| status.as_str() == name)
    .ok_or_else(|| format!("unknown workspace status {name:?}"))
}

/// The membership status named `name`.
fn membership_status(name: &str) -> Result<MembershipStatus, String> {
    [MembershipStatus::Active, MembershipStatus::Suspended]
        .into_iter()
        .find(|status| status.as_str() == name)
        .ok_or_else(|| format!("unknown membership status {name:?}"))
}

/// What the scenario repositories hold at one step.
struct Held {
    workspace: WorkspaceStatus,
    membership: MembershipStatus,
    role: String,
    concurrent_bump: Option<VersionCounter>,
}

/// Repositories answering the rows a step names, counting the reads, and bumping a counter after
/// the rows are read and before the fill when a step asks for a concurrent change.
struct ScenarioRows<'a, P: ?Sized> {
    probe: &'a P,
    identifier_key: &'a [u8; 64],
    held: Mutex<Held>,
    reads: AtomicUsize,
}

impl<P: MembershipCacheProbe + ?Sized> ScenarioRows<'_, P> {
    /// The rows the repositories hold now.
    fn rows(&self) -> (MembershipRowsRead, Option<VersionCounter>) {
        let mut held = lock(&self.held);
        let workspace = Workspace {
            id: MEMBER.workspace_id.to_owned(),
            tenant_id: MEMBER.tenant_id.to_owned(),
            name: "W".to_owned(),
            status: held.workspace,
            created_at: OffsetDateTime::UNIX_EPOCH,
            deletion_scheduled_at: None,
        };
        let membership = Membership {
            tenant_id: MEMBER.tenant_id.to_owned(),
            workspace_id: MEMBER.workspace_id.to_owned(),
            user_id: MEMBER.user_id.to_owned(),
            role: held.role.clone(),
            status: held.membership,
            invited_by_user_id: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let read = MembershipRowsRead {
            workspace: Some(workspace),
            membership: Some(membership),
        };
        (read, held.concurrent_bump.take())
    }
}

#[async_trait]
impl<P: MembershipCacheProbe + ?Sized> MembershipRows for ScenarioRows<'_, P> {
    async fn read_rows(&self, _: MembershipRef<'_>) -> Result<MembershipRowsRead, RepositoryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let (read, concurrent) = self.rows();
        if let Some(counter) = concurrent {
            bump(self.probe, self.identifier_key, counter)
                .await
                .map_err(|error| RepositoryError::Backend(error.into()))?;
        }
        Ok(read)
    }
}

/// Bumps a counter the way a writer does.
async fn bump<P: MembershipCacheProbe + ?Sized>(
    probe: &P,
    identifier_key: &[u8; 64],
    counter: VersionCounter,
) -> Result<u64, String> {
    let bumped = match counter {
        VersionCounter::Workspace => {
            bump_workspace(probe, identifier_key, MEMBER.workspace()).await
        }
        VersionCounter::Membership => bump_membership(probe, identifier_key, MEMBER).await,
    };
    bumped.map_err(|error| format!("bump failed: {error}"))
}

/// One store, its identifiers and the scenario repositories.
struct Harness<'a, P: ?Sized> {
    probe: &'a P,
    identifier_key: &'a [u8; 64],
    ids: MembershipCacheIds,
    rows: ScenarioRows<'a, P>,
}

impl<P: MembershipCacheProbe + ?Sized> Harness<'_, P> {
    /// The current versions, as the store holds them.
    async fn versions(&self) -> MembershipVersions {
        let counter = |name| self.probe.counter(name, self.ids.counter(name));
        MembershipVersions {
            workspace: counter(VersionCounter::Workspace).await.unwrap_or(0),
            membership: counter(VersionCounter::Membership).await.unwrap_or(0),
        }
    }

    /// The role an entry under `versions` caches, read by the contract's parsing rule.
    async fn cached(&self, versions: MembershipVersions) -> Option<String> {
        let raw = self.probe.entry(&self.ids.entry(versions)).await;
        raw.as_deref().and_then(entry_role)
    }

    /// Sets the rows a step names.
    fn hold(&self, step: &Step) -> Result<(), String> {
        let mut held = lock(&self.rows.held);
        held.workspace = workspace_status(&step.repository.workspace)?;
        held.membership = membership_status(&step.repository.membership)?;
        held.role.clone_from(&step.repository.role);
        held.concurrent_bump = step.concurrent_bump.map(VersionCounter::from);
        Ok(())
    }
}

/// Performs the action of one step, other than the resolution that follows it.
async fn act<P: MembershipCacheProbe + ?Sized>(
    harness: &Harness<'_, P>,
    step: &Step,
) -> Result<(), String> {
    let key = harness.identifier_key;
    match step.action {
        Action::BumpMembership => {
            bump(harness.probe, key, VersionCounter::Membership).await?;
        }
        Action::BumpWorkspace => {
            bump(harness.probe, key, VersionCounter::Workspace).await?;
        }
        Action::SeedEntry => {
            let under = parse_versions(step.under.as_deref().unwrap_or_default())?;
            let raw = step.entry.as_deref().ok_or("seedEntry names no entry")?;
            harness
                .probe
                .seed_entry(&harness.ids.entry(under), raw)
                .await;
        }
        Action::DropCounter => {
            let counter = VersionCounter::from(step.counter.ok_or("dropCounter names no counter")?);
            let id = harness.ids.counter(counter);
            harness.probe.drop_counter(counter, id).await;
        }
        Action::Resolve => {}
    }
    Ok(())
}

/// Resolves the member and checks the answer and where it came from.
async fn resolve<P: MembershipCacheProbe + ?Sized>(
    harness: &Harness<'_, P>,
    expect: &Expect,
) -> Result<(), String> {
    let cache = MembershipCache {
        store: harness.probe,
        identifier_key: harness.identifier_key,
        ttl: MembershipCacheTtl::default(),
    };
    let before = harness.rows.reads.load(Ordering::SeqCst);
    let resolution = resolve_membership(&cache, &harness.rows, MEMBER)
        .await
        .map_err(|error| format!("resolve failed: {error}"))?;
    let read_rows = harness.rows.reads.load(Ordering::SeqCst) > before;
    let (answer, source) = match resolution {
        Resolution::Member { role, source } => (Some(role), source),
        Resolution::NotMember(_) => (None, ResolutionSource::Repository),
    };
    let named = if read_rows { "repository" } else { "cache" };
    if (source == ResolutionSource::Repository) != read_rows {
        return Err(format!(
            "the answer claims {source:?} but the rows say {named}"
        ));
    }
    let wanted = expect
        .answer
        .as_ref()
        .map(|value| value.as_str().map(str::to_owned));
    if let Some(wanted) = wanted
        && wanted != answer
    {
        return Err(format!("answer {answer:?}, expected {wanted:?}"));
    }
    match &expect.source {
        Some(wanted) if wanted != named => Err(format!("source {named}, expected {wanted}")),
        _ => Ok(()),
    }
}

/// Checks `cachedUnder`: the entry under the versions it names caches the answer, or, for `null`,
/// nothing is readable under the current versions.
async fn check_cached<P: MembershipCacheProbe + ?Sized>(
    harness: &Harness<'_, P>,
    expect: &Expect,
    current: MembershipVersions,
) -> Result<(), String> {
    match &expect.cached_under {
        Some(Value::Null) if harness.cached(current).await.is_some() => {
            Err(format!("an entry is readable under the current {current}"))
        }
        Some(Value::String(under)) => {
            let role = harness.cached(parse_versions(under)?).await;
            let answer = expect.answer.as_ref().and_then(Value::as_str);
            if role.is_none() || (answer.is_some() && role.as_deref() != answer) {
                return Err(format!(
                    "entry under {under} is {role:?}, expected {answer:?}"
                ));
            }
            Ok(())
        }
        Some(Value::Null) | None => Ok(()),
        Some(other) => Err(format!("cachedUnder {other} is neither null nor text")),
    }
}

/// Checks the state a step leaves: the versions, the entries and the counters.
async fn check<P: MembershipCacheProbe + ?Sized>(
    harness: &Harness<'_, P>,
    expect: &Expect,
) -> Result<(), String> {
    let current = harness.versions().await;
    if let Some(wanted) = &expect.versions
        && parse_versions(wanted)? != current
    {
        return Err(format!("versions {current}, expected {wanted}"));
    }
    check_cached(harness, expect, current).await?;
    for under in &expect.absent_under {
        let raw = harness
            .probe
            .entry(&harness.ids.entry(parse_versions(under)?))
            .await;
        if raw.is_some() {
            return Err(format!("an entry exists under {under}"));
        }
    }
    if expect.counters_absent {
        for counter in [VersionCounter::Workspace, VersionCounter::Membership] {
            let value = harness
                .probe
                .counter(counter, harness.ids.counter(counter))
                .await;
            if value.is_some() {
                return Err(format!("the {counter:?} counter exists"));
            }
        }
    }
    Ok(())
}

/// Plays one sequence of steps on one store.
async fn play<P: MembershipCacheProbe + ?Sized>(
    probe: &P,
    identifier_key: &[u8; 64],
    steps: &[Step],
) -> Result<(), String> {
    let ids = MembershipCacheIds::derive(identifier_key, MEMBER).map_err(|e| e.to_string())?;
    let held = Held {
        workspace: WorkspaceStatus::Active,
        membership: MembershipStatus::Active,
        role: String::new(),
        concurrent_bump: None,
    };
    let rows = ScenarioRows {
        probe,
        identifier_key,
        held: Mutex::new(held),
        reads: AtomicUsize::new(0),
    };
    let harness = Harness {
        probe,
        identifier_key,
        ids,
        rows,
    };
    for (index, step) in steps.iter().enumerate() {
        let failed = |error: String| format!("step {index} ({:?}): {error}", step.action);
        harness.hold(step).map_err(failed)?;
        act(&harness, step).await.map_err(failed)?;
        if matches!(step.action, Action::Resolve | Action::SeedEntry) {
            resolve(&harness, &step.expect).await.map_err(failed)?;
        }
        check(&harness, &step.expect).await.map_err(failed)?;
    }
    Ok(())
}

/// Plays `workspaceMembershipCache.scenarios` of the shared contract: `steps` on one fresh store,
/// then `counterLoss.steps` on another, each store from `fresh`. Returns how many steps ran.
///
/// The entry lifetime is the option's default, and `identifier_key` derives every key.
///
/// # Errors
///
/// A description of the first step that did not do what the contract expects, of a section the
/// runner cannot read (an unknown step, field or status), or of a store `fresh` could not give.
pub async fn run_membership_cache_scenarios<P, F, Fut>(
    scenarios: &Value,
    identifier_key: &[u8; 64],
    mut fresh: F,
) -> Result<usize, String>
where
    P: MembershipCacheProbe,
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<P>>,
{
    let parsed = Scenarios::deserialize(scenarios).map_err(|error| error.to_string())?;
    let mut played = 0;
    for (name, steps) in [
        ("steps", &parsed.steps),
        ("counterLoss", &parsed.counter_loss.steps),
    ] {
        if steps.is_empty() {
            return Err(format!("{name} has no steps"));
        }
        let store = fresh().await.ok_or("no fresh store")?;
        play(&store, identifier_key, steps)
            .await
            .map_err(|error| format!("{name}: {error}"))?;
        played += steps.len();
    }
    Ok(played)
}
