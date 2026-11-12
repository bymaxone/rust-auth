//! Testcontainers coverage of the Redis `MembershipCacheStore` (layer: store adapter, integration
//! tests).
//!
//! The contract's scenarios run here through the same runner the in-memory store plays
//! (`bymax_auth_core::testing::membership_cache_scenarios`), so the two implementations are held to
//! one table. The rest pins the wire: the keys and the entry nest-auth reads, the retention every
//! bump and fill leaves on a counter, and a read that creates nothing.
//!
//! Without Docker every container-backed case skips and says so; `BYMAX_REQUIRE_DOCKER=1` makes
//! that a failure.

#[path = "common/docker_gate.rs"]
mod docker_gate;

use std::num::NonZeroU64;

use async_trait::async_trait;
use bymax_auth_core::services::membership_cache::{
    MembershipCache, Repositories, Resolution, ResolutionSource, resolve_membership,
};
use bymax_auth_core::testing::InMemoryWorkspaces;
use bymax_auth_core::testing::membership_cache_scenarios::{
    MembershipCacheProbe, run_membership_cache_scenarios,
};
use bymax_auth_core::traits::{FillOutcome, MembershipCacheRead, MembershipCacheStore};
use bymax_auth_core::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceStatus,
};
use bymax_auth_core::workspace::limits::VERSION_RETENTION_SECONDS;
use bymax_auth_core::workspace::membership_cache::{
    MembershipCacheIds, MembershipCacheTtl, MembershipVersions, VersionCounter, entry_value,
};
use bymax_auth_redis::{NamespacedRedis, Prefix, RedisStores};
use bymax_auth_types::AuthError;
use serde_json::Value;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");

/// The `workspaceMembershipCache` section.
fn section() -> Value {
    serde_json::from_str::<Value>(CONTRACT)
        .map_or(Value::Null, |root| root["workspaceMembershipCache"].clone())
}

/// The identifier-HMAC key the contract's vectors use.
fn identifier_key() -> [u8; 64] {
    let root: Value = serde_json::from_str(CONTRACT).unwrap_or(Value::Null);
    let hex = root["hmacKeyDerivation"]["vectors"][0]["derivedKeyHex"]
        .as_str()
        .unwrap_or_default();
    let mut key = [0_u8; 64];
    if hex.len() == key.len() {
        key.copy_from_slice(hex.as_bytes());
    }
    key
}

/// A running `redis:8` container plus the URL bound to it (kept alive while in scope).
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

/// Start a `redis:8` container, or `None` when Docker is not available.
async fn try_start() -> Option<TestRedis> {
    let container = match Redis::default().with_tag("8").start().await {
        Ok(container) => container,
        Err(error) => return docker_gate::docker_unavailable("redis:8", error),
    };
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

impl TestRedis {
    /// A probe that must connect: a container that started and refuses a connection fails the
    /// case instead of passing it.
    async fn connected(&self, namespace: &str) -> Option<RedisProbe> {
        let probe = self.probe(namespace).await;
        assert!(
            probe.is_some(),
            "the started container refused a connection"
        );
        probe
    }

    /// A store and its raw keyspace under `namespace`.
    async fn probe(&self, namespace: &str) -> Option<RedisProbe> {
        let _ = self.container.id();
        let stores = RedisStores::connect(&self.url, namespace.to_owned()).ok()?;
        let client = redis::Client::open(self.url.as_str()).ok()?;
        let raw = client.get_multiplexed_async_connection().await.ok()?;
        let keys = NamespacedRedis::new(namespace.to_owned());
        Some(RedisProbe { stores, raw, keys })
    }
}

/// The Redis store, with a raw connection that reaches its keyspace for the scenario probes.
struct RedisProbe {
    stores: RedisStores,
    raw: redis::aio::MultiplexedConnection,
    keys: NamespacedRedis,
}

impl RedisProbe {
    /// The full key of a counter.
    fn counter_key(&self, counter: VersionCounter, id: &str) -> String {
        let prefix = match counter {
            VersionCounter::Workspace => Prefix::Wsv,
            VersionCounter::Membership => Prefix::Wmv,
        };
        self.keys.key(prefix, id)
    }

    /// The text at `key`, or `None` when it is absent.
    async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.raw.clone();
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .ok()
            .flatten()
    }

    /// `TTL key`: `-2` absent, `-1` no expiry.
    async fn ttl(&self, key: &str) -> i64 {
        let mut conn = self.raw.clone();
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap_or(-2)
    }

    /// Every key of the namespace, sorted.
    async fn keys(&self) -> Vec<String> {
        let mut conn = self.raw.clone();
        let pattern = format!("{}:*", self.keys.namespace());
        let mut keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        keys.sort();
        keys
    }

    /// `SET key value EX ttl`, as another writer would.
    async fn set(&self, key: &str, value: &str, ttl: u64) -> bool {
        let mut conn = self.raw.clone();
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(&mut conn)
            .await
            .is_ok()
    }
}

#[async_trait]
impl MembershipCacheStore for RedisProbe {
    async fn read(&self, ids: &MembershipCacheIds) -> Result<MembershipCacheRead, AuthError> {
        self.stores.read(ids).await
    }

    async fn fill(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, AuthError> {
        self.stores.fill(ids, versions, role, ttl).await
    }

    async fn bump_workspace(&self, workspace_id: &str) -> Result<u64, AuthError> {
        self.stores.bump_workspace(workspace_id).await
    }

    async fn bump_membership(&self, membership_id: &str) -> Result<u64, AuthError> {
        self.stores.bump_membership(membership_id).await
    }
}

#[async_trait]
impl MembershipCacheProbe for RedisProbe {
    async fn seed_entry(&self, entry_id: &str, raw: &str) {
        let _ = self
            .set(
                &self.keys.key(Prefix::Wm, entry_id),
                raw,
                VERSION_RETENTION_SECONDS,
            )
            .await;
    }

    async fn entry(&self, entry_id: &str) -> Option<String> {
        self.get(&self.keys.key(Prefix::Wm, entry_id)).await
    }

    async fn counter(&self, counter: VersionCounter, id: &str) -> Option<u64> {
        let value = self.get(&self.counter_key(counter, id)).await?;
        value.parse().ok()
    }

    async fn drop_counter(&self, counter: VersionCounter, id: &str) {
        let mut conn = self.raw.clone();
        let _: Result<i64, _> = redis::cmd("DEL")
            .arg(self.counter_key(counter, id))
            .query_async(&mut conn)
            .await;
    }
}

/// The identifiers of the member every case below names.
fn ids() -> Option<MembershipCacheIds> {
    let member = MembershipRef {
        tenant_id: "tenant-1",
        workspace_id: "ws-1",
        user_id: "user-1",
    };
    MembershipCacheIds::derive(&identifier_key(), member).ok()
}

/// An entry lifetime of `seconds`.
fn ttl(seconds: u64) -> NonZeroU64 {
    NonZeroU64::new(seconds).unwrap_or(NonZeroU64::MIN)
}

/// Whether a TTL reading is the counters' retention, less a margin for the time a test takes.
fn is_retention(ttl: i64) -> bool {
    let retention = i64::try_from(VERSION_RETENTION_SECONDS).unwrap_or(i64::MAX);
    ttl <= retention && ttl >= retention - 5
}

#[tokio::test]
async fn the_contract_scenarios_pass_against_a_real_redis() {
    let Some(redis) = try_start().await else { return };
    let mut run = 0;
    let played = run_membership_cache_scenarios(&section()["scenarios"], &identifier_key(), || {
        run += 1;
        let namespace = format!("scenario{run}");
        let redis = &redis;
        async move { redis.probe(&namespace).await }
    })
    .await;
    assert!(matches!(played, Ok(steps) if steps > 10), "{played:?}");
}

#[tokio::test]
async fn the_keys_and_the_entry_are_the_ones_the_contract_pins() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    // A read of a fresh keyspace reads 0:0 and creates nothing.
    let read = probe.read(&ids).await;
    assert!(matches!(&read, Ok(read) if read.versions == MembershipVersions::default()));
    assert!(probe.keys().await.is_empty());

    let filled = probe
        .fill(&ids, MembershipVersions::default(), "editor", ttl(60))
        .await;
    assert!(matches!(filled, Ok(FillOutcome::Written)));
    let entry_key = probe
        .keys
        .key(Prefix::Wm, &ids.entry(MembershipVersions::default()));
    assert_eq!(probe.keys().await, std::slice::from_ref(&entry_key));
    assert_eq!(probe.get(&entry_key).await, Some(entry_value("editor")));
    let left = probe.ttl(&entry_key).await;
    assert!((55..=60).contains(&left), "{left}");

    assert!(matches!(probe.bump_workspace(&ids.workspace).await, Ok(1)));
    assert!(matches!(
        probe.bump_membership(&ids.membership).await,
        Ok(1)
    ));
    for counter in [VersionCounter::Workspace, VersionCounter::Membership] {
        let key = probe.counter_key(counter, ids.counter(counter));
        assert_eq!(probe.get(&key).await.as_deref(), Some("1"), "{counter:?}");
        assert!(is_retention(probe.ttl(&key).await), "{counter:?}");
    }
}

/// Reads the version a vector names, as a number.
fn version_of(vector: &Value, name: &str) -> u64 {
    vector[name]
        .as_str()
        .unwrap_or_default()
        .parse()
        .unwrap_or(u64::MAX)
}

#[tokio::test]
async fn every_full_key_vector_names_the_keys_the_store_writes() {
    let Some(redis) = try_start().await else { return };
    let vectors = section()["fullKeyVectors"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!vectors.is_empty());
    for (index, vector) in vectors.iter().enumerate() {
        let Some(probe) = redis.connected(&format!("vec{index}")).await else { return };
        let member = MembershipRef {
            tenant_id: vector["tenantId"].as_str().unwrap_or_default(),
            workspace_id: vector["workspaceId"].as_str().unwrap_or_default(),
            user_id: vector["userId"].as_str().unwrap_or_default(),
        };
        let Ok(ids) = MembershipCacheIds::derive(&identifier_key(), member) else { return };
        let versions = MembershipVersions {
            workspace: version_of(vector, "workspaceVersion"),
            membership: version_of(vector, "membershipVersion"),
        };
        let expected = |name: &str| {
            let key = vector[name].as_str().unwrap_or_default();
            key.replace("{namespace}", &format!("vec{index}"))
        };
        for (counter, name, version) in [
            (
                VersionCounter::Workspace,
                "workspaceVersionKey",
                versions.workspace,
            ),
            (
                VersionCounter::Membership,
                "membershipVersionKey",
                versions.membership,
            ),
        ] {
            let key = probe.counter_key(counter, ids.counter(counter));
            assert_eq!(key, expected(name), "{index} {name}");
            assert!(version == 0 || probe.set(&key, &version.to_string(), 60).await);
        }
        let filled = probe.fill(&ids, versions, "editor", ttl(60)).await;
        assert!(matches!(filled, Ok(FillOutcome::Written)), "{index}");
        let entry = probe.keys.key(Prefix::Wm, &ids.entry(versions));
        assert_eq!(entry, expected("membershipCacheKey"), "{index}");
        assert_eq!(
            probe.get(&entry).await,
            Some(entry_value("editor")),
            "{index}"
        );
    }
}

#[tokio::test]
async fn every_bump_restores_the_retention() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    let key = probe.counter_key(VersionCounter::Membership, &ids.membership);
    assert!(probe.set(&key, "7", 30).await);
    assert!(matches!(
        probe.bump_membership(&ids.membership).await,
        Ok(8)
    ));
    assert!(is_retention(probe.ttl(&key).await));
    assert!(matches!(
        probe.bump_membership(&ids.membership).await,
        Ok(9)
    ));
    assert!(is_retention(probe.ttl(&key).await));
}

#[tokio::test]
async fn a_fill_extends_existing_counters_and_never_creates_one() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    let workspace_key = probe.counter_key(VersionCounter::Workspace, &ids.workspace);
    let membership_key = probe.counter_key(VersionCounter::Membership, &ids.membership);
    assert!(probe.set(&workspace_key, "3", 30).await);
    let versions = MembershipVersions {
        workspace: 3,
        membership: 0,
    };
    let filled = probe.fill(&ids, versions, "owner", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Written)));
    assert!(is_retention(probe.ttl(&workspace_key).await));
    assert_eq!(probe.ttl(&membership_key).await, -2);
    assert_eq!(
        probe.entry(&ids.entry(versions)).await,
        Some(entry_value("owner"))
    );
}

#[tokio::test]
async fn a_fill_that_finds_a_counter_moved_writes_and_refreshes_nothing() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    let membership_key = probe.counter_key(VersionCounter::Membership, &ids.membership);
    assert!(probe.set(&membership_key, "2", 30).await);
    let stale = MembershipVersions {
        workspace: 0,
        membership: 1,
    };
    let filled = probe.fill(&ids, stale, "owner", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Moved)));
    assert_eq!(probe.keys().await, std::slice::from_ref(&membership_key));
    assert!(probe.ttl(&membership_key).await <= 30);
}

#[tokio::test]
async fn a_counter_that_expired_after_the_read_no_longer_matches() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    let workspace_key = probe.counter_key(VersionCounter::Workspace, &ids.workspace);
    assert!(probe.set(&workspace_key, "1", 30).await);
    let read = probe.read(&ids).await.map(|read| read.versions);
    let seen = MembershipVersions {
        workspace: 1,
        membership: 0,
    };
    assert_eq!(read.ok(), Some(seen));
    probe
        .drop_counter(VersionCounter::Workspace, &ids.workspace)
        .await;
    let filled = probe.fill(&ids, seen, "owner", ttl(60)).await;
    assert!(matches!(filled, Ok(FillOutcome::Moved)));
    assert!(probe.keys().await.is_empty());
}

#[tokio::test]
async fn an_entry_another_writer_spelled_differently_is_read_by_parsing() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    let entry = ids.entry(MembershipVersions::default());
    probe
        .seed_entry(&entry, "{\"status\":\"active\", \"role\":\"viewer\"}")
        .await;
    let read = probe.read(&ids).await;
    assert!(matches!(read, Ok(read) if read.cached_role().as_deref() == Some("viewer")));
    probe
        .seed_entry(&entry, "{\"role\":\"viewer\",\"status\":\"suspended\"}")
        .await;
    let read = probe.read(&ids).await;
    assert!(matches!(read, Ok(read) if read.entry.is_some() && read.cached_role().is_none()));
}

#[tokio::test]
async fn a_counter_that_is_not_a_number_fails_the_read() {
    let Some(redis) = try_start().await else { return };
    let (Some(probe), Some(ids)) = (redis.connected("auth").await, ids()) else { return };
    assert!(
        probe
            .set(
                &probe.counter_key(VersionCounter::Workspace, &ids.workspace),
                "x",
                30
            )
            .await
    );
    assert!(probe.read(&ids).await.is_err());
}

/// The workspace and the membership of the member [`ids`] names, both active.
fn seeded_repositories() -> InMemoryWorkspaces {
    let repositories = InMemoryWorkspaces::new();
    let epoch = time::OffsetDateTime::UNIX_EPOCH;
    repositories.seed_workspace(Workspace {
        id: "ws-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        name: "W".to_owned(),
        status: WorkspaceStatus::Active,
        created_at: epoch,
        deletion_scheduled_at: None,
    });
    repositories.seed_membership(Membership {
        tenant_id: "tenant-1".to_owned(),
        workspace_id: "ws-1".to_owned(),
        user_id: "user-1".to_owned(),
        role: "editor".to_owned(),
        status: MembershipStatus::Active,
        invited_by_user_id: None,
        created_at: epoch,
        updated_at: epoch,
    });
    repositories
}

#[tokio::test]
async fn an_unreachable_redis_answers_from_the_repositories() {
    // Nothing listens on port 1; the pool fails at the first command.
    let Ok(stores) = RedisStores::connect("redis://127.0.0.1:1", "auth") else { return };
    let repositories = seeded_repositories();
    let rows = Repositories {
        workspaces: &repositories,
        memberships: &repositories,
    };
    let key = identifier_key();
    let cache = MembershipCache {
        store: &stores,
        identifier_key: &key,
        ttl: MembershipCacheTtl::default(),
    };
    let member = MembershipRef {
        tenant_id: "tenant-1",
        workspace_id: "ws-1",
        user_id: "user-1",
    };
    let answer = resolve_membership(&cache, &rows, member).await;
    let expected = Resolution::Member {
        role: "editor".to_owned(),
        source: ResolutionSource::Repository,
    };
    assert_eq!(answer.ok(), Some(expected));
    assert!(stores.bump_membership("m").await.is_err());
}
