//! Testcontainers coverage of the Redis `WorkspaceInvitationStore` (layer: store adapter,
//! integration tests).
//!
//! The scenarios run here through the same runner the in-memory store plays
//! (`bymax_auth_core::testing::workspace_invitation_scenarios`), so the two implementations are
//! held to one table: the lost compare-and-set, the cap, the expiry of the record with its index
//! and set, and the inviter counter's lifetime. The rest pins the wire: the keys and values
//! `workspaceInvitations` in the shared contract names, derived from its vectors.
//!
//! Without Docker every container-backed case skips and says so; `BYMAX_REQUIRE_DOCKER=1` makes
//! that a failure.

#[path = "common/docker_gate.rs"]
mod docker_gate;

use std::num::NonZeroU64;
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_core::testing::workspace_invitation_scenarios::{
    InvitationStoreProbe, run_invitation_store_scenarios,
};
use bymax_auth_core::traits::{
    IndexedInvitation, InvitationPlace, PendingInvitation, Publication, PublishOutcome,
    WorkspaceInvitationStore,
};
use bymax_auth_core::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use bymax_auth_core::workspace::keys::{
    invitation_index_id, invitation_record_id, invitation_set_id, inviter_rate_id,
};
use bymax_auth_redis::{NamespacedRedis, Prefix, RedisStores};
use bymax_auth_types::AuthError;
use serde_json::Value;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");

/// The `workspaceInvitations` section.
fn section() -> Value {
    serde_json::from_str::<Value>(CONTRACT)
        .map_or(Value::Null, |root| root["workspaceInvitations"].clone())
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
    /// A store and its raw keyspace under `namespace`; a container that started and refuses a
    /// connection fails the case instead of passing it.
    async fn probe(&self, namespace: &str) -> Option<RedisProbe> {
        let _ = self.container.id();
        let stores = RedisStores::connect(&self.url, namespace.to_owned()).ok();
        let client = redis::Client::open(self.url.as_str()).ok();
        let raw = match client {
            Some(client) => client.get_multiplexed_async_connection().await.ok(),
            None => None,
        };
        assert!(
            stores.is_some() && raw.is_some(),
            "the started container refused a connection"
        );
        Some(RedisProbe {
            stores: stores?,
            raw: raw?,
            keys: NamespacedRedis::new(namespace.to_owned()),
        })
    }
}

/// The Redis store, with a raw connection that reaches its keyspace for the scenario probes.
struct RedisProbe {
    stores: RedisStores,
    raw: redis::aio::MultiplexedConnection,
    keys: NamespacedRedis,
}

impl RedisProbe {
    /// The full key of a record key (`winv:{hash}`) as stored in the index and the set.
    fn full(&self, record_key: &str) -> String {
        format!("{}:{record_key}", self.keys.namespace())
    }

    async fn text(&self, key: &str) -> Option<String> {
        let mut conn = self.raw.clone();
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .ok()
            .flatten()
    }

    /// `TTL key` as a lifetime: `None` when the key is absent.
    async fn left(&self, key: &str) -> Option<u64> {
        let mut conn = self.raw.clone();
        let left: i64 = redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap_or(-2);
        u64::try_from(left).ok()
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) {
        let mut conn = self.raw.clone();
        let _: Result<(), _> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query_async(&mut conn)
            .await;
    }

    /// Every key of the namespace, sorted.
    async fn all_keys(&self) -> Vec<String> {
        let mut conn = self.raw.clone();
        let mut keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{}:*", self.keys.namespace()))
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        keys.sort();
        keys
    }
}

#[async_trait]
impl WorkspaceInvitationStore for RedisProbe {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        self.stores.read_record(record_key).await
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        self.stores.read_index(place).await
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        self.stores.publish(publication).await
    }

    async fn remove(&self, place: &InvitationPlace, record_key: &str) -> Result<bool, AuthError> {
        self.stores.remove(place, record_key).await
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        self.stores.pending(place).await
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        self.stores.count_inviter(rate_id).await
    }
}

#[async_trait]
impl InvitationStoreProbe for RedisProbe {
    async fn pass_time(&self, by: Duration) {
        tokio::time::sleep(by).await;
    }

    async fn plant_raw_record(&self, record_key: &str, raw: &str, ttl: Duration) {
        self.set(&self.full(record_key), raw, ttl).await;
    }

    async fn point_index(&self, place: &InvitationPlace, record_key: &str, ttl: Duration) {
        self.set(
            &self.keys.key(Prefix::Winvidx, &place.index_id),
            record_key,
            ttl,
        )
        .await;
    }

    async fn delete_record(&self, record_key: &str) {
        let mut conn = self.raw.clone();
        let _: Result<i64, _> = redis::cmd("DEL")
            .arg(self.full(record_key))
            .query_async(&mut conn)
            .await;
    }

    async fn set_members(&self, place: &InvitationPlace) -> Vec<String> {
        let mut conn = self.raw.clone();
        let mut members: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.keys.key(Prefix::Winvset, &place.set_id))
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        members.sort();
        members
    }

    async fn record_ttl(&self, record_key: &str) -> Option<u64> {
        self.left(&self.full(record_key)).await
    }

    async fn index_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        self.left(&self.keys.key(Prefix::Winvidx, &place.index_id))
            .await
    }

    async fn set_ttl(&self, place: &InvitationPlace) -> Option<u64> {
        self.left(&self.keys.key(Prefix::Winvset, &place.set_id))
            .await
    }

    async fn rate_ttl(&self, rate_id: &str) -> Option<u64> {
        self.left(&self.keys.key(Prefix::Winvrl, rate_id)).await
    }
}

#[tokio::test]
async fn the_scenarios_pass_against_a_real_redis() {
    let Some(redis) = try_start().await else { return };
    let Some(probe) = redis.probe("scenarios").await else { return };
    run_invitation_store_scenarios(&probe).await;
}

/// A member record any case can publish.
fn record(email: &str) -> InvitationRecord {
    InvitationRecord::Member {
        base: InvitationBase {
            email: email.to_owned(),
            role: "member".to_owned(),
            tenant_id: "t".to_owned(),
            workspace_id: "w".to_owned(),
            created_at: "2026-11-20T10:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        inviter_user_id: "u1".to_owned(),
    }
}

/// A vector's text field.
fn text(vector: &Value, field: &str) -> String {
    vector[field].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn the_keys_and_values_written_are_the_ones_the_contract_vectors_name() {
    let Some(redis) = try_start().await else { return };
    let vectors = section()["fullKeyVectors"].clone();
    let vectors = vectors.as_array().cloned().unwrap_or_default();
    assert!(!vectors.is_empty(), "the contract lists no key vectors");
    for (n, vector) in vectors.iter().enumerate() {
        let namespace = format!("vector{n}");
        let Some(probe) = redis.probe(&namespace).await else { return };
        let (tenant, workspace, email) = (
            text(vector, "tenantId"),
            text(vector, "workspaceId"),
            text(vector, "email"),
        );
        let place = InvitationPlace {
            index_id: invitation_index_id(&identifier_key(), &tenant, &workspace, &email)
                .unwrap_or_default(),
            set_id: invitation_set_id(&identifier_key(), &tenant, &workspace).unwrap_or_default(),
        };
        let key = record_key(&invitation_record_id(&text(vector, "token")));
        let ttl = NonZeroU64::new(600).unwrap_or(NonZeroU64::MIN);
        let outcome = probe
            .publish(Publication {
                place: &place,
                record_key: &key,
                record: &record(&email),
                ttl,
                pending_limit: 0,
                expected_key: None,
            })
            .await;
        assert!(
            matches!(outcome, Ok(PublishOutcome::Published)),
            "{outcome:?}"
        );
        let named = |field: &str| text(vector, field).replace("{namespace}", &namespace);
        let mut expected = vec![named("indexKey"), named("setKey"), named("recordKey")];
        expected.sort();
        assert_eq!(
            probe.all_keys().await,
            expected,
            "vector {n}: the keys written"
        );
        assert_eq!(
            probe.text(&named("indexKey")).await,
            Some(key.clone()),
            "the index holds the record key"
        );
        assert_eq!(
            probe.set_members(&place).await,
            vec![key],
            "the set holds the record key"
        );
    }
}

#[tokio::test]
async fn the_inviter_counter_is_written_under_the_contract_key() {
    let Some(redis) = try_start().await else { return };
    let vectors = section()["inviterRateVectors"].clone();
    let vectors = vectors.as_array().cloned().unwrap_or_default();
    assert!(!vectors.is_empty(), "the contract lists no inviter vectors");
    for (n, vector) in vectors.iter().enumerate() {
        let namespace = format!("rate{n}");
        let Some(probe) = redis.probe(&namespace).await else { return };
        let id = inviter_rate_id(
            &identifier_key(),
            &text(vector, "tenantId"),
            &text(vector, "userId"),
        )
        .unwrap_or_default();
        assert!(matches!(probe.count_inviter(&id).await, Ok(1)));
        let key = text(vector, "key").replace("{namespace}", &namespace);
        assert_eq!(probe.all_keys().await, vec![key.clone()], "vector {n}");
        assert_eq!(probe.text(&key).await, Some("1".to_owned()));
    }
}
