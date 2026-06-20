//! Testcontainers coverage of the Redis `OAuthStateStore` implementation: the single-use
//! OAuth `state` + PKCE record under the `os:` keyspace — `SET ... EX 600` on `put_state`,
//! atomic `GETDEL` on `take_state` (so a captured `state` is consumed exactly once), an absent
//! state reads as `None`, the 600 s TTL is applied, and the key is namespaced with no PII (the
//! id segment is the engine-supplied `sha256(state)`, never the raw `state`).
//!
//! The whole file compiles only under the `oauth` feature (the trait it drives is
//! `oauth`-gated). When Docker is unavailable every case returns early, so a no-Docker
//! `cargo test` still passes.
#![cfg(feature = "oauth")]

use bymax_auth_core::traits::OAuthStateStore;
use bymax_auth_redis::RedisStores;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// The single-use record TTL the engine applies to the `os:` keyspace (ten minutes).
const STATE_TTL_SECS: u64 = 600;

/// A running `redis:8` container plus the URL bound to it (kept alive while in scope).
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

impl TestRedis {
    fn stores(&self, namespace: &str) -> Option<RedisStores> {
        RedisStores::connect(&self.url, namespace.to_owned()).ok()
    }

    /// A raw connection for keyspace inspection (`KEYS`, `TTL`); also keeps the container read.
    async fn raw(&self) -> Option<redis::aio::MultiplexedConnection> {
        let _ = self.container.id();
        let client = redis::Client::open(self.url.as_str()).ok()?;
        client.get_multiplexed_async_connection().await.ok()
    }

    /// Every key currently in the keyspace, for the no-PII / namespacing assertions.
    async fn all_keys(&self) -> Vec<String> {
        let Some(mut conn) = self.raw().await else {
            return Vec::new();
        };
        redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default()
    }

    /// The TTL (seconds) of a key: `-2` when absent, `-1` when it has no expiry.
    async fn ttl(&self, key: &str) -> i64 {
        let Some(mut conn) = self.raw().await else {
            return -2;
        };
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap_or(-2)
    }
}

/// Start a `redis:8` container, or `None` when Docker is not available.
async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

#[tokio::test]
async fn state_record_is_set_then_getdel_consumed_exactly_once() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("oauthstate") else { return };

    // The engine passes the hex sha256(state) as the key id; this opaque value stands in for it.
    let state_hash = "a".repeat(64);
    let payload = "{\"tenantId\":\"t1\",\"codeVerifier\":\"pkce-verifier\"}";

    // `put_state` writes the os: record with a 600 s TTL.
    assert!(
        stores
            .put_state(&state_hash, payload, STATE_TTL_SECS)
            .await
            .is_ok()
    );

    // The TTL is applied (allow a one-second clock slack below 600).
    let keys = redis.all_keys().await;
    assert_eq!(keys.len(), 1, "exactly one os: record exists");
    let Some(key) = keys.first() else { return };
    assert_eq!(*key, format!("oauthstate:os:{state_hash}"));
    let ttl = redis.ttl(key).await;
    assert!(
        (599..=600).contains(&ttl),
        "the 600 s TTL is set (observed {ttl})"
    );

    // `take_state` returns the payload verbatim, exactly once (GETDEL).
    assert!(matches!(
        stores.take_state(&state_hash).await,
        Ok(Some(ref v)) if v == payload
    ));
    // A second consume of the same state is a miss: the captured state cannot be replayed.
    assert!(matches!(stores.take_state(&state_hash).await, Ok(None)));
}

#[tokio::test]
async fn absent_state_reads_as_none() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("oauthabsent") else { return };

    // A never-issued state hash is unknown to the store — Ok(None), not an error.
    assert!(matches!(stores.take_state(&"f".repeat(64)).await, Ok(None)));
}

#[tokio::test]
async fn the_key_is_namespaced_and_carries_no_pii() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("oauthns") else { return };

    let state_hash = "b".repeat(64);
    assert!(
        stores
            .put_state(
                &state_hash,
                "{\"tenantId\":\"t1\",\"codeVerifier\":\"v\"}",
                STATE_TTL_SECS
            )
            .await
            .is_ok()
    );
    // The key is `{namespace}:os:{sha256(state)}` — namespaced, under the os: prefix, and its id
    // segment is the supplied hash (no email, no raw state, no `@`).
    let keys = redis.all_keys().await;
    assert!(
        keys.iter().all(|k| {
            k.starts_with("oauthns:os:") && k.ends_with(&state_hash) && !k.contains('@')
        })
    );
}
