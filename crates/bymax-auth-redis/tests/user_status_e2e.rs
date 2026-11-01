//! Testcontainers coverage of the Redis `UserStatusCacheStore`: the keys and values are the ones
//! the shared wire contract pins (`{ns}:us:{subject hash}` and `{ns}:uev:{subject hash}`), every
//! entry carries a TTL, `invalidate` drops both facts, and two handles on one Redis see each
//! other's entries.
//!
//! When Docker is unavailable every case returns early, so a no-Docker `cargo test` still passes.

use bymax_auth_core::traits::UserStatusCacheStore;
use bymax_auth_redis::RedisStores;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// A running `redis:8` container plus the URL bound to it (kept alive while in scope).
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

impl TestRedis {
    fn stores(&self) -> Option<RedisStores> {
        RedisStores::connect(&self.url, "auth".to_owned()).ok()
    }

    async fn connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        let _ = self.container.id();
        let client = redis::Client::open(self.url.as_str()).ok()?;
        client.get_multiplexed_async_connection().await.ok()
    }

    /// Every key currently in the keyspace, sorted.
    async fn all_keys(&self) -> Vec<String> {
        let Some(mut conn) = self.connection().await else {
            return Vec::new();
        };
        let mut keys: Vec<String> = redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        keys.sort();
        keys
    }

    /// The raw string at `key`, as nest-auth would read it.
    async fn raw(&self, key: &str) -> Option<String> {
        let mut conn = self.connection().await?;
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .ok()?
    }

    /// The key's remaining TTL in seconds (`-1` no expiry, `-2` absent).
    async fn ttl(&self, key: &str) -> i64 {
        let Some(mut conn) = self.connection().await else {
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

/// A subject hash as the engine derives it: 64 lower-case hex characters.
const SUBJECT: &str = "40a3b06eff7ff26d20d5ff7b9f238ddf5858d7f42505bd646acf5ecd3ed9c50b";
/// Another account's subject hash.
const OTHER: &str = "ee454d898fc64c5c6021212945ac239004538d927c35f7b32f544aa0b68eb962";

#[tokio::test]
async fn the_entries_are_the_keys_and_values_the_contract_pins() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };

    assert!(stores.put_status(SUBJECT, "ACTIVE", 60).await.is_ok());
    assert!(stores.put_verified(SUBJECT, false, 60).await.is_ok());
    let (status_key, verified_key) = (format!("auth:us:{SUBJECT}"), format!("auth:uev:{SUBJECT}"));
    let mut expected = vec![verified_key.clone(), status_key.clone()];
    expected.sort();
    assert_eq!(redis.all_keys().await, expected);
    assert_eq!(redis.raw(&status_key).await.as_deref(), Some("ACTIVE"));
    assert_eq!(redis.raw(&verified_key).await.as_deref(), Some("0"));
    assert!(matches!(stores.get_status(SUBJECT).await, Ok(Some(s)) if s == "ACTIVE"));
    assert!(matches!(
        stores.get_verified(SUBJECT).await,
        Ok(Some(false))
    ));

    assert!(stores.put_verified(SUBJECT, true, 60).await.is_ok());
    assert_eq!(redis.raw(&verified_key).await.as_deref(), Some("1"));
    assert!(matches!(stores.get_verified(SUBJECT).await, Ok(Some(true))));
}

#[tokio::test]
async fn a_value_written_by_another_implementation_other_than_zero_reads_as_verified() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };
    let Some(mut conn) = redis.connection().await else { return };
    let _: () = redis::cmd("SET")
        .arg(format!("auth:uev:{SUBJECT}"))
        .arg("yes")
        .query_async(&mut conn)
        .await
        .unwrap_or_default();
    assert!(matches!(stores.get_verified(SUBJECT).await, Ok(Some(true))));
    assert!(matches!(stores.get_verified(OTHER).await, Ok(None)));
}

#[tokio::test]
async fn every_entry_expires_and_two_accounts_never_meet() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };

    assert!(stores.put_status(SUBJECT, "BANNED", 30).await.is_ok());
    assert!(stores.put_verified(SUBJECT, true, 30).await.is_ok());
    for key in [format!("auth:us:{SUBJECT}"), format!("auth:uev:{SUBJECT}")] {
        let ttl = redis.ttl(&key).await;
        assert!((1..=30).contains(&ttl), "{key} has TTL {ttl}");
    }
    assert!(matches!(stores.get_status(OTHER).await, Ok(None)));
    assert!(matches!(stores.get_verified(OTHER).await, Ok(None)));
}

#[tokio::test]
async fn invalidate_drops_both_facts_for_every_handle_on_that_redis() {
    let Some(redis) = try_start().await else { return };
    let (Some(first), Some(second)) = (redis.stores(), redis.stores()) else {
        return;
    };
    assert!(first.put_status(SUBJECT, "ACTIVE", 60).await.is_ok());
    assert!(first.put_verified(SUBJECT, true, 60).await.is_ok());
    // A different account's entry survives.
    assert!(first.put_status(OTHER, "ACTIVE", 60).await.is_ok());

    assert!(matches!(second.get_status(SUBJECT).await, Ok(Some(_))));
    assert!(second.invalidate(SUBJECT).await.is_ok());
    assert!(matches!(first.get_status(SUBJECT).await, Ok(None)));
    assert!(matches!(first.get_verified(SUBJECT).await, Ok(None)));
    assert_eq!(redis.all_keys().await, vec![format!("auth:us:{OTHER}")]);
}
