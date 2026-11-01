//! Testcontainers coverage of the Redis `RateLimitStore`: the counter is shared by every store
//! handle on one Redis (two application instances share one budget), its window opens at the
//! first request and is never extended, and its key holds a hash, not an address.
//!
//! When Docker is unavailable every case returns early, so a no-Docker `cargo test` still passes.

#[path = "common/docker_gate.rs"]
mod docker_gate;

use bymax_auth_core::traits::RateLimitStore;
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

    /// Every key currently in the keyspace.
    async fn all_keys(&self) -> Vec<String> {
        let Some(mut conn) = self.connection().await else {
            return Vec::new();
        };
        redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default()
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
    let container = match Redis::default().with_tag("8").start().await {
        Ok(container) => container,
        Err(error) => return docker_gate::docker_unavailable("redis:8", error),
    };
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

#[tokio::test]
async fn two_instances_on_one_redis_share_one_budget() {
    let Some(redis) = try_start().await else { return };
    let (Some(first), Some(second)) = (redis.stores(), redis.stores()) else {
        return;
    };

    // Requests alternate between the two handles, as a load balancer would spread them.
    assert!(matches!(first.hit("login", "bucket-a", 60).await, Ok(1)));
    assert!(matches!(second.hit("login", "bucket-a", 60).await, Ok(2)));
    assert!(matches!(first.hit("login", "bucket-a", 60).await, Ok(3)));
    // A different route, and a different bucket, are separate budgets.
    assert!(matches!(
        second.hit("register", "bucket-a", 60).await,
        Ok(1)
    ));
    assert!(matches!(second.hit("login", "bucket-b", 60).await, Ok(1)));
}

#[tokio::test]
async fn the_window_is_set_once_and_the_key_carries_a_hash() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };

    assert!(matches!(stores.hit("login", "deadbeef", 60).await, Ok(1)));
    let key = "auth:rl:login:deadbeef";
    let first_ttl = redis.ttl(key).await;
    assert!((1..=60).contains(&first_ttl), "{first_ttl}");

    // A later request in the same window must not extend it: asking for a much longer window
    // changes nothing about the key that already exists.
    assert!(matches!(stores.hit("login", "deadbeef", 3600).await, Ok(2)));
    let second_ttl = redis.ttl(key).await;
    assert!((1..=60).contains(&second_ttl), "{second_ttl}");

    let keys = redis.all_keys().await;
    assert_eq!(keys, vec![key.to_owned()]);
}
