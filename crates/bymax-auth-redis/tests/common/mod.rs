//! Shared testcontainers harness for the Redis integration tier.
//!
//! [`try_start`] spins up a real `redis:8` container and yields a connected [`RedisStores`]
//! plus a raw connection for keyspace inspection. When Docker is unavailable it returns
//! `None`, so a no-Docker `cargo test` still compiles and runs (the integration cases skip
//! via a `let Some(..) else { return }`); under Docker every case executes. Every helper
//! defined here is exercised by the single integration test file that includes the module.

use bymax_auth_redis::RedisStores;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// The default key namespace used across the integration tier.
pub const NAMESPACE: &str = "auth";

/// A running Redis container plus the URL bound to it. The container is kept alive for the
/// lifetime of this value; dropping it stops the container.
pub struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

impl TestRedis {
    /// A fresh store handle over the running container, under the default namespace.
    pub fn stores(&self) -> Option<RedisStores> {
        RedisStores::connect(&self.url, NAMESPACE).ok()
    }

    /// A fresh store handle under a custom namespace, for the namespacing assertions.
    pub fn stores_with_namespace(&self, namespace: &str) -> Option<RedisStores> {
        RedisStores::connect(&self.url, namespace.to_owned()).ok()
    }

    /// A raw multiplexed connection for keyspace inspection (`KEYS`, `TTL`). Also confirms the
    /// container is reachable, which keeps the held container handle meaningfully read.
    async fn raw(&self) -> Option<redis::aio::MultiplexedConnection> {
        // Touch the container handle so it is unambiguously kept alive (and read) for as long
        // as the harness is in scope; dropping `TestRedis` tears the container down.
        let _ = self.container.id();
        let client = redis::Client::open(self.url.as_str()).ok()?;
        client.get_multiplexed_async_connection().await.ok()
    }

    /// Every key currently present in the keyspace (test databases are small and isolated).
    pub async fn all_keys(&self) -> Vec<String> {
        let Some(mut conn) = self.raw().await else {
            return Vec::new();
        };
        redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default()
    }

    /// Delete a key out-of-band (used to simulate a per-session detail that expired ahead of
    /// its session-index membership). Returns whether the command succeeded.
    pub async fn del(&self, key: &str) -> bool {
        let Some(mut conn) = self.raw().await else {
            return false;
        };
        redis::cmd("DEL")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .is_ok()
    }

    /// The TTL (seconds) of a key: `-2` when absent, `-1` when it has no expiry.
    pub async fn ttl(&self, key: &str) -> i64 {
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

/// Start a `redis:8` container, returning `None` when Docker is not available so the test can
/// skip cleanly rather than fail.
pub async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}
