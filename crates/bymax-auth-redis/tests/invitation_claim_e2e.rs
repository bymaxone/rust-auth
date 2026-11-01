//! Testcontainers coverage of the Redis invitee-index compare-and-set: a claim proceeds only
//! while the index still holds exactly what the caller approved, with the invitation's TTL.
//!
//! When Docker is unavailable every case returns early, so a no-Docker `cargo test` still passes.

use bymax_auth_core::traits::InvitationStore;
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

    /// The remaining TTL of `key` in seconds (`-1` no expiry, `-2` absent).
    async fn ttl(&self, key: &str) -> i64 {
        let _ = self.container.id();
        let Ok(client) = redis::Client::open(self.url.as_str()) else {
            return -2;
        };
        let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
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

const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn the_claim_proceeds_only_while_the_index_holds_what_was_approved() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };

    // Nothing indexed: a claim expecting "absent" wins, one expecting a hash does not.
    assert!(matches!(
        stores
            .claim_invitation_index("t1", "cafe", OLD, 600, Some(NEW))
            .await,
        Ok(false)
    ));
    assert!(matches!(
        stores
            .claim_invitation_index("t1", "cafe", OLD, 600, None)
            .await,
        Ok(true)
    ));
    assert!(matches!(stores.read_invitation_index("t1", "cafe").await, Ok(Some(h)) if h == OLD));

    // The index now holds OLD: a claim that still expects "absent" loses and changes nothing,
    // a claim naming the wrong hash loses, and one naming OLD wins.
    assert!(matches!(
        stores
            .claim_invitation_index("t1", "cafe", NEW, 600, None)
            .await,
        Ok(false)
    ));
    assert!(matches!(
        stores
            .claim_invitation_index("t1", "cafe", NEW, 600, Some(NEW))
            .await,
        Ok(false)
    ));
    assert!(matches!(stores.read_invitation_index("t1", "cafe").await, Ok(Some(h)) if h == OLD));
    assert!(matches!(
        stores
            .claim_invitation_index("t1", "cafe", NEW, 600, Some(OLD))
            .await,
        Ok(true)
    ));
    assert!(matches!(stores.read_invitation_index("t1", "cafe").await, Ok(Some(h)) if h == NEW));

    // The claimed entry carries the invitation's TTL, and tenants do not share an index.
    let ttl = redis.ttl("auth:invidx:t1:cafe").await;
    assert!((1..=600).contains(&ttl), "{ttl}");
    assert!(matches!(
        stores.read_invitation_index("t2", "cafe").await,
        Ok(None)
    ));
}
