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

/// Claim `hash` for the address `cafe` in tenant `t1` expecting `expected`, with a 600 s TTL.
async fn claim(stores: &RedisStores, hash: &str, expected: Option<&str>) -> bool {
    stores
        .claim_invitation_index("t1", "cafe", hash, 600, expected)
        .await
        .unwrap_or(false)
}

/// The hash the index names for `cafe` in tenant `t1`.
async fn named(stores: &RedisStores) -> Option<String> {
    stores
        .read_invitation_index("t1", "cafe")
        .await
        .unwrap_or_default()
}

#[tokio::test]
async fn a_claim_expecting_an_absent_entry_wins_only_on_an_empty_index() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };

    // Nothing indexed: a claim expecting a hash loses, one expecting "absent" wins.
    assert!(!claim(&stores, OLD, Some(NEW)).await);
    assert!(claim(&stores, OLD, None).await);
    assert_eq!(named(&stores).await.as_deref(), Some(OLD));
    // Now the index is occupied, a claim still expecting "absent" loses and changes nothing.
    assert!(!claim(&stores, NEW, None).await);
    assert_eq!(named(&stores).await.as_deref(), Some(OLD));
}

#[tokio::test]
async fn a_claim_naming_the_wrong_hash_loses_and_one_naming_the_current_hash_wins() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };
    assert!(claim(&stores, OLD, None).await);

    assert!(!claim(&stores, NEW, Some(NEW)).await);
    assert_eq!(named(&stores).await.as_deref(), Some(OLD));
    assert!(claim(&stores, NEW, Some(OLD)).await);
    assert_eq!(named(&stores).await.as_deref(), Some(NEW));
}

#[tokio::test]
async fn a_claim_carries_the_ttl_and_a_claim_on_the_held_hash_renews_it() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };
    assert!(claim(&stores, OLD, None).await);
    let ttl = redis.ttl("auth:invidx:t1:cafe").await;
    assert!((1..=600).contains(&ttl), "{ttl}");

    // An invite that writes its record later than its claim renews the index so the record
    // cannot outlive the entry that names it.
    let renewed = stores
        .claim_invitation_index("t1", "cafe", OLD, 6000, Some(OLD))
        .await;
    assert!(matches!(renewed, Ok(true)));
    let after = redis.ttl("auth:invidx:t1:cafe").await;
    assert!(after > 600, "{after}");
}

#[tokio::test]
async fn tenants_do_not_share_an_index() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { return };
    assert!(claim(&stores, OLD, None).await);
    assert!(matches!(
        stores.read_invitation_index("t2", "cafe").await,
        Ok(None)
    ));
}
