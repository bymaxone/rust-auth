//! Testcontainers coverage of the Redis invitation publication, withdrawal and index release:
//! each proceeds only while the stored values are exactly what the caller names.
//!
//! When Docker is unavailable every case returns early, so a no-Docker `cargo test` still passes.

#[path = "common/docker_gate.rs"]
mod docker_gate;
#[path = "common/redis_ready.rs"]
mod redis_ready;

use bymax_auth_core::testing::invitation_index_scenarios::run_invitation_index_scenarios;
use bymax_auth_core::traits::{InvitationStore, InvitationWithdrawal, StoredInvitation};
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
    let container = match Redis::default().with_tag("8").start().await {
        Ok(container) => container,
        Err(error) => return docker_gate::docker_unavailable("redis:8", error),
    };
    let Ok(host) = container.get_host().await else { unreachable!() };
    let Ok(port) = container.get_host_port_ipv4(REDIS_PORT).await else { unreachable!() };
    let url = redis_ready::redis_url(&host.to_string(), port);
    redis_ready::wait_until_ready(&url).await;
    Some(TestRedis { container, url })
}

const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INDEX: &str = "auth:invidx:t1:cafe";

fn invitation() -> StoredInvitation {
    StoredInvitation {
        email: "invitee@example.com".to_owned(),
        role: "MEMBER".to_owned(),
        tenant_id: "t1".to_owned(),
        inviter_user_id: "owner".to_owned(),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

/// Publish `hash` for the address `cafe` in tenant `t1` over `superseded`, with a TTL of `ttl`.
async fn publish(stores: &RedisStores, hash: &str, ttl: u64, superseded: Option<&str>) -> bool {
    stores
        .publish_invitation("t1", "cafe", hash, &invitation(), ttl, superseded)
        .await
        .unwrap_or(false)
}

#[tokio::test]
async fn a_publication_gives_the_record_and_the_index_the_ttl() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { unreachable!() };
    assert!(publish(&stores, OLD, 600, None).await);
    for key in [INDEX.to_owned(), format!("auth:inv:{OLD}")] {
        let ttl = redis.ttl(&key).await;
        assert!((1..=600).contains(&ttl), "{key} {ttl}");
    }
    assert!(publish(&stores, NEW, 6000, Some(OLD)).await);
    for key in [INDEX.to_owned(), format!("auth:inv:{NEW}")] {
        let ttl = redis.ttl(&key).await;
        assert!(ttl > 600, "{key} {ttl}");
    }
    assert_eq!(redis.ttl(&format!("auth:inv:{OLD}")).await, -2);
}

#[tokio::test]
async fn a_withdrawal_removes_both_keys() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { unreachable!() };
    assert!(publish(&stores, OLD, 600, None).await);
    let judged = stores.read_invitation_record(OLD).await.unwrap_or_default();
    assert!(matches!(
        stores
            .withdraw_invitation("t1", "cafe", OLD, judged.as_deref())
            .await,
        Ok(InvitationWithdrawal::Removed)
    ));
    assert_eq!(redis.ttl(INDEX).await, -2);
    assert_eq!(redis.ttl(&format!("auth:inv:{OLD}")).await, -2);
}

#[tokio::test]
async fn the_redis_store_keeps_the_invitation_index_rules() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores() else { unreachable!() };
    run_invitation_index_scenarios(&stores).await;
}
