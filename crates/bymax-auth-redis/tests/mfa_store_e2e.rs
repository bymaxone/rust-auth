//! Testcontainers coverage of the Redis `MfaStore` implementation: the AES-protected
//! pending-setup record (`SET NX`/`GET`/`GETDEL`), the single-use temp-token marker, the
//! standalone TOTP anti-replay marker, and the fused `mfa_challenge` Lua — including the
//! single-consume guarantee under concurrent submissions of the same code.
//!
//! The whole file compiles only under the `mfa` feature (the trait it drives is
//! `mfa`-gated). When Docker is unavailable every case returns early, so a no-Docker
//! `cargo test` still passes.
#![cfg(feature = "mfa")]

use std::sync::Arc;

use bymax_auth_core::traits::MfaStore;
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
    fn stores(&self, namespace: &str) -> Option<RedisStores> {
        RedisStores::connect(&self.url, namespace.to_owned()).ok()
    }

    /// Every key currently in the keyspace, for the no-PII / namespacing assertions.
    async fn all_keys(&self) -> Vec<String> {
        let _ = self.container.id();
        let Ok(client) = redis::Client::open(self.url.as_str()) else {
            return Vec::new();
        };
        let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
            return Vec::new();
        };
        redis::cmd("KEYS")
            .arg("*")
            .query_async(&mut conn)
            .await
            .unwrap_or_default()
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
async fn setup_record_is_nx_then_get_then_getdel() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfastore") else { return };

    // `SET NX` wins once; a second NX for the same user loses.
    assert!(matches!(
        stores.put_setup_nx("uhash", "cipher", 600).await,
        Ok(true)
    ));
    assert!(matches!(
        stores.put_setup_nx("uhash", "other", 600).await,
        Ok(false)
    ));
    // `GET` reads without consuming; the original value (not the loser's) is stored.
    assert!(matches!(stores.get_setup("uhash").await, Ok(Some(ref v)) if v == "cipher"));
    assert!(matches!(stores.get_setup("uhash").await, Ok(Some(_))));
    // `GETDEL` consumes exactly once.
    assert!(matches!(stores.take_setup("uhash").await, Ok(Some(ref v)) if v == "cipher"));
    assert!(matches!(stores.take_setup("uhash").await, Ok(None)));
    assert!(matches!(stores.get_setup("uhash").await, Ok(None)));
    // The key carried only the hashed user id, namespaced — no PII.
    let keys = redis.all_keys().await;
    assert!(
        keys.iter()
            .all(|k| k.starts_with("mfastore:") && !k.contains('@'))
    );
}

#[tokio::test]
async fn temp_token_marker_is_put_get_nonconsuming_then_deleted() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfatemp") else { return };

    assert!(stores.put_temp("jtihash", "user-1", 300).await.is_ok());
    // GET (never GETDEL): two reads both succeed, so a mistyped code stays retryable.
    assert!(matches!(stores.get_temp("jtihash").await, Ok(Some(ref u)) if u == "user-1"));
    assert!(matches!(stores.get_temp("jtihash").await, Ok(Some(_))));
    // DEL is idempotent.
    assert!(stores.del_temp("jtihash").await.is_ok());
    assert!(stores.del_temp("jtihash").await.is_ok());
    assert!(matches!(stores.get_temp("jtihash").await, Ok(None)));
}

#[tokio::test]
async fn standalone_replay_marker_rejects_a_second_use() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfareplay") else { return };

    // First mark is new; a second mark of the same id is a replay.
    assert!(matches!(
        stores.mark_totp_used("replay-id", 90).await,
        Ok(true)
    ));
    assert!(matches!(
        stores.mark_totp_used("replay-id", 90).await,
        Ok(false)
    ));
}

#[tokio::test]
async fn fused_challenge_consumes_the_temp_token_exactly_once() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfafused") else { return };

    // Plant the temp-token marker, then fuse the replay-mark + consume.
    assert!(stores.put_temp("jti-1", "user-1", 300).await.is_ok());
    assert!(matches!(
        stores.challenge_consume("replay-1", "jti-1", 90).await,
        Ok(true)
    ));
    // The temp token was consumed (the marker is gone).
    assert!(matches!(stores.get_temp("jti-1").await, Ok(None)));
    // A replay of the same code returns false and does not touch the (already-gone) token.
    assert!(matches!(
        stores.challenge_consume("replay-1", "jti-1", 90).await,
        Ok(false)
    ));
}

#[tokio::test]
async fn fused_challenge_admits_one_winner_under_concurrency() {
    let Some(redis) = try_start().await else { return };
    let Some(stores) = redis.stores("mfaconc") else { return };
    let stores = Arc::new(stores);

    // One temp token, eight concurrent submissions of the SAME correct code: exactly one wins
    // the fused step (consumes the token); the rest see the replay marker already present.
    assert!(stores.put_temp("jti-c", "user-c", 300).await.is_ok());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let stores = stores.clone();
        handles.push(tokio::spawn(async move {
            stores.challenge_consume("replay-c", "jti-c", 90).await
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if let Ok(Ok(true)) = handle.await {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "exactly one concurrent submission may consume the token"
    );
    assert!(matches!(stores.get_temp("jti-c").await, Ok(None)));
}
