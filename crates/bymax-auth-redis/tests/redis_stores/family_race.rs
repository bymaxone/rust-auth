//! A family member that rotates while its family is being removed or its owner is being read,
//! against a real Redis. A relay in front of the container rotates the member just before a chosen
//! command reaches the server. A child module of the combined store suite, so it reuses that
//! suite's container harness.

use super::*;
use bymax_auth_redis::RedisStores;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FAMILY_KEY: &str = "auth:fam:fam-race";

/// One rotation to inject: before the command holding `marker`, `from` becomes `to`.
#[derive(Clone, Copy)]
struct Step {
    marker: &'static str,
    from: &'static str,
    to: &'static str,
}

type Steps = Arc<Mutex<VecDeque<Step>>>;

/// Take the next step when `chunk` holds its marker.
fn due(steps: &Steps, chunk: &[u8]) -> Option<Step> {
    let mut steps = steps.lock().unwrap_or_else(PoisonError::into_inner);
    let marker = steps.front()?.marker.as_bytes();
    let held = chunk.windows(marker.len()).any(|window| window == marker);
    if held { steps.pop_front() } else { None }
}

/// Replace `from` by `to` in the family set and move its record, as a rotation does.
async fn rotate_member(url: &str, step: &Step) {
    let Ok(client) = redis::Client::open(url) else {
        return;
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return;
    };
    let mut pipe = redis::pipe();
    pipe.srem(FAMILY_KEY, step.from).sadd(FAMILY_KEY, step.to);
    // A member planted without a record leaves nothing to move; the set still changes.
    pipe.rename(
        format!("auth:rt:{}", step.from),
        format!("auth:rt:{}", step.to),
    );
    let _: Result<(), _> = pipe.query_async(&mut conn).await;
}

/// Forward one client to the server, applying each step before the command it names.
async fn relay(client: TcpStream, url: String, steps: Steps) {
    let address = url.trim_start_matches("redis://").to_owned();
    let Ok(server) = TcpStream::connect(address).await else {
        return;
    };
    let (mut from_client, mut to_client) = client.into_split();
    let (mut from_server, mut to_server) = server.into_split();
    tokio::spawn(async move { tokio::io::copy(&mut from_server, &mut to_client).await });
    let mut buffer = vec![0_u8; 16 * 1024];
    while let Ok(read @ 1..) = from_client.read(&mut buffer).await {
        let chunk = &buffer[..read];
        if let Some(step) = due(&steps, chunk) {
            rotate_member(&url, &step).await;
        }
        if to_server.write_all(chunk).await.is_err() {
            return;
        }
    }
}

/// A store connected through a relay that applies `steps` in front of `url`.
async fn stores_behind_relay(url: &str, steps: Vec<Step>) -> Option<RedisStores> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let port = listener.local_addr().ok()?.port();
    let url = url.to_owned();
    let steps: Steps = Arc::new(Mutex::new(steps.into()));
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(relay(client, url.clone(), Arc::clone(&steps)));
        }
    });
    RedisStores::connect(&format!("redis://127.0.0.1:{port}"), "auth").ok()
}

/// Plant a one-member family whose record names `u1`.
async fn plant_owned_family(redis: &common::TestRedis) {
    let json = serde_json::to_string(&record("u1")).unwrap_or_default();
    assert!(redis.sadd(FAMILY_KEY, "old").await);
    assert!(redis.set_raw("auth:rt:old", &json).await);
}

#[tokio::test]
async fn a_member_that_rotates_during_the_removal_is_reported_under_both_hashes() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    assert!(redis.sadd(FAMILY_KEY, "old").await);
    let before_script = Step {
        marker: "EVALSHA",
        from: "old",
        to: "new",
    };
    let Some(stores) = stores_behind_relay(redis.url(), vec![before_script]).await else {
        unreachable!()
    };

    let reported = stores
        .revoke_family(SessionKind::Dashboard, "fam-race", None)
        .await;

    assert!(
        matches!(&reported, Ok(hashes) if hashes == &["old", "new"]),
        "{reported:?}"
    );
    assert_eq!(redis.ttl(FAMILY_KEY).await, -2);
}

#[tokio::test]
async fn an_owner_is_named_when_the_member_read_rotates_before_its_record_is_read() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    plant_owned_family(&redis).await;
    let steps = vec![Step {
        marker: "auth:rt:old",
        from: "old",
        to: "new1",
    }];
    let Some(stores) = stores_behind_relay(redis.url(), steps).await else { unreachable!() };

    let owner = stores
        .find_family_owner(SessionKind::Dashboard, "fam-race")
        .await;

    let named = owner.ok().flatten().map(|record| record.user_id);
    assert_eq!(named.as_deref(), Some("u1"));
}

#[tokio::test]
async fn a_family_is_read_three_times_for_an_owner_and_no_more() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let three = [
        Step {
            marker: "auth:rt:old",
            from: "old",
            to: "new1",
        },
        Step {
            marker: "auth:rt:new1",
            from: "new1",
            to: "new2",
        },
        Step {
            marker: "auth:rt:new2",
            from: "new2",
            to: "new3",
        },
    ];
    for (raced, expected) in [(2, Some("u1")), (3, None)] {
        plant_owned_family(&redis).await;
        let steps = three[..raced].to_vec();
        let Some(stores) = stores_behind_relay(redis.url(), steps).await else { unreachable!() };

        let owner = stores
            .find_family_owner(SessionKind::Dashboard, "fam-race")
            .await;

        let named = owner.ok().flatten().map(|record| record.user_id);
        assert_eq!(named.as_deref(), expected, "after {raced} raced reads");
        let swept = stores
            .revoke_family(SessionKind::Dashboard, "fam-race", None)
            .await;
        assert!(swept.is_ok());
    }
}
