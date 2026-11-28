//! A family member that rotates while its family is being removed, against a real Redis. A relay
//! in front of the container changes the family set just before the removal script reaches the
//! server. A child module of the combined store suite, so it reuses that suite's container harness.

use super::*;
use bymax_auth_redis::RedisStores;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FAMILY_KEY: &str = "auth:fam:fam-race";

/// Replace `old` by `new` in the family set, as a rotation does.
async fn rotate_member(url: &str) {
    let Ok(client) = redis::Client::open(url) else {
        return;
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return;
    };
    let mut pipe = redis::pipe();
    pipe.srem(FAMILY_KEY, "old").sadd(FAMILY_KEY, "new");
    let _: Result<(), _> = pipe.query_async(&mut conn).await;
}

/// Forward one client to the server, rotating a member before the first script call.
async fn relay(client: TcpStream, url: String) {
    let address = url.trim_start_matches("redis://").to_owned();
    let Ok(server) = TcpStream::connect(address).await else {
        return;
    };
    let (mut from_client, mut to_client) = client.into_split();
    let (mut from_server, mut to_server) = server.into_split();
    tokio::spawn(async move { tokio::io::copy(&mut from_server, &mut to_client).await });
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut rotated = false;
    while let Ok(read @ 1..) = from_client.read(&mut buffer).await {
        let chunk = &buffer[..read];
        if !rotated && chunk.windows(7).any(|window| window == b"EVALSHA") {
            rotate_member(&url).await;
            rotated = true;
        }
        if to_server.write_all(chunk).await.is_err() {
            return;
        }
    }
}

/// The URL of a relay in front of `url`.
async fn relay_in_front_of(url: &str) -> Option<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let port = listener.local_addr().ok()?.port();
    let url = url.to_owned();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(relay(client, url.clone()));
        }
    });
    Some(format!("redis://127.0.0.1:{port}"))
}

#[tokio::test]
async fn a_member_that_rotates_during_the_removal_is_reported_under_both_hashes() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    assert!(redis.sadd(FAMILY_KEY, "old").await);
    let Some(relay_url) = relay_in_front_of(redis.url()).await else { unreachable!() };
    let Ok(stores) = RedisStores::connect(&relay_url, "auth") else { unreachable!() };

    let reported = stores
        .revoke_family(SessionKind::Dashboard, "fam-race", None)
        .await;

    assert!(
        matches!(&reported, Ok(hashes) if hashes == &["old", "new"]),
        "{reported:?}"
    );
    assert_eq!(redis.ttl(FAMILY_KEY).await, -2);
}
