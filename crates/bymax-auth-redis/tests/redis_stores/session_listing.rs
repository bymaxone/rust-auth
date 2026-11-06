//! Listing the live sessions of an account when a session's detail record is damaged or gone:
//! the display listing leaves such a session out, the entries still name it, a dead member is
//! pruned only when its own key is gone, and a failed read prunes nothing. A child module of the
//! combined store suite, so it reuses that suite's container harness and fixtures.

use super::*;

/// Four sessions for `lu`: `h1` and `h2` are whole, `h3` has a damaged detail but a live refresh
/// key, and `h4` has lost both its detail and its refresh key.
async fn seed_damaged_and_dead_sessions(
    redis: &common::TestRedis,
    stores: &bymax_auth_redis::RedisStores,
) {
    for hash in ["h1", "h2", "h3", "h4"] {
        let created = stores
            .create_session(
                SessionKind::Dashboard,
                &subject("lu"),
                hash,
                &record("lu"),
                3600,
            )
            .await;
        assert!(created.is_ok());
    }
    assert!(redis.set_raw("auth:sd:h3", "{broken").await);
    assert!(redis.del("auth:sd:h4").await && redis.del("auth:rt:h4").await);
}

#[tokio::test]
async fn listing_leaves_out_a_damaged_detail_and_prunes_only_a_dead_member() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    seed_damaged_and_dead_sessions(&redis, &stores).await;

    // The entries name every live session, with no detail for the damaged one, and omit the dead
    // one: what revocation and the session cap act on.
    let entries = stores
        .list_session_entries(kind, &subject("lu"))
        .await
        .unwrap_or_default();
    let mut seen: Vec<(String, bool)> = entries
        .into_iter()
        .map(|e| (e.session_hash, e.detail.is_some()))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("h1".to_owned(), true),
            ("h2".to_owned(), true),
            ("h3".to_owned(), false)
        ],
        "a damaged detail hides a session from the display only"
    );

    // The display listing leaves the damaged one out.
    let listed = stores.list_sessions(kind, &subject("lu")).await;
    let mut hashes: Vec<String> = listed
        .map(|v| v.into_iter().map(|d| d.session_hash).collect())
        .unwrap_or_default();
    hashes.sort();
    assert_eq!(
        hashes,
        ["h1", "h2"],
        "one damaged record must not hide the others"
    );

    // Only the dead member left the index; the live session with a damaged detail stays.
    let mut members = redis.smembers("auth:sess:s-lu").await;
    members.sort();
    assert_eq!(members, ["rt:h1", "rt:h2", "rt:h3"]);
}

#[tokio::test]
async fn a_failed_detail_read_fails_the_listing_and_prunes_nothing() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    for hash in ["h1", "h2"] {
        let created = stores
            .create_session(kind, &subject("fu2"), hash, &record("fu2"), 3600)
            .await;
        assert!(created.is_ok());
    }
    // h1 is dead: detail and refresh key gone. h2's detail key holds the wrong type, so reading it
    // fails (WRONGTYPE) whichever order the members come back in.
    assert!(redis.del("auth:sd:h1").await && redis.del("auth:rt:h1").await);
    assert!(redis.del("auth:sd:h2").await && redis.sadd("auth:sd:h2", "x").await);
    // A grace pointer whose key has expired is dead too, and is not pruned on a failed read either.
    assert!(redis.sadd("auth:sess:s-fu2", "rp:gone").await);

    assert!(stores.list_sessions(kind, &subject("fu2")).await.is_err());

    let mut members = redis.smembers("auth:sess:s-fu2").await;
    members.sort();
    assert_eq!(
        members,
        ["rp:gone", "rt:h1", "rt:h2"],
        "a failed read must prune nothing"
    );
}
