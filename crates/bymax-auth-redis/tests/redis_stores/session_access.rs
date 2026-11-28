//! The entry that ends one session's access tokens, against a real Redis: its key per plane, its
//! value and its TTL. A child module of the combined store suite, so it reuses that suite's
//! container harness.

use super::*;

const SID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

#[tokio::test]
async fn the_entry_is_written_under_the_plane_s_prefix_with_the_value_one_and_the_ttl() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { unreachable!() };

    for (kind, other, key) in [
        (
            SessionKind::Dashboard,
            SessionKind::Platform,
            format!("auth:rvs:{SID}"),
        ),
        (
            SessionKind::Platform,
            SessionKind::Dashboard,
            format!("auth:prvs:{SID}"),
        ),
    ] {
        let before = stores.is_session_access_revoked(kind, SID).await;
        assert_eq!(before.ok(), Some(false));
        assert!(stores.revoke_session_access(kind, SID, 960).await.is_ok());

        assert_eq!(redis.get(&key).await.as_deref(), Some("1"));
        let ttl = redis.ttl(&key).await;
        assert!((900..=960).contains(&ttl), "ttl {ttl}");
        let after = stores.is_session_access_revoked(kind, SID).await;
        assert_eq!(after.ok(), Some(true));
        // The other plane's entry is another key.
        if kind == SessionKind::Dashboard {
            let elsewhere = stores.is_session_access_revoked(other, SID).await;
            assert_eq!(elsewhere.ok(), Some(false));
        }
    }
}
