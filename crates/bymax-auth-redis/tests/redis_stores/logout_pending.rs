//! The owner marker a failed logout leaves, against a real Redis: written with the TTL it was
//! given under `lp:`/`plp:`, readable without being consumed, claimed by exactly one of several
//! callers, and stored in the contract's record form. A child module of the combined store
//! suite, so it reuses that suite's container harness and fixtures.

use bymax_auth_core::traits::LogoutOwner;

use super::*;

fn owner(tenant: Option<&str>) -> LogoutOwner {
    LogoutOwner {
        user_id: "u1".to_owned(),
        tenant_id: tenant.map(str::to_owned),
    }
}

#[tokio::test]
async fn the_marker_is_written_under_the_plane_s_prefix_with_the_ttl_and_the_contract_record() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let put = stores
        .put_logout_pending(SessionKind::Dashboard, "dh", &owner(Some("t1")), 900)
        .await;
    assert!(put.is_ok());
    let platform = stores
        .put_logout_pending(SessionKind::Platform, "dh", &owner(None), 300)
        .await;
    assert!(platform.is_ok());

    let ttl = redis.ttl("auth:lp:dh").await;
    assert!((1..=900).contains(&ttl), "ttl {ttl}");
    let stored = redis.get("auth:lp:dh").await.unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&stored).unwrap_or_default();
    assert_eq!(
        json,
        serde_json::json!({ "userId": "u1", "tenantId": "t1" })
    );
    // The platform plane's record carries no tenant at all, and lives under its own prefix.
    let bare = redis.get("auth:plp:dh").await.unwrap_or_default();
    let bare: serde_json::Value = serde_json::from_str(&bare).unwrap_or_default();
    assert_eq!(bare, serde_json::json!({ "userId": "u1" }));
}

#[tokio::test]
async fn reading_leaves_the_marker_and_claiming_removes_it_for_exactly_one_caller() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    assert!(
        stores
            .put_logout_pending(kind, "ch", &owner(None), 900)
            .await
            .is_ok()
    );
    for _ in 0..2 {
        let read = stores.read_logout_pending(kind, "ch").await.ok().flatten();
        assert_eq!(read, Some(owner(None)));
    }
    let (first, second) = (
        stores.claim_logout_pending(kind, "ch").await.ok(),
        stores.claim_logout_pending(kind, "ch").await.ok(),
    );
    assert_eq!((first, second), (Some(true), Some(false)));
    assert!(matches!(
        stores.read_logout_pending(kind, "ch").await,
        Ok(None)
    ));
}

#[tokio::test]
async fn an_unreadable_value_names_nobody() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    assert!(redis.set_raw("auth:lp:bad", "{not json").await);
    let read = stores
        .read_logout_pending(SessionKind::Dashboard, "bad")
        .await;
    assert!(matches!(read, Ok(None)));
}
