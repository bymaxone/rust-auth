//! The logout-pending helpers on their own: the marker's lifetime, which owner a logout
//! resolves, when an attempt leaves a marker, and who announces a completed logout. The record
//! shape and the guarantee are read back from the shared contract so a drift on either side fails
//! here.

use std::time::Duration;

use super::*;
use crate::testing::InMemoryStores;

const HASH: &str = "hhhhhhhh";

fn owner() -> LogoutOwner {
    LogoutOwner {
        user_id: "u1".to_owned(),
        tenant_id: Some("t1".to_owned()),
    }
}

fn store() -> InMemoryStores {
    InMemoryStores::new()
}

async fn mark(store: &InMemoryStores, ttl: u64) {
    let put = store
        .put_logout_pending(SessionKind::Dashboard, HASH, &owner(), ttl)
        .await;
    assert!(put.is_ok());
}

/// The `logoutPending` row of the shared contract.
fn contract_row() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["recordEncodings"]["logoutPending"].clone()
}

#[test]
fn a_marker_lives_the_access_lifetime_rounded_up_and_never_under_five_minutes() {
    let ttl = |millis: u64| marker_ttl_secs(Duration::from_millis(millis));
    assert_eq!(ttl(0), 300);
    assert_eq!(ttl(299_000), 300);
    assert_eq!(ttl(300_000), 300);
    assert_eq!(ttl(300_001), 301);
    assert_eq!(ttl(900_000), 900);
    assert_eq!(ttl(900_500), 901);
}

#[test]
fn the_stored_form_is_the_contracts_record() {
    let row = contract_row();
    let fields: Vec<&str> = row["fields"]
        .as_array()
        .map(|f| f.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert_eq!(fields, ["userId", "tenantId"]);
    let with_tenant = serde_json::to_value(owner()).unwrap_or_default();
    let mut keys: Vec<&str> = with_tenant
        .as_object()
        .map_or(vec![], |o| o.keys().map(String::as_str).collect());
    keys.sort_unstable();
    assert_eq!(keys, ["tenantId", "userId"]);
    // `tenantId` is omitted from the record entirely when the session carried none.
    let without = LogoutOwner {
        tenant_id: None,
        ..owner()
    };
    let bare = serde_json::to_value(without).unwrap_or_default();
    assert_eq!(bare.as_object().map(serde_json::Map::len), Some(1));
    assert!(
        row["tenantId"]
            .as_str()
            .is_some_and(|rule| rule.contains("omitted"))
    );
}

#[test]
fn the_rules_the_contract_states_are_the_ones_this_module_implements() {
    let row = contract_row();
    let ttl = row["ttl"].as_str().unwrap_or_default();
    assert!(ttl.contains("rounded up") && ttl.contains("never less than 300"));
    // The guarantee sentence is copied from the contract row into this module's documentation.
    let guarantee = row["guarantee"].as_str().unwrap_or_default();
    let sentence = guarantee.split(" (").next().unwrap_or_default();
    assert!(sentence.starts_with("exactly-once for sequential retries"));
    assert!(include_str!("../logout_pending.rs").contains(sentence));
}

#[tokio::test]
async fn a_live_owner_is_never_looked_up_in_the_store() {
    let store = store();
    store.fail_logout_pending_ops(0, 1);
    let resolved = resolve_owner(&store, SessionKind::Dashboard, Some(HASH), Some(owner())).await;
    assert_eq!(resolved.ok(), Some(ResolvedOwner::live(Some(owner()))));
    let none = resolve_owner(&store, SessionKind::Dashboard, None, None).await;
    assert_eq!(none.ok(), Some(ResolvedOwner::live(None)));
}

#[tokio::test]
async fn a_gone_session_takes_its_owner_from_the_marker_and_an_unreadable_marker_ends_the_logout() {
    let store = store();
    mark(&store, 900).await;
    let resolved = resolve_owner(&store, SessionKind::Dashboard, Some(HASH), None).await;
    assert_eq!(resolved.ok().map(|r| r.owner), Some(Some(owner())));
    let nobody = resolve_owner(&store, SessionKind::Dashboard, Some("other"), None).await;
    assert_eq!(nobody.ok().map(|r| r.owner), Some(None));
    store.fail_logout_pending_ops(0, 1);
    let unreadable = resolve_owner(&store, SessionKind::Dashboard, Some(HASH), None).await;
    assert!(matches!(unreadable, Err(AuthError::Internal(_))));
}

#[tokio::test]
async fn only_an_attempt_that_read_the_live_session_leaves_a_marker() {
    let (live, marked) = (
        ResolvedOwner::live(Some(owner())),
        ResolvedOwner {
            owner: Some(owner()),
            from_marker: true,
        },
    );
    let kind = SessionKind::Dashboard;
    let store = store();
    remember_failed_attempt(&store, kind, Some(HASH), &marked, 900).await;
    remember_failed_attempt(&store, kind, None, &live, 900).await;
    remember_failed_attempt(&store, kind, Some(HASH), &ResolvedOwner::live(None), 900).await;
    assert_eq!(store.peek_logout_pending(kind, HASH), None);
    remember_failed_attempt(&store, kind, Some(HASH), &live, 900).await;
    assert_eq!(store.peek_logout_pending(kind, HASH), Some((owner(), 900)));
}

#[tokio::test]
async fn a_marker_that_cannot_be_written_is_logged_and_does_not_raise() {
    let store = store();
    store.fail_logout_pending_ops(0, 1);
    let live = ResolvedOwner::live(Some(owner()));
    remember_failed_attempt(&store, SessionKind::Dashboard, Some(HASH), &live, 900).await;
    assert_eq!(
        store.peek_logout_pending(SessionKind::Dashboard, HASH),
        None
    );
}

#[tokio::test]
async fn a_marker_owner_announces_only_for_the_call_that_removed_the_marker() {
    let store = store();
    mark(&store, 900).await;
    let marked = ResolvedOwner {
        owner: Some(owner()),
        from_marker: true,
    };
    let kind = SessionKind::Dashboard;
    assert_eq!(
        settle_completed(&store, kind, Some(HASH), &marked, 900)
            .await
            .ok(),
        Some(true)
    );
    // A racing retry that read the marker before it was removed finds it gone.
    assert_eq!(
        settle_completed(&store, kind, Some(HASH), &marked, 900)
            .await
            .ok(),
        Some(false)
    );
    mark(&store, 900).await;
    store.fail_logout_pending_ops(0, 1);
    let unclaimable = settle_completed(&store, kind, Some(HASH), &marked, 900).await;
    assert!(matches!(unclaimable, Err(AuthError::Internal(_))));
}

#[tokio::test]
async fn a_live_owner_announces_regardless_and_clears_a_stale_marker() {
    let (store, kind) = (store(), SessionKind::Dashboard);
    mark(&store, 900).await;
    let live = ResolvedOwner::live(Some(owner()));
    assert_eq!(
        settle_completed(&store, kind, Some(HASH), &live, 900)
            .await
            .ok(),
        Some(true)
    );
    assert_eq!(store.peek_logout_pending(kind, HASH), None);
}

#[tokio::test]
async fn a_stale_marker_that_cannot_be_removed_is_announced_only_when_shown_absent() {
    let (store, kind) = (store(), SessionKind::Dashboard);
    let live = ResolvedOwner::live(Some(owner()));
    // No marker was there to remove, so a failed removal leaves nothing a retry could claim.
    store.fail_logout_pending_ops(0, 1);
    assert_eq!(
        settle_completed(&store, kind, Some(HASH), &live, 900)
            .await
            .ok(),
        Some(true)
    );
    // A marker that is still there would be claimed, and announced again, by a later retry.
    mark(&store, 900).await;
    store.fail_logout_pending_ops(0, 1);
    let stale = settle_completed(&store, kind, Some(HASH), &live, 900).await;
    assert!(matches!(stale, Err(AuthError::Internal(_))));
    assert!(store.peek_logout_pending(kind, HASH).is_some());
    // Neither the removal nor the second read answered: the marker cannot be shown absent, so the
    // owner is recorded again for the retry to claim.
    assert_eq!(
        store.claim_logout_pending(kind, HASH).await.ok(),
        Some(true)
    );
    store.fail_logout_pending_ops(0, 2);
    let unknown = settle_completed(&store, kind, Some(HASH), &live, 450).await;
    assert!(matches!(unknown, Err(AuthError::Internal(_))));
    assert_eq!(store.peek_logout_pending(kind, HASH), Some((owner(), 450)));
}

#[tokio::test]
async fn a_logout_with_no_owner_announces_nothing() {
    let store = store();
    let nobody = ResolvedOwner::live(None);
    let settled = settle_completed(&store, SessionKind::Dashboard, Some(HASH), &nobody, 900).await;
    assert_eq!(settled.ok(), Some(false));
    let no_hash = settle_completed(&store, SessionKind::Dashboard, None, &nobody, 900).await;
    assert_eq!(no_hash.ok(), Some(false));
}
