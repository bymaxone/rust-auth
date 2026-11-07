//! A presented refresh-token hash stands for the live session it names, or, for a token that
//! rotated away inside its grace window, for the one live successor its grace pointer names.

use super::*;
use crate::traits::SessionRotation;

/// Store a live session for `user` under `session_hash`.
async fn seed_session(store: &InMemoryStores, user: &str, session_hash: &str) {
    let created = store
        .create_session(
            SessionKind::Dashboard,
            &subject(user),
            session_hash,
            &record(user, OffsetDateTime::UNIX_EPOCH),
            3600,
        )
        .await;
    assert!(created.is_ok());
}

/// Rotate `old` into `new` for `user`, leaving the grace pointer a refresh leaves.
async fn rotate(store: &InMemoryStores, user: &str, old: &str, new: &str) {
    let rotation = SessionRotation {
        old_hash: old.to_owned(),
        new_hash: new.to_owned(),
        new_raw: String::new(),
        new_record: record(user, OffsetDateTime::UNIX_EPOCH),
        subject_hash: subject(user),
        refresh_ttl: 3600,
        grace_ttl: 30,
    };
    assert!(
        store
            .rotate(SessionKind::Dashboard, &rotation)
            .await
            .is_ok()
    );
}

fn svc(store: &Arc<InMemoryStores>) -> SessionService {
    service(
        store.clone(),
        Arc::new(InMemoryUserRepository::new()),
        Arc::new(NoOpAuthHooks),
        config(5, None),
    )
}

#[tokio::test]
async fn a_live_session_stands_for_itself_without_reading_a_pointer() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert_eq!(resolved.ok(), Some(hash("aaaa")));
    assert_eq!(store.grace_pointer_reads(), 0);
}

#[tokio::test]
async fn a_rotated_token_stands_for_its_live_successor_and_the_pointer_is_read_once() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    rotate(&store, "u1", &hash("aaaa"), &hash("bbbb")).await;
    let service = svc(&store);

    let resolved = service
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert_eq!(resolved.ok(), Some(hash("bbbb")));
    assert_eq!(
        store.grace_pointer_reads(),
        1,
        "exactly one read of the pointer"
    );
    // Reading it consumed nothing: the same token resolves again.
    let again = service
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert_eq!(again.ok(), Some(hash("bbbb")));
}

#[tokio::test]
async fn a_successor_that_is_no_longer_live_names_nothing() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    rotate(&store, "u1", &hash("aaaa"), &hash("bbbb")).await;
    assert!(
        store
            .revoke_session(SessionKind::Dashboard, &subject("u1"), &hash("bbbb"))
            .await
            .is_ok()
    );
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert!(matches!(resolved, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
async fn another_accounts_pointer_names_nothing() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u2", &hash("aaaa")).await;
    rotate(&store, "u2", &hash("aaaa"), &hash("bbbb")).await;
    // The pointer and its live successor belong to u2: u1 presenting the same token gets nothing.
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert!(matches!(resolved, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
async fn a_token_past_its_grace_window_names_nothing() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    rotate(&store, "u1", &hash("aaaa"), &hash("bbbb")).await;
    assert!(
        store
            .delete_grace_pointer(SessionKind::Dashboard, &hash("aaaa"))
            .await
            .is_ok()
    );
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert!(matches!(resolved, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
async fn only_one_hop_is_followed() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    rotate(&store, "u1", &hash("aaaa"), &hash("bbbb")).await;
    rotate(&store, "u1", &hash("bbbb"), &hash("cccc")).await;
    // `aaaa` names `bbbb`, which is no longer live; `cccc` is live but two hops away.
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", &hash("aaaa"))
        .await;
    assert!(matches!(resolved, Err(AuthError::SessionNotFound)));
    assert_eq!(store.grace_pointer_reads(), 1);
}

#[tokio::test]
async fn a_malformed_hash_is_refused_before_any_store_read() {
    let store = Arc::new(InMemoryStores::new());
    let resolved = svc(&store)
        .resolve_live_session("t1", "u1", "not-a-hash")
        .await;
    assert!(matches!(resolved, Err(AuthError::SessionNotFound)));
    assert_eq!(store.grace_pointer_reads(), 0);
}

#[tokio::test]
async fn revoke_all_except_current_keeps_the_successor_of_a_rotated_token() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    seed_session(&store, "u1", &hash("dddd")).await;
    rotate(&store, "u1", &hash("aaaa"), &hash("bbbb")).await;
    let outcome = svc(&store)
        .revoke_all_except_current("t1", "u1", &hash("aaaa"))
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let live: Vec<_> = store
        .list_sessions(SessionKind::Dashboard, &subject("u1"))
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|detail| detail.session_hash)
        .collect();
    assert_eq!(live, vec![hash("bbbb")]);
}

#[tokio::test]
async fn revoke_all_except_current_with_an_unknown_token_changes_nothing() {
    let store = Arc::new(InMemoryStores::new());
    seed_session(&store, "u1", &hash("aaaa")).await;
    let outcome = svc(&store)
        .revoke_all_except_current("t1", "u1", &hash("ffff"))
        .await;
    assert!(matches!(outcome, Err(AuthError::SessionNotFound)));
    let live = store
        .list_sessions(SessionKind::Dashboard, &subject("u1"))
        .await
        .unwrap_or_default();
    assert_eq!(live.len(), 1, "no session was revoked");
}
