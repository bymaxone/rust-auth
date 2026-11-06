//! The concurrent-session cap runs after the new session is committed, so a listing the store
//! cannot answer leaves that session alone and the login that created it succeeds.

use super::*;

/// Store two sessions for one user under a cap of one: `old` and the just-created `new`.
async fn two_sessions_over_a_cap_of_one(
    store: &InMemoryStores,
    uid: &str,
) -> (String, String, SessionRecord) {
    let old = hash("aaaa");
    let new = hash("cccc");
    let base = OffsetDateTime::UNIX_EPOCH;
    for (session_hash, created) in [(&old, base), (&new, base + time::Duration::seconds(1))] {
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &subject(uid),
                    session_hash,
                    &record(uid, created),
                    3600,
                )
                .await
                .is_ok()
        );
    }
    (old, new, record(uid, base + time::Duration::seconds(1)))
}

async fn live_hashes(store: &InMemoryStores, uid: &str) -> Vec<String> {
    let mut hashes: Vec<String> = store
        .list_sessions(SessionKind::Dashboard, &subject(uid))
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|detail| detail.session_hash)
        .collect();
    hashes.sort();
    hashes
}

#[tokio::test]
async fn an_unreadable_listing_evicts_nobody_and_does_not_fail_the_login() {
    let store = Arc::new(InMemoryStores::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "capfail").await;
    let hooks = Arc::new(CountingHooks::default());
    let (old, new, new_record) = two_sessions_over_a_cap_of_one(&store, &uid).await;

    store.fail_next_session_listings(1);
    let svc = service(store.clone(), users, hooks.clone(), config(1, None));
    let outcome = svc.after_session_created(&new_record, &new, &ctx()).await;

    assert!(
        outcome.is_ok(),
        "the committed session must not fail the login: {outcome:?}"
    );
    // Nobody was evicted: the cap is simply not enforced for this login.
    let mut expected = vec![old, new];
    expected.sort();
    assert_eq!(live_hashes(&store, &uid).await, expected);
    // The session is still announced, and nothing is reported as evicted.
    settle_until(|| hooks.new_sessions.load(Ordering::Relaxed) >= 1).await;
    assert_eq!(hooks.new_sessions.load(Ordering::Relaxed), 1);
    assert_eq!(hooks.evictions.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn the_next_login_enforces_the_cap_again() {
    let store = Arc::new(InMemoryStores::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "capagain").await;
    let hooks = Arc::new(CountingHooks::default());
    let (old, new, new_record) = two_sessions_over_a_cap_of_one(&store, &uid).await;
    let svc = service(store.clone(), users, hooks.clone(), config(1, None));

    store.fail_next_session_listings(1);
    assert!(
        svc.after_session_created(&new_record, &new, &ctx())
            .await
            .is_ok()
    );
    assert_eq!(live_hashes(&store, &uid).await.len(), 2);

    // The failure was one listing; the following login lists normally and evicts the oldest.
    assert!(
        svc.after_session_created(&new_record, &new, &ctx())
            .await
            .is_ok()
    );
    assert_eq!(live_hashes(&store, &uid).await, vec![new]);
    settle_until(|| hooks.evictions.load(Ordering::Relaxed) >= 1).await;
    assert_eq!(
        hooks
            .evicted_hashes
            .lock()
            .map(|h| h.clone())
            .unwrap_or_default(),
        vec![old]
    );
}
