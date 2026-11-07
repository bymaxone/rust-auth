//! The concurrent-session cap runs after the new session is committed, so a listing the store
//! cannot answer leaves that session alone and the login that created it succeeds.

use super::damaged_detail_tests::DamagedDetails;
use super::*;

/// Store two sessions for one user under a cap of one: `old` and the just-created `new`.
pub(super) async fn two_sessions_over_a_cap_of_one(
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

#[tokio::test]
async fn the_unenforced_cap_is_reported_once_with_its_cause_and_without_a_hash() {
    let store = Arc::new(InMemoryStores::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "capwarn").await;
    let hooks = Arc::new(CountingHooks::default());
    let (old, new, new_record) = two_sessions_over_a_cap_of_one(&store, &uid).await;
    let svc = service(store.clone(), users, hooks, config(1, None));

    store.fail_next_session_listings(1);
    let (events, guard) = crate::log_capture::capture_events();
    assert!(
        svc.after_session_created(&new_record, &new, &ctx())
            .await
            .is_ok()
    );
    drop(guard);

    let reported: Vec<_> = events
        .iter()
        .into_iter()
        .filter(|event| event.rendered.contains("the session cap was not enforced"))
        .collect();
    assert_eq!(reported.len(), 1, "one line per login: {reported:?}");
    let line = &reported[0];
    assert_eq!(line.level, tracing::Level::WARN);
    // The cause is what an operator needs: AuthError's Display alone prints just "internal error".
    assert!(
        line.rendered.contains("forced session listing failure"),
        "{}",
        line.rendered
    );
    assert!(
        line.rendered.contains(&format!("user_id={uid}")),
        "{}",
        line.rendered
    );
    // No session hash and no account subject hash reaches the log.
    for secret in [old, new, subject(&uid)] {
        assert!(!events.contains(&secret), "{secret} must not be logged");
    }
}

/// A host store's error: its `Display` is the message its author meant for a log, while its
/// `Debug` carries the session details it was holding.
pub(super) struct HostStoreError {
    pub(super) session_detail: &'static str,
}

impl std::fmt::Debug for HostStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostStoreError")
            .field("session_detail", &self.session_detail)
            .finish()
    }
}

impl std::fmt::Display for HostStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host store unavailable")
    }
}

impl std::error::Error for HostStoreError {}

#[tokio::test]
async fn a_host_stores_error_is_logged_by_its_display_chain_not_its_debug() {
    const MARKER: &str = "MARKER-203.0.113.9-Pixel-7";
    let inner = Arc::new(InMemoryStores::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "caphost").await;
    let (_old, new, new_record) = two_sessions_over_a_cap_of_one(&inner, &uid).await;
    let store = Arc::new(
        DamagedDetails::new(inner.clone(), &[]).failing_entries_with(|| {
            AuthError::Internal(Box::new(HostStoreError {
                session_detail: MARKER,
            }))
        }),
    );
    let svc = SessionService::new(
        store,
        users,
        Arc::new(CountingHooks::default()),
        config(1, None),
        3600,
        zeroize::Zeroizing::new(TEST_IDENTIFIER_KEY),
    );

    let (events, guard) = crate::log_capture::capture_events();
    assert!(
        svc.after_session_created(&new_record, &new, &ctx())
            .await
            .is_ok()
    );
    drop(guard);

    let reported: Vec<_> = events
        .iter()
        .into_iter()
        .filter(|event| event.rendered.contains("the session cap was not enforced"))
        .collect();
    assert_eq!(reported.len(), 1, "{reported:?}");
    // The error and each source, by `Display`, joined: what the error's author chose to say.
    assert!(
        reported[0]
            .rendered
            .contains("cause=internal error: host store unavailable"),
        "{}",
        reported[0].rendered
    );
    // What `Debug` would add - the held session details - must not reach the log.
    assert!(
        !events.contains(MARKER),
        "the Debug marker was logged: {}",
        reported[0].rendered
    );
}
