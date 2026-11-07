//! A store that refuses to evict a session over the cap is logged by the error's `Display`
//! chain, and the login that scheduled the eviction still succeeds.

use super::damaged_detail_tests::DamagedDetails;
use super::listing_failure_tests::HostStoreError;
use super::*;

#[tokio::test]
async fn a_refused_eviction_is_logged_with_its_cause_and_never_fails_the_login() {
    const MARKER: &str = "MARKER-eviction-Pixel-7";
    let inner = Arc::new(InMemoryStores::new());
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "evictfail").await;
    let (_old, new, new_record) =
        super::listing_failure_tests::two_sessions_over_a_cap_of_one(&inner, &uid).await;
    let store = Arc::new(DamagedDetails::new(inner, &[]).failing_revokes_with(|| {
        AuthError::Internal(Box::new(HostStoreError {
            session_detail: MARKER,
        }))
    }));
    let svc = SessionService::new(
        store,
        users,
        Arc::new(CountingHooks::default()),
        config(1, None),
        3600,
        zeroize::Zeroizing::new(TEST_IDENTIFIER_KEY),
    );

    let (events, guard) = crate::log_capture::capture_events();
    let outcome = svc.after_session_created(&new_record, &new, &ctx()).await;
    drop(guard);

    assert!(
        outcome.is_ok(),
        "an eviction failure must not fail the login"
    );
    let reported: Vec<_> = events
        .iter()
        .into_iter()
        .filter(|event| {
            event
                .rendered
                .contains("eviction of an over-cap session failed")
        })
        .collect();
    assert_eq!(reported.len(), 1, "{reported:?}");
    let line = &reported[0].rendered;
    assert!(
        line.contains("cause=internal error: host store unavailable"),
        "{line}"
    );
    assert!(
        !events.contains(MARKER),
        "the Debug marker was logged: {line}"
    );
}
