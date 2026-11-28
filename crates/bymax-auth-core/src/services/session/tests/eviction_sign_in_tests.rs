//! The cap's eviction when ending one session ends others of its sign-in: how many counted
//! sessions it removes, and which of them the eviction hook is told about (service layer tests).

use super::damaged_detail_tests::DamagedDetails;
use super::*;

const FAMILY_A: &str = "0f8fad5b-d9cb-469f-a165-70867728950a";
const FAMILY_B: &str = "0f8fad5b-d9cb-469f-a165-70867728950b";

/// One seeded session: its hash prefix and the family its record names.
type Seed<'a> = (&'a str, &'a str);

/// Store `seeds` oldest first for `owner`, then answer the record of the last one.
async fn seed(store: &InMemoryStores, owner: &str, seeds: &[Seed<'_>]) -> Option<SessionRecord> {
    let mut last = None;
    for (age, (prefix, family)) in seeds.iter().enumerate() {
        let created =
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(i64::try_from(age).ok()?);
        let record = SessionRecord {
            family_id: (*family).to_owned(),
            ..record(owner, created)
        };
        store
            .create_session(
                SessionKind::Dashboard,
                &subject(owner),
                &hash(prefix),
                &record,
                3600,
            )
            .await
            .ok()?;
        last = Some(record);
    }
    last
}

/// What a pass over the cap left: the live hashes and the hashes the eviction hook was given,
/// both sorted.
struct Outcome {
    live: Vec<String>,
    told: Vec<String>,
}

/// Run the cap of two over `seeds`, the last of which is the session just created.
async fn run(
    inner: Arc<InMemoryStores>,
    store: Arc<dyn SessionStore>,
    seeds: &[Seed<'_>],
    hooks_expected: usize,
) -> Option<Outcome> {
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "signincap").await;
    let new_record = seed(&inner, &uid, seeds).await?;
    let new_hash = hash(seeds.last()?.0);
    let hooks = Arc::new(CountingHooks::default());
    let svc = SessionService::new(
        store,
        users,
        hooks.clone(),
        config(2, None),
        3600,
        std::time::Duration::from_secs(900),
        zeroize::Zeroizing::new(TEST_IDENTIFIER_KEY),
    );
    svc.after_session_created(&new_record, &new_hash, &ctx())
        .await
        .ok()?;
    settle_until(|| hooks.evictions.load(Ordering::Relaxed) >= hooks_expected).await;
    let mut live: Vec<String> = inner
        .list_sessions(SessionKind::Dashboard, &subject(&uid))
        .await
        .ok()?
        .into_iter()
        .map(|detail| detail.session_hash)
        .collect();
    live.sort();
    let mut told = hooks.evicted_hashes.lock().ok()?.clone();
    told.sort();
    Some(Outcome { live, told })
}

fn hashes(prefixes: &[&str]) -> Vec<String> {
    prefixes.iter().map(|prefix| hash(prefix)).collect()
}

/// Two of one sign-in on either side of another session: ending the older removes both, which is
/// as many as the cap asked for.
const SIBLINGS_AROUND: &[Seed<'_>] = &[
    ("a1", FAMILY_A),
    ("b1", FAMILY_B),
    ("a2", FAMILY_A),
    ("c1", ""),
];

#[tokio::test]
async fn a_sign_in_that_covers_the_excess_leaves_the_next_chosen_session_live() {
    let inner = Arc::new(InMemoryStores::new());
    let Some(outcome) = run(inner.clone(), inner, SIBLINGS_AROUND, 1).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["b1", "c1"]));
    assert_eq!(outcome.told, hashes(&["a1"]));
}

#[tokio::test]
async fn the_removed_sessions_count_when_the_access_entry_is_refused() {
    let inner = Arc::new(InMemoryStores::new());
    inner.fail_next_session_access_writes(1);
    let Some(outcome) = run(inner.clone(), inner, SIBLINGS_AROUND, 1).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["b1", "c1"]));
}

#[tokio::test]
async fn a_chosen_session_already_removed_with_its_sign_in_still_reaches_the_hook() {
    let inner = Arc::new(InMemoryStores::new());
    let seeds = [
        ("a1", FAMILY_A),
        ("a2", FAMILY_A),
        ("b1", FAMILY_B),
        ("c1", ""),
    ];
    let Some(outcome) = run(inner.clone(), inner, &seeds, 2).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["b1", "c1"]));
    assert_eq!(outcome.told, hashes(&["a1", "a2"]));
}

#[tokio::test]
async fn a_family_member_the_cap_did_not_count_does_not_reduce_the_excess() {
    let inner = Arc::new(InMemoryStores::new());
    let elsewhere = SessionRecord {
        family_id: FAMILY_A.to_owned(),
        ..record("elsewhere", OffsetDateTime::UNIX_EPOCH)
    };
    let planted = inner
        .create_session(
            SessionKind::Dashboard,
            &subject("elsewhere"),
            &hash("ee"),
            &elsewhere,
            3600,
        )
        .await;
    assert!(planted.is_ok());
    let seeds = [("a1", FAMILY_A), ("b1", ""), ("d1", ""), ("c1", "")];
    let Some(outcome) = run(inner.clone(), inner, &seeds, 2).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["c1", "d1"]));
}

/// Three are over the cap: the oldest, then one whose sibling `z1` is newer than the third chosen.
const THREE_OVER: &[Seed<'_>] = &[
    ("a1", FAMILY_A),
    ("b1", FAMILY_B),
    ("d1", ""),
    ("bb", FAMILY_B),
    ("c1", ""),
];

#[tokio::test]
async fn a_victim_whose_family_removal_fails_still_counts_as_removed() {
    let inner = Arc::new(InMemoryStores::new());
    inner.fail_next_family_removals(1);
    let Some(outcome) = run(inner.clone(), inner, THREE_OVER, 2).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["c1", "d1"]));
}

#[tokio::test]
async fn a_victim_a_concurrent_logout_removed_counts_as_removed_and_is_not_logged() {
    let inner = Arc::new(InMemoryStores::new());
    let store = Arc::new(DamagedDetails::new(inner.clone(), &[]).losing(&hash("a1")));
    let (events, guard) = crate::log_capture::capture_events();
    let outcome = run(inner, store, THREE_OVER, 2).await;
    drop(guard);
    let Some(outcome) = outcome else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["c1", "d1"]));
    assert!(!events.contains("eviction of an over-cap session failed"));
}

/// Two are over the cap: `a1`, whose sibling `aa` is newer than the second chosen `b1`.
const TWO_OVER: &[Seed<'_>] = &[
    ("a1", FAMILY_A),
    ("b1", FAMILY_B),
    ("aa", FAMILY_A),
    ("c1", ""),
];

#[tokio::test]
async fn a_sibling_that_rotates_before_the_removal_does_not_cost_a_further_sign_in() {
    let inner = Arc::new(InMemoryStores::new());
    let store = DamagedDetails::new(inner.clone(), &[]);
    let store = Arc::new(store.rotating_before_removal(&hash("aa"), &hash("af")));
    let Some(outcome) = run(inner, store, TWO_OVER, 1).await else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["b1", "c1"]));
    assert_eq!(outcome.told, hashes(&["a1"]));
}

#[tokio::test]
async fn a_removed_session_the_index_still_lists_is_not_counted_as_live() {
    let inner = Arc::new(InMemoryStores::new());
    let store = Arc::new(DamagedDetails::new(inner.clone(), &[]).leaving_members_listed());
    let Some(outcome) = run(inner, store, SIBLINGS_AROUND, 1).await else { unreachable!() };
    assert_eq!(outcome.told, hashes(&["a1"]));
    assert!(outcome.live.contains(&hash("b1")));
}

#[tokio::test]
async fn an_index_that_cannot_be_read_again_ends_no_further_session_and_is_logged() {
    let inner = Arc::new(InMemoryStores::new());
    let store = Arc::new(DamagedDetails::new(inner.clone(), &[]).listing_only(1));
    let seeds = [("a1", FAMILY_A), ("b1", ""), ("d1", ""), ("c1", "")];
    let (events, guard) = crate::log_capture::capture_events();
    let outcome = run(inner, store, &seeds, 1).await;
    drop(guard);
    let Some(outcome) = outcome else { unreachable!() };
    assert_eq!(outcome.live, hashes(&["b1", "c1", "d1"]));
    assert_eq!(outcome.told, hashes(&["a1"]));
    assert!(events.contains("the session cap was not enforced"));
}

#[tokio::test]
async fn a_victim_found_already_gone_is_followed_by_a_second_read_of_the_index() {
    let inner = Arc::new(InMemoryStores::new());
    let store = DamagedDetails::new(inner.clone(), &[]).losing(&hash("a1"));
    let store = Arc::new(store.listing_only(1));
    let seeds = [("a1", FAMILY_A), ("b1", ""), ("d1", ""), ("c1", "")];
    let Some(outcome) = run(inner, store, &seeds, 1).await else { unreachable!() };
    assert!(outcome.live.contains(&hash("b1")));
}

#[tokio::test]
async fn a_victim_whose_family_removal_fails_is_followed_by_a_second_read_of_the_index() {
    let inner = Arc::new(InMemoryStores::new());
    inner.fail_next_family_removals(1);
    let store = Arc::new(DamagedDetails::new(inner.clone(), &[]).listing_only(1));
    let seeds = [("a1", FAMILY_A), ("b1", ""), ("d1", ""), ("c1", "")];
    let Some(outcome) = run(inner, store, &seeds, 1).await else { unreachable!() };
    assert!(outcome.live.contains(&hash("b1")));
}
