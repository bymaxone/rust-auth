//! A damaged session detail may hide a session from the DISPLAY listing, never from revocation
//! or the concurrent-session cap. The store here behaves as the Redis store does for such a
//! session: the display listing omits it, the entries still name it with no detail.

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use super::*;
use crate::traits::{SessionDetail, SessionEntry, SessionRotation};

/// Builds the error a failing entries listing returns.
type ListingError = Box<dyn Fn() -> AuthError + Send + Sync>;

/// An in-memory store that hides chosen sessions' details, and can make the entries listing
/// fail with an error of the test's choosing.
pub(super) struct DamagedDetails {
    inner: Arc<InMemoryStores>,
    damaged: Mutex<HashSet<String>>,
    listing_error: Option<ListingError>,
    revoke_error: Option<ListingError>,
    lost: Option<String>,
    rotating: Mutex<Option<(String, String)>>,
    refused_listings: Range<usize>,
    listings: AtomicUsize,
    ownerless: bool,
}

impl DamagedDetails {
    pub(super) fn new(inner: Arc<InMemoryStores>, damaged: &[&str]) -> Self {
        let damaged = damaged.iter().map(|hash| (*hash).to_owned()).collect();
        Self {
            inner,
            damaged: Mutex::new(damaged),
            listing_error: None,
            revoke_error: None,
            lost: None,
            rotating: Mutex::new(None),
            refused_listings: 0..0,
            listings: AtomicUsize::new(0),
            ownerless: false,
        }
    }

    /// Make every `list_session_entries` call fail with the error `make` builds.
    pub(super) fn failing_entries_with(
        mut self,
        make: impl Fn() -> AuthError + Send + Sync + 'static,
    ) -> Self {
        self.listing_error = Some(Box::new(make));
        self
    }

    /// Make every `revoke_session` call fail with the error `make` builds.
    pub(super) fn failing_revokes_with(
        mut self,
        make: impl Fn() -> AuthError + Send + Sync + 'static,
    ) -> Self {
        self.revoke_error = Some(Box::new(make));
        self
    }

    /// Make revoking `hash` find it already gone, as when a concurrent logout removed it first.
    pub(super) fn losing(mut self, hash: &str) -> Self {
        self.lost = Some(hash.to_owned());
        self
    }

    /// Rotate `old` to `new` as the first family removal is asked for, which is after the cap has
    /// listed the index and before the family is read.
    pub(super) fn rotating_before_removal(self, old: &str, new: &str) -> Self {
        let rotation = Some((old.to_owned(), new.to_owned()));
        Self {
            rotating: Mutex::new(rotation),
            ..self
        }
    }

    /// Refuse the entries listings whose position, counted from zero, falls in `refused`.
    pub(super) fn refusing_listings(mut self, refused: Range<usize>) -> Self {
        self.refused_listings = refused;
        self
    }

    /// Remove families without pruning the index, as when its `SREM` is refused.
    pub(super) fn leaving_members_listed(mut self) -> Self {
        self.ownerless = true;
        self
    }

    async fn rotate_pending(
        &self,
        kind: SessionKind,
        owner_subject_hash: Option<&str>,
    ) -> Result<(), AuthError> {
        let pending = self.rotating.lock().ok().and_then(|mut slot| slot.take());
        let (Some((old, new)), Some(subject_hash)) = (pending, owner_subject_hash) else {
            return Ok(());
        };
        let Some(new_record) = self.inner.find_session(kind, &old).await? else {
            return Ok(());
        };
        let rotation = SessionRotation {
            old_hash: old,
            new_hash: new,
            new_raw: String::new(),
            new_record,
            subject_hash: subject_hash.to_owned(),
            refresh_ttl: 3600,
            grace_ttl: 60,
        };
        self.inner.rotate(kind, &rotation).await.map(|_| ())
    }

    fn is_damaged(&self, hash: &str) -> bool {
        self.damaged.lock().is_ok_and(|set| set.contains(hash))
    }
}

#[async_trait::async_trait]
impl SessionStore for DamagedDetails {
    async fn list_sessions(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        let all = self.inner.list_sessions(kind, subject_hash).await?;
        Ok(all
            .into_iter()
            .filter(|detail| !self.is_damaged(&detail.session_hash))
            .collect())
    }

    async fn list_session_entries(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<Vec<SessionEntry>, AuthError> {
        if let Some(make) = &self.listing_error {
            return Err(make());
        }
        let position = self.listings.fetch_add(1, Ordering::SeqCst);
        if self.refused_listings.contains(&position) {
            return Err(crate::services::internal_error("listing refused"));
        }
        let all = self.inner.list_sessions(kind, subject_hash).await?;
        Ok(all
            .into_iter()
            .map(|detail| SessionEntry {
                session_hash: detail.session_hash.clone(),
                detail: (!self.is_damaged(&detail.session_hash)).then_some(detail),
            })
            .collect())
    }

    async fn create_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .create_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await
    }

    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError> {
        self.inner.rotate(kind, rotation).await
    }

    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.inner.find_session(kind, token_hash).await
    }

    async fn create_recovered_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<bool, AuthError> {
        self.inner
            .create_recovered_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        if let Some(make) = &self.revoke_error {
            return Err(make());
        }
        self.inner
            .revoke_session(kind, subject_hash, session_hash)
            .await?;
        if self.lost.as_deref() == Some(session_hash) {
            return Err(AuthError::SessionNotFound);
        }
        Ok(())
    }

    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.inner.delete_grace_pointer(kind, session_hash).await
    }

    async fn sweep_grace_pointers(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<(), AuthError> {
        self.inner.sweep_grace_pointers(kind, subject_hash).await
    }

    async fn revoke_all(&self, kind: SessionKind, subject_hash: &str) -> Result<(), AuthError> {
        self.inner.revoke_all(kind, subject_hash).await
    }

    async fn find_family_owner(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.inner.find_family_owner(kind, family_id).await
    }

    async fn revoke_family(
        &self,
        kind: SessionKind,
        family_id: &str,
        owner_subject_hash: Option<&str>,
    ) -> Result<Vec<String>, AuthError> {
        self.rotate_pending(kind, owner_subject_hash).await?;
        let owner = owner_subject_hash.filter(|_| !self.ownerless);
        self.inner.revoke_family(kind, family_id, owner).await
    }

    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .blacklist_access(jti_or_hash, remaining_ttl_secs)
            .await
    }

    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError> {
        self.inner.is_blacklisted(jti_or_hash).await
    }

    async fn revoke_session_access(
        &self,
        kind: SessionKind,
        session_id: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .revoke_session_access(kind, session_id, ttl_secs)
            .await
    }

    async fn is_session_access_revoked(
        &self,
        kind: SessionKind,
        session_id: &str,
    ) -> Result<bool, AuthError> {
        self.inner.is_session_access_revoked(kind, session_id).await
    }

    async fn current_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.inner.current_epoch(kind, subject_hash).await
    }

    async fn bump_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.inner.bump_epoch(kind, subject_hash).await
    }

    async fn create_session_with_recent_auth(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
        recent_auth_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .create_session_with_recent_auth(
                kind,
                subject_hash,
                token_hash,
                detail,
                ttl_secs,
                recent_auth_ttl_secs,
            )
            .await
    }

    async fn has_recent_auth(&self, user_id_hash: &str, sid: &str) -> Result<bool, AuthError> {
        self.inner.has_recent_auth(user_id_hash, sid).await
    }
}

/// A service over a store in which the sessions named in `damaged` have no readable detail.
/// Returns the service and the underlying store, to look at what is really stored.
fn damaged_service(damaged: &[&str], cap: u32) -> (SessionService, Arc<InMemoryStores>) {
    let inner = Arc::new(InMemoryStores::new());
    let store = Arc::new(DamagedDetails::new(inner.clone(), damaged));
    let svc = SessionService::new(
        store,
        Arc::new(InMemoryUserRepository::new()),
        Arc::new(NoOpAuthHooks),
        config(cap, None),
        3600,
        std::time::Duration::from_secs(900),
        zeroize::Zeroizing::new(TEST_IDENTIFIER_KEY),
    );
    (svc, inner)
}

/// Store a session for `u1` that is `age` seconds after the epoch.
async fn seed(store: &InMemoryStores, session: &str, age: i64) {
    let created = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(age);
    let stored = store
        .create_session(
            SessionKind::Dashboard,
            &subject("u1"),
            session,
            &record("u1", created),
            3600,
        )
        .await;
    assert!(stored.is_ok());
}

/// Whether the underlying store still holds the session.
async fn alive(store: &InMemoryStores, session: &str) -> bool {
    matches!(
        store.find_session(SessionKind::Dashboard, session).await,
        Ok(Some(_))
    )
}

#[tokio::test]
async fn signing_out_the_other_devices_revokes_a_session_whose_detail_is_damaged() {
    let (current, healthy, damaged) = (hash("aa"), hash("bb"), hash("cc"));
    let (svc, store) = damaged_service(&[&damaged], 10);
    for (session, age) in [(&current, 1), (&healthy, 2), (&damaged, 3)] {
        seed(&store, session, age).await;
    }

    let outcome = svc.revoke_all_except_current("t1", "u1", &current).await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        alive(&store, &current).await,
        "the caller's own session stays"
    );
    assert!(!alive(&store, &healthy).await);
    assert!(
        !alive(&store, &damaged).await,
        "a session with a damaged detail must not survive 'sign out other devices'"
    );
}

#[tokio::test]
async fn the_session_cap_counts_a_damaged_detail_session_and_evicts_it_as_the_oldest() {
    // Cap 2 with three sessions: the damaged one is both counted and, having no creation time to
    // order by, treated as the oldest, so it is the one evicted.
    let (damaged, healthy, newest) = (hash("cc"), hash("bb"), hash("dd"));
    let (svc, store) = damaged_service(&[&damaged], 2);
    for (session, age) in [(&damaged, 1), (&healthy, 2), (&newest, 3)] {
        seed(&store, session, age).await;
    }
    let new_record = record(
        "u1",
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(3),
    );

    let outcome = svc
        .after_session_created(&new_record, &newest, &ctx())
        .await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        !alive(&store, &damaged).await,
        "the over-cap session with a damaged detail was not counted"
    );
    assert!(alive(&store, &healthy).await);
    assert!(alive(&store, &newest).await);
}

#[tokio::test]
async fn the_display_listing_still_omits_a_damaged_detail_session() {
    let (healthy, damaged) = (hash("bb"), hash("cc"));
    let (svc, store) = damaged_service(&[&damaged], 10);
    seed(&store, &healthy, 1).await;
    seed(&store, &damaged, 2).await;

    let listed = svc.list_sessions("t1", "u1", None).await;

    let hashes: Vec<String> = listed
        .map(|sessions| sessions.into_iter().map(|s| s.session_hash).collect())
        .unwrap_or_default();
    assert_eq!(hashes, [healthy]);
}
