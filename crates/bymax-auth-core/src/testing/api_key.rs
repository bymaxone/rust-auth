//! The in-memory [`ApiKeyRepository`]: a `Mutex<HashMap>` keyed on the row id, with the
//! monotonic last-used write the trait demands, a read counter so a test can pin how many times
//! `find_by_id` ran, and a switch that makes every call fail like a datastore outage.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::RepositoryError;
use crate::services::api_key::ApiKeyClock;
use crate::traits::{ApiKey, ApiKeyRepository, NewApiKey};

/// An in-memory [`ApiKeyRepository`].
#[derive(Debug)]
pub struct InMemoryApiKeyRepository {
    rows: Mutex<HashMap<String, ApiKey>>,
    reads: AtomicUsize,
    failing: AtomicBool,
    /// Calls still allowed to succeed before every call fails; negative means no limit.
    allowed: AtomicI64,
}

impl Default for InMemoryApiKeyRepository {
    fn default() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            reads: AtomicUsize::new(0),
            failing: AtomicBool::new(false),
            allowed: AtomicI64::new(-1),
        }
    }
}

impl InMemoryApiKeyRepository {
    /// An empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Let the next `calls` calls succeed, then fail every call like an outage.
    pub fn fail_after(&self, calls: u32) {
        self.allowed.store(i64::from(calls), Ordering::SeqCst);
    }

    /// Make every later call fail with [`RepositoryError::Backend`] (`true`) or work again
    /// (`false`).
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// How many times [`ApiKeyRepository::find_by_id`] has been called.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// The stored row, bypassing the failure switch and the read counter.
    #[must_use]
    pub fn row(&self, id: &str) -> Option<ApiKey> {
        self.rows().get(id).cloned()
    }

    fn check(&self) -> Result<(), RepositoryError> {
        let spent = self.allowed.load(Ordering::SeqCst) == 0;
        if self.failing.load(Ordering::SeqCst) || spent {
            return Err(RepositoryError::Backend("api key store unavailable".into()));
        }
        // A negative budget is "no limit"; a positive one counts a call down.
        let _ = self
            .allowed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n > 0).then(|| n - 1)
            });
        Ok(())
    }

    /// The rows. A panic in another test thread must not turn every later call into an error, so
    /// a poisoned lock is read through.
    fn rows(&self) -> std::sync::MutexGuard<'_, HashMap<String, ApiKey>> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl ApiKeyRepository for InMemoryApiKeyRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, RepositoryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        Ok(self.rows().get(id).cloned())
    }

    async fn create(&self, row: NewApiKey) -> Result<ApiKey, RepositoryError> {
        self.check()?;
        let stored = ApiKey {
            id: row.id,
            label: row.label,
            digest: row.digest,
            scopes: row.scopes,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: None,
            last_used_at: None,
        };
        let mut rows = self.rows();
        if rows.contains_key(&stored.id) {
            return Err(RepositoryError::Conflict(
                "api key id already exists".into(),
            ));
        }
        rows.insert(stored.id.clone(), stored.clone());
        Ok(stored)
    }

    async fn mark_revoked(&self, id: &str, at: OffsetDateTime) -> Result<bool, RepositoryError> {
        self.check()?;
        Ok(self
            .rows()
            .get_mut(id)
            .map(|key| {
                key.revoked_at.get_or_insert(at);
            })
            .is_some())
    }

    async fn limit_expiry(&self, id: &str, at: OffsetDateTime) -> Result<bool, RepositoryError> {
        self.check()?;
        Ok(self
            .rows()
            .get_mut(id)
            .map(|key| key.expires_at = Some(key.expires_at.map_or(at, |own| own.min(at))))
            .is_some())
    }

    async fn touch_last_used(
        &self,
        entries: &[(String, OffsetDateTime)],
    ) -> Result<(), RepositoryError> {
        self.check()?;
        let mut rows = self.rows();
        for (id, at) in entries {
            if let Some(key) = rows.get_mut(id)
                && key.last_used_at.is_none_or(|seen| seen < *at)
            {
                key.last_used_at = Some(*at);
            }
        }
        Ok(())
    }

    async fn list_by_label(&self, label: &str) -> Result<Vec<ApiKey>, RepositoryError> {
        self.check()?;
        let mut keys: Vec<ApiKey> = self
            .rows()
            .values()
            .filter(|key| key.label == label)
            .cloned()
            .collect();
        keys.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(keys)
    }
}

/// An [`ApiKeyClock`] a test sets and advances by hand, so expiry, rotation and last-used tests
/// never wait and never depend on the wall clock.
#[derive(Debug)]
pub struct ManualApiKeyClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualApiKeyClock {
    /// A clock standing at `start`.
    #[must_use]
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// Move the clock to `at`, forwards or backwards.
    pub fn set(&self, at: OffsetDateTime) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = at;
    }

    /// Move the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        self.set(self.now() + by);
    }
}

impl ApiKeyClock for ManualApiKeyClock {
    fn now(&self) -> OffsetDateTime {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
