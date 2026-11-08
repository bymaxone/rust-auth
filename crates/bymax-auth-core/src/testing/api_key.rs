//! The in-memory [`ApiKeyRepository`]: a `Mutex<HashMap>` keyed on the row id, with the
//! monotonic last-used write the trait demands, a read counter so a test can pin how many rows a
//! verification read, and a switch that makes every call fail like a datastore outage.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::RepositoryError;
use crate::traits::{ApiKey, ApiKeyRepository, NewApiKey};

/// An in-memory [`ApiKeyRepository`].
#[derive(Debug, Default)]
pub struct InMemoryApiKeyRepository {
    rows: Mutex<HashMap<String, ApiKey>>,
    reads: AtomicUsize,
    failing: AtomicBool,
}

impl InMemoryApiKeyRepository {
    /// An empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        self.rows.lock().ok()?.get(id).cloned()
    }

    fn check(&self) -> Result<(), RepositoryError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(RepositoryError::Backend("api key store unavailable".into()));
        }
        Ok(())
    }

    fn rows(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, ApiKey>>, RepositoryError> {
        self.rows
            .lock()
            .map_err(|_| RepositoryError::Backend("api key store lock poisoned".into()))
    }
}

#[async_trait]
impl ApiKeyRepository for InMemoryApiKeyRepository {
    async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>, RepositoryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        Ok(self.rows()?.get(id).cloned())
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
        let mut rows = self.rows()?;
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
            .rows()?
            .get_mut(id)
            .map(|key| {
                key.revoked_at.get_or_insert(at);
            })
            .is_some())
    }

    async fn set_expiry(&self, id: &str, at: OffsetDateTime) -> Result<bool, RepositoryError> {
        self.check()?;
        Ok(self
            .rows()?
            .get_mut(id)
            .map(|key| key.expires_at = Some(at))
            .is_some())
    }

    async fn touch_last_used(
        &self,
        entries: &[(String, OffsetDateTime)],
    ) -> Result<(), RepositoryError> {
        self.check()?;
        let mut rows = self.rows()?;
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
            .rows()?
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
