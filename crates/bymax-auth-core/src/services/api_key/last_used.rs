//! Coalesced last-used timestamps. A verified request only records the instant in memory; the
//! host flushes the batch on its own schedule, so a busy key costs one store write per flush
//! rather than one per request. The write is advisory: a crash loses at most the unflushed window.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use time::OffsetDateTime;

use crate::RepositoryError;
use crate::traits::ApiKeyRepository;

/// The instants waiting to be written, newest per key.
#[derive(Debug, Default)]
pub(super) struct LastUsed {
    pending: Mutex<HashMap<String, OffsetDateTime>>,
}

impl LastUsed {
    /// Remember that `id` verified at `at`, keeping the newest instant seen.
    pub(super) fn record(&self, id: &str, at: OffsetDateTime) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = pending.entry(id.to_owned()).or_insert(at);
        if *slot < at {
            *slot = at;
        }
    }

    /// Write every pending instant in one batch. A failed write puts the entries back, so the
    /// next flush retries them, without overwriting an instant recorded in the meantime.
    pub(super) async fn flush(
        &self,
        repository: &dyn ApiKeyRepository,
    ) -> Result<(), RepositoryError> {
        let batch: Vec<(String, OffsetDateTime)> = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending.drain().collect()
        };
        if batch.is_empty() {
            return Ok(());
        }
        let written = repository.touch_last_used(&batch).await;
        if written.is_err() {
            for (id, at) in &batch {
                self.record(id, *at);
            }
        }
        written
    }
}
