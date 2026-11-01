//! The in-memory [`UserStatusCacheStore`]: entries expire on the wall clock like the Redis keys
//! they stand in for, and are keyed by the account's subject hash, which already folds the tenant
//! in, so two tenants' ids never meet.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::{InMemoryStores, lock};
use crate::traits::UserStatusCacheStore;

/// The cache's entries: `(subject hash, fact)` to `(value, when it expires)`.
pub(super) type Entries = std::collections::HashMap<(String, &'static str), (String, Instant)>;

/// The two facts an entry can hold.
const STATUS: &str = "status";
const VERIFIED: &str = "verified";

impl InMemoryStores {
    /// The live value of one fact, dropping it when its TTL has run out.
    fn read_fact(&self, subject_hash: &str, fact: &'static str) -> Option<String> {
        let mut entries = lock(&self.user_status);
        let key = (subject_hash.to_owned(), fact);
        match entries.get(&key) {
            Some((value, expires)) if *expires > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store one fact for `ttl_secs`.
    fn write_fact(&self, subject_hash: &str, fact: &'static str, value: String, ttl_secs: u64) {
        lock(&self.user_status).insert(
            (subject_hash.to_owned(), fact),
            (value, Instant::now() + Duration::from_secs(ttl_secs)),
        );
    }
}

#[async_trait]
impl UserStatusCacheStore for InMemoryStores {
    async fn get_status(&self, subject_hash: &str) -> Result<Option<String>, AuthError> {
        Ok(self.read_fact(subject_hash, STATUS))
    }

    async fn get_verified(&self, subject_hash: &str) -> Result<Option<bool>, AuthError> {
        Ok(self
            .read_fact(subject_hash, VERIFIED)
            .map(|value| value != "0"))
    }

    async fn put_status(
        &self,
        subject_hash: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.write_fact(subject_hash, STATUS, status.to_owned(), ttl_secs);
        Ok(())
    }

    async fn put_verified(
        &self,
        subject_hash: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let value = if verified { "1" } else { "0" };
        self.write_fact(subject_hash, VERIFIED, value.to_owned(), ttl_secs);
        Ok(())
    }

    async fn invalidate(&self, subject_hash: &str) -> Result<(), AuthError> {
        let mut entries = lock(&self.user_status);
        for fact in [VERIFIED, STATUS] {
            entries.remove(&(subject_hash.to_owned(), fact));
        }
        Ok(())
    }
}
