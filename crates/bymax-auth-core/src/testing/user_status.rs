//! The in-memory [`UserStatusCacheStore`]: entries expire on the wall clock like the Redis keys
//! they stand in for, and are keyed by `(tenant, user)` so two tenants' ids never meet.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::{InMemoryStores, lock};
use crate::traits::UserStatusCacheStore;

/// The cache's entries: `(tenant, user, fact)` to `(value, when it expires)`.
pub(super) type Entries =
    std::collections::HashMap<(String, String, &'static str), (String, Instant)>;

/// The two facts an entry can hold.
const STATUS: &str = "status";
const VERIFIED: &str = "verified";

impl InMemoryStores {
    /// The live value of one fact, dropping it when its TTL has run out.
    fn read_fact(&self, tenant_id: &str, user_id: &str, fact: &'static str) -> Option<String> {
        let mut entries = lock(&self.user_status);
        let key = (tenant_id.to_owned(), user_id.to_owned(), fact);
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
    fn write_fact(
        &self,
        tenant_id: &str,
        user_id: &str,
        fact: &'static str,
        value: String,
        ttl_secs: u64,
    ) {
        lock(&self.user_status).insert(
            (tenant_id.to_owned(), user_id.to_owned(), fact),
            (value, Instant::now() + Duration::from_secs(ttl_secs)),
        );
    }
}

#[async_trait]
impl UserStatusCacheStore for InMemoryStores {
    async fn get_status(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, AuthError> {
        Ok(self.read_fact(tenant_id, user_id, STATUS))
    }

    async fn get_verified(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<bool>, AuthError> {
        Ok(self
            .read_fact(tenant_id, user_id, VERIFIED)
            .map(|value| value != "0"))
    }

    async fn put_status(
        &self,
        tenant_id: &str,
        user_id: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.write_fact(tenant_id, user_id, STATUS, status.to_owned(), ttl_secs);
        Ok(())
    }

    async fn put_verified(
        &self,
        tenant_id: &str,
        user_id: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let value = if verified { "1" } else { "0" };
        self.write_fact(tenant_id, user_id, VERIFIED, value.to_owned(), ttl_secs);
        Ok(())
    }

    async fn invalidate(&self, tenant_id: &str, user_id: &str) -> Result<(), AuthError> {
        let mut entries = lock(&self.user_status);
        for fact in [VERIFIED, STATUS] {
            entries.remove(&(tenant_id.to_owned(), user_id.to_owned(), fact));
        }
        Ok(())
    }
}
