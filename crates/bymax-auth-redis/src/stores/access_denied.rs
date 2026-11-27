//! [`AccessDeniedStore`] over Redis: the two `access.denied` counters nest-auth shares (layer:
//! store adapter).
//!
//! Both counters go through `brute_force_incr`, which sets the expiry in the same atomic step as
//! the increment that creates the key. The take is one `GETDEL`.

use async_trait::async_trait;
use bymax_auth_core::traits::AccessDeniedStore;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

impl RedisStores {
    /// `INCR prefix:digest`, setting `ttl_seconds` only when the increment creates the key.
    async fn count_access_denied(
        &self,
        prefix: Prefix,
        digest: &str,
        ttl_seconds: u64,
    ) -> Result<u64, RedisStoreError> {
        let mut conn = self.connection().await?;
        let count: u64 = script::BRUTE_FORCE_INCR
            .prepare()
            .key(self.keys().key(prefix, digest))
            .arg(ttl_seconds)
            .invoke_async(&mut conn)
            .await?;
        Ok(count)
    }

    /// `GETDEL wads:digest`.
    async fn take_access_denied_suppressed(
        &self,
        digest: &str,
    ) -> Result<Option<String>, RedisStoreError> {
        let mut conn = self.connection().await?;
        let held: Option<String> = redis::cmd("GETDEL")
            .arg(self.keys().key(Prefix::Wads, digest))
            .query_async(&mut conn)
            .await?;
        Ok(held)
    }
}

#[async_trait]
impl AccessDeniedStore for RedisStores {
    async fn count_denial(&self, digest: &str, window_seconds: u64) -> Result<u64, AuthError> {
        self.count_access_denied(Prefix::Wad, digest, window_seconds)
            .await
            .map_err(AuthError::from)
    }

    async fn count_suppressed(&self, digest: &str, ttl_seconds: u64) -> Result<(), AuthError> {
        self.count_access_denied(Prefix::Wads, digest, ttl_seconds)
            .await
            .map(drop)
            .map_err(AuthError::from)
    }

    async fn take_suppressed(&self, digest: &str) -> Result<Option<String>, AuthError> {
        self.take_access_denied_suppressed(digest)
            .await
            .map_err(AuthError::from)
    }
}
