//! [`RateLimitStore`] over Redis: the same fixed-window counter as the failed-login one, so the
//! window opens at the first request and later requests never extend it, shared by every
//! instance that talks to this Redis.

use async_trait::async_trait;
use bymax_auth_core::traits::RateLimitStore;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::pool::RedisStores;
use crate::script;

impl RedisStores {
    /// Atomically increment the counter, setting the window TTL only on the 0->1 transition.
    async fn hit_inner(
        &self,
        route: &str,
        bucket_hash: &str,
        window_secs: u64,
    ) -> Result<i64, RedisStoreError> {
        let key = self.keys().rate_limit_key(route, bucket_hash);
        let mut conn = self.connection().await?;
        let count: i64 = script::BRUTE_FORCE_INCR
            .prepare()
            .key(&key)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count)
    }
}

#[async_trait]
impl RateLimitStore for RedisStores {
    async fn hit(
        &self,
        route: &str,
        bucket_hash: &str,
        window_secs: u64,
    ) -> Result<i64, AuthError> {
        self.hit_inner(route, bucket_hash, window_secs)
            .await
            .map_err(AuthError::from)
    }
}
