//! [`BruteForceStore`] over Redis: a fixed-window failed-attempt counter whose TTL is set
//! only on the first failure, so the window starts at the first failure and never slides
//! (section 12.5.3). The identifier is already an HMAC of `tenant:email`.

use async_trait::async_trait;
use bymax_auth_core::traits::BruteForceStore;
use bymax_auth_types::AuthError;
use redis::AsyncCommands;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

impl RedisStores {
    /// Whether the identifier's counter has reached `max_attempts`.
    async fn is_locked_inner(
        &self,
        identifier: &str,
        max_attempts: u32,
    ) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(Prefix::Lf, identifier);
        let mut conn = self.connection().await?;
        let count: Option<i64> = conn.get(&key).await?;
        Ok(count.unwrap_or(0) >= i64::from(max_attempts))
    }

    /// Atomically increment the counter, setting the window TTL only on the 0->1 transition.
    async fn record_failure_inner(
        &self,
        identifier: &str,
        window_secs: u64,
    ) -> Result<i64, RedisStoreError> {
        let key = self.keys().key(Prefix::Lf, identifier);
        let mut conn = self.connection().await?;
        let count: i64 = script::BRUTE_FORCE_INCR
            .prepare()
            .key(&key)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count)
    }

    /// Delete the counter (on a successful authentication).
    async fn reset_inner(&self, identifier: &str) -> Result<(), RedisStoreError> {
        let key = self.keys().key(Prefix::Lf, identifier);
        let mut conn = self.connection().await?;
        conn.del::<_, ()>(&key).await?;
        Ok(())
    }

    /// The counter's residual TTL clamped to `>= 0` (a missing or never-expiring key yields
    /// `0`), so the caller can derive a `Retry-After`.
    async fn remaining_lockout_secs_inner(&self, identifier: &str) -> Result<u64, RedisStoreError> {
        let key = self.keys().key(Prefix::Lf, identifier);
        let mut conn = self.connection().await?;
        let ttl: i64 = conn.ttl(&key).await?;
        Ok(u64::try_from(ttl).unwrap_or(0))
    }
}

#[async_trait]
impl BruteForceStore for RedisStores {
    async fn is_locked(&self, identifier: &str, max_attempts: u32) -> Result<bool, AuthError> {
        self.is_locked_inner(identifier, max_attempts)
            .await
            .map_err(AuthError::from)
    }

    async fn record_failure(&self, identifier: &str, window_secs: u64) -> Result<i64, AuthError> {
        self.record_failure_inner(identifier, window_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn reset(&self, identifier: &str) -> Result<(), AuthError> {
        self.reset_inner(identifier).await.map_err(AuthError::from)
    }

    async fn remaining_lockout_secs(&self, identifier: &str) -> Result<u64, AuthError> {
        self.remaining_lockout_secs_inner(identifier)
            .await
            .map_err(AuthError::from)
    }
}
