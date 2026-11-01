//! [`UserStatusCacheStore`] over Redis: the account-status cache nest-auth reads and writes
//! under the same keys. The status is a plain string at `us:{subject hash}` and the
//! verified-address flag the string `1` or `0` at `uev:{subject hash}`, both with a TTL, so the
//! two libraries can serve one deployment off one Redis.

use async_trait::async_trait;
use bymax_auth_core::traits::UserStatusCacheStore;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;

impl RedisStores {
    /// `GET` one cache key.
    async fn read_key(&self, key: &str) -> Result<Option<String>, RedisStoreError> {
        let mut conn = self.connection().await?;
        Ok(redis::cmd("GET").arg(key).query_async(&mut conn).await?)
    }

    /// `SET key value EX ttl`.
    async fn write_key(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// `DEL` one cache key.
    async fn delete_key(&self, key: &str) -> Result<(), RedisStoreError> {
        let mut conn = self.connection().await?;
        redis::cmd("DEL")
            .arg(key)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl UserStatusCacheStore for RedisStores {
    async fn get_status(&self, subject_hash: &str) -> Result<Option<String>, AuthError> {
        let status_key = self.keys().key(Prefix::Us, subject_hash);
        self.read_key(&status_key).await.map_err(AuthError::from)
    }

    async fn get_verified(&self, subject_hash: &str) -> Result<Option<bool>, AuthError> {
        let verified_key = self.keys().key(Prefix::Uev, subject_hash);
        let raw = self
            .read_key(&verified_key)
            .await
            .map_err(AuthError::from)?;
        Ok(raw.map(|value| value != "0"))
    }

    async fn put_status(
        &self,
        subject_hash: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let status_key = self.keys().key(Prefix::Us, subject_hash);
        self.write_key(&status_key, status, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn put_verified(
        &self,
        subject_hash: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let verified_key = self.keys().key(Prefix::Uev, subject_hash);
        self.write_key(&verified_key, if verified { "1" } else { "0" }, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn invalidate(&self, subject_hash: &str) -> Result<(), AuthError> {
        let status_key = self.keys().key(Prefix::Us, subject_hash);
        let verified_key = self.keys().key(Prefix::Uev, subject_hash);
        // The verified flag first: if the second delete fails, the entry left behind is the one
        // whose staleness merely costs a repository read.
        self.delete_key(&verified_key)
            .await
            .map_err(AuthError::from)?;
        self.delete_key(&status_key).await.map_err(AuthError::from)
    }
}
