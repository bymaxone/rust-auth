//! `FailingStores` delegating the account-status cache to the in-memory stores it wraps, so it
//! still satisfies the bundle bound of `redis_stores`.

use async_trait::async_trait;
use bymax_auth_core::traits::UserStatusCacheStore;
use bymax_auth_types::AuthError;

use super::FailingStores;

#[async_trait]
impl UserStatusCacheStore for FailingStores {
    async fn get_status(&self, subject_hash: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_status(subject_hash).await
    }
    async fn get_verified(&self, subject_hash: &str) -> Result<Option<bool>, AuthError> {
        self.inner.get_verified(subject_hash).await
    }
    async fn put_status(
        &self,
        subject_hash: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner.put_status(subject_hash, status, ttl_secs).await
    }
    async fn put_verified(
        &self,
        subject_hash: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .put_verified(subject_hash, verified, ttl_secs)
            .await
    }
    async fn invalidate(&self, subject_hash: &str) -> Result<(), AuthError> {
        self.inner.invalidate(subject_hash).await
    }
}
