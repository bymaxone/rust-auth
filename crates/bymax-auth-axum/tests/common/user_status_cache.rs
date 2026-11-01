//! `FailingStores` delegating the account-status cache to the in-memory stores it wraps, so it
//! still satisfies the bundle bound of `redis_stores`.

use async_trait::async_trait;
use bymax_auth_core::traits::UserStatusCacheStore;
use bymax_auth_types::AuthError;

use super::FailingStores;

#[async_trait]
impl UserStatusCacheStore for FailingStores {
    async fn get_status(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, AuthError> {
        self.inner.get_status(tenant_id, user_id).await
    }
    async fn get_verified(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<bool>, AuthError> {
        self.inner.get_verified(tenant_id, user_id).await
    }
    async fn put_status(
        &self,
        tenant_id: &str,
        user_id: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .put_status(tenant_id, user_id, status, ttl_secs)
            .await
    }
    async fn put_verified(
        &self,
        tenant_id: &str,
        user_id: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .put_verified(tenant_id, user_id, verified, ttl_secs)
            .await
    }
    async fn invalidate(&self, tenant_id: &str, user_id: &str) -> Result<(), AuthError> {
        self.inner.invalidate(tenant_id, user_id).await
    }
}
