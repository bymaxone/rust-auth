//! [`PasswordResetStore`] and [`InvitationStore`] over Redis: the small single-use
//! opaque-token keyspaces (`pr:`/`prv:`/`inv:`, section 12.4). Each stores a JSON value keyed
//! by `sha256(token)` — the raw token is never a key — with a TTL, and consumes it atomically
//! with `GETDEL` so a proof or invitation is valid exactly once. The reset link token also
//! supports an out-of-band `DEL` used to clean up after an undeliverable email.

use async_trait::async_trait;
use bymax_auth_core::traits::{
    InvitationStore, PasswordResetStore, ResetContext, StoredInvitation,
};
use bymax_auth_crypto::mac::sha256;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::{Prefix, to_hex};
use crate::pool::RedisStores;

impl RedisStores {
    /// The fully-qualified key for an opaque token under `prefix`: `sha256(token)` hex, never
    /// the raw token.
    fn token_key(&self, prefix: Prefix, token: &str) -> String {
        self.keys().key(prefix, &to_hex(&sha256(token.as_bytes())))
    }

    /// Store a JSON-serializable value under `prefix:{sha256(token)}` with a TTL.
    async fn put_value<T: serde::Serialize>(
        &self,
        prefix: Prefix,
        token: &str,
        value: &T,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self.token_key(prefix, token);
        let json = serde_json::to_string(value)?;
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Atomically consume (`GETDEL`) the value at `prefix:{sha256(token)}`, deserializing it.
    /// `None` when the key is absent (unknown / expired / already consumed).
    async fn consume_value<T: serde::de::DeserializeOwned>(
        &self,
        prefix: Prefix,
        token: &str,
    ) -> Result<Option<T>, RedisStoreError> {
        let key = self.token_key(prefix, token);
        let mut conn = self.connection().await?;
        let raw: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
        match raw {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Delete the value at `prefix:{sha256(token)}` without reading it (the undeliverable-email
    /// cleanup for a reset link token).
    async fn delete_value(&self, prefix: Prefix, token: &str) -> Result<(), RedisStoreError> {
        let key = self.token_key(prefix, token);
        let mut conn = self.connection().await?;
        redis::cmd("DEL")
            .arg(&key)
            .query_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl PasswordResetStore for RedisStores {
    async fn put_token(
        &self,
        token: &str,
        context: &ResetContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_value(Prefix::Pr, token, context, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_token(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        self.consume_value(Prefix::Pr, token)
            .await
            .map_err(AuthError::from)
    }

    async fn delete_token(&self, token: &str) -> Result<(), AuthError> {
        self.delete_value(Prefix::Pr, token)
            .await
            .map_err(AuthError::from)
    }

    async fn put_verified(
        &self,
        token: &str,
        context: &ResetContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_value(Prefix::Prv, token, context, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_verified(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        self.consume_value(Prefix::Prv, token)
            .await
            .map_err(AuthError::from)
    }
}

#[async_trait]
impl InvitationStore for RedisStores {
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &StoredInvitation,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_value(Prefix::Inv, token, invitation, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_invitation(&self, token: &str) -> Result<Option<StoredInvitation>, AuthError> {
        self.consume_value(Prefix::Inv, token)
            .await
            .map_err(AuthError::from)
    }
}
