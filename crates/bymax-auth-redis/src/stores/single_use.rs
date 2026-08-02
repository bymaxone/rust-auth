//! [`PasswordResetStore`] and [`InvitationStore`] over Redis: the small single-use
//! opaque-token keyspaces (`pw_reset:`/`pw_vtok:`/`inv:`, section 12.4). Each stores a JSON value keyed
//! by `sha256(token)` — the raw token is never a key — with a TTL, and consumes it atomically
//! with `GETDEL` so a proof or invitation is valid exactly once. The reset link token also
//! supports an out-of-band `DEL` used to clean up after an undeliverable email.

use async_trait::async_trait;
use bymax_auth_core::traits::{
    EmailChangeContext, InvitationStore, PasswordResetStore, ResetContext, StoredInvitation,
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

    /// The invitee index key: `invidx:{tenantId}:{invitee_hash}`.
    ///
    /// The identifier arrives already derived — the engine HMACs the address, so a dump of the
    /// keyspace does not enumerate who a tenant has been inviting, which the invitation record
    /// itself never exposes either. Hashing it again here would move the keyspace away from
    /// nest-auth's, which writes the same keys into the same Redis.
    fn invitee_key(&self, tenant_id: &str, invitee_hash: &str) -> String {
        self.keys()
            .key(Prefix::Invidx, &format!("{tenant_id}:{invitee_hash}"))
    }

    /// `SET invidx:{tenantId}:{hash} {token_hash} EX {ttl}`.
    ///
    /// Split out, like every other command in this crate, so the redis failure converts through
    /// `?` rather than through a closure at the call site. A closure there is a region of its
    /// own that only a broken connection reaches, which is not something the suite can arrange.
    async fn put_invitation_index_inner(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self.invitee_key(tenant_id, invitee_hash);
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(token_hash)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// `GET invidx:{tenantId}:{hash}` — read the token hash, leaving the entry in place.
    async fn read_invitation_index_inner(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, RedisStoreError> {
        let key = self.invitee_key(tenant_id, invitee_hash);
        let mut conn = self.connection().await?;
        let hash = redis::cmd("GET")
            .arg(&key)
            .query_async::<Option<String>>(&mut conn)
            .await?;
        Ok(hash)
    }

    /// `GETDEL invidx:{tenantId}:{hash}` — read and consume the entry in one step.
    async fn take_invitation_index_inner(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, RedisStoreError> {
        let key = self.invitee_key(tenant_id, invitee_hash);
        let mut conn = self.connection().await?;
        let hash = redis::cmd("GETDEL")
            .arg(&key)
            .query_async::<Option<String>>(&mut conn)
            .await?;
        Ok(hash)
    }

    /// `GET inv:{token_hash}` — read an invitation without consuming it.
    ///
    /// A record that no longer parses is answered as absent: the revocation path deletes it
    /// either way, and it could not have been accepted either.
    async fn read_invitation_by_hash_inner(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredInvitation>, RedisStoreError> {
        let key = self.keys().key(Prefix::Inv, token_hash);
        let mut conn = self.connection().await?;
        let raw: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
        Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
    }

    /// `DEL inv:{token_hash}` — returns whether a record was removed.
    async fn delete_invitation_by_hash_inner(
        &self,
        token_hash: &str,
    ) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(Prefix::Inv, token_hash);
        let mut conn = self.connection().await?;
        let removed: i64 = redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
        Ok(removed > 0)
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
        self.put_value(Prefix::PwReset, token, context, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_token(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        self.consume_value(Prefix::PwReset, token)
            .await
            .map_err(AuthError::from)
    }

    async fn delete_token(&self, token: &str) -> Result<(), AuthError> {
        self.delete_value(Prefix::PwReset, token)
            .await
            .map_err(AuthError::from)
    }

    async fn put_verified(
        &self,
        token: &str,
        context: &ResetContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_value(Prefix::PwVtok, token, context, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn put_email_change(
        &self,
        token: &str,
        context: &EmailChangeContext,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_value(Prefix::Ec, token, context, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_email_change(
        &self,
        token: &str,
    ) -> Result<Option<EmailChangeContext>, AuthError> {
        self.consume_value(Prefix::Ec, token)
            .await
            .map_err(AuthError::from)
    }

    async fn consume_verified(&self, token: &str) -> Result<Option<ResetContext>, AuthError> {
        self.consume_value(Prefix::PwVtok, token)
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

    async fn put_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_invitation_index_inner(tenant_id, invitee_hash, token_hash, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn read_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, AuthError> {
        self.read_invitation_index_inner(tenant_id, invitee_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn take_invitation_index(
        &self,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, AuthError> {
        self.take_invitation_index_inner(tenant_id, invitee_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn read_invitation_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredInvitation>, AuthError> {
        self.read_invitation_by_hash_inner(token_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn delete_invitation_by_hash(&self, token_hash: &str) -> Result<bool, AuthError> {
        self.delete_invitation_by_hash_inner(token_hash)
            .await
            .map_err(AuthError::from)
    }
}
