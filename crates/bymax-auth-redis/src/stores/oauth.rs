//! [`OAuthStateStore`] over Redis: the single-use OAuth `state` + PKCE keyspace (`os:`,
//! section 12.4). The engine writes `os:{sha256(state)} = <opaque payload>` on initiate with a
//! short TTL (600 s) and consumes it atomically with `GETDEL` on callback, so a captured
//! `state` is valid exactly once (the existence check is the CSRF guard, the deletion is the
//! replay guard).
//!
//! Unlike the other single-use keyspaces, this store does **not** hash its input: the engine
//! already passes the hex `sha256(state)` as `state_hash`, so the raw `state` is never a key
//! and the opaque payload (the tenant scope plus the PKCE `code_verifier`) is written verbatim
//! — this layer never sees the raw `state` or the verifier in cleartext.

use async_trait::async_trait;
use bymax_auth_core::traits::OAuthStateStore;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;

impl RedisStores {
    /// `SET os:{state_hash} payload EX ttl` — store the opaque state payload under the
    /// already-hashed key with a TTL.
    async fn put_state_inner(
        &self,
        state_hash: &str,
        payload: &str,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self.keys().key(Prefix::Os, state_hash);
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(payload)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// `GETDEL os:{state_hash}` — atomically read and delete the payload, so the `state` is
    /// verified and consumed in a single step. `None` when the key is absent (unknown / expired
    /// / already consumed).
    async fn take_state_inner(&self, state_hash: &str) -> Result<Option<String>, RedisStoreError> {
        let key = self.keys().key(Prefix::Os, state_hash);
        let mut conn = self.connection().await?;
        let raw: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
        Ok(raw)
    }
}

#[async_trait]
impl OAuthStateStore for RedisStores {
    async fn put_state(
        &self,
        state_hash: &str,
        payload: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.put_state_inner(state_hash, payload, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn take_state(&self, state_hash: &str) -> Result<Option<String>, AuthError> {
        self.take_state_inner(state_hash)
            .await
            .map_err(AuthError::from)
    }
}
