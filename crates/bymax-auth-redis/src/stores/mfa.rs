//! [`MfaStore`] over Redis: the AES-protected pending-setup record (`mfa_setup:`), the
//! single-use MFA temp-token marker (`mfa:`), and the TOTP anti-replay marker (`tu:`)
//! (section 12.4). Every transition that could race — the `SET NX` setup gate, the `GETDEL`
//! completion gate, and the fused replay-mark + temp-token consume — is a single atomic step
//! (a one-shot Redis command or the `mfa_challenge` Lua, section 7.5.6).
//!
//! The values stored here are produced by the engine's MFA service: the setup record is the
//! AES-256-GCM wire string of the encrypted secret + keyed recovery-code hashes, and the
//! `mfa:`/`tu:` keys carry only hashed identifiers — this layer never sees a plaintext
//! secret, recovery code, or raw `jti`.

use async_trait::async_trait;
use bymax_auth_core::traits::MfaStore;
use bymax_auth_types::AuthError;
use redis::AsyncCommands;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

impl RedisStores {
    /// `SET mfa_setup:{user_id_hash} value NX EX ttl` — store the pending-setup record only
    /// when absent, returning whether this call created it.
    async fn put_setup_nx_inner(
        &self,
        user_id_hash: &str,
        value: &str,
        ttl: u64,
    ) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(Prefix::MfaSetup, user_id_hash);
        let mut conn = self.connection().await?;
        // `SET ... NX EX` returns the bulk string "OK" when it wrote and nil when the key was
        // already present; `Option<String>` maps that to `Some`/`None` without a second call.
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut conn)
            .await?;
        Ok(set.is_some())
    }

    /// `GET mfa_setup:{user_id_hash}` — read the pending-setup record without consuming it.
    async fn get_setup_inner(&self, user_id_hash: &str) -> Result<Option<String>, RedisStoreError> {
        let key = self.keys().key(Prefix::MfaSetup, user_id_hash);
        let mut conn = self.connection().await?;
        Ok(conn.get(&key).await?)
    }

    /// `GETDEL mfa_setup:{user_id_hash}` — atomically read and consume the completion gate.
    async fn take_setup_inner(
        &self,
        user_id_hash: &str,
    ) -> Result<Option<String>, RedisStoreError> {
        let key = self.keys().key(Prefix::MfaSetup, user_id_hash);
        let mut conn = self.connection().await?;
        Ok(redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await?)
    }

    /// `SET mfa:{jti_hash} user_id EX ttl` — write the single-use temp-token marker.
    async fn put_temp_inner(
        &self,
        jti_hash: &str,
        user_id: &str,
        ttl: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self.keys().key(Prefix::Mfa, jti_hash);
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(user_id)
            .arg("EX")
            .arg(ttl)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// `GET mfa:{jti_hash}` — read the temp-token marker without consuming it (the
    /// non-consuming verify of section 7.3.5).
    async fn get_temp_inner(&self, jti_hash: &str) -> Result<Option<String>, RedisStoreError> {
        let key = self.keys().key(Prefix::Mfa, jti_hash);
        let mut conn = self.connection().await?;
        Ok(conn.get(&key).await?)
    }

    /// `DEL mfa:{jti_hash}` — consume the temp-token marker (idempotent).
    async fn del_temp_inner(&self, jti_hash: &str) -> Result<(), RedisStoreError> {
        let key = self.keys().key(Prefix::Mfa, jti_hash);
        let mut conn = self.connection().await?;
        conn.del::<_, ()>(&key).await?;
        Ok(())
    }

    /// `SET tu:{replay_id} "1" NX EX ttl` — set the standalone anti-replay marker, returning
    /// whether it was newly created (the code had not been seen).
    async fn mark_totp_used_inner(
        &self,
        replay_id: &str,
        ttl: u64,
    ) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(Prefix::Tu, replay_id);
        let mut conn = self.connection().await?;
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut conn)
            .await?;
        Ok(set.is_some())
    }

    /// The fused `mfa_challenge` Lua: set `tu:{replay_id}` `NX EX ttl` and, iff newly created,
    /// `DEL mfa:{jti_hash}`, gating success on the deletion — returning whether this call both
    /// freshly marked the code and removed the still-present temp token (the sole winner), in one
    /// atomic step. A distinct still-valid code that loses the race for an already-consumed token
    /// is rolled back (its marker is dropped) and reports `false`.
    async fn challenge_consume_inner(
        &self,
        replay_id: &str,
        jti_hash: &str,
        ttl: u64,
    ) -> Result<bool, RedisStoreError> {
        let tu_key = self.keys().key(Prefix::Tu, replay_id);
        let mfa_key = self.keys().key(Prefix::Mfa, jti_hash);
        let mut conn = self.connection().await?;
        let created: i64 = script::MFA_CHALLENGE
            .prepare()
            .key(&tu_key)
            .key(&mfa_key)
            .arg(ttl)
            .invoke_async(&mut conn)
            .await?;
        Ok(created == 1)
    }
}

#[async_trait]
impl MfaStore for RedisStores {
    async fn put_setup_nx(
        &self,
        user_id_hash: &str,
        value: &str,
        ttl: u64,
    ) -> Result<bool, AuthError> {
        self.put_setup_nx_inner(user_id_hash, value, ttl)
            .await
            .map_err(AuthError::from)
    }

    async fn get_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError> {
        self.get_setup_inner(user_id_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn take_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError> {
        self.take_setup_inner(user_id_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn put_temp(&self, jti_hash: &str, user_id: &str, ttl: u64) -> Result<(), AuthError> {
        self.put_temp_inner(jti_hash, user_id, ttl)
            .await
            .map_err(AuthError::from)
    }

    async fn get_temp(&self, jti_hash: &str) -> Result<Option<String>, AuthError> {
        self.get_temp_inner(jti_hash).await.map_err(AuthError::from)
    }

    async fn del_temp(&self, jti_hash: &str) -> Result<(), AuthError> {
        self.del_temp_inner(jti_hash).await.map_err(AuthError::from)
    }

    async fn mark_totp_used(&self, replay_id: &str, ttl: u64) -> Result<bool, AuthError> {
        self.mark_totp_used_inner(replay_id, ttl)
            .await
            .map_err(AuthError::from)
    }

    async fn challenge_consume(
        &self,
        replay_id: &str,
        jti_hash: &str,
        ttl: u64,
    ) -> Result<bool, AuthError> {
        self.challenge_consume_inner(replay_id, jti_hash, ttl)
            .await
            .map_err(AuthError::from)
    }
}
