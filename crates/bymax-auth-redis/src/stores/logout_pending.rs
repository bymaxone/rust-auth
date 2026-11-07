//! The pending-logout marker in Redis: `lp:`/`plp:{sha256(refreshToken)}` holds the owner a failed
//! logout attempt was ending, so the retry that completes the logout can name it.
//!
//! Layer: a helper of the session store. The trait methods that forward here live in
//! `session.rs`; the key, the stored JSON and the claim are the shared contract's
//! `recordEncodings.logoutPending`.

use bymax_auth_core::traits::{LogoutOwner, SessionKind};

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;

/// The keyspace of the marker on this plane: `lp:` for dashboard sessions, `plp:` for platform.
fn marker_prefix(kind: SessionKind) -> Prefix {
    match kind {
        SessionKind::Dashboard => Prefix::Lp,
        SessionKind::Platform => Prefix::Plp,
    }
}

impl RedisStores {
    /// Record whom a failed logout was ending: `SET lp:{hash} {json} EX ttl` (`plp:` on the platform
    /// plane). The stored form is `{"userId":..,"tenantId":..}` with `tenantId` omitted when the
    /// session record carried none, byte-identical to what nest-auth writes.
    pub(super) async fn put_marker(
        &self,
        kind: SessionKind,
        session_hash: &str,
        owner: &LogoutOwner,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let key = self.keys().key(marker_prefix(kind), session_hash);
        let value = serde_json::to_string(owner)?;
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs.max(1))
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Read the owner a failed logout recorded: one `GET`, leaving the marker in place. A value
    /// that does not decode is no owner: a hint that cannot be read names nobody.
    pub(super) async fn read_marker(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<Option<LogoutOwner>, RedisStoreError> {
        let key = self.keys().key(marker_prefix(kind), session_hash);
        let mut conn = self.connection().await?;
        let raw: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
        Ok(raw.and_then(|value| serde_json::from_str(&value).ok()))
    }

    /// Remove the marker and report whether this call removed it: `DEL` answers the number of keys
    /// it removed, so of several callers racing to claim one marker exactly one sees `1`.
    pub(super) async fn claim_marker(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(marker_prefix(kind), session_hash);
        let mut conn = self.connection().await?;
        let removed: i64 = redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
        Ok(removed > 0)
    }
}
