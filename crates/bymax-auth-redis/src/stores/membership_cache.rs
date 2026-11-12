//! [`MembershipCacheStore`] over Redis: the workspace-membership cache nest-auth reads and writes
//! under the same keys (layer: store adapter).
//!
//! The read is three single-key `GET`s in the contract's order (`wsv`, `wmv`, then the entry they
//! name), so it needs no script and works on a store that shards by key. The fill and the bump are
//! the Lua scripts `membership_cache_fill` and `membership_cache_bump`, which declare every key
//! they touch in `KEYS`.

use std::num::NonZeroU64;

use async_trait::async_trait;
use bymax_auth_core::traits::{FillOutcome, MembershipCacheRead, MembershipCacheStore};
use bymax_auth_core::workspace::limits::VERSION_RETENTION_SECONDS;
use bymax_auth_core::workspace::membership_cache::{
    MembershipCacheIds, MembershipVersions, entry_value,
};
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

/// What `membership_cache_fill` answers when it wrote the entry.
const FILL_WRITTEN: &str = "written";
/// What `membership_cache_fill` answers when a counter had moved.
const FILL_MOVED: &str = "moved";

impl RedisStores {
    /// `GET wsv`, `GET wmv`, then `GET` the entry they name, one command at a time in that order.
    async fn read_membership_cache(
        &self,
        ids: &MembershipCacheIds,
    ) -> Result<MembershipCacheRead, RedisStoreError> {
        let mut conn = self.connection().await?;
        let workspace: Option<u64> = redis::cmd("GET")
            .arg(self.keys().key(Prefix::Wsv, &ids.workspace))
            .query_async(&mut conn)
            .await?;
        let membership: Option<u64> = redis::cmd("GET")
            .arg(self.keys().key(Prefix::Wmv, &ids.membership))
            .query_async(&mut conn)
            .await?;
        let versions = MembershipVersions {
            workspace: workspace.unwrap_or(0),
            membership: membership.unwrap_or(0),
        };
        let entry: Option<String> = redis::cmd("GET")
            .arg(self.keys().key(Prefix::Wm, &ids.entry(versions)))
            .query_async(&mut conn)
            .await?;
        Ok(MembershipCacheRead { versions, entry })
    }

    /// Run `membership_cache_fill`.
    async fn fill_membership_cache(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, RedisStoreError> {
        let mut conn = self.connection().await?;
        let reply: String = script::MEMBERSHIP_CACHE_FILL
            .prepare()
            .key(self.keys().key(Prefix::Wsv, &ids.workspace))
            .key(self.keys().key(Prefix::Wmv, &ids.membership))
            .key(self.keys().key(Prefix::Wm, &ids.entry(versions)))
            .arg(entry_value(role))
            .arg(ttl.get())
            .arg(VERSION_RETENTION_SECONDS)
            .arg(versions.workspace)
            .arg(versions.membership)
            .invoke_async(&mut conn)
            .await?;
        fill_outcome(&reply)
    }

    /// Run `membership_cache_bump` on the counter `prefix:id`.
    async fn bump_version(&self, prefix: Prefix, id: &str) -> Result<u64, RedisStoreError> {
        let mut conn = self.connection().await?;
        let version: u64 = script::MEMBERSHIP_CACHE_BUMP
            .prepare()
            .key(self.keys().key(prefix, id))
            .arg(VERSION_RETENTION_SECONDS)
            .invoke_async(&mut conn)
            .await?;
        Ok(version)
    }
}

/// The outcome a `membership_cache_fill` reply names; any other reply is an error.
fn fill_outcome(reply: &str) -> Result<FillOutcome, RedisStoreError> {
    match reply {
        FILL_WRITTEN => Ok(FillOutcome::Written),
        FILL_MOVED => Ok(FillOutcome::Moved),
        _ => Err(RedisStoreError::Command(redis::RedisError::from((
            redis::ErrorKind::Parse,
            "unexpected membership_cache_fill reply",
        )))),
    }
}

#[async_trait]
impl MembershipCacheStore for RedisStores {
    async fn read(&self, ids: &MembershipCacheIds) -> Result<MembershipCacheRead, AuthError> {
        self.read_membership_cache(ids)
            .await
            .map_err(AuthError::from)
    }

    async fn fill(
        &self,
        ids: &MembershipCacheIds,
        versions: MembershipVersions,
        role: &str,
        ttl: NonZeroU64,
    ) -> Result<FillOutcome, AuthError> {
        self.fill_membership_cache(ids, versions, role, ttl)
            .await
            .map_err(AuthError::from)
    }

    async fn bump_workspace(&self, workspace_id: &str) -> Result<u64, AuthError> {
        self.bump_version(Prefix::Wsv, workspace_id)
            .await
            .map_err(AuthError::from)
    }

    async fn bump_membership(&self, membership_id: &str) -> Result<u64, AuthError> {
        self.bump_version(Prefix::Wmv, membership_id)
            .await
            .map_err(AuthError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_reply_names_its_outcome_and_anything_else_is_an_error() {
        assert!(matches!(
            fill_outcome(FILL_WRITTEN),
            Ok(FillOutcome::Written)
        ));
        assert!(matches!(fill_outcome(FILL_MOVED), Ok(FillOutcome::Moved)));
        for reply in ["", "1", "WRITTEN", "moved "] {
            assert!(matches!(
                fill_outcome(reply),
                Err(RedisStoreError::Command(_))
            ));
        }
    }

    #[test]
    fn the_replies_are_the_ones_the_script_returns() {
        let source = include_str!("../lua/membership_cache_fill.lua");
        for reply in [FILL_WRITTEN, FILL_MOVED] {
            assert!(source.contains(&format!("return '{reply}'")), "{reply}");
        }
    }
}
