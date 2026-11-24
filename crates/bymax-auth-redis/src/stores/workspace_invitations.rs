//! [`WorkspaceInvitationStore`] over Redis: the workspace invitations nest-auth reads and writes
//! under the same keys (layer: store adapter).
//!
//! The publication and the removal are the Lua scripts `workspace_invitation_publish` and
//! `workspace_invitation_remove`, which declare every key they touch in `KEYS`. The index and the
//! set hold the record key as the contract names it, `winv:{sha256(token)}` without the namespace,
//! so a script receives that text in `ARGV` and the namespaced key in `KEYS`. The inviter counter
//! is the fixed-window counter the brute-force store uses: its lifetime starts at the first
//! increment and a later one never extends it.
//!
//! The scripts touch several keys, and the dead-member prune names the keys it reads in `ARGV`, so
//! a cluster deployment needs a namespace whose hash tag puts them all in one slot.

use async_trait::async_trait;
use bymax_auth_core::traits::{
    IndexedInvitation, InvitationPlace, PendingInvitation, Publication, PublishOutcome, Removal,
    WorkspaceInvitationStore,
};
use bymax_auth_core::workspace::invitation::InvitationRecord;
use bymax_auth_core::workspace::limits::INVITER_WINDOW_SECONDS;
use bymax_auth_types::AuthError;

use super::session_listing::prune_dead_members;
use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

/// What `TTL` answers for a key that exists and has no expiry.
const NO_LIFETIME: i64 = -1;

/// What a record key held.
enum Held {
    /// Nothing.
    Gone,
    /// A value, written with a lifetime.
    Value(String),
    /// A value that has no lifetime, which a publication never writes.
    NoLifetime,
}

impl Held {
    /// The record the key holds, `None` when it holds no value or a value that is not a record.
    fn record(&self) -> Option<InvitationRecord> {
        match self {
            Self::Value(raw) => InvitationRecord::parse(raw),
            Self::Gone | Self::NoLifetime => None,
        }
    }
}

/// What `workspace_invitation_publish` answers when it wrote the record.
const PUBLISHED: &str = "published";
/// What it answers when the index no longer held the key the writer read.
const LOST: &str = "lost";
/// What it answers when the workspace was at its limit.
const FULL: &str = "full";

impl RedisStores {
    /// The namespaced key of a record key as stored in the index and the set.
    fn invitation_record_key(&self, record_key: &str) -> String {
        format!("{}:{record_key}", self.keys().namespace())
    }

    /// `GET` the value under `record_key`, and `TTL` of it: a record is written with a lifetime,
    /// so one that has none was not written by a publication and is not trusted.
    async fn read_invitation_raw(&self, record_key: &str) -> Result<Held, RedisStoreError> {
        let mut conn = self.connection().await?;
        let key = self.invitation_record_key(record_key);
        let raw: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
        let Some(raw) = raw else {
            return Ok(Held::Gone);
        };
        let left: i64 = redis::cmd("TTL").arg(&key).query_async(&mut conn).await?;
        Ok(if left == NO_LIFETIME {
            Held::NoLifetime
        } else {
            Held::Value(raw)
        })
    }

    /// `GET` the record under `record_key` and parse it; anything that is not a record is `None`.
    async fn read_invitation_record(
        &self,
        record_key: &str,
    ) -> Result<Option<InvitationRecord>, RedisStoreError> {
        let held = self.read_invitation_raw(record_key).await?;
        Ok(held.record())
    }

    async fn read_invitation_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, RedisStoreError> {
        let mut conn = self.connection().await?;
        let record_key: Option<String> = redis::cmd("GET")
            .arg(self.keys().key(Prefix::Winvidx, &place.index_id))
            .query_async(&mut conn)
            .await?;
        drop(conn);
        match record_key {
            None => Ok(None),
            Some(record_key) => {
                let held = self.read_invitation_raw(&record_key).await?;
                let record = held.record();
                let unreadable = !matches!(held, Held::Gone) && record.is_none();
                Ok(Some(IndexedInvitation {
                    record_key,
                    record,
                    unreadable,
                }))
            }
        }
    }

    async fn publish_invitation(
        &self,
        publication: Publication<'_>,
    ) -> Result<PublishOutcome, RedisStoreError> {
        let Publication {
            place,
            record_key,
            record,
            ttl,
            pending_limit,
            expected_key,
        } = publication;
        if pending_limit > 0 {
            // Members whose record expired still count in the set, so they are dropped before it
            // is counted.
            self.pending_invitations(place).await?;
        }
        let mut conn = self.connection().await?;
        let replaced = self.invitation_record_key(expected_key.unwrap_or(record_key));
        let reply: String = script::WORKSPACE_INVITATION_PUBLISH
            .prepare()
            .key(self.keys().key(Prefix::Winvidx, &place.index_id))
            .key(self.invitation_record_key(record_key))
            .key(self.keys().key(Prefix::Winvset, &place.set_id))
            .key(replaced)
            .arg(record_key)
            .arg(record.to_json())
            .arg(ttl.get())
            .arg(pending_limit)
            .arg(expected_key.unwrap_or_default())
            .invoke_async(&mut conn)
            .await?;
        publish_outcome(&reply)
    }

    async fn remove_invitation(
        &self,
        place: &InvitationPlace,
        record_key: &str,
        removal: Removal,
    ) -> Result<bool, RedisStoreError> {
        let mut conn = self.connection().await?;
        let released: u8 = script::WORKSPACE_INVITATION_REMOVE
            .prepare()
            .key(self.keys().key(Prefix::Winvidx, &place.index_id))
            .key(self.invitation_record_key(record_key))
            .key(self.keys().key(Prefix::Winvset, &place.set_id))
            .arg(record_key)
            .arg(if removal == Removal::Owned { "1" } else { "0" })
            .invoke_async(&mut conn)
            .await?;
        Ok(released == 1)
    }

    /// The set's live invitations. A member whose key is gone is dropped from the set after every
    /// read succeeded; one that holds a value that is not a record is left alone and not listed.
    async fn pending_invitations(
        &self,
        place: &InvitationPlace,
    ) -> Result<Vec<PendingInvitation>, RedisStoreError> {
        let set_key = self.keys().key(Prefix::Winvset, &place.set_id);
        let mut conn = self.connection().await?;
        let members: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&set_key)
            .query_async(&mut conn)
            .await?;
        let mut live = Vec::new();
        for member in &members {
            let key = self.invitation_record_key(member);
            let raw: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
            let Some(record) = raw.and_then(|raw| InvitationRecord::parse(&raw)) else {
                continue;
            };
            let left: i64 = redis::cmd("TTL").arg(&key).query_async(&mut conn).await?;
            if left == NO_LIFETIME {
                continue;
            }
            live.push(PendingInvitation {
                record_key: member.clone(),
                record,
                ttl_seconds: u64::try_from(left).unwrap_or(0),
            });
        }
        let candidates: Vec<&str> = members.iter().map(String::as_str).collect();
        prune_dead_members(&mut conn, self.keys().namespace(), &set_key, &candidates).await?;
        Ok(live)
    }

    async fn count_invitation_inviter(&self, rate_id: &str) -> Result<u64, RedisStoreError> {
        let mut conn = self.connection().await?;
        let count: u64 = script::BRUTE_FORCE_INCR
            .prepare()
            .key(self.keys().key(Prefix::Winvrl, rate_id))
            .arg(INVITER_WINDOW_SECONDS)
            .invoke_async(&mut conn)
            .await?;
        Ok(count)
    }
}

/// The outcome a `workspace_invitation_publish` reply names; any other reply is an error.
fn publish_outcome(reply: &str) -> Result<PublishOutcome, RedisStoreError> {
    match reply {
        PUBLISHED => Ok(PublishOutcome::Published),
        LOST => Ok(PublishOutcome::Lost),
        FULL => Ok(PublishOutcome::Full),
        _ => Err(RedisStoreError::Command(redis::RedisError::from((
            redis::ErrorKind::Parse,
            "unexpected workspace_invitation_publish reply",
        )))),
    }
}

#[async_trait]
impl WorkspaceInvitationStore for RedisStores {
    async fn read_record(&self, record_key: &str) -> Result<Option<InvitationRecord>, AuthError> {
        self.read_invitation_record(record_key)
            .await
            .map_err(AuthError::from)
    }

    async fn read_index(
        &self,
        place: &InvitationPlace,
    ) -> Result<Option<IndexedInvitation>, AuthError> {
        self.read_invitation_index(place)
            .await
            .map_err(AuthError::from)
    }

    async fn publish(&self, publication: Publication<'_>) -> Result<PublishOutcome, AuthError> {
        self.publish_invitation(publication)
            .await
            .map_err(AuthError::from)
    }

    async fn remove(
        &self,
        place: &InvitationPlace,
        record_key: &str,
        removal: Removal,
    ) -> Result<bool, AuthError> {
        self.remove_invitation(place, record_key, removal)
            .await
            .map_err(AuthError::from)
    }

    async fn pending(&self, place: &InvitationPlace) -> Result<Vec<PendingInvitation>, AuthError> {
        self.pending_invitations(place)
            .await
            .map_err(AuthError::from)
    }

    async fn count_inviter(&self, rate_id: &str) -> Result<u64, AuthError> {
        self.count_invitation_inviter(rate_id)
            .await
            .map_err(AuthError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_publish_reply_names_its_outcome_and_anything_else_is_an_error() {
        assert!(matches!(
            publish_outcome(PUBLISHED),
            Ok(PublishOutcome::Published)
        ));
        assert!(matches!(publish_outcome(LOST), Ok(PublishOutcome::Lost)));
        assert!(matches!(publish_outcome(FULL), Ok(PublishOutcome::Full)));
        for reply in ["", "1", "PUBLISHED", "full "] {
            assert!(matches!(
                publish_outcome(reply),
                Err(RedisStoreError::Command(_))
            ));
        }
    }

    #[test]
    fn the_replies_are_the_ones_the_script_returns() {
        let source = include_str!("../lua/workspace_invitation_publish.lua");
        for reply in [PUBLISHED, LOST, FULL] {
            assert!(source.contains(&format!("return '{reply}'")), "{reply}");
        }
    }
}
