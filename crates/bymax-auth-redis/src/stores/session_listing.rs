//! Reading one session-detail record for a listing: which members surface and which are left out.
//!
//! Layer: a helper of the session store. The decision is pure, so it is testable without a
//! server; the one Redis call here removes the dead index members in one script.

use bymax_auth_core::traits::{SessionDetail, SessionEntry, SessionKind};
use deadpool_redis::Connection;
use redis::AsyncCommands;

use super::session::{SessionDetailValue, index_member, kind_prefixes, live_member_hash};
use crate::error::RedisStoreError;
use crate::pool::RedisStores;
use crate::script;

/// What reading one `sd:`/`psd:` record means for the listing.
#[derive(Debug, PartialEq)]
pub(super) enum DetailRead {
    /// A well-formed record: the session is listed.
    Listed(SessionDetail),
    /// Absent, or present but not a whole detail record. The session is left out of the listing;
    /// whether its index member is also dead is a separate question that only the `rt:` key
    /// answers, because a live session whose detail was lost or damaged is still a session.
    Excluded,
}

/// Interpret the raw `sd:`/`psd:` value stored for the session `hash`.
///
/// A record that fails to parse is excluded rather than failing the whole listing: one corrupt
/// or foreign-written value must not hide every other session of the account.
pub(super) fn read_detail(hash: &str, raw: Option<&str>) -> DetailRead {
    let Some(raw) = raw else { return DetailRead::Excluded };
    match serde_json::from_str::<SessionDetailValue>(raw) {
        Ok(value) => DetailRead::Listed(SessionDetail {
            session_hash: hash.to_owned(),
            device: value.device,
            ip: value.ip,
            created_at: value.created_at,
            last_activity_at: value.last_activity_at,
        }),
        Err(_) => DetailRead::Excluded,
    }
}

/// Remove from the index `sess_key` every candidate in `members` whose own key is gone, on the
/// connection the caller already holds, and return the members it removed. Existence is the only evidence admitted: a detail that is
/// missing or damaged does not make a session dead, and removing a live one from the index lets
/// it outlive a sign-out-everywhere. The caller runs this after every read succeeded, so a failed
/// read never leaves the index half-pruned.
pub(super) async fn prune_dead_members(
    conn: &mut Connection,
    namespace: &str,
    sess_key: &str,
    members: &[&str],
) -> Result<Vec<String>, RedisStoreError> {
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let mut invocation = script::SESSION_PRUNE_DEAD.prepare();
    invocation.key(sess_key).arg(namespace);
    for member in members {
        invocation.arg(*member);
    }
    Ok(invocation.invoke_async(conn).await?)
}

impl RedisStores {
    /// List a user's live sessions by reading the `sess:` SET and each member's `sd:` detail.
    ///
    /// Only `rt:`/`prt:` members are live sessions; the `rp:`/`prp:` rotation grace pointers
    /// share the index (so `revoke_all` can sweep them) but are not sessions and are filtered
    /// out here, matching nest-auth's `members.filter(m => m.startsWith('rt:'))`.
    ///
    /// # Dead grace pointers
    ///
    /// Not a live session. If it is a grace pointer whose key has already expired,
    /// drop the member rather than leaving it: a rotation removes `rt:{old}`
    /// and adds TWO members — `rt:{new}` and `rp:{old}` — and until now only a full
    /// revoke-all ever removed the second. The `rp:` KEY dies with the grace window
    /// (30 s by default); the MEMBER did not, while `refresh_rotate` re-arms the
    /// set's own TTL on every rotation. The index therefore gained one permanent
    /// ~70-byte entry per refresh and never aged out while the account was in use.
    ///
    /// It is a growth defect with an amplifier attached, because every reader of
    /// this index is linear in its size: this method, `sweep_grace_pointers` (two
    /// sequential round trips per member), and `invalidate_user_sessions`, which
    /// iterates it inside a Lua script and so blocks the whole single-threaded
    /// store. One stolen refresh token rotated at the route limit adds ~14k members
    /// a day to its own index, with no ceiling.
    ///
    /// Pruned from the LIST path rather than from the rotation: the rotation is the
    /// hot path and an O(n) sweep there would trade a slow leak for a slow refresh.
    /// Session-cap enforcement lists too, so a login bounds it.
    ///
    /// A pointer still inside its window is left alone — that is what lets a
    /// revoke-all also kill a token rotated away moments earlier.
    pub(super) async fn list_session_entries_inner(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<Vec<SessionEntry>, RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let sess_key = keys.key(prefixes.sess, subject_hash);
        let mut conn = self.connection().await?;
        let members: Vec<String> = conn.smembers(&sess_key).await?;
        let mut entries = Vec::with_capacity(members.len());
        let mut stale: Vec<&str> = Vec::new();
        let grace_prefix = format!("{}:", prefixes.rp.as_str());
        for member in &members {
            let Some(hash) = live_member_hash(member, prefixes.rt) else {
                // Not a live session: an expired grace pointer is queued for the prune.
                if member.starts_with(&grace_prefix) {
                    stale.push(member.as_str());
                }
                continue;
            };
            // The detail record is keyed by the BARE hash, so the member's prefix is stripped.
            let sd_key = keys.key(prefixes.sd, hash);
            let raw: Option<String> = conn.get(&sd_key).await?;
            let session_hash = hash.to_owned();
            match read_detail(hash, raw.as_deref()) {
                DetailRead::Listed(detail) => entries.push(SessionEntry {
                    session_hash,
                    detail: Some(detail),
                }),
                // Still an entry, with no detail; pruned once, after every read, only if its `rt:`
                // key is gone too.
                DetailRead::Excluded => {
                    stale.push(member.as_str());
                    entries.push(SessionEntry {
                        session_hash,
                        detail: None,
                    });
                }
            }
        }
        let removed = prune_dead_members(&mut conn, keys.namespace(), &sess_key, &stale).await?;
        // A removed member's key is gone: that session is dead, not merely detail-less.
        entries.retain(|entry| {
            entry.detail.is_some()
                || !removed.contains(&index_member(prefixes.rt, &entry.session_hash))
        });
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed stored detail value.
    fn valid(device: &str) -> String {
        format!(
            r#"{{"device":"{device}","ip":"1.2.3.4","createdAt":1700000000000,"lastActivityAt":1700000001000}}"#
        )
    }

    #[test]
    fn a_well_formed_record_is_listed_under_its_hash() {
        let read = read_detail("h1", Some(&valid("Firefox")));
        assert!(matches!(&read, DetailRead::Listed(d)
            if d.session_hash == "h1" && d.device == "Firefox" && d.ip == "1.2.3.4"));
    }

    #[test]
    fn an_absent_record_is_excluded() {
        assert_eq!(read_detail("h1", None), DetailRead::Excluded);
    }

    #[test]
    fn a_record_that_is_not_a_whole_detail_is_excluded() {
        for raw in [
            "",
            "not json",
            "null",
            "[]",
            "{}",
            r#"{"device":"x","ip":"1.2.3.4","createdAt":"1","lastActivityAt":2}"#,
            r#"{"device":1,"ip":"1.2.3.4","createdAt":1,"lastActivityAt":2}"#,
            r#"{"device":"x","ip":"1.2.3.4","createdAt":1}"#,
        ] {
            assert_eq!(read_detail("h", Some(raw)), DetailRead::Excluded, "{raw:?}");
        }
    }

    #[test]
    fn one_corrupt_record_among_many_still_lists_the_others() {
        let hashes = ["a", "b", "c", "d", "e"];
        let stored = [
            Some(valid("A")),
            Some(valid("B")),
            Some("{broken".to_owned()),
            Some(valid("D")),
            Some(valid("E")),
        ];
        let listed: Vec<String> = hashes
            .iter()
            .zip(&stored)
            .filter_map(|(hash, raw)| match read_detail(hash, raw.as_deref()) {
                DetailRead::Listed(detail) => Some(detail.session_hash),
                DetailRead::Excluded => None,
            })
            .collect();
        assert_eq!(listed, ["a", "b", "d", "e"]);
    }
}
