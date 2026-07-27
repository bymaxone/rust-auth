//! [`SessionStore`] over Redis: refresh-session lifecycle, atomic rotation with a grace
//! window, ownership-checked revocation, the revoke-all transaction, and the access-JWT
//! (`jti`) blacklist — all keyed by [`SessionKind`] (section 12).

use async_trait::async_trait;
use bymax_auth_core::traits::store::unix_millis;
use bymax_auth_core::traits::{
    RotateOutcome, SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore,
    TOKEN_EPOCH_RETENTION_SECS,
};
use bymax_auth_types::AuthError;
use deadpool_redis::Connection;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::RedisStoreError;
use crate::keys::Prefix;
use crate::pool::RedisStores;
use crate::script;

/// The tag the `refresh_rotate` script prepends to a grace-window recovery payload, matching
/// the literal in `lua/refresh_rotate.lua`.
const GRACE_TAG: &str = "GRACE:";

/// The tag the `refresh_rotate` script prepends to a reuse-detection reply (a replay of a
/// consumed token past its grace window), carrying the compromised family id. Matches the
/// literal in `lua/refresh_rotate.lua`.
const REUSED_TAG: &str = "REUSED:";

/// The stored `sd:`/`psd:` per-session detail value. The `session_hash` lives in the key, so
/// it is absent here; the field set is byte-identical to nest-auth.
///
/// The timestamps are Unix-millisecond numbers, not RFC 3339 strings: nest-auth writes them
/// with `Date.now()` and discards any detail record whose `createdAt`/`lastActivityAt` are not
/// numbers, so the string form made every rust-written session invisible in a nest-auth
/// listing (and vice versa) on a shared Redis.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDetailValue {
    /// Human-readable device/browser string.
    device: String,
    /// Originating IP.
    ip: String,
    /// Session creation time, as Unix milliseconds.
    #[serde(with = "unix_millis")]
    created_at: OffsetDateTime,
    /// Last observed activity time, as Unix milliseconds.
    #[serde(with = "unix_millis")]
    last_activity_at: OffsetDateTime,
}

impl SessionDetailValue {
    /// Build the detail value for a freshly-created session: `last_activity_at` starts equal
    /// to `created_at`.
    fn at_creation(record: &SessionRecord) -> Self {
        Self {
            device: record.device.clone(),
            ip: record.ip.clone(),
            created_at: record.created_at,
            last_activity_at: record.created_at,
        }
    }
}

/// The prefix sextet selected by a [`SessionKind`]: the refresh-session, grace-pointer,
/// consumed-family marker, family-index, session-index, and per-session-detail keyspaces.
struct KindPrefixes {
    rt: Prefix,
    rp: Prefix,
    cf: Prefix,
    fam: Prefix,
    sess: Prefix,
    sd: Prefix,
}

/// Build a session-index SET member: the full key **suffix** `{prefix}:{hash}`.
///
/// Members are stored this way — never as a bare hash — for two reasons. First, parity: it is
/// byte-identical to what nest-auth writes (`rt:{hash}`, `prt:{hash}`, `rp:{oldHash}`,
/// `prp:{oldHash}`), so on a shared Redis either backend can revoke a session the other
/// created. Second, security: a bare hash cannot say which keyspace it belongs to, so a
/// revoke-all could not distinguish a live `rt:` session from an `rp:` rotation grace pointer
/// and therefore could not delete the latter — leaving a rotated-away refresh token able to
/// recover a session for its whole grace window after the user logged everything out.
fn index_member(prefix: Prefix, hash: &str) -> String {
    format!("{}:{}", prefix.as_str(), hash)
}

/// Recover the bare session hash from a **live-session** index member, or `None` when the
/// member belongs to another keyspace. Used by listing to keep grace pointers (`rp:`/`prp:`)
/// out of the user-visible session list and to rebuild the `sd:`/`psd:` detail key, which is
/// keyed by the bare hash.
fn live_member_hash(member: &str, live: Prefix) -> Option<&str> {
    member
        .strip_prefix(live.as_str())
        .and_then(|rest| rest.strip_prefix(':'))
}

/// Map a [`SessionKind`] onto its prefix sextet (`rt`/`rp`/`cf`/`fam`/`sess`/`sd` for dashboard,
/// `prt`/`prp`/`pcf`/`pfam`/`psess`/`psd` for platform).
fn kind_prefixes(kind: SessionKind) -> KindPrefixes {
    match kind {
        SessionKind::Dashboard => KindPrefixes {
            rt: Prefix::Rt,
            rp: Prefix::Rp,
            cf: Prefix::Cf,
            fam: Prefix::Fam,
            sess: Prefix::Sess,
            sd: Prefix::Sd,
        },
        SessionKind::Platform => KindPrefixes {
            rt: Prefix::Prt,
            rp: Prefix::Prp,
            cf: Prefix::Pcf,
            fam: Prefix::Pfam,
            sess: Prefix::Psess,
            sd: Prefix::Psd,
        },
    }
}

/// The parsed outcome of the `refresh_rotate` script, before the non-atomic session-index
/// bookkeeping the caller performs on a live rotation.
enum RotateParsed {
    /// The old token was live and consumed; carries the consumed (old) record.
    Rotated(SessionRecord),
    /// The old token was inside the grace window; carries the recovered record.
    Grace(SessionRecord),
    /// The old token was already consumed and its grace window has closed — a reuse; carries
    /// the compromised family id.
    Reused(String),
    /// Neither the live token, a grace pointer, nor a consumed marker was present.
    Invalid,
}

/// Interpret the raw `refresh_rotate` reply: `nil` is an invalid refresh, a `"GRACE:"`-tagged
/// payload is a grace-window hit, a `"REUSED:"`-tagged payload is a consumed-token reuse
/// carrying its family id, and any other payload is the consumed old-session JSON.
fn interpret_rotate(raw: Option<String>) -> Result<RotateParsed, RedisStoreError> {
    let Some(payload) = raw else {
        return Ok(RotateParsed::Invalid);
    };
    if let Some(grace_json) = payload.strip_prefix(GRACE_TAG) {
        return Ok(RotateParsed::Grace(serde_json::from_str(grace_json)?));
    }
    if let Some(family) = payload.strip_prefix(REUSED_TAG) {
        return Ok(RotateParsed::Reused(family.to_owned()));
    }
    Ok(RotateParsed::Rotated(serde_json::from_str(&payload)?))
}

impl RedisStores {
    /// Persist a freshly-issued refresh session: the record under `rt:`, the `rt:{hash}`
    /// member in the user's `sess:` SET, and the detail under `sd:`, each with the refresh TTL.
    async fn create_session_inner(
        &self,
        kind: SessionKind,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let rt_key = keys.key(prefixes.rt, token_hash);
        let sess_key = keys.key(prefixes.sess, &detail.user_id);
        let sd_key = keys.key(prefixes.sd, token_hash);
        let live_member = index_member(prefixes.rt, token_hash);
        let record_json = serde_json::to_string(detail)?;
        let detail_json = serde_json::to_string(&SessionDetailValue::at_creation(detail))?;
        let ttl_window = i64::try_from(ttl_secs).unwrap_or(i64::MAX);

        let mut pipe = redis::pipe();
        pipe.cmd("SET")
            .arg(&rt_key)
            .arg(&record_json)
            .arg("EX")
            .arg(ttl_secs)
            .ignore()
            .cmd("SADD")
            .arg(&sess_key)
            .arg(&live_member)
            .ignore()
            .cmd("SET")
            .arg(&sd_key)
            .arg(&detail_json)
            .arg("EX")
            .arg(ttl_secs)
            .ignore()
            .cmd("EXPIRE")
            .arg(&sess_key)
            .arg(ttl_window)
            .ignore();
        // Register the session in its family index (skipped for a legacy record with no family),
        // so the whole lineage can be revoked on reuse detection. The index carries the refresh
        // TTL so it ages out with the sessions it tracks.
        if !detail.family_id.is_empty() {
            let fam_key = keys.key(prefixes.fam, &detail.family_id);
            pipe.cmd("SADD")
                .arg(&fam_key)
                .arg(token_hash)
                .ignore()
                .cmd("EXPIRE")
                .arg(&fam_key)
                .arg(ttl_window)
                .ignore();
        }

        let mut conn = self.connection().await?;
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }

    /// Run the `refresh_rotate` script and, on a live rotation, move the session-index
    /// membership and detail from the old hash to the new one.
    async fn rotate_inner(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let rt_old = keys.key(prefixes.rt, &rotation.old_hash);
        let rt_new = keys.key(prefixes.rt, &rotation.new_hash);
        let rp_old = keys.key(prefixes.rp, &rotation.old_hash);
        let cf_old = keys.key(prefixes.cf, &rotation.old_hash);
        // The family index of the presented session's lineage. When the new record carries no
        // family (a legacy rotation) the script's `ARGV[4] == ''` guard skips every family write,
        // so this key is built but never touched.
        let family = &rotation.new_record.family_id;
        let fam_key = keys.key(prefixes.fam, family);
        let new_json = serde_json::to_string(&rotation.new_record)?;

        let mut conn = self.connection().await?;
        let raw: Option<String> = script::REFRESH_ROTATE
            .prepare()
            .key(&rt_old)
            .key(&rt_new)
            .key(&rp_old)
            .key(&cf_old)
            .key(&fam_key)
            .arg(&new_json)
            .arg(rotation.refresh_ttl)
            .arg(rotation.grace_ttl)
            .arg(family)
            .arg(&rotation.old_hash)
            .arg(&rotation.new_hash)
            .invoke_async(&mut conn)
            .await?;

        match interpret_rotate(raw)? {
            RotateParsed::Invalid => Ok(RotateOutcome::Invalid),
            RotateParsed::Grace(record) => {
                if self
                    .family_is_alive(&mut conn, prefixes.fam, &record)
                    .await?
                {
                    Ok(RotateOutcome::Grace(record))
                } else {
                    Ok(RotateOutcome::Invalid)
                }
            }
            RotateParsed::Reused(family) => Ok(RotateOutcome::Reused(family)),
            RotateParsed::Rotated(old_record) => {
                self.move_session_member(&mut conn, &prefixes, rotation, &old_record.user_id)
                    .await?;
                Ok(RotateOutcome::Rotated(old_record))
            }
        }
    }

    /// Whether the lineage a recovered grace record belongs to is still alive.
    ///
    /// A grace pointer can outlive its own lineage: reuse detection revokes the family's live
    /// sessions, but a pointer planted by an *earlier* rotation of that same lineage can still be
    /// inside its (much shorter) window at that moment — detection only proves the replayed
    /// token's own pointer expired, which says nothing about a younger sibling's. Recovering from
    /// such a pointer would mint a fresh session carrying the revoked family id and hand the thief
    /// back the lineage the revocation just killed.
    ///
    /// A record written before families existed carries none and recovers as before.
    async fn family_is_alive(
        &self,
        conn: &mut Connection,
        fam: Prefix,
        record: &SessionRecord,
    ) -> Result<bool, RedisStoreError> {
        if record.family_id.is_empty() {
            return Ok(true);
        }
        let fam_key = self.keys().key(fam, &record.family_id);
        let present: bool = conn.exists(&fam_key).await?;
        Ok(present)
    }

    /// Run the `revoke_family` transaction, deleting every live member's `rt:`/`sd:` key, pruning
    /// each from its owner's `sess:` SET, and dropping the family index — the reuse-detection
    /// lockout of a stolen token's whole lineage.
    ///
    /// The owner is resolved here rather than decoded inside the script: every member of one
    /// family belongs to the same login, so the first readable record names it, and reading it
    /// with a real parser keeps the script free of `cjson`.
    async fn revoke_family_inner(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<(), RedisStoreError> {
        // An empty family id has no index key; nothing to revoke.
        if family_id.is_empty() {
            return Ok(());
        }
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let fam_key = keys.key(prefixes.fam, family_id);
        let mut conn = self.connection().await?;
        let members: Vec<String> = conn.smembers(&fam_key).await?;
        let owner_index = self
            .resolve_family_owner_index(&mut conn, &prefixes, &members)
            .await?;
        script::REVOKE_FAMILY
            .prepare()
            .key(&fam_key)
            .arg(keys.namespace())
            .arg(prefixes.rt.as_str())
            .arg(prefixes.sd.as_str())
            .arg(&owner_index)
            .invoke_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }

    /// Resolve the namespaced session-index key of the user a family belongs to, or an empty
    /// string when no member record is readable — every member may have already expired, in
    /// which case there is no index left to prune.
    async fn resolve_family_owner_index(
        &self,
        conn: &mut Connection,
        prefixes: &KindPrefixes,
        members: &[String],
    ) -> Result<String, RedisStoreError> {
        let keys = self.keys();
        for hash in members {
            let raw: Option<String> = conn.get(keys.key(prefixes.rt, hash)).await?;
            let Some(raw) = raw else { continue };
            let Ok(record) = serde_json::from_str::<SessionRecord>(&raw) else {
                continue;
            };
            if !record.user_id.is_empty() {
                return Ok(keys.key(prefixes.sess, &record.user_id));
            }
        }
        Ok(String::new())
    }

    /// Move the session-index membership and detail from the old hash to the new hash after a
    /// live rotation — the non-atomic bookkeeping the rotation script leaves to the caller.
    ///
    /// The rotation grace pointer written by the script (`rp:{oldHash}` / `prp:{oldHash}`) is
    /// **also** added to the index, exactly as nest-auth does. That membership is what lets
    /// `revoke_all` delete the grace pointer: without it a token that was just rotated away
    /// could still recover a live session through the grace window for the whole grace TTL,
    /// even after the user revoked every session. A zero-width grace window writes no pointer,
    /// so no member is added for it.
    async fn move_session_member(
        &self,
        conn: &mut Connection,
        prefixes: &KindPrefixes,
        rotation: &SessionRotation,
        user_id: &str,
    ) -> Result<(), RedisStoreError> {
        let keys = self.keys();
        let sess_key = keys.key(prefixes.sess, user_id);
        let sd_old = keys.key(prefixes.sd, &rotation.old_hash);
        let sd_new = keys.key(prefixes.sd, &rotation.new_hash);
        let old_member = index_member(prefixes.rt, &rotation.old_hash);
        let new_member = index_member(prefixes.rt, &rotation.new_hash);
        let detail_json =
            serde_json::to_string(&SessionDetailValue::at_creation(&rotation.new_record))?;
        let ttl_window = i64::try_from(rotation.refresh_ttl).unwrap_or(i64::MAX);
        let mut pipe = redis::pipe();
        pipe.cmd("SREM")
            .arg(&sess_key)
            .arg(&old_member)
            .ignore()
            .cmd("DEL")
            .arg(&sd_old)
            .ignore()
            .cmd("SADD")
            .arg(&sess_key)
            .arg(&new_member)
            .ignore();
        if rotation.grace_ttl > 0 {
            pipe.cmd("SADD")
                .arg(&sess_key)
                .arg(index_member(prefixes.rp, &rotation.old_hash))
                .ignore();
        }
        pipe.cmd("SET")
            .arg(&sd_new)
            .arg(&detail_json)
            .arg("EX")
            .arg(rotation.refresh_ttl)
            .ignore()
            .cmd("EXPIRE")
            .arg(&sess_key)
            .arg(ttl_window)
            .ignore()
            .query_async::<()>(conn)
            .await?;
        Ok(())
    }

    /// Look up a live session by refresh-token hash.
    async fn find_session_inner(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let key = self.keys().key(prefixes.rt, token_hash);
        let mut conn = self.connection().await?;
        let raw: Option<String> = conn.get(&key).await?;
        match raw {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// List a user's live sessions by reading the `sess:` SET and each member's `sd:` detail.
    ///
    /// Only `rt:`/`prt:` members are live sessions; the `rp:`/`prp:` rotation grace pointers
    /// share the index (so `revoke_all` can sweep them) but are not sessions and are filtered
    /// out here, matching nest-auth's `members.filter(m => m.startsWith('rt:'))`.
    async fn list_sessions_inner(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<Vec<SessionDetail>, RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let sess_key = keys.key(prefixes.sess, user_id);
        let mut conn = self.connection().await?;
        let members: Vec<String> = conn.smembers(&sess_key).await?;
        let mut details = Vec::with_capacity(members.len());
        for member in &members {
            let Some(hash) = live_member_hash(member, prefixes.rt) else {
                continue;
            };
            // The detail record is keyed by the BARE hash, so the member's prefix is stripped.
            let sd_key = keys.key(prefixes.sd, hash);
            let raw: Option<String> = conn.get(&sd_key).await?;
            if let Some(json) = raw {
                let value: SessionDetailValue = serde_json::from_str(&json)?;
                details.push(SessionDetail {
                    session_hash: hash.to_owned(),
                    device: value.device,
                    ip: value.ip,
                    created_at: value.created_at,
                    last_activity_at: value.last_activity_at,
                });
            }
        }
        Ok(details)
    }

    /// Run the ownership-checked `session_revoke` script. Returns whether the hash was owned.
    async fn revoke_session_inner(
        &self,
        kind: SessionKind,
        user_id: &str,
        session_hash: &str,
    ) -> Result<bool, RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let sess_key = keys.key(prefixes.sess, user_id);
        let rt_key = keys.key(prefixes.rt, session_hash);
        let sd_key = keys.key(prefixes.sd, session_hash);
        // The ownership check is a SISMEMBER against the index, whose members are full key
        // suffixes — so the ARGV is `rt:{hash}`, not the bare hash.
        let member = index_member(prefixes.rt, session_hash);
        let mut conn = self.connection().await?;
        let owned: bool = script::SESSION_REVOKE
            .prepare()
            .key(&sess_key)
            .key(&rt_key)
            .key(&sd_key)
            .arg(&member)
            .invoke_async(&mut conn)
            .await?;
        Ok(owned)
    }

    /// Delete the rotation grace pointer (`rp:`/`prp:`) for a refresh-token hash. Idempotent: a
    /// `DEL` of an absent key is a no-op. Logout calls this after the ownership-checked revoke so
    /// a just-rotated token cannot recover a session through the grace window post-logout.
    async fn delete_grace_pointer_inner(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let rp_key = self.keys().key(prefixes.rp, session_hash);
        let mut conn = self.connection().await?;
        redis::cmd("DEL")
            .arg(&rp_key)
            .query_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }

    /// Run the `invalidate_user_sessions` transaction, deleting the key each member names
    /// (`rt:`/`prt:` live sessions **and** `rp:`/`prp:` grace pointers), each live member's
    /// `sd:`/`psd:` detail, and the `sess:` SET itself in one atomic step.
    async fn revoke_all_inner(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<(), RedisStoreError> {
        let prefixes = kind_prefixes(kind);
        let keys = self.keys();
        let sess_key = keys.key(prefixes.sess, user_id);
        let mut conn = self.connection().await?;
        script::INVALIDATE_USER_SESSIONS
            .prepare()
            .key(&sess_key)
            .arg(keys.namespace())
            .arg(prefixes.rt.as_str())
            .arg(prefixes.sd.as_str())
            .invoke_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }

    /// Add an access-token `jti` (or full-JWT hash) to the `rv:` blacklist for its remaining
    /// lifetime. A zero TTL is a no-op: the token has already expired.
    async fn blacklist_access_inner(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), RedisStoreError> {
        if remaining_ttl_secs == 0 {
            return Ok(());
        }
        let key = self.keys().key(Prefix::Rv, jti_or_hash);
        let mut conn = self.connection().await?;
        conn.set_ex::<_, _, ()>(&key, "1", remaining_ttl_secs)
            .await?;
        Ok(())
    }

    /// Whether an access `jti`/JWT hash is on the `rv:` blacklist.
    async fn is_blacklisted_inner(&self, jti_or_hash: &str) -> Result<bool, RedisStoreError> {
        let key = self.keys().key(Prefix::Rv, jti_or_hash);
        let mut conn = self.connection().await?;
        let present: bool = conn.exists(&key).await?;
        Ok(present)
    }

    /// Read the user's token epoch (`ep:`/`pep:`), defaulting to `0` when no key exists — a
    /// plain `GET` that never creates the key, so only a user who has actually been bumped
    /// carries one.
    async fn current_epoch_inner(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<u64, RedisStoreError> {
        let key = self.keys().key(epoch_prefix(kind), user_id);
        let mut conn = self.connection().await?;
        let value: Option<u64> = conn.get(&key).await?;
        Ok(value.unwrap_or(0))
    }

    /// Atomically increment the user's token epoch (`INCR`, creating it at `1` when absent) and
    /// (re)apply its TTL, returning the new value. The TTL is deliberately far longer than any
    /// access token lives, so a bump stays effective for the whole window a pre-bump token could
    /// still be presented, while still bounding growth to a small integer per reset-affected user.
    async fn bump_epoch_inner(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<u64, RedisStoreError> {
        let key = self.keys().key(epoch_prefix(kind), user_id);
        let mut conn = self.connection().await?;
        let (new_value, _): (u64, bool) = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(&key)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(EPOCH_TTL_SECS)
            .query_async(&mut conn)
            .await?;
        Ok(new_value)
    }
}

/// TTL applied to a token-epoch key, in seconds. Pinned to the [`TOKEN_EPOCH_RETENTION_SECS`]
/// store contract rather than a local literal: startup validation rejects a `jwt.access_expires_in`
/// longer than that bound, so a bump can never lapse while a pre-bump token is still presentable.
/// A small fixed integer key per reset-affected user is negligible.
const EPOCH_TTL_SECS: u64 = TOKEN_EPOCH_RETENTION_SECS;

/// The token-epoch key prefix for a session kind (`ep:` dashboard, `pep:` platform).
fn epoch_prefix(kind: SessionKind) -> Prefix {
    match kind {
        SessionKind::Dashboard => Prefix::Ep,
        SessionKind::Platform => Prefix::Pep,
    }
}

#[async_trait]
impl SessionStore for RedisStores {
    async fn create_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.create_session_inner(kind, token_hash, detail, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError> {
        self.rotate_inner(kind, rotation)
            .await
            .map_err(AuthError::from)
    }

    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.find_session_inner(kind, token_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn list_sessions(
        &self,
        kind: SessionKind,
        user_id: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        self.list_sessions_inner(kind, user_id)
            .await
            .map_err(AuthError::from)
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        user_id: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        let owned = self
            .revoke_session_inner(kind, user_id, session_hash)
            .await
            .map_err(AuthError::from)?;
        if owned {
            Ok(())
        } else {
            Err(AuthError::SessionNotFound)
        }
    }

    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.delete_grace_pointer_inner(kind, session_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn revoke_all(&self, kind: SessionKind, user_id: &str) -> Result<(), AuthError> {
        self.revoke_all_inner(kind, user_id)
            .await
            .map_err(AuthError::from)
    }

    async fn revoke_family(&self, kind: SessionKind, family_id: &str) -> Result<(), AuthError> {
        self.revoke_family_inner(kind, family_id)
            .await
            .map_err(AuthError::from)
    }

    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.blacklist_access_inner(jti_or_hash, remaining_ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError> {
        self.is_blacklisted_inner(jti_or_hash)
            .await
            .map_err(AuthError::from)
    }

    async fn current_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError> {
        self.current_epoch_inner(kind, user_id)
            .await
            .map_err(AuthError::from)
    }

    async fn bump_epoch(&self, kind: SessionKind, user_id: &str) -> Result<u64, AuthError> {
        self.bump_epoch_inner(kind, user_id)
            .await
            .map_err(AuthError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SessionRecord {
        SessionRecord {
            user_id: "u1".to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            device: "Chrome".to_owned(),
            ip: "203.0.113.4".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            mfa_enabled: false,
            family_id: "fam-1".to_owned(),
            family_created_at: Some(OffsetDateTime::UNIX_EPOCH),
        }
    }

    #[test]
    fn kind_prefixes_selects_the_dashboard_and_platform_quartets() {
        // The kind drives the prefix pair; both arms must map to their catalog prefixes.
        let dash = kind_prefixes(SessionKind::Dashboard);
        assert_eq!(
            (
                dash.rt.as_str(),
                dash.rp.as_str(),
                dash.sess.as_str(),
                dash.sd.as_str()
            ),
            ("rt", "rp", "sess", "sd")
        );
        let plat = kind_prefixes(SessionKind::Platform);
        assert_eq!(
            (
                plat.rt.as_str(),
                plat.rp.as_str(),
                plat.sess.as_str(),
                plat.sd.as_str()
            ),
            ("prt", "prp", "psess", "psd")
        );
    }

    #[test]
    fn interpret_rotate_covers_invalid_grace_rotated_and_malformed() {
        // `nil` is invalid; a `GRACE:`-tagged payload recovers the record; a bare payload is
        // the consumed old record; malformed JSON surfaces a decode error.
        assert!(matches!(interpret_rotate(None), Ok(RotateParsed::Invalid)));
        let json = serde_json::to_string(&record()).unwrap_or_default();
        assert!(matches!(
            interpret_rotate(Some(format!("GRACE:{json}"))),
            Ok(RotateParsed::Grace(_))
        ));
        // A `REUSED:`-tagged reply carries the compromised family id verbatim (never JSON).
        assert!(matches!(
            interpret_rotate(Some("REUSED:fam-1".to_owned())),
            Ok(RotateParsed::Reused(family)) if family == "fam-1"
        ));
        assert!(matches!(
            interpret_rotate(Some(json)),
            Ok(RotateParsed::Rotated(_))
        ));
        assert!(matches!(
            interpret_rotate(Some("not json".to_owned())),
            Err(RedisStoreError::Decode(_))
        ));
    }

    #[test]
    fn session_detail_value_round_trips_camel_case() {
        // The `sd:` value is camelCase and omits the session hash (which lives in the key).
        let value = SessionDetailValue::at_creation(&record());
        let json = serde_json::to_string(&value).unwrap_or_default();
        assert!(json.contains("\"lastActivityAt\":"));
        assert!(!json.contains("sessionHash"));
        let back: Result<SessionDetailValue, _> = serde_json::from_str(&json);
        assert!(matches!(back, Ok(v) if v.device == "Chrome"));
    }

    #[test]
    fn session_detail_value_encodes_timestamps_as_unix_millisecond_numbers() {
        // Cross-backend parity for the `sd:`/`psd:` value: nest-auth writes
        // `createdAt`/`lastActivityAt` as `Date.now()` numbers and treats any record whose
        // fields are not numbers as stale (dropping the session from its listing and SREM-ing the
        // member). The RFC 3339 string this used to emit therefore made every rust-written
        // session vanish from a nest-auth listing on a shared Redis — and made nest-written
        // details undecodable here. Pin the numeric form in both directions.
        let value = SessionDetailValue::at_creation(&SessionRecord {
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            ..record()
        });
        let json = serde_json::to_string(&value).unwrap_or_default();
        assert!(json.contains("\"createdAt\":1700000000000"));
        assert!(json.contains("\"lastActivityAt\":1700000000000"));
        assert!(!json.contains("\"createdAt\":\""));

        // A detail record written by nest-auth (numbers, millisecond precision) decodes here.
        let from_nest: Result<SessionDetailValue, _> = serde_json::from_str(
            r#"{"device":"Safari","ip":"198.51.100.9","createdAt":1700000000123,"lastActivityAt":1700000060456}"#,
        );
        assert!(matches!(
            from_nest,
            Ok(v)
                if v.device == "Safari"
                && v.created_at.unix_timestamp_nanos() / 1_000_000 == 1_700_000_000_123
                && v.last_activity_at.unix_timestamp_nanos() / 1_000_000 == 1_700_000_060_456
        ));
    }

    #[test]
    fn index_member_renders_the_full_key_suffix_for_every_keyspace() {
        // The `sess:`/`psess:` SET members are key SUFFIXES, byte-identical to nest-auth's
        // `rt:{hash}` / `prt:{hash}` / `rp:{oldHash}` / `prp:{oldHash}`. This is what makes a
        // cross-backend revoke work at all (each backend deletes `{ns}:{member}` verbatim) and
        // what makes a grace pointer distinguishable from a live session inside revoke-all.
        assert_eq!(index_member(Prefix::Rt, "deadbeef"), "rt:deadbeef");
        assert_eq!(index_member(Prefix::Prt, "deadbeef"), "prt:deadbeef");
        assert_eq!(index_member(Prefix::Rp, "deadbeef"), "rp:deadbeef");
        assert_eq!(index_member(Prefix::Prp, "deadbeef"), "prp:deadbeef");
        // A bare hash is never a valid member — the regression this format replaced.
        assert_ne!(index_member(Prefix::Rt, "deadbeef"), "deadbeef");
    }

    #[test]
    fn live_member_hash_accepts_only_the_matching_live_prefix() {
        // Listing must yield live sessions only: a `rp:`/`prp:` grace pointer shares the index
        // (so revoke-all can sweep it) but is not a session and must not surface as one. The
        // helper also strips the prefix, because the `sd:`/`psd:` detail key is keyed by the
        // BARE hash — reusing the member verbatim would look up `sd:rt:{hash}` and find nothing.
        assert_eq!(live_member_hash("rt:abc123", Prefix::Rt), Some("abc123"));
        assert_eq!(live_member_hash("prt:abc123", Prefix::Prt), Some("abc123"));
        // Grace pointers are rejected for their own keyspace's live prefix.
        assert_eq!(live_member_hash("rp:abc123", Prefix::Rt), None);
        assert_eq!(live_member_hash("prp:abc123", Prefix::Prt), None);
        // Cross-keyspace members are rejected: `prt:` must not be read as a dashboard session,
        // and `rt:` is not a prefix of `prt:` so the platform side rejects it too.
        assert_eq!(live_member_hash("prt:abc123", Prefix::Rt), None);
        assert_eq!(live_member_hash("rt:abc123", Prefix::Prt), None);
        // A legacy bare-hash member (the old format) is not a live member and is skipped.
        assert_eq!(live_member_hash("abc123", Prefix::Rt), None);
        // The separator is required — a prefix match without the colon is not a member.
        assert_eq!(live_member_hash("rtabc123", Prefix::Rt), None);
    }

    #[test]
    fn invalidate_user_sessions_script_deletes_the_member_key_directly() {
        // Static guard on the revoke-all Lua: it must delete `{namespace}:{member}` (the member
        // already names its keyspace) instead of re-prefixing a bare hash with the live prefix.
        // Re-prefixing is what made grace pointers unsweepable — a rotated-away refresh token
        // survived logout-all for its whole grace window. Also assert the detail key is still
        // rebuilt from the stripped hash, so `sd:`/`psd:` records are not orphaned.
        let source = include_str!("../lua/invalidate_user_sessions.lua");
        assert!(source.contains("redis.call('DEL', ARGV[1] .. ':' .. member)"));
        assert!(!source.contains("ARGV[1] .. ':' .. ARGV[2] .. ':' .. member"));
        assert!(source.contains("string.sub(member, #live + 1)"));
    }
}
