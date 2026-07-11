//! [`SessionStore`] over Redis: refresh-session lifecycle, atomic rotation with a grace
//! window, ownership-checked revocation, the revoke-all transaction, and the access-JWT
//! (`jti`) blacklist — all keyed by [`SessionKind`] (section 12).

use async_trait::async_trait;
use bymax_auth_core::traits::{
    RotateOutcome, SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore,
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
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDetailValue {
    /// Human-readable device/browser string.
    device: String,
    /// Originating IP.
    ip: String,
    /// Session creation time.
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Last observed activity time.
    #[serde(with = "time::serde::rfc3339")]
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
    /// Persist a freshly-issued refresh session: the record under `rt:`, the hash in the
    /// user's `sess:` SET, and the detail under `sd:`, each with the refresh TTL.
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
            .arg(token_hash)
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
            RotateParsed::Grace(record) => Ok(RotateOutcome::Grace(record)),
            RotateParsed::Reused(family) => Ok(RotateOutcome::Reused(family)),
            RotateParsed::Rotated(old_record) => {
                self.move_session_member(&mut conn, &prefixes, rotation, &old_record.user_id)
                    .await?;
                Ok(RotateOutcome::Rotated(old_record))
            }
        }
    }

    /// Run the `revoke_family` transaction, deleting every live member's `rt:`/`sd:` key, pruning
    /// each from its owner's `sess:` SET, and dropping the family index — the reuse-detection
    /// lockout of a stolen token's whole lineage.
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
        script::REVOKE_FAMILY
            .prepare()
            .key(&fam_key)
            .arg(keys.namespace())
            .arg(prefixes.rt.as_str())
            .arg(prefixes.sd.as_str())
            .arg(prefixes.sess.as_str())
            .invoke_async::<i64>(&mut conn)
            .await?;
        Ok(())
    }

    /// Move the session-index membership and detail from the old hash to the new hash after a
    /// live rotation — the non-atomic bookkeeping the rotation script leaves to the caller.
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
        let detail_json =
            serde_json::to_string(&SessionDetailValue::at_creation(&rotation.new_record))?;
        let ttl_window = i64::try_from(rotation.refresh_ttl).unwrap_or(i64::MAX);
        redis::pipe()
            .cmd("SREM")
            .arg(&sess_key)
            .arg(&rotation.old_hash)
            .ignore()
            .cmd("DEL")
            .arg(&sd_old)
            .ignore()
            .cmd("SADD")
            .arg(&sess_key)
            .arg(&rotation.new_hash)
            .ignore()
            .cmd("SET")
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
        for member in members {
            let sd_key = keys.key(prefixes.sd, &member);
            let raw: Option<String> = conn.get(&sd_key).await?;
            if let Some(json) = raw {
                let value: SessionDetailValue = serde_json::from_str(&json)?;
                details.push(SessionDetail {
                    session_hash: member,
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
        let mut conn = self.connection().await?;
        let owned: bool = script::SESSION_REVOKE
            .prepare()
            .key(&sess_key)
            .key(&rt_key)
            .key(&sd_key)
            .arg(session_hash)
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

    /// Run the `invalidate_user_sessions` transaction, deleting every member's `rt:`/`sd:`
    /// key and the `sess:` SET in one atomic step.
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
            family_id: "fam-1".to_owned(),
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
}
