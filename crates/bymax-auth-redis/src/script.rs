//! The Lua-script loader and the cached, ready-to-invoke catalog of atomic scripts.
//!
//! Each multi-step state transition that could race under concurrency (section 12.5) runs
//! as a single Lua script. [`LuaScript`] wraps [`redis::Script`], which computes the script
//! SHA once at construction and invokes it via `EVALSHA`, transparently falling back to
//! `EVAL` + `SCRIPT LOAD` on a `NOSCRIPT` reply — so the system stays correct across Redis
//! restarts and failovers with no warm-up step. The scripts are compiled once into the
//! process-wide statics below and shared by every store.

use std::sync::LazyLock;

use redis::{Script, ScriptInvocation};

/// A compiled Lua script: its source plus the cached SHA managed by [`redis::Script`].
pub struct LuaScript {
    script: Script,
}

impl LuaScript {
    /// Compile `source` into a script, caching its SHA for `EVALSHA` dispatch.
    fn new(source: &str) -> Self {
        Self {
            script: Script::new(source),
        }
    }

    /// Begin an invocation. Callers attach `KEYS` via [`ScriptInvocation::key`] and `ARGV`
    /// via [`ScriptInvocation::arg`], then run it with `invoke_async`, which performs the
    /// `EVALSHA`-with-`EVAL`-fallback dispatch.
    #[must_use]
    pub fn prepare(&self) -> ScriptInvocation<'_> {
        self.script.prepare_invoke()
    }
}

/// `refresh_rotate` — atomic refresh rotation with a grace window (section 12.5.1).
pub static REFRESH_ROTATE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/refresh_rotate.lua")));

/// `recover_grace` — write a grace-recovered session atomically with the check that a
/// revoke-all has not already swept the account.
pub static RECOVER_GRACE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/recover_grace.lua")));

/// `session_revoke` — ownership-checked single revoke (section 12.5.2).
pub static SESSION_REVOKE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/session_revoke.lua")));

/// `session_prune_dead` — remove a session-index member only if the key it names is gone.
pub static SESSION_PRUNE_DEAD: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/session_prune_dead.lua")));

/// `invalidate_user_sessions` — revoke every session for a user in one transaction.
pub static INVALIDATE_USER_SESSIONS: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/invalidate_user_sessions.lua")));

/// `revoke_family` — revoke every live session in a refresh-token family on reuse detection
/// (section 12.5.2).
pub static REVOKE_FAMILY: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/revoke_family.lua")));

/// `brute_force_incr` — fixed-window failure counter (section 12.5.3).
pub static BRUTE_FORCE_INCR: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/brute_force_incr.lua")));

/// The source of [`PUBLISH_INVITATION`], byte-identical with nest-auth's
/// `PUBLISH_INVITATION_SCRIPT`.
const PUBLISH_INVITATION_SOURCE: &str = "\nif (redis.call('GET', KEYS[1]) or '') ~= ARGV[1] then\n  return 0\nend\nif ARGV[1] ~= '' then\n  redis.call('DEL', KEYS[3])\nend\nredis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[4])\nredis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[4])\nreturn 1";

/// `publish_invitation` — store an invitation, point the invitee index at it and delete the one it
/// supersedes, only while the index still names what the caller's rank check approved.
///
/// `KEYS` are the index, the new record and the superseded record (the new one again when there is
/// none); `ARGV` are the superseded hash or the empty string, the new hash, the record and the TTL.
/// Replies `1` when stored and `0` when the index differs.
pub static PUBLISH_INVITATION: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(PUBLISH_INVITATION_SOURCE));

/// The source of [`WITHDRAW_INVITATION`], byte-identical with nest-auth's
/// `WITHDRAW_INVITATION_SCRIPT`.
const WITHDRAW_INVITATION_SOURCE: &str = "\nif redis.call('GET', KEYS[1]) ~= ARGV[1] then\n  return -1\nend\nif (redis.call('GET', KEYS[2]) or '') ~= ARGV[2] then\n  return -1\nend\nlocal removed = redis.call('DEL', KEYS[2])\nredis.call('DEL', KEYS[1])\nreturn removed";

/// `withdraw_invitation` — delete an invitation's record and its index, only while both are what
/// the caller read.
///
/// `KEYS` are the index and the record; `ARGV` are the token hash and the record as read, or the
/// empty string for none. Replies a negative number when either changed, `0` when there was no
/// record and a positive number when one was removed.
pub static WITHDRAW_INVITATION: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(WITHDRAW_INVITATION_SOURCE));

/// The source of [`RELEASE_INDEX`], byte-identical with nest-auth's `RELEASE_INDEX_SCRIPT`: the two
/// libraries run it against one keyspace, so it carries no comment header and no final newline.
const RELEASE_INDEX_SOURCE: &str = "\nif redis.call('GET', KEYS[1]) == ARGV[1] then\n  return redis.call('DEL', KEYS[1])\nend\nreturn 0";

/// `release_index` — delete an invitee index only while it holds the value the caller read.
pub static RELEASE_INDEX: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(RELEASE_INDEX_SOURCE));

/// `membership_cache_fill` — write a cached workspace membership only while both version counters
/// hold the versions read, extending every counter that exists to the retention (section 12.5.6).
pub static MEMBERSHIP_CACHE_FILL: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/membership_cache_fill.lua")));

/// `membership_cache_bump` — `INCR` then `EXPIRE` to the retention of one workspace or membership
/// version counter (section 12.5.6).
pub static MEMBERSHIP_CACHE_BUMP: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/membership_cache_bump.lua")));

/// `workspace_invitation_publish` — the one atomic publication of a workspace invitation: index
/// compare-and-set, pending cap, record, index, set and the retirement of the replaced record.
pub static WORKSPACE_INVITATION_PUBLISH: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/workspace_invitation_publish.lua")));

/// `workspace_invitation_remove` — delete a record and its set member, and the index only while it
/// still names the record.
pub static WORKSPACE_INVITATION_REMOVE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/workspace_invitation_remove.lua")));

/// `otp_verify` — attempt-bounded verify + consume (section 12.5.5), as one atomic step so
/// concurrent guesses cannot pass the ceiling.
///
/// `KEYS[1]` is the `otp:` record, a HASH of `code` and `attempts`; `ARGV` is the submitted code
/// and the ceiling. The reply is `(tag, storedCode)`: `EXPIRED` for no record or no `code` field,
/// `MAX` (record consumed) at the ceiling, otherwise `PRESENT`, where a plain match consumes the
/// record and a mismatch bumps `attempts` in place, leaving the TTL. The caller repeats the
/// comparison in constant time, which is the authoritative one.
///
/// An absent `attempts` counts as 0. A present one counts only as `0` or a positive integer of at
/// most 18 characters, and anything else counts as the ceiling: a negative value buys guesses, and
/// no wrong guess is counted against a value `HINCRBY` cannot bump. `tonumber` alone is not the
/// test, since a NaN is below every ceiling.
///
/// The source is shared byte for byte with nest-auth, so it carries no comments of its own.
pub static OTP_VERIFY: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/otp_verify.lua")));

/// `mfa_challenge` — the fused TOTP anti-replay mark + temp-token consume (section 7.5.6).
#[cfg(feature = "mfa")]
pub static MFA_CHALLENGE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/mfa_challenge.lua")));

/// `release_lock` — compare-and-delete, so a lock can only be released by the call that took it.
#[cfg(feature = "mfa")]
pub static RELEASE_LOCK: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/release_lock.lua")));

#[cfg(test)]
mod tests {
    use super::{PUBLISH_INVITATION_SOURCE, WITHDRAW_INVITATION_SOURCE};
    use crate::keys::to_hex;
    use bymax_auth_crypto::mac::sha256;

    #[test]
    fn the_otp_verify_script_keeps_its_recorded_digest() {
        // The same cross-repository limit as the invitation digests below.
        assert_eq!(
            to_hex(&sha256(include_str!("lua/otp_verify.lua").as_bytes())),
            "3040819a4b8ce00a8936b5b3005f26908d6dbed4aad1b7afa37b7f222cefe480"
        );
    }

    #[test]
    fn the_invitation_scripts_keep_their_recorded_digests() {
        // Both libraries run these against one keyspace, so an edit here has to be made in
        // nest-auth too. Nothing here reads nest-auth: a change made only there passes.
        assert_eq!(
            to_hex(&sha256(PUBLISH_INVITATION_SOURCE.as_bytes())),
            "6570eda685cf80b5a6ec3947ed9958671573a4057d69250cac5a1f8292eeac62"
        );
        assert_eq!(
            to_hex(&sha256(WITHDRAW_INVITATION_SOURCE.as_bytes())),
            "79e032bef2663bdb42d93efc3ae62bcfa15a5e71459290f5e8e31a97217a43f3"
        );
    }
}
