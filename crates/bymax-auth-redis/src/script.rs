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

/// `session_revoke` — ownership-checked single revoke (section 12.5.2).
pub static SESSION_REVOKE: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/session_revoke.lua")));

/// `invalidate_user_sessions` — revoke every session for a user in one transaction.
pub static INVALIDATE_USER_SESSIONS: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/invalidate_user_sessions.lua")));

/// `brute_force_incr` — fixed-window failure counter (section 12.5.3).
pub static BRUTE_FORCE_INCR: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/brute_force_incr.lua")));

/// `otp_verify` — attempt-bounded verify + consume (section 12.5.4).
pub static OTP_VERIFY: LazyLock<LuaScript> =
    LazyLock::new(|| LuaScript::new(include_str!("lua/otp_verify.lua")));
