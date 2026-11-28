//! The counters that bound `access.denied`, shared with nest-auth (layer: store seam).
//!
//! The keys are pinned by `workspaceRealtime.rules.accessDeniedEvents` in the shared wire
//! contract: `wad:{digest}` counts the denials of one account in a fixed window and
//! `wads:{digest}` those the window did not report. A deployment that runs both libraries counts
//! one budget per account.

use async_trait::async_trait;
use bymax_auth_types::AuthError;

/// The counters of one account, named by the digest of its dashboard subject.
///
/// Each increment sets the expiry on the increment that creates the counter, in ONE atomic step: a
/// counter left without an expiry would silence its account for good.
///
/// # Errors
///
/// Every method returns [`AuthError`] on a store failure; the caller then emits nothing.
#[async_trait]
pub trait AccessDeniedStore: Send + Sync {
    /// Increments `wad:{digest}`, which expires `window_seconds` after it is created, and returns
    /// the new count.
    async fn count_denial(&self, digest: &str, window_seconds: u64) -> Result<u64, AuthError>;

    /// Increments `wads:{digest}`, which expires `ttl_seconds` after it is created.
    async fn count_suppressed(&self, digest: &str, ttl_seconds: u64) -> Result<(), AuthError>;

    /// Reads and deletes `wads:{digest}` in one atomic step; `None` when it does not exist.
    async fn take_suppressed(&self, digest: &str) -> Result<Option<String>, AuthError>;
}
