//! The per-route request counter behind the adapter's rate limit (layer: store seam).
//!
//! A fixed window that starts at the first request and never slides, held in the shared store so
//! the limit holds across instances: an in-process counter gives every replica its own budget,
//! which multiplies the limit by the replica count.

use async_trait::async_trait;
use bymax_auth_types::AuthError;

/// A shared fixed-window request counter.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Count one request against `bucket_hash` on `route` and return the new count.
    ///
    /// The window length is applied when the counter is created (the first request) and is never
    /// extended by later ones, so the window starts at the first request and does not slide under
    /// a steady trickle. `bucket_hash` is the keyed hash of the client's address bucket, never
    /// the address itself.
    async fn hit(&self, route: &str, bucket_hash: &str, window_secs: u64)
    -> Result<i64, AuthError>;
}
