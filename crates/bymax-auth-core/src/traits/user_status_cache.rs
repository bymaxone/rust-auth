//! The cache of an account's lifecycle status behind the per-request status gate (layer: store
//! seam).
//!
//! Re-reading the account on every authenticated request costs a repository round trip per
//! request. The cache holds two facts per account for a short TTL, the status string and (only
//! where verification is required) whether the address is verified, so a suspension takes effect
//! within that TTL rather than instantly. The entries are shared with nest-auth, which reads the
//! same keyspace, under the key the shared wire contract pins (`userStatusCache`).

use async_trait::async_trait;
use bymax_auth_types::AuthError;

/// A shared, TTL-bounded cache of one account's status and verified-address flag.
///
/// Every method takes the account's **subject hash**, `hmac_sha256(hmacKey, userSubject)` in
/// lower-case hex, which the engine derives from the tenant and the user id together (see
/// `AuthEngine::session_subject`). A repository id is unique only within a tenant, so a key on
/// the id alone would let one tenant's cached status answer for another's account; the store
/// never sees a raw id and never holds the hashing key.
///
/// # Errors
///
/// Returns [`AuthError`] on a store failure.
#[async_trait]
pub trait UserStatusCacheStore: Send + Sync {
    /// The cached status string, if any.
    async fn get_status(&self, subject_hash: &str) -> Result<Option<String>, AuthError>;

    /// The cached verified-address flag, if any. Any stored value other than `"0"` reads as
    /// verified, as nest-auth reads it: only an explicit `"0"` refuses.
    async fn get_verified(&self, subject_hash: &str) -> Result<Option<bool>, AuthError>;

    /// Cache `status` for `ttl_secs`.
    async fn put_status(
        &self,
        subject_hash: &str,
        status: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Cache the verified-address flag for `ttl_secs`.
    async fn put_verified(
        &self,
        subject_hash: &str,
        verified: bool,
        ttl_secs: u64,
    ) -> Result<(), AuthError>;

    /// Drop both facts. The verified flag is deleted **first**: if the second delete fails, the
    /// entry left behind should be the one whose staleness merely costs a repository read, since
    /// a stale `0` locks a just-verified account out of every protected route until it expires.
    async fn invalidate(&self, subject_hash: &str) -> Result<(), AuthError>;
}
