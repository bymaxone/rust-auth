//! The per-request account-status gate and its cache (layer: engine surface used by the
//! adapters).
//!
//! A token outlives the account state it was minted under, so every authenticated request
//! re-checks the account. Reading the repository each time costs a round trip per request, so the
//! status (and, where the deployment requires verification, the verified-address flag) is cached
//! for `user_status_cache_ttl`: a suspension therefore takes effect within that TTL unless the
//! host calls [`AuthEngine::invalidate_account_status`] where it changes the account. Mirrors
//! nest-auth's `AccountStatusService`, whose cache this shares.

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::normalize::log_safe;
use crate::services::auth::map_repository_error;
use crate::traits::UserStatusCacheStore;

/// What the gate needs to know about an account.
struct AccountFacts {
    /// The lifecycle status as stored.
    status: String,
    /// Whether the address is verified, known only when the gate asked for it.
    verified: Option<bool>,
}

impl AuthEngine {
    /// The cache the gate may use: the configured one, unless the TTL is zero (a zero TTL turns
    /// the cache off rather than writing entries that expire at once).
    fn status_cache(&self) -> Option<(&dyn UserStatusCacheStore, u64)> {
        let ttl = self.config().config().user_status_cache_ttl.as_secs();
        let cache = self.user_status_cache()?;
        (ttl > 0).then_some((cache.as_ref(), ttl))
    }

    /// Resolve the account's status (and, when `want_verified`, its verified flag), from the cache
    /// when it holds every fact asked for and from the tenant-scoped repository read otherwise.
    ///
    /// A miss on either fact is answered by one repository read that refills both, and an account
    /// that no longer exists is [`AuthError::TokenInvalid`]: the token outlived it.
    async fn account_facts(
        &self,
        sub: &str,
        tenant_id: &str,
        want_verified: bool,
    ) -> Result<AccountFacts, AuthError> {
        let cache = self.status_cache();
        let (mut status, mut verified) = (None, None);
        if let Some((cache, _)) = cache {
            status = cache.get_status(tenant_id, sub).await?;
            if want_verified {
                verified = cache.get_verified(tenant_id, sub).await?;
            }
        }
        if let (Some(status), true) = (&status, !want_verified || verified.is_some()) {
            return Ok(AccountFacts {
                status: status.clone(),
                verified,
            });
        }
        let user = self
            .user_repository()
            .find_by_id(sub, Some(tenant_id))
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::TokenInvalid)?;
        if let Some((cache, ttl)) = cache {
            cache.put_status(tenant_id, sub, &user.status, ttl).await?;
            if self.config().config().email_verification.required {
                cache
                    .put_verified(tenant_id, sub, user.email_verified, ttl)
                    .await?;
            }
        }
        Ok(AccountFacts {
            status: user.status,
            verified: Some(user.email_verified),
        })
    }

    /// The gate: refuse a blocked status, then (when `check_verified` and the deployment requires
    /// verification) an unverified address. A blocked status is refused first, so a banned
    /// account is told it is banned rather than that it must verify.
    pub(crate) async fn assert_account_usable(
        &self,
        sub: &str,
        tenant_id: &str,
        check_verified: bool,
    ) -> Result<(), AuthError> {
        let require_verified = check_verified && self.config().config().email_verification.required;
        let facts = self.account_facts(sub, tenant_id, require_verified).await?;
        self.assert_user_not_blocked(&facts.status)?;
        if require_verified && facts.verified == Some(false) {
            return Err(AuthError::EmailNotVerified);
        }
        Ok(())
    }

    /// Drop the cached status and verified flag of one account, so the next check reads the
    /// repository.
    ///
    /// Call it wherever the host changes an account's status or verified flag, or the change
    /// reaches requests only after `user_status_cache_ttl`. It narrows that window to one
    /// repository read, not to zero: a check already resolving when this runs can write the old
    /// value back. An empty id names nothing the gate could have cached and is a no-op.
    ///
    /// # Errors
    ///
    /// A store [`AuthError`] when the cache cannot be reached. Flows that call this after their
    /// own work is committed log that failure instead of surfacing it (see
    /// [`Self::drop_cached_account_facts`]).
    pub async fn invalidate_account_status(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<(), AuthError> {
        let Some((cache, _)) = self.status_cache() else {
            return Ok(());
        };
        if user_id.trim().is_empty() || tenant_id.trim().is_empty() {
            return Ok(());
        }
        cache.invalidate(tenant_id, user_id).await
    }

    /// [`Self::invalidate_account_status`] for a flow whose irreversible work is already
    /// committed: a failure is logged and swallowed, because reporting it would tell the caller
    /// that work which succeeded had failed, and where the flow spent a single-use credential
    /// there is nothing left to retry. The worst a missed invalidation costs is the staleness it
    /// exists to avoid, bounded by the TTL.
    pub(crate) async fn drop_cached_account_facts(&self, user_id: &str, tenant_id: &str) {
        if let Err(error) = self.invalidate_account_status(user_id, tenant_id).await {
            let tenant = log_safe(tenant_id);
            tracing::error!(
                tenant_id = %tenant,
                %error,
                "account status cache: invalidation failed"
            );
        }
    }
}

#[cfg(test)]
mod tests;
