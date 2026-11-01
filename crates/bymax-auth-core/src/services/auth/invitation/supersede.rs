//! Superseding a pending invitation when an address is invited again (layer: engine service).
//!
//! Superseding destroys a pending invitation, the same end state a revoke produces, so it is
//! held to the same bar: the caller must outrank the role the pending invitation grants.
//! Without that, the only authorisation was the role being REQUESTED, which says nothing about
//! the role of the record being destroyed.

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::normalize::log_safe;
use crate::services::auth::invitation::has_role;
use crate::traits::InvitationStore;

/// How many times the approval is re-derived when the pending record moves underneath it. The
/// contention is between legitimate inviters, so a lost race is retried rather than refused,
/// but an unbounded retry would turn a hot address into an unbounded loop.
const SUPERSEDE_ATTEMPTS: usize = 3;

impl AuthEngine {
    /// Claim the invitee index for a new invitation and return the token hash it displaced, or
    /// `None` when nothing was pending.
    ///
    /// The index is claimed first and atomically, because it is the serialization point: the
    /// record is keyed by a token nobody on the issuing side has seen, and the index is the only
    /// handle they have. The claim is a compare-and-swap against the hash the rank check
    /// approved, so an outranked caller cannot pass the check while the index is momentarily
    /// empty and then displace a higher-ranked invitation created in between.
    ///
    /// # Errors
    ///
    /// [`AuthError::InsufficientRole`] when the caller is outranked by the pending invitation,
    /// or when the index kept moving for the whole retry budget (the caller has not been shown
    /// to be allowed to destroy whatever is there now); a store [`AuthError`] otherwise.
    pub(super) async fn claim_invitation_slot(
        &self,
        store: &Arc<dyn InvitationStore>,
        inviter_role: &str,
        tenant_id: &str,
        invitee_hash: &str,
        token_hash: &str,
        ttl_secs: u64,
    ) -> Result<Option<String>, AuthError> {
        for _ in 0..SUPERSEDE_ATTEMPTS {
            let approved = self
                .approve_supersede(store, inviter_role, tenant_id, invitee_hash)
                .await?;
            if store
                .claim_invitation_index(
                    tenant_id,
                    invitee_hash,
                    token_hash,
                    ttl_secs,
                    approved.as_deref(),
                )
                .await?
            {
                return Ok(approved);
            }
        }
        tracing::warn!(
            tenant_id = %log_safe(tenant_id),
            "invitation: refused, the pending invitation kept changing under the rank check"
        );
        Err(AuthError::InsufficientRole)
    }

    /// The token hash currently pending for the address, after checking the caller may destroy
    /// it. An unparseable record is superseded without a check, exactly as a revoke treats it:
    /// it can no longer be accepted either, and leaving it behind would be worse.
    async fn approve_supersede(
        &self,
        store: &Arc<dyn InvitationStore>,
        inviter_role: &str,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<Option<String>, AuthError> {
        let Some(pending_hash) = store.read_invitation_index(tenant_id, invitee_hash).await? else {
            return Ok(None);
        };
        if let Some(pending) = store.read_invitation_by_hash(&pending_hash).await?
            && !has_role(
                inviter_role,
                &pending.role,
                &self.config().config().roles.hierarchy,
            )
        {
            tracing::warn!(
                tenant_id = %log_safe(tenant_id),
                "invitation: refused, outranked by the pending invitation"
            );
            return Err(AuthError::InsufficientRole);
        }
        Ok(Some(pending_hash))
    }
}
