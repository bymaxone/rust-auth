//! Withdrawing the pending invitation of an address (layer: service).

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::services::auth::invitation::has_role;
use crate::traits::InvitationStore;

/// How many times a revoke reads the address again after a later invite claimed its index.
const REVOKE_ATTEMPTS: usize = 3;

impl AuthEngine {
    /// Remove the invitation the invitee index names, when `revoker_role` may withdraw it;
    /// `true` when this call removed a record.
    ///
    /// A record that is there is deleted before its index is released, so a failed release
    /// leaves an index a retry can still act on. An index that names no record is released
    /// first, so that an invite about to write it cannot confirm. A release that finds the index
    /// claimed by a later invite reads the address again and judges what replaced the
    /// invitation.
    ///
    /// # Errors
    ///
    /// [`AuthError::TooManyRequests`] when the invitation was replaced under every attempt; a
    /// store [`AuthError`] otherwise.
    pub(super) async fn withdraw_pending(
        &self,
        store: &Arc<dyn InvitationStore>,
        revoker_role: &str,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<bool, AuthError> {
        let mut withdrew = false;
        for _ in 0..REVOKE_ATTEMPTS {
            let Some(hash) = store.read_invitation_index(tenant_id, invitee_hash).await? else {
                return Ok(withdrew);
            };
            let record = store.read_invitation_by_hash(&hash).await?;
            if record
                .as_ref()
                .is_some_and(|record| self.outranks_revoker(revoker_role, &record.role))
            {
                return Ok(withdrew);
            }
            let absent = record.is_none();
            if absent
                && !store
                    .release_invitation_index(tenant_id, invitee_hash, &hash)
                    .await?
            {
                continue;
            }
            if store.delete_invitation_by_hash(&hash).await? {
                withdrew = true;
                tracing::info!(
                    event = "RUST_AUTH_INVITATION_WITHDRAWN",
                    "invitation: withdrawn"
                );
            }
            if absent
                || store
                    .release_invitation_index(tenant_id, invitee_hash, &hash)
                    .await?
            {
                return Ok(withdrew);
            }
        }
        Err(AuthError::TooManyRequests {
            retry_after_seconds: None,
        })
    }

    /// Whether `granted` is a role `revoker_role` may not withdraw, logged when it is.
    ///
    /// The role comes from the record: the caller names an address, not a role. A record that no
    /// longer parses reads as absent and is withdrawn without a check, since it can no longer be
    /// accepted either.
    ///
    /// The caller answers an outranked revoker exactly as one asking about an address with nothing
    /// pending. A refusal would say that there is a pending invitation for the address at a role
    /// above the caller's, which hashing the address into the index exists to prevent; it is
    /// logged instead, where an operator can see it and the prober cannot.
    fn outranks_revoker(&self, revoker_role: &str, granted: &str) -> bool {
        let outranked = !has_role(
            revoker_role,
            granted,
            &self.config().config().roles.hierarchy,
        );
        if outranked {
            tracing::warn!(
                event = "RUST_AUTH_INVITATION_REVOKE_OUTRANKED",
                "invitation: revoke refused — outranked by the invitation"
            );
        }
        outranked
    }
}
