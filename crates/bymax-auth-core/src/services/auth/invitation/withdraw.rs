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
    /// The index is released only while it still names the invitation that was judged. When a
    /// later invite has claimed it meanwhile, the address is read again and what replaced it is
    /// judged anew. The record goes first, so a failed release leaves an index a retry can still
    /// act on.
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
            if self.outranked_by(store, revoker_role, &hash).await? {
                return Ok(withdrew);
            }
            let removed = store.delete_invitation_by_hash(&hash).await?;
            let released = store
                .release_invitation_index(tenant_id, invitee_hash, &hash)
                .await?;
            // An invite in flight can write its record after a delete that found nothing and
            // confirm it before the release. No invite can confirm once the index is released,
            // so deleting again leaves nothing redeemable that no index names.
            let swept = released && !removed && store.delete_invitation_by_hash(&hash).await?;
            if removed || swept {
                withdrew = true;
                tracing::info!(
                    event = "RUST_AUTH_INVITATION_WITHDRAWN",
                    "invitation: withdrawn"
                );
            }
            if released {
                return Ok(withdrew);
            }
        }
        Err(AuthError::TooManyRequests {
            retry_after_seconds: None,
        })
    }

    /// Whether the record under `hash` grants a role `revoker_role` may not withdraw.
    ///
    /// The role comes from the record: the caller names an address, not a role. A record that no
    /// longer parses reads as absent and is withdrawn without a check, since it can no longer be
    /// accepted either.
    ///
    /// The caller answers an outranked revoker exactly as one asking about an address with nothing
    /// pending. A refusal would say that there is a pending invitation for the address at a role
    /// above the caller's, which hashing the address into the index exists to prevent; it is
    /// logged instead, where an operator can see it and the prober cannot.
    async fn outranked_by(
        &self,
        store: &Arc<dyn InvitationStore>,
        revoker_role: &str,
        hash: &str,
    ) -> Result<bool, AuthError> {
        let outranked = store
            .read_invitation_by_hash(hash)
            .await?
            .is_some_and(|invitation| {
                !has_role(
                    revoker_role,
                    &invitation.role,
                    &self.config().config().roles.hierarchy,
                )
            });
        if outranked {
            tracing::warn!(
                event = "RUST_AUTH_INVITATION_REVOKE_OUTRANKED",
                "invitation: revoke refused — outranked by the invitation"
            );
        }
        Ok(outranked)
    }
}
