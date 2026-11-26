//! Superseding a pending invitation when an address is invited again (layer: engine service).
//!
//! Superseding destroys a pending invitation, the same end state a revoke produces, so it is
//! held to the same bar: the caller must outrank the role the pending invitation grants. Being
//! authorised for the role being requested says nothing about the role of the record being
//! destroyed.

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::services::auth::invitation::{has_role, parse_record};
use crate::traits::{InvitationStore, StoredInvitation};

/// How many times the approval is re-derived when the pending record moves underneath it. The
/// contention is between legitimate inviters, so a lost race is retried rather than refused,
/// but an unbounded retry would turn a hot address into an unbounded loop.
const SUPERSEDE_ATTEMPTS: usize = 3;

impl AuthEngine {
    /// Approve the supersede and store the invitation over what was approved.
    ///
    /// The rank check and the write are separate round trips, so the write is a compare-and-swap
    /// against the hash the check approved: an outranked caller cannot pass the check while the
    /// index is empty and then displace a higher-ranked invitation created in between. It stores
    /// the record, points the index at it and deletes the superseded record in one step.
    ///
    /// # Errors
    ///
    /// [`AuthError::InsufficientRole`] when the caller is outranked by the pending invitation,
    /// or when the index kept moving for the whole retry budget (the caller has not been shown
    /// to be allowed to destroy whatever is there now); a store [`AuthError`] otherwise.
    pub(super) async fn publish_over_approved(
        &self,
        store: &Arc<dyn InvitationStore>,
        inviter_role: &str,
        invitee_hash: &str,
        token_hash: &str,
        invitation: &StoredInvitation,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        let tenant_id = &invitation.tenant_id;
        for _ in 0..SUPERSEDE_ATTEMPTS {
            let approved = self
                .approve_supersede(store, inviter_role, tenant_id, invitee_hash)
                .await?;
            if store
                .publish_invitation(
                    tenant_id,
                    invitee_hash,
                    token_hash,
                    invitation,
                    ttl_secs,
                    approved.as_deref(),
                )
                .await?
            {
                return Ok(());
            }
        }
        tracing::warn!(
            event = "RUST_AUTH_INVITATION_SUPERSEDE_CONTENDED",
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
        let raw = store.read_invitation_record(&pending_hash).await?;
        if let Some(pending) = raw.as_deref().and_then(parse_record)
            && !has_role(
                inviter_role,
                &pending.role,
                &self.config().config().roles.hierarchy,
            )
        {
            tracing::warn!(
                event = "RUST_AUTH_INVITATION_SUPERSEDE_OUTRANKED",
                "invitation: refused, outranked by the pending invitation"
            );
            return Err(AuthError::InsufficientRole);
        }
        Ok(Some(pending_hash))
    }
}
