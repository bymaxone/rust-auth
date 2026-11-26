//! Withdrawing the pending invitation of an address (layer: service).

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::services::auth::invitation::{has_role, parse_record};
use crate::traits::{InvitationStore, InvitationWithdrawal};

/// How many times a revoke reads the address again after it changed under the withdrawal.
const REVOKE_ATTEMPTS: usize = 3;

impl AuthEngine {
    /// Remove the invitation the invitee index names, when `revoker_role` may withdraw it;
    /// `true` when this call removed a record.
    ///
    /// The record and the index go in one step, and only while both are still what was read and
    /// judged here. Anything written to the address in between is read and judged again.
    ///
    /// # Errors
    ///
    /// [`AuthError::TooManyRequests`] when the invitation changed under every attempt; a store
    /// [`AuthError`] otherwise.
    pub(super) async fn withdraw_pending(
        &self,
        store: &Arc<dyn InvitationStore>,
        revoker_role: &str,
        tenant_id: &str,
        invitee_hash: &str,
    ) -> Result<bool, AuthError> {
        for _ in 0..REVOKE_ATTEMPTS {
            let Some(hash) = store.read_invitation_index(tenant_id, invitee_hash).await? else {
                return Ok(false);
            };
            let raw = store.read_invitation_record(&hash).await?;
            if raw
                .as_deref()
                .and_then(parse_record)
                .is_some_and(|record| self.outranks_revoker(revoker_role, &record.role))
            {
                return Ok(false);
            }
            match store
                .withdraw_invitation(tenant_id, invitee_hash, &hash, raw.as_deref())
                .await?
            {
                InvitationWithdrawal::Changed => {}
                InvitationWithdrawal::Absent => return Ok(false),
                InvitationWithdrawal::Removed => {
                    tracing::info!(
                        event = "RUST_AUTH_INVITATION_WITHDRAWN",
                        "invitation: withdrawn"
                    );
                    return Ok(true);
                }
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
