//! Removing the invitation an address holds: the loop both planes' revocations share, judging
//! what is there afresh on every attempt (layer: service).

use bymax_auth_types::AuthError;

use super::too_many_requests;
use crate::traits::{InvitationPlace, Removal, WorkspaceInvitationStore};
use crate::workspace::invitation::InvitationRecord;

/// How many times a revoke reads the address again after a replacement landed under it.
const REVOKE_ATTEMPTS: usize = 3;

/// Removes the address's invitation when `may_withdraw` accepts what is there, and answers the
/// role it offered; `None` when nothing was removed.
///
/// # Errors
///
/// [`AuthError::TooManyRequests`] when the address kept changing under every attempt, and
/// [`AuthError::Internal`] for a store failure.
pub(super) async fn withdraw(
    store: &dyn WorkspaceInvitationStore,
    place: &InvitationPlace,
    may_withdraw: impl Fn(&InvitationRecord) -> bool + Send,
) -> Result<Option<String>, AuthError> {
    for _ in 0..REVOKE_ATTEMPTS {
        let Some(indexed) = store.read_index(place).await? else {
            return Ok(None);
        };
        let Some(record) = indexed.record else {
            // A store reads the index and then the record, and a resend between the two retires
            // the record it was about to read. An index that moved is read again.
            let replaced = !indexed.unreadable
                && store
                    .read_index(place)
                    .await?
                    .is_some_and(|now| now.record_key != indexed.record_key);
            if replaced {
                continue;
            }
            return Ok(None);
        };
        if !may_withdraw(&record) {
            return Ok(None);
        }
        if store
            .remove(place, &indexed.record_key, Removal::Owned)
            .await?
        {
            return Ok(Some(record.base().role.clone()));
        }
        // The index no longer names the record that was read: a replacement landed between the
        // read and the removal. Read again, so the replacement is judged anew.
    }
    Err(too_many_requests())
}
