//! Ending one sign-in, access tokens included (services layer).
//!
//! An access token is stateless, so deleting its session does not stop it. The paths that end one
//! session write an entry naming the session's family, which is what the token's `sid` claim
//! carries, and every check of an access token or of a WebSocket ticket refuses a session that has
//! one. The entry outlives the longest access token the session can hold, and nest-auth reads and
//! writes the same entry (`recordEncodings.sessionRevocation` in the shared contract).
//!
//! Only a family id in the form the claim is defined for is written or looked up: no token can
//! name any other.

use std::time::Duration;

use bymax_auth_types::AuthError;

use crate::traits::{LogoutOwner, SessionKind, SessionStore};

/// How long the entry outlives the access lifetime, in seconds, for the clocks of the backends
/// that share it.
const CLOCK_MARGIN_SECS: u64 = 60;

/// How long the entry is kept: the access-token lifetime rounded up to whole seconds, plus the
/// clock margin.
fn entry_ttl_secs(access_ttl: Duration) -> u64 {
    access_ttl
        .as_secs()
        .saturating_add(u64::from(access_ttl.subsec_nanos() > 0))
        .saturating_add(CLOCK_MARGIN_SECS)
}

/// Refuse, from now on, the access tokens of the session `family_id` names. A family id that is
/// not in the `sid` claim's form writes nothing.
///
/// # Errors
///
/// Returns a store [`AuthError`] when the entry cannot be written.
pub(crate) async fn end_session_access(
    store: &dyn SessionStore,
    kind: SessionKind,
    family_id: &str,
    access_ttl: Duration,
) -> Result<(), AuthError> {
    match crate::services::session_id(family_id) {
        Some(sid) => {
            store
                .revoke_session_access(kind, sid, entry_ttl_secs(access_ttl))
                .await
        }
        None => Ok(()),
    }
}

/// End the sign-in `family_id` names: remove every refresh session of the family, then refuse its
/// access tokens. The sessions go first, so none is left able to refresh into a token the entry
/// refuses; when they cannot be removed, no entry is written. A family id that is not in the `sid`
/// claim's form touches nothing.
///
/// `owner_subject_hash` names the session index the removed sessions are pruned from. The hashes
/// of the removed sessions are appended to `removed`, also when the entry write then fails.
///
/// # Errors
///
/// Returns a store [`AuthError`] when the family cannot be removed or the entry cannot be written.
pub(crate) async fn end_sign_in(
    store: &dyn SessionStore,
    kind: SessionKind,
    family_id: &str,
    owner_subject_hash: &str,
    access_ttl: Duration,
    removed: &mut Vec<String>,
) -> Result<(), AuthError> {
    let Some(sid) = crate::services::session_id(family_id) else {
        return Ok(());
    };
    let family = store
        .revoke_family(kind, sid, Some(owner_subject_hash))
        .await?;
    removed.extend(family);
    end_session_access(store, kind, sid, access_ttl).await
}

/// [`end_sign_in`] for the sign-in a logout resolved. A logout with no owner, or whose owner names
/// no family, writes nothing.
///
/// # Errors
///
/// As [`end_sign_in`].
pub(crate) async fn end_logout_access(
    store: &dyn SessionStore,
    kind: SessionKind,
    owner: Option<&LogoutOwner>,
    owner_subject_hash: &str,
    access_ttl: Duration,
) -> Result<(), AuthError> {
    match owner.and_then(|owner| owner.family_id.as_deref()) {
        Some(family) => {
            let mut removed = Vec::new();
            end_sign_in(
                store,
                kind,
                family,
                owner_subject_hash,
                access_ttl,
                &mut removed,
            )
            .await
        }
        None => Ok(()),
    }
}

/// Whether the session a `sid` claim names has been ended. An absent or non-conforming `sid`
/// names no session.
///
/// # Errors
///
/// Returns a store [`AuthError`] when the entry cannot be read: the caller refuses rather than
/// accept a token it could not check.
pub(crate) async fn is_session_ended(
    store: &dyn SessionStore,
    kind: SessionKind,
    sid: Option<&str>,
) -> Result<bool, AuthError> {
    match sid.and_then(crate::services::session_id) {
        Some(sid) => store.is_session_access_revoked(kind, sid).await,
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests;
