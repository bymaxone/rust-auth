//! The owner marker a failed logout leaves for the retry that completes it (services layer).
//!
//! A logout attempt that fails a revocation write still deletes the refresh session, so the retry
//! that completes the logout finds no record to say whose logout it was, and the `afterLogout`
//! hook would be lost. Only a failing attempt that read its owner from the live session writes a
//! marker; a retry that finds the session gone reads the owner from it, and the atomic removal of
//! the marker is the claim that makes exactly one retry announce. The same helpers serve both
//! planes; the store keys the marker by plane.
//!
//! The guarantee, as the shared contract states it:
//!
//! > exactly-once for sequential retries; at-least-once when attempts of one logout run concurrently
//!
//! Attempts that all read the live session each announce on completing, and a failed attempt
//! slower than a successful one can write its marker after that one cleared it, leaving a marker
//! a later retry claims.

use bymax_auth_types::AuthError;

use crate::traits::{LogoutOwner, SessionKind, SessionStore};

/// The shortest time a marker is kept, in seconds, whatever the access-token lifetime.
const MIN_MARKER_TTL_SECS: u64 = 300;

/// Who a logout belongs to, and where that was read from.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResolvedOwner {
    /// The account, or `None` when the session was already gone and no marker named one.
    pub(crate) owner: Option<LogoutOwner>,
    /// Whether the owner came from a marker rather than from the live session.
    from_marker: bool,
}

impl ResolvedOwner {
    /// An owner read from the live session (or none at all).
    pub(crate) fn live(owner: Option<LogoutOwner>) -> Self {
        Self {
            owner,
            from_marker: false,
        }
    }
}

/// How long a marker is kept: the access-token lifetime rounded up to whole seconds, and never
/// less than 300.
pub(crate) fn marker_ttl_secs(access_ttl: std::time::Duration) -> u64 {
    let rounded = access_ttl.as_secs() + u64::from(access_ttl.subsec_nanos() > 0);
    rounded.max(MIN_MARKER_TTL_SECS)
}

/// The owner of this logout: the live session's when there is one, otherwise the one a failed
/// earlier attempt recorded under `session_hash`.
///
/// # Errors
///
/// A marker that cannot be read ends the logout before any write, as a session lookup that
/// cannot be read does: the owner is unknown, and completing without it would lose the
/// announcement for good.
pub(crate) async fn resolve_owner(
    store: &dyn SessionStore,
    kind: SessionKind,
    session_hash: Option<&str>,
    live: Option<LogoutOwner>,
) -> Result<ResolvedOwner, AuthError> {
    let Some(hash) = session_hash.filter(|_| live.is_none()) else {
        return Ok(ResolvedOwner::live(live));
    };
    let marker = store
        .read_logout_pending(kind, hash)
        .await
        .map_err(|error| {
            let cause = crate::services::error_chain(&error);
            tracing::warn!(%cause, "logout: pending owner lookup failed");
            crate::services::internal_error("a logout could not read its pending owner")
        })?;
    Ok(ResolvedOwner {
        from_marker: marker.is_some(),
        owner: marker,
    })
}

/// Leave the marker a retry will read, after an attempt that failed a revocation write.
///
/// Written only when the owner came from the live session: a retry that read only the marker
/// does not write one. Best effort, and before the caller raises the logout's own failure.
pub(crate) async fn remember_failed_attempt(
    store: &dyn SessionStore,
    kind: SessionKind,
    session_hash: Option<&str>,
    resolved: &ResolvedOwner,
    ttl_secs: u64,
) {
    let (Some(hash), Some(owner), false) = (session_hash, &resolved.owner, resolved.from_marker)
    else {
        return;
    };
    if let Err(error) = store.put_logout_pending(kind, hash, owner, ttl_secs).await {
        let cause = crate::services::error_chain(&error);
        tracing::warn!(%cause, "logout: the pending owner could not be recorded");
    }
}

/// Settle a logout that completed with no failure, returning whether to announce it.
///
/// An owner read from a marker is announced only if THIS call removed the marker, so racing
/// retries announce once. An owner read from the live session is announced regardless, and any
/// stale marker is removed.
///
/// # Errors
///
/// A claim that cannot be made answers an error, so the client retries: announcing without
/// the claim could announce twice.
pub(crate) async fn settle_completed(
    store: &dyn SessionStore,
    kind: SessionKind,
    session_hash: Option<&str>,
    resolved: &ResolvedOwner,
) -> Result<bool, AuthError> {
    let announce = resolved.owner.is_some();
    let Some(hash) = session_hash.filter(|_| announce) else {
        return Ok(announce);
    };
    if resolved.from_marker {
        return store
            .claim_logout_pending(kind, hash)
            .await
            .map_err(|error| {
                let cause = crate::services::error_chain(&error);
                tracing::warn!(%cause, "logout: the pending owner could not be claimed");
                crate::services::internal_error("a logout could not claim its pending owner")
            });
    }
    if let Err(error) = store.claim_logout_pending(kind, hash).await {
        let cause = crate::services::error_chain(&error);
        tracing::warn!(%cause, "logout: a stale pending owner could not be removed");
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
