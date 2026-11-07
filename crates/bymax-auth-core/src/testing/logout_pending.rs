//! The in-memory pending-logout markers: what a failed logout attempt recorded, and the failures a
//! test can arm against reading, writing or claiming them.
//!
//! Layer: a test double of the session store, beside the other in-memory stores.

use std::collections::HashMap;
use std::sync::Mutex;

use bymax_auth_types::AuthError;

use super::{InMemoryStores, lock};
use crate::traits::{LogoutOwner, SessionKind};

/// The markers, keyed by plane and refresh-token hash, each with the TTL it was written with so a
/// test can read the rule back; and the operations to let through and then to fail, in that order.
#[derive(Debug, Default)]
pub(super) struct Double {
    entries: Mutex<HashMap<(SessionKind, String), (LogoutOwner, u64)>>,
    failures: Mutex<(usize, usize)>,
}

impl InMemoryStores {
    /// Let the next `skip` logout-pending operations (a write, a read or a claim, in the order the
    /// flow issues them) through, then fail `count` of them with a backend error.
    ///
    /// `skip` is what lets a test reach one particular operation of a logout: a retry reads the
    /// marker first and claims it last.
    pub fn fail_logout_pending_ops(&self, skip: usize, count: usize) {
        *lock(&self.logout_pending.failures) = (skip, count);
    }

    /// The owner and TTL a failed logout recorded under `session_hash`, without removing it.
    #[must_use]
    pub fn peek_logout_pending(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Option<(LogoutOwner, u64)> {
        lock(&self.logout_pending.entries)
            .get(&(kind, session_hash.to_owned()))
            .cloned()
    }

    /// Consume one armed failure, if this operation is the one to fail.
    fn take_pending_failure(&self) -> Result<(), AuthError> {
        let mut armed = lock(&self.logout_pending.failures);
        if armed.0 > 0 {
            armed.0 -= 1;
            return Ok(());
        }
        if armed.1 == 0 {
            return Ok(());
        }
        armed.1 -= 1;
        Err(AuthError::Internal(
            "logout pending store unavailable".into(),
        ))
    }

    /// Record `owner` under `session_hash`.
    pub(super) fn put_pending(
        &self,
        kind: SessionKind,
        session_hash: &str,
        owner: &LogoutOwner,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.take_pending_failure()?;
        lock(&self.logout_pending.entries)
            .insert((kind, session_hash.to_owned()), (owner.clone(), ttl_secs));
        Ok(())
    }

    /// The owner recorded under `session_hash`, leaving the marker in place.
    pub(super) fn read_pending(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<Option<LogoutOwner>, AuthError> {
        self.take_pending_failure()?;
        Ok(self
            .peek_logout_pending(kind, session_hash)
            .map(|(owner, _)| owner))
    }

    /// Remove the marker, reporting whether this call removed it.
    pub(super) fn claim_pending(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<bool, AuthError> {
        self.take_pending_failure()?;
        Ok(lock(&self.logout_pending.entries)
            .remove(&(kind, session_hash.to_owned()))
            .is_some())
    }
}
