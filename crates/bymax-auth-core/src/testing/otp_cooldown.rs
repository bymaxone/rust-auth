//! Failure injection for the in-memory resend-cooldown gate.
//!
//! Layer: a test double of the OTP store, beside the other in-memory stores.

use bymax_auth_types::AuthError;

use super::{InMemoryStores, lock};
use crate::traits::OtpPurpose;

impl InMemoryStores {
    /// Make the next `count` resend-cooldown gate calls fail with a backend error. The flows
    /// that begin a resend must answer a failure of the gate itself, which a store that always
    /// succeeds never exercises.
    pub fn fail_next_resend_gates(&self, count: usize) {
        *lock(&self.forced_resend_gate_failures) = count;
    }

    /// Make the next `count` resend-cooldown release calls fail with a backend error.
    pub fn fail_next_resend_releases(&self, count: usize) {
        *lock(&self.forced_resend_release_failures) = count;
    }

    /// Consume one armed release failure, if any.
    pub(super) fn take_resend_release_failure(&self) -> Result<(), AuthError> {
        let mut remaining = lock(&self.forced_resend_release_failures);
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(AuthError::Internal("resend cooldown unavailable".into()))
    }

    /// Whether the resend cooldown for `purpose` + `identifier` is held, without releasing it.
    #[must_use]
    pub fn resend_cooldown_held(&self, purpose: OtpPurpose, identifier: &str) -> bool {
        lock(&self.resend).contains(&(purpose, identifier.to_owned()))
    }

    /// Consume one armed gate failure, if any.
    pub(super) fn take_resend_gate_failure(&self) -> Result<(), AuthError> {
        let mut remaining = lock(&self.forced_resend_gate_failures);
        if *remaining == 0 {
            return Ok(());
        }
        *remaining -= 1;
        Err(AuthError::Internal("resend cooldown unavailable".into()))
    }
}
