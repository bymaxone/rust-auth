//! A read-only view of the dashboard login lockout, for a host that shows or acts on it.
//!
//! Layer: engine facade over the brute-force service. Deliberately offers no write: a way to
//! raise or clear the counter from outside the login flow is a way to bypass it, and clearing is
//! already the host's explicit decision in [`AuthEngine::unlock_account`].

use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::normalize::normalize_email;

/// Whether a dashboard login is currently refused for one address, and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginLockout {
    /// `true` while the fixed failure window has reached the configured cap.
    pub locked: bool,
    /// Seconds until the window ends and logins are tried again, `0` when not locked.
    pub retry_after_secs: u64,
}

impl AuthEngine {
    /// Read the lockout state `login` would apply to this address in this tenant.
    ///
    /// Read from the same counter, under the same identifier, as `login` and
    /// [`AuthEngine::unlock_account`]: the address is normalized exactly as they normalize it.
    /// The state depends on the failures recorded for the address, never on whether an account
    /// exists, so an unknown address answers as a known one does.
    ///
    /// The caller decides who may ask. The state is not a secret to the account owner, but
    /// serving it to an unauthenticated caller tells them whether an attack on the address is
    /// under way, so the adapter ships no route for it.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] if the counter cannot be read.
    pub async fn login_lockout(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<LoginLockout, AuthError> {
        let identifier = self.lockout_identifier(tenant_id, &normalize_email(email));
        if !self.brute_force().is_locked(&identifier).await? {
            return Ok(LoginLockout {
                locked: false,
                retry_after_secs: 0,
            });
        }
        let retry_after_secs = self
            .brute_force()
            .remaining_lockout_secs(&identifier)
            .await?;
        Ok(LoginLockout {
            locked: true,
            retry_after_secs,
        })
    }
}
