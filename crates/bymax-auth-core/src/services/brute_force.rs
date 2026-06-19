//! The engine's brute-force service: a fixed-window failed-attempt counter keyed on an
//! HMAC of the low-entropy identifier, with a guard that rejects any identifier that could
//! corrupt the namespaced store key (§7.7).
//!
//! The window does **not** extend on subsequent failures (the store sets the TTL once, on
//! the first failure), and the counter is reset on every successful authentication. No raw
//! email or PII is ever passed to the store — the caller builds the identifier
//! (`hmac_sha256("{tenant}:{email}")`, hex) with the engine's derived key (§7.7), and this
//! service consumes that already-hashed value.

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::traits::BruteForceStore;

/// Maximum accepted identifier length, in bytes (§7.7). A longer value is rejected before
/// any store call.
const MAX_IDENTIFIER_LENGTH: usize = 512;

/// Throttles credential endpoints with a hashed-identifier fixed-window lockout.
pub struct BruteForceService {
    store: Arc<dyn BruteForceStore>,
    max_attempts: u32,
    window_secs: u64,
}

impl BruteForceService {
    /// Assemble the service from the store and the configured lockout policy.
    pub(crate) fn new(
        store: Arc<dyn BruteForceStore>,
        max_attempts: u32,
        window_secs: u64,
    ) -> Self {
        Self {
            store,
            max_attempts,
            window_secs,
        }
    }

    /// Reject an identifier that could corrupt the namespaced store key — one containing
    /// `:`, `\n`, or `\r`, or exceeding `MAX_IDENTIFIER_LENGTH` bytes — with
    /// [`AuthError::Forbidden`]. The rejection is logged without the identifier value.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] for any identifier that fails the contract.
    pub fn validate_identifier(&self, identifier: &str) -> Result<(), AuthError> {
        if identifier.len() > MAX_IDENTIFIER_LENGTH || identifier.contains([':', '\n', '\r']) {
            tracing::error!("brute-force identifier rejected by the key-injection guard");
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }

    /// Whether the identifier has reached the lockout threshold within its window.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] for an invalid identifier, or a store [`AuthError`].
    pub async fn is_locked(&self, identifier: &str) -> Result<bool, AuthError> {
        self.validate_identifier(identifier)?;
        self.store.is_locked(identifier, self.max_attempts).await
    }

    /// Record one failed attempt, starting the fixed window on the first failure.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] for an invalid identifier, or a store [`AuthError`].
    pub async fn record_failure(&self, identifier: &str) -> Result<(), AuthError> {
        self.validate_identifier(identifier)?;
        self.store
            .record_failure(identifier, self.window_secs)
            .await?;
        Ok(())
    }

    /// Reset the counter after a successful authentication.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] for an invalid identifier, or a store [`AuthError`].
    pub async fn reset(&self, identifier: &str) -> Result<(), AuthError> {
        self.validate_identifier(identifier)?;
        self.store.reset(identifier).await
    }

    /// Seconds remaining on this identifier's fixed window, for a `Retry-After` after a
    /// confirmed lockout.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] for an invalid identifier, or a store [`AuthError`].
    pub async fn remaining_lockout_secs(&self, identifier: &str) -> Result<u64, AuthError> {
        self.validate_identifier(identifier)?;
        self.store.remaining_lockout_secs(identifier).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::InMemoryStores;

    fn service(store: Arc<InMemoryStores>, max_attempts: u32) -> BruteForceService {
        BruteForceService::new(store, max_attempts, 900)
    }

    /// A representative hashed identifier (64 lower-case hex chars), the form the engine
    /// builds from `hmac_sha256("{tenant}:{email}")`.
    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validate_identifier_accepts_a_hashed_id_and_rejects_key_injecting_inputs() {
        // A hashed identifier passes; each character that would corrupt the namespaced key,
        // and an over-length value, is rejected with Forbidden (no internal detail leaks).
        let svc = service(Arc::new(InMemoryStores::new()), 5);
        assert!(svc.validate_identifier(ID).is_ok());
        for bad in ["has:colon", "has\nnewline", "has\rcarriage"] {
            assert!(matches!(
                svc.validate_identifier(bad),
                Err(AuthError::Forbidden)
            ));
        }
        let too_long = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        assert!(matches!(
            svc.validate_identifier(&too_long),
            Err(AuthError::Forbidden)
        ));
        // The boundary length is accepted.
        assert!(
            svc.validate_identifier(&"a".repeat(MAX_IDENTIFIER_LENGTH))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn lockout_triggers_at_max_attempts_holds_the_window_and_resets() {
        // Failures accumulate to the threshold (lockout), the window does not extend, the
        // remaining-seconds reflect the fixed window, and a reset clears the counter.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store, 3);
        assert!(matches!(svc.is_locked(ID).await, Ok(false)));
        assert!(matches!(svc.remaining_lockout_secs(ID).await, Ok(0)));
        for _ in 0..3 {
            assert!(svc.record_failure(ID).await.is_ok());
        }
        assert!(matches!(svc.is_locked(ID).await, Ok(true)));
        assert!(matches!(svc.remaining_lockout_secs(ID).await, Ok(900)));
        assert!(svc.reset(ID).await.is_ok());
        assert!(matches!(svc.is_locked(ID).await, Ok(false)));
    }

    #[tokio::test]
    async fn every_entry_point_enforces_the_identifier_guard() {
        // The guard runs before any store call on each method, so an injecting identifier is
        // Forbidden across is_locked / record_failure / reset / remaining_lockout_secs.
        let svc = service(Arc::new(InMemoryStores::new()), 5);
        let bad = "tenant:email";
        assert!(matches!(
            svc.is_locked(bad).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            svc.record_failure(bad).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(svc.reset(bad).await, Err(AuthError::Forbidden)));
        assert!(matches!(
            svc.remaining_lockout_secs(bad).await,
            Err(AuthError::Forbidden)
        ));
    }
}
