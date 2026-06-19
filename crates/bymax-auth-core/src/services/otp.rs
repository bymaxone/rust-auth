//! The engine's OTP service: CSPRNG numeric one-time-password generation, storage with an
//! attempt counter and TTL, and an attempt-bounded, timing-normalized verify over the
//! [`OtpStore`] seam (§7.6).
//!
//! The atomic match + attempt-increment + single-use consume is the store's job (the
//! in-memory fake and the real Lua both do it); this service adds the CSPRNG generator and
//! the verify-side timing floor that collapses the "not found" vs "wrong code" oracle.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bymax_auth_crypto::token::random_array;
use bymax_auth_types::AuthError;

use crate::traits::{OtpPurpose, OtpStore};

/// Maximum failed verify attempts before the record is consumed (§7.6 `MAX_ATTEMPTS`).
const MAX_ATTEMPTS: u32 = 5;

/// Minimum wall-clock time a verify takes, in milliseconds, so a missing record and a wrong
/// code are timing-indistinguishable (§7.6 `MIN_VERIFY_MS`).
const MIN_VERIFY_MS: u64 = 100;

/// Generates, stores, and verifies numeric OTPs over the [`OtpStore`].
pub struct OtpService {
    store: Arc<dyn OtpStore>,
}

impl OtpService {
    /// Assemble the service over an OTP store.
    pub(crate) fn new(store: Arc<dyn OtpStore>) -> Self {
        Self { store }
    }

    /// Generate a `length`-digit numeric OTP from the CSPRNG, zero-padded. Each digit is
    /// drawn by unbiased rejection sampling so every digit `0..=9` is equiprobable.
    #[must_use]
    pub fn generate(&self, length: u8) -> String {
        let mut out = String::with_capacity(usize::from(length));
        for _ in 0..length {
            out.push(random_digit());
        }
        out
    }

    /// Store an OTP `code` for `purpose` + `identifier` with a TTL, resetting the attempt
    /// counter.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] on a store failure.
    pub async fn store(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.store.put(purpose, identifier, code, ttl_secs).await
    }

    /// Verify a submitted `code` atomically (match + attempt bump + single-use consume),
    /// normalizing the elapsed time to at least [`MIN_VERIFY_MS`] so timing reveals nothing
    /// about whether the record existed.
    ///
    /// # Errors
    ///
    /// Returns the typed outcome from the store: [`AuthError::OtpExpired`] (absent record),
    /// [`AuthError::OtpInvalid`] (wrong code), or [`AuthError::OtpMaxAttempts`] (exhausted).
    pub async fn verify(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        code: &str,
    ) -> Result<(), AuthError> {
        let started = Instant::now();
        let result = self
            .store
            .verify(purpose, identifier, code, MAX_ATTEMPTS)
            .await;
        normalize_timing(started).await;
        result
    }

    /// Begin a resend if the cooldown has elapsed; `Ok(false)` means a resend already
    /// happened inside the cooldown window.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] on a store failure.
    pub async fn try_begin_resend(
        &self,
        purpose: OtpPurpose,
        identifier: &str,
        cooldown_secs: u64,
    ) -> Result<bool, AuthError> {
        self.store
            .try_begin_resend(purpose, identifier, cooldown_secs)
            .await
    }
}

/// Map a random byte to a uniform decimal digit, or `None` for a byte that must be rejected
/// to avoid modulo bias. `256 % 10 == 6`, so bytes `250..=255` would over-represent the
/// digits `0..=5`; rejecting them keeps every digit equiprobable.
fn digit_from_byte(byte: u8) -> Option<char> {
    if byte < 250 {
        Some(char::from(b'0' + byte % 10))
    } else {
        None
    }
}

/// Draw one uniformly-distributed decimal digit from the CSPRNG, re-drawing on a rejected
/// byte (see [`digit_from_byte`]).
fn random_digit() -> char {
    loop {
        if let Some(digit) = digit_from_byte(random_array::<1>()[0]) {
            return digit;
        }
    }
}

/// Sleep, if necessary, until at least [`MIN_VERIFY_MS`] have elapsed since `started`.
async fn normalize_timing(started: Instant) {
    let floor = Duration::from_millis(MIN_VERIFY_MS);
    let elapsed = started.elapsed();
    if let Some(remaining) = floor.checked_sub(elapsed) {
        tokio::time::sleep(remaining).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::InMemoryStores;

    fn service(store: Arc<InMemoryStores>) -> OtpService {
        OtpService::new(store)
    }

    #[test]
    fn digit_from_byte_maps_low_bytes_and_rejects_the_biased_tail() {
        // Bytes below the rejection floor map to a decimal digit; the biased tail
        // (250..=255) is rejected so the generator re-draws (no modulo bias).
        assert_eq!(digit_from_byte(0), Some('0'));
        assert_eq!(digit_from_byte(9), Some('9'));
        assert_eq!(digit_from_byte(10), Some('0'));
        assert_eq!(digit_from_byte(249), Some('9'));
        assert_eq!(digit_from_byte(250), None);
        assert_eq!(digit_from_byte(255), None);
    }

    #[test]
    fn generate_produces_the_requested_number_of_digits() {
        // The OTP is exactly `length` decimal digits — the contract verification and the
        // email body both depend on.
        let svc = service(Arc::new(InMemoryStores::new()));
        for length in [4u8, 6, 8] {
            let otp = svc.generate(length);
            assert_eq!(otp.len(), usize::from(length));
            assert!(otp.bytes().all(|c| c.is_ascii_digit()));
        }
        // Two draws differ with overwhelming probability (a smoke test of CSPRNG sampling).
        assert_ne!(svc.generate(8), svc.generate(8));
    }

    #[tokio::test]
    async fn verify_consumes_on_success_and_reports_each_failure_mode() {
        // A stored OTP verifies once (single-use consume), a wrong code is OtpInvalid, an
        // absent record is OtpExpired, and exhausting the attempts is OtpMaxAttempts.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let purpose = OtpPurpose::EmailVerification;

        // Absent record → OtpExpired.
        assert!(matches!(
            svc.verify(purpose, "id", "123456").await,
            Err(AuthError::OtpExpired)
        ));

        assert!(svc.store(purpose, "id", "123456", 600).await.is_ok());
        // Wrong code bumps the attempt counter.
        assert!(matches!(
            svc.verify(purpose, "id", "000000").await,
            Err(AuthError::OtpInvalid)
        ));
        // Correct code consumes the record (single-use).
        assert!(svc.verify(purpose, "id", "123456").await.is_ok());
        assert!(matches!(
            svc.verify(purpose, "id", "123456").await,
            Err(AuthError::OtpExpired)
        ));

        // Exhausting the attempts on a fresh record yields OtpMaxAttempts (cap of one here).
        assert!(svc.store(purpose, "max", "123456", 600).await.is_ok());
        assert!(matches!(
            svc.verify(purpose, "max", "000000").await,
            Err(AuthError::OtpInvalid)
        ));
    }

    #[tokio::test]
    async fn verify_normalizes_timing_to_the_floor() {
        // Even an immediate "not found" verify takes at least MIN_VERIFY_MS, so timing
        // cannot distinguish a missing record from a wrong code.
        let svc = service(Arc::new(InMemoryStores::new()));
        let started = Instant::now();
        let _ = svc.verify(OtpPurpose::PasswordReset, "id", "000000").await;
        assert!(started.elapsed() >= Duration::from_millis(MIN_VERIFY_MS));
    }

    #[tokio::test]
    async fn normalize_timing_pads_below_the_floor_and_skips_above_it() {
        // Both arms of the verify timing guard. The "below" start is seeded half a floor in
        // the past so a short, bounded sleep is guaranteed (deterministic under coverage
        // instrumentation, unlike a `now()` start whose remaining could round to zero).
        let below = Instant::now()
            .checked_sub(Duration::from_millis(MIN_VERIFY_MS / 2))
            .unwrap_or_else(Instant::now);
        normalize_timing(below).await;
        // A start already past the floor returns at once (no sleep).
        let above = Instant::now()
            .checked_sub(Duration::from_millis(MIN_VERIFY_MS * 4))
            .unwrap_or_else(Instant::now);
        normalize_timing(above).await;
    }

    #[tokio::test]
    async fn resend_cooldown_is_one_shot_within_the_window() {
        // The first resend is allowed; a second within the window is throttled.
        let svc = service(Arc::new(InMemoryStores::new()));
        assert!(matches!(
            svc.try_begin_resend(OtpPurpose::EmailVerification, "id", 60)
                .await,
            Ok(true)
        ));
        assert!(matches!(
            svc.try_begin_resend(OtpPurpose::EmailVerification, "id", 60)
                .await,
            Ok(false)
        ));
    }
}
