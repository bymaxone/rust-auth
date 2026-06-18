//! The crate-wide error type.
//!
//! Every fallible primitive in this crate reports failure through [`CryptoError`].
//! Its variants are deliberately **opaque**: they name the *category* of failure
//! (hash, verify, decrypt, …) but never the internal step that failed, so an error
//! value can never become an oracle that distinguishes, say, a malformed ciphertext
//! from a wrong key.

/// Opaque cryptographic error.
///
/// Variants describe only the broad operation that failed and never reveal which
/// internal check tripped — collapsing every failure of an operation to one variant
/// keeps the error from leaking information to an attacker (e.g. tamper-vs-wrong-key
/// on decryption, or invalid-hash-vs-wrong-password on verification).
///
/// Marked `#[non_exhaustive]` so new categories can be added without a breaking
/// change; downstream `match`es must carry a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A hashing operation failed.
    #[error("hash operation failed")]
    Hash,
    /// Verification failed because of a malformed input or an internal error.
    ///
    /// A *wrong password* is **not** this variant — verification returns
    /// `Ok(false)` for that case so the error path stays free of credential signal.
    #[error("verification failed")]
    Verify,
    /// Authenticated decryption failed (wrong key, tampered ciphertext, or bad wire format).
    #[error("decryption failed")]
    Decrypt,
    /// A parameter was outside the accepted range (e.g. a below-floor KDF cost).
    #[error("invalid parameters")]
    InvalidParams,
    /// An encoding or parsing step failed (e.g. malformed Base32 / Base64).
    #[error("encoding error")]
    Encoding,
}
