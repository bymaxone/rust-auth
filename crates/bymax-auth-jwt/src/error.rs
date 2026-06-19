//! The crate's error type.
//!
//! Every fallible operation reports failure through [`JwtError`]. The variants name
//! only the *category* of failure (malformed framing, unsupported algorithm, bad
//! signature, expiry, claims decode) and never the internal step, so an error value can
//! never become an oracle. At the HTTP boundary the engine collapses all of them into
//! the public `auth.token_invalid` (with `Expired` mapping through the internal-only
//! `token_expired` first), so a client cannot distinguish "expired" from "forged" from
//! "garbage".

/// Opaque JWT failure.
///
/// Marked `#[non_exhaustive]` so new categories can be added without a breaking change;
/// downstream `match`es must carry a wildcard arm. `PartialEq`/`Eq` make the category
/// directly assertable (the variants carry no data, so equality is just the category).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// The token is not three base64url segments, or a segment is not valid base64url.
    #[error("malformed token")]
    Malformed,
    /// The header's `alg` is not `HS256` (covers `none`, `RS256`, `ES256`, and every
    /// other algorithm — all rejected before any signature math).
    #[error("unsupported algorithm")]
    UnsupportedAlg,
    /// The HMAC tag did not match (wrong key, tampered header/payload, or forged tag).
    #[error("bad signature")]
    BadSignature,
    /// `exp` is in the past beyond the configured leeway. The engine maps this through
    /// the internal-only `token_expired` to the public `token_invalid`. (An `iat` in the
    /// future is reported as [`JwtError::Malformed`] instead, since it maps directly to
    /// `token_invalid` with no internal-expired step.)
    #[error("token expired")]
    Expired,
    /// The payload did not deserialize into the requested claims type.
    #[error("claims decode failed")]
    Decode,
}
