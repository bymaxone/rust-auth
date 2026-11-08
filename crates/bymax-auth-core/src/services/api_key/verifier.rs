//! The verification of a presented API key.
//!
//! Every outcome takes the same steps: a value that does not parse is replaced by a well-formed
//! dummy key id and secret, the repository is read once, the digest is computed and two 32-byte
//! buffers are compared in constant time (against a fixed dummy digest when there is no row).
//! Only then is the verdict decided, so no refusal is faster or cheaper than another.

use bymax_auth_crypto::api_key;
use secrecy::ExposeSecret;

use super::ApiKeyRuntime;
use crate::RepositoryError;
use crate::traits::ApiKey;

/// Why a presented key was refused. One answer reaches the caller whichever it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyRejection {
    /// No key was presented.
    Missing,
    /// A value was presented that does not parse as a key.
    Malformed,
    /// The key id names no row.
    Unknown,
    /// The row exists and the secret does not match.
    WrongSecret,
    /// The key was revoked.
    Revoked,
    /// The key is at or past its expiry.
    Expired,
}

/// The result of verifying one presented key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKeyVerdict {
    /// The key is valid. Carries the stored row.
    Accepted(ApiKey),
    /// The key is refused. `key` is the row the key id named, when the value parsed and a row
    /// exists, so an audit can say whose key it was.
    Rejected {
        /// Why.
        reason: ApiKeyRejection,
        /// The identified row, if any.
        key: Option<ApiKey>,
    },
}

impl ApiKeyRuntime {
    /// Verify the value of the configured header (`None` when it was absent).
    ///
    /// # Errors
    ///
    /// Returns the repository's error when the row cannot be read.
    pub(crate) async fn verify(
        &self,
        header: Option<&str>,
    ) -> Result<ApiKeyVerdict, RepositoryError> {
        let parsed = header.and_then(|value| api_key::parse(value, &self.prefix));
        let (key_id, secret) = parsed
            .as_ref()
            .map_or((api_key::DUMMY_KEY_ID, api_key::DUMMY_SECRET), |p| {
                (p.key_id, p.secret)
            });

        let row = self.repository.find_by_id(key_id).await?;

        let computed = api_key::digest(secret, self.pepper.expose_secret());
        let stored = row
            .as_ref()
            .map_or(api_key::DUMMY_DIGEST, |r| r.digest.as_str());
        let equal = api_key::digests_match(&computed, stored);

        let now = self.clock.now();
        let rejected = |reason, key| Ok(ApiKeyVerdict::Rejected { reason, key });
        match (parsed.is_some(), row) {
            (false, _) if header.is_none() => rejected(ApiKeyRejection::Missing, None),
            (false, _) => rejected(ApiKeyRejection::Malformed, None),
            (true, None) => rejected(ApiKeyRejection::Unknown, None),
            (true, Some(row)) if !equal => rejected(ApiKeyRejection::WrongSecret, Some(row)),
            (true, Some(row)) if row.revoked_at.is_some() => {
                rejected(ApiKeyRejection::Revoked, Some(row))
            }
            (true, Some(row)) if row.expires_at.is_some_and(|expiry| expiry <= now) => {
                rejected(ApiKeyRejection::Expired, Some(row))
            }
            (true, Some(row)) => {
                self.last_used.record(&row.id, now);
                Ok(ApiKeyVerdict::Accepted(row))
            }
        }
    }
}
