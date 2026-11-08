//! Minting, revoking and rotating service API keys.
//!
//! The plaintext key exists only in the value [`issue`](ApiKeyRuntime::issue) returns: the
//! repository receives the id and the HMAC digest of the secret, never the secret.

use std::fmt;

use bymax_auth_crypto::api_key;
use bymax_auth_types::{AuthError, FieldError};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};

use super::ApiKeyRuntime;
use crate::RepositoryError;
use crate::engine::AuthEngine;
use crate::services::new_uuid_v4;
use crate::traits::{ApiKey, ApiKeySummary, NewApiKey};

/// The longest a key label may be, in characters.
const MAX_LABEL_CHARS: usize = 128;

/// The longest overlap a rotation may leave the old key valid for: thirty days, in seconds.
pub const MAX_OVERLAP_SECONDS: u64 = 2_592_000;

/// What to mint a key with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IssueApiKeyInput {
    /// The machine caller's name. Not unique: several active keys may share one label.
    pub label: String,
    /// The scopes the key holds, each from the configured vocabulary, none repeated.
    pub scopes: Vec<String>,
    /// When the key stops verifying; must be in the future. `None` for a key that does not expire.
    pub expires_at: Option<OffsetDateTime>,
}

impl IssueApiKeyInput {
    /// An input with no expiry.
    #[must_use]
    pub fn new(label: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            label: label.into(),
            scopes,
            expires_at: None,
        }
    }
}

/// How to rotate a key.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct RotateApiKeyInput {
    /// How long the old key keeps verifying after the new one exists, `0` to `2 592 000` seconds.
    /// `0` retires it at once.
    pub overlap_seconds: u64,
    /// When the NEW key stops verifying; must be in the future. `None` for no expiry.
    pub expires_at: Option<OffsetDateTime>,
}

impl RotateApiKeyInput {
    /// A rotation with the given overlap and a new key that does not expire.
    #[must_use]
    pub fn new(overlap_seconds: u64) -> Self {
        Self {
            overlap_seconds,
            expires_at: None,
        }
    }
}

/// A freshly minted key. This is the only place the plaintext ever appears.
#[non_exhaustive]
pub struct IssuedApiKey {
    /// The plaintext key to hand to the machine caller. Shown once; it cannot be recovered.
    pub key: String,
    /// The stored row without its digest.
    pub record: ApiKeySummary,
}

impl fmt::Debug for IssuedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedApiKey")
            .field("key", &"<redacted>")
            .field("record", &self.record)
            .finish()
    }
}

impl ApiKeyRuntime {
    /// Mint a key.
    ///
    /// # Errors
    ///
    /// [`AuthError::Validation`] naming the offending field, or [`AuthError::Internal`] when the
    /// repository fails.
    pub(crate) async fn issue(&self, input: IssueApiKeyInput) -> Result<IssuedApiKey, AuthError> {
        let now = self.clock.now();
        let label = validated_label(&input.label)?;
        let scopes = self.validated_scopes(&input.scopes)?;
        let expires_at = validated_expiry(input.expires_at, now)?;

        let id = new_uuid_v4();
        let secret = api_key::generate_secret();
        let stored = self
            .repository
            .create(NewApiKey {
                id: id.clone(),
                label,
                digest: api_key::digest(&secret, self.pepper.expose_secret()),
                scopes,
                created_at: now,
                expires_at,
            })
            .await
            .map_err(internal)?;
        Ok(IssuedApiKey {
            key: api_key::format(&self.prefix, &id, &secret),
            record: stored.into(),
        })
    }

    /// Revoke a key.
    ///
    /// # Errors
    ///
    /// [`AuthError::ApiKeyNotFound`] when `id` names no key, [`AuthError::Internal`] when the
    /// repository fails.
    pub(crate) async fn revoke(&self, id: &str) -> Result<(), AuthError> {
        if !is_uuid(id)
            || !self
                .repository
                .mark_revoked(id, self.clock.now())
                .await
                .map_err(internal)?
        {
            return Err(AuthError::ApiKeyNotFound);
        }
        Ok(())
    }

    /// Replace a key with a new one that keeps its label and scopes, retiring the old one after
    /// the overlap.
    ///
    /// The new key is minted through [`issue`](Self::issue), so it is held to the CURRENT scope
    /// vocabulary: a key holding a scope that has since left the vocabulary cannot be rotated
    /// until the scope is back or the key is replaced by hand.
    ///
    /// # Errors
    ///
    /// [`AuthError::Validation`] for a bad overlap, expiry or inherited scope,
    /// [`AuthError::ApiKeyNotFound`] when `id` names no active key, [`AuthError::Internal`] when
    /// the repository fails.
    pub(crate) async fn rotate(
        &self,
        id: &str,
        input: RotateApiKeyInput,
    ) -> Result<IssuedApiKey, AuthError> {
        let now = self.clock.now();
        if input.overlap_seconds > MAX_OVERLAP_SECONDS {
            return Err(validation(
                "overlapSeconds",
                "overlapSeconds must be an integer from 0 to 2592000",
            ));
        }
        let new_expiry = validated_expiry(input.expires_at, now)?;

        let old = match is_uuid(id) {
            true => self.repository.find_by_id(id).await.map_err(internal)?,
            false => None,
        };
        let old = old
            .filter(|key| is_active(key, now))
            .ok_or(AuthError::ApiKeyNotFound)?;

        let issued = self
            .issue(IssueApiKeyInput {
                label: old.label.clone(),
                scopes: old.scopes.clone(),
                expires_at: new_expiry,
            })
            .await?;

        if input.overlap_seconds == 0 {
            self.repository
                .mark_revoked(&old.id, now)
                .await
                .map_err(internal)?;
        } else {
            let retire_at =
                now + Duration::seconds(i64::try_from(input.overlap_seconds).unwrap_or(i64::MAX));
            let sooner = old.expires_at.map_or(retire_at, |own| own.min(retire_at));
            self.repository
                .set_expiry(&old.id, sooner)
                .await
                .map_err(internal)?;
        }
        Ok(issued)
    }

    /// Write the coalesced last-used instants to the repository.
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] when the repository fails; the entries stay queued for the next call.
    pub(crate) async fn flush_last_used(&self) -> Result<(), AuthError> {
        self.last_used
            .flush(self.repository.as_ref())
            .await
            .map_err(internal)
    }

    /// The scopes, each from the vocabulary, none repeated, at least one.
    fn validated_scopes(&self, scopes: &[String]) -> Result<Vec<String>, AuthError> {
        if scopes.is_empty() {
            return Err(validation("scopes", "scopes must be a non-empty list"));
        }
        for (index, scope) in scopes.iter().enumerate() {
            if !self.scopes.contains(scope) {
                return Err(validation(
                    "scopes",
                    "every scope must come from the configured vocabulary",
                ));
            }
            if scopes[..index].contains(scope) {
                return Err(validation("scopes", "scopes must not repeat"));
            }
        }
        Ok(scopes.to_vec())
    }
}

/// A label: 1 to 128 characters, not blank, no control or invisible separator characters.
fn validated_label(label: &str) -> Result<String, AuthError> {
    if label.trim().is_empty()
        || label.chars().count() > MAX_LABEL_CHARS
        || label.chars().any(is_invisible)
    {
        return Err(validation(
            "label",
            "label must be 1 to 128 characters with no control characters",
        ));
    }
    Ok(label.to_owned())
}

/// Control characters, the line and paragraph separators and the common zero-width format
/// characters: everything that could make a label read as something else in a log or a console.
fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'
        )
}

/// An expiry, when given, must lie strictly in the future.
fn validated_expiry(
    expiry: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, AuthError> {
    match expiry {
        Some(at) if at <= now => Err(validation(
            "expiresAt",
            "expiresAt must be a valid date in the future",
        )),
        other => Ok(other),
    }
}

/// Neither revoked nor past its expiry.
fn is_active(key: &ApiKey, now: OffsetDateTime) -> bool {
    key.revoked_at.is_none() && key.expires_at.is_none_or(|expiry| expiry > now)
}

/// A lowercase canonical UUID, the only shape a key id can have.
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// A validation error naming one field.
fn validation(field: &str, message: &str) -> AuthError {
    AuthError::Validation {
        details: vec![FieldError {
            field: field.to_owned(),
            message: message.to_owned(),
        }],
    }
}

/// A repository failure as the opaque internal error, the cause kept for the log.
fn internal(error: RepositoryError) -> AuthError {
    AuthError::Internal(Box::new(error))
}

impl AuthEngine {
    /// Mint a service API key.
    ///
    /// # Errors
    ///
    /// [`AuthError::Validation`] naming the offending field; [`AuthError::Internal`] when the
    /// repository fails or API keys are not enabled.
    pub async fn issue_api_key(&self, input: IssueApiKeyInput) -> Result<IssuedApiKey, AuthError> {
        self.enabled_api_keys()?.issue(input).await
    }

    /// Revoke a service API key.
    ///
    /// # Errors
    ///
    /// [`AuthError::ApiKeyNotFound`] when `id` names no key; [`AuthError::Internal`] when the
    /// repository fails or API keys are not enabled.
    pub async fn revoke_api_key(&self, id: &str) -> Result<(), AuthError> {
        self.enabled_api_keys()?.revoke(id).await
    }

    /// Replace a key with a new one that keeps its label and scopes, retiring the old one after
    /// the overlap. See `ApiKeyRuntime::rotate` for the scope-vocabulary caveat.
    ///
    /// # Errors
    ///
    /// [`AuthError::Validation`], [`AuthError::ApiKeyNotFound`] when `id` names no active key,
    /// or [`AuthError::Internal`] when the repository fails or API keys are not enabled.
    pub async fn rotate_api_key(
        &self,
        id: &str,
        input: RotateApiKeyInput,
    ) -> Result<IssuedApiKey, AuthError> {
        self.enabled_api_keys()?.rotate(id, input).await
    }

    /// Write the coalesced last-used instants to the repository. The host calls this on its own
    /// schedule (every `api_keys.last_used_flush`) and once at shutdown; the core runs no timer.
    ///
    /// # Errors
    ///
    /// [`AuthError::Internal`] when the repository fails (the entries stay queued for the next
    /// call) or API keys are not enabled.
    pub async fn flush_api_key_last_used(&self) -> Result<(), AuthError> {
        self.enabled_api_keys()?.flush_last_used().await
    }

    /// The runtime, or the error every API-key entry point answers when the group is off.
    pub(super) fn enabled_api_keys(&self) -> Result<&ApiKeyRuntime, AuthError> {
        self.api_keys()
            .ok_or_else(|| AuthError::Internal("api keys are not enabled".into()))
    }
}
