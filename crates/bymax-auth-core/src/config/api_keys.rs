//! Configuration of scoped service API keys and its startup validation (layer: configuration).
//!
//! The pepper is the HMAC-SHA-256 key of the key digests, so changing it makes every issued key
//! unverifiable: it means re-issuing all of them. The pepper is therefore held to
//! the bar of the signing secret and must not be shared with another key the deployment holds,
//! since a key reused across purposes is one leak away from all of them.

use std::time::Duration;

use secrecy::SecretString;

use super::AuthConfig;
use crate::error::ConfigError;

/// What a failing audit hook does to the request it audits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiKeyAuditMode {
    /// A failing audit hook never changes an answer; the failure is only logged.
    #[default]
    BestEffort,
    /// A failing audit hook refuses a request that would have been admitted. For hosts whose
    /// audit row is a record they must have.
    Required,
}

/// Scoped service API keys for machine callers. Opt-in.
///
/// Enabling it also requires the `api-keys` feature and an
/// [`ApiKeyRepository`](crate::traits::ApiKeyRepository) on the builder, and supplying a
/// repository without enabling it is refused too, so a half-configured feature fails at startup
/// instead of silently authenticating nothing.
///
/// `#[non_exhaustive]`: build it from [`ApiKeysConfig::default`] and set the fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ApiKeysConfig {
    /// Enables the feature. Default: `false`.
    pub enabled: bool,
    /// The HMAC key every digest is computed under. Held to the same strength bar as
    /// `jwt.secret`, and refused when it equals `jwt.secret`, a retired JWT secret,
    /// `identifier_key` or an MFA encryption key. Keep it in a secrets manager, apart from the
    /// database that stores the digests.
    pub pepper: SecretString,
    /// The closed vocabulary of scopes: 1 to 64 characters of letters, digits and `: . _ -`,
    /// starting with a letter or digit. A key may hold only scopes from it.
    pub scopes: Vec<String>,
    /// The header the key is read from, lowercase. Never the query string. Default `x-api-key`.
    pub header: String,
    /// The prefix of every issued key: 2 to 16 lowercase letters and digits starting with a
    /// letter, no underscore (the underscore separates the parts of a key). A literal prefix lets
    /// secret scanners find leaked keys. Default `bak`.
    pub prefix: String,
    /// How often last-used timestamps are flushed to the store in one batch, a whole number of
    /// seconds from 1 to 3600. Default 60s.
    pub last_used_flush: Duration,
    /// What a failing audit hook does to the request it audits. Default best-effort.
    pub audit_mode: ApiKeyAuditMode,
}

impl Default for ApiKeysConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // Placeholders: validation requires a real pepper and vocabulary before `enabled` can
            // be true, so these values are never used to hash or admit anything.
            pepper: SecretString::from(String::new()),
            scopes: Vec::new(),
            header: "x-api-key".to_owned(),
            prefix: bymax_auth_crypto::api_key::DEFAULT_PREFIX.to_owned(),
            last_used_flush: Duration::from_secs(60),
            audit_mode: ApiKeyAuditMode::default(),
        }
    }
}

/// Validate the `api_keys` group. Nothing is checked while the feature is off.
pub(super) fn validate_api_keys(config: &AuthConfig) -> Result<(), ConfigError> {
    let group = &config.api_keys;
    if !group.enabled {
        return Ok(());
    }
    // Without the feature nothing could verify a key, so enabling the group is refused outright.
    #[cfg(not(feature = "api-keys"))]
    return Err(ConfigError::ApiKeysFeatureDisabled);
    #[cfg(feature = "api-keys")]
    rules::validate_enabled(config)
}

#[cfg(feature = "api-keys")]
mod rules {
    use std::collections::HashSet;

    use secrecy::ExposeSecret;

    use super::{AuthConfig, ConfigError};
    use crate::config::validate::{MIN_SECRET_ENTROPY, MIN_SECRET_LEN, shannon_entropy};

    /// Headers a key may not be read from, so it never travels through a path built for something
    /// else.
    const RESERVED_HEADERS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "user-agent",
        "origin",
        "sec-fetch-site",
        "content-encoding",
        "content-length",
        "transfer-encoding",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "x-original-forwarded-for",
        "host",
    ];

    /// The longest a scope name may be.
    const MAX_SCOPE_LEN: usize = 64;

    /// The range `last_used_flush` must fall in, in seconds.
    const FLUSH_RANGE_SECS: std::ops::RangeInclusive<u64> = 1..=3600;

    /// The rules that apply once the group is on and the feature is compiled in.
    pub(super) fn validate_enabled(config: &AuthConfig) -> Result<(), ConfigError> {
        let group = &config.api_keys;
        validate_pepper(config)?;
        validate_scopes(&group.scopes)?;
        validate_transport(&group.header, &group.prefix)?;
        if !FLUSH_RANGE_SECS.contains(&group.last_used_flush.as_secs())
            || group.last_used_flush.subsec_nanos() != 0
        {
            return Err(ConfigError::ApiKeysFlushInterval {
                millis: group.last_used_flush.as_millis(),
            });
        }
        Ok(())
    }

    /// The pepper clears the signing secret's bar and equals no other key the deployment holds.
    fn validate_pepper(config: &AuthConfig) -> Result<(), ConfigError> {
        let pepper = config.api_keys.pepper.expose_secret();
        let len = pepper.chars().count();
        if len < MIN_SECRET_LEN {
            return Err(ConfigError::ApiKeysPepperTooShort { len });
        }
        let entropy = shannon_entropy(pepper);
        if entropy < MIN_SECRET_ENTROPY {
            return Err(ConfigError::ApiKeysPepperLowEntropy { entropy });
        }
        let mut others: Vec<(&'static str, &str)> =
            vec![("jwt.secret", config.jwt.secret.expose_secret())];
        others.extend(
            config
                .jwt
                .previous_secrets
                .iter()
                .map(|s| ("a retired jwt secret", s.expose_secret())),
        );
        if let Some(key) = &config.identifier_key {
            others.push(("identifier_key", key.expose_secret()));
        }
        if let Some(mfa) = &config.mfa {
            others.push(("an MFA encryption key", mfa.encryption_key.expose_secret()));
            others.extend(
                mfa.previous_encryption_keys
                    .iter()
                    .map(|k| ("an MFA encryption key", k.expose_secret())),
            );
        }
        match others.into_iter().find(|(_, value)| *value == pepper) {
            Some((reused, _)) => Err(ConfigError::ApiKeysPepperReused { reused }),
            None => Ok(()),
        }
    }

    /// The scope vocabulary is non-empty, well-formed and free of repeats.
    fn validate_scopes(scopes: &[String]) -> Result<(), ConfigError> {
        if scopes.is_empty() {
            return Err(ConfigError::ApiKeysScopes {
                index: None,
                reason: "must be a non-empty list: it is the closed vocabulary every issued key is checked against",
            });
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for (index, scope) in scopes.iter().enumerate() {
            if !is_scope_name(scope) {
                return Err(ConfigError::ApiKeysScopes {
                    index: Some(index),
                    reason: "must be 1 to 64 characters of letters, digits and ':', '.', '_', '-', starting with a letter or digit",
                });
            }
            if !seen.insert(scope.as_str()) {
                return Err(ConfigError::ApiKeysScopes {
                    index: Some(index),
                    reason: "repeats an earlier scope",
                });
            }
        }
        Ok(())
    }

    /// Whether `scope` is a well-formed scope name.
    fn is_scope_name(scope: &str) -> bool {
        let mut chars = scope.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && scope.len() <= MAX_SCOPE_LEN
            && scope
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
    }

    /// The header and prefix are ones the key grammar and the transport can carry.
    fn validate_transport(header: &str, prefix: &str) -> Result<(), ConfigError> {
        let header_ok = !header.is_empty()
            && header.len() <= 64
            && header
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !header.starts_with('-')
            && !RESERVED_HEADERS.contains(&header);
        if !header_ok {
            return Err(ConfigError::ApiKeysTransport {
                field: "header",
                reason: "must be a lowercase header name other than one the library reads or derives a field from (authorization, cookie, user-agent, origin, the forwarded-address headers and the like)",
            });
        }
        let prefix_ok = (2..=16).contains(&prefix.len())
            && prefix.starts_with(|c: char| c.is_ascii_lowercase())
            && prefix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        if !prefix_ok {
            return Err(ConfigError::ApiKeysTransport {
                field: "prefix",
                reason: "must be 2 to 16 lowercase letters and digits starting with a letter; an underscore is not allowed, it separates the parts of a key",
            });
        }
        Ok(())
    }
}
