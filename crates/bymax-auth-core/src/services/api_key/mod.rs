//! Scoped service API keys for machine callers (layer: services).
//!
//! The runtime ties the repository port to the clock, the configured pepper and the last-used
//! recorder; the files beside this one are the verifier (decides whether a presented key is
//! valid), the issuing service (mints, revokes and rotates keys) and the access decision a
//! transport adapter calls for each guarded request.

mod access;
mod clock;
mod issuing;
mod last_used;
mod verifier;

#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod issuing_tests;
#[cfg(test)]
mod last_used_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod verifier_tests;

use std::sync::Arc;

use secrecy::SecretString;

pub use access::ApiKeyRoute;
pub use clock::{ApiKeyClock, SystemApiKeyClock};
pub use issuing::{IssueApiKeyInput, IssuedApiKey, RotateApiKeyInput};
pub use verifier::{ApiKeyRejection, ApiKeyVerdict};

use crate::config::{ApiKeyAuditMode, ApiKeysConfig};
use crate::error::ConfigError;
use crate::traits::ApiKeyRepository;
use last_used::LastUsed;

/// Everything the API-key features need, built once when `api_keys.enabled` is set.
pub(crate) struct ApiKeyRuntime {
    pub(crate) repository: Arc<dyn ApiKeyRepository>,
    clock: Arc<dyn ApiKeyClock>,
    last_used: LastUsed,
    pepper: SecretString,
    prefix: String,
    header: String,
    scopes: Vec<String>,
    audit_mode: ApiKeyAuditMode,
}

impl ApiKeyRuntime {
    /// Decide whether the engine gets a runtime, from the configuration group and what the
    /// builder was given. `None` when the group is off.
    ///
    /// The repository must be present exactly when the group is on: either mismatch leaves a
    /// deployment that believes keys authenticate while nothing can, or the reverse. A mandatory
    /// audit also needs hooks that can write it, since the default no-op hooks would admit every
    /// request without recording one.
    ///
    /// # Errors
    ///
    /// The `ConfigError` for the mismatch.
    pub(crate) fn assemble(
        config: &ApiKeysConfig,
        repository: Option<Arc<dyn ApiKeyRepository>>,
        clock: Option<Arc<dyn ApiKeyClock>>,
        hooks_supplied: bool,
    ) -> Result<Option<Self>, ConfigError> {
        match (config.enabled, repository) {
            (true, None) => Err(ConfigError::ApiKeysRepositoryRequired),
            (false, Some(_)) => Err(ConfigError::ApiKeysRepositoryUnused),
            (true, Some(_))
                if config.audit_mode == ApiKeyAuditMode::Required && !hooks_supplied =>
            {
                Err(ConfigError::ApiKeysAuditRequiresHooks)
            }
            (true, Some(repository)) => {
                let clock = clock.unwrap_or_else(|| Arc::new(SystemApiKeyClock));
                Ok(Some(Self::new(config, repository, clock)))
            }
            (false, None) => Ok(None),
        }
    }

    /// Assemble the runtime from the validated configuration group.
    fn new(
        config: &ApiKeysConfig,
        repository: Arc<dyn ApiKeyRepository>,
        clock: Arc<dyn ApiKeyClock>,
    ) -> Self {
        Self {
            repository,
            clock,
            last_used: LastUsed::default(),
            pepper: config.pepper.clone(),
            prefix: config.prefix.clone(),
            header: config.header.clone(),
            scopes: config.scopes.clone(),
            audit_mode: config.audit_mode,
        }
    }
}
