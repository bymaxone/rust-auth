//! The API-key repository and `api_keys.enabled` must agree at build time, and the engine hands
//! the repository back only when the group is on.

use std::sync::Arc;

use secrecy::SecretString;

use crate::config::Environment;
use crate::engine::{AuthEngine, AuthEngineBuilder};
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;
use crate::testing::{InMemoryApiKeyRepository, InMemoryStores, InMemoryUserRepository};

fn builder(enabled: bool) -> AuthEngineBuilder {
    let mut cfg = base_config();
    if enabled {
        cfg.api_keys.enabled = true;
        cfg.api_keys.pepper =
            SecretString::from("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned());
        cfg.api_keys.scopes = vec!["reports:read".to_owned()];
    }
    AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
}

#[test]
fn enabled_with_a_repository_builds_and_exposes_it() {
    let built = builder(true)
        .api_key_repository(Arc::new(InMemoryApiKeyRepository::new()))
        .build();

    assert!(built.is_ok_and(|engine| engine.api_key_repository().is_some()));
}

#[test]
fn enabled_without_a_repository_is_refused() {
    assert!(matches!(
        builder(true).build(),
        Err(ConfigError::ApiKeysRepositoryRequired)
    ));
}

#[test]
fn a_repository_without_the_group_enabled_is_refused() {
    let built = builder(false)
        .api_key_repository(Arc::new(InMemoryApiKeyRepository::new()))
        .build();

    assert!(matches!(built, Err(ConfigError::ApiKeysRepositoryUnused)));
}

#[test]
fn disabled_without_a_repository_builds_with_no_repository() {
    let built = builder(false).build();

    assert!(built.is_ok_and(|engine| engine.api_key_repository().is_none()));
}
