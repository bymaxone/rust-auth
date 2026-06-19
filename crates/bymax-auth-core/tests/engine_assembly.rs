//! End-to-end assembly tests for the engine builder, driven through the public API with
//! the in-memory trait doubles. Compiled only under the `testing` feature, which exposes
//! those doubles.
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::Arc;

use bymax_auth_core::testing::{
    InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository,
};
use bymax_auth_core::traits::{PlatformUserRepository, UserRepository};
use bymax_auth_core::{AuthConfig, AuthEngine, ConfigError, Environment};
use secrecy::SecretString;

/// A configuration that passes validation: a strong secret and a non-empty, referentially
/// consistent role hierarchy.
fn base_config() -> AuthConfig {
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
        ("MEMBER".to_owned(), Vec::new()),
    ]);
    config
}

/// A full, valid wiring assembles an engine whose resolved config reflects the inputs.
#[test]
fn assembles_a_full_engine_from_the_builder() {
    let users: Arc<dyn UserRepository> = Arc::new(InMemoryUserRepository::new());
    let result = AuthEngine::builder()
        .config(base_config())
        .environment(Environment::Production)
        .user_repository(users)
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build();
    assert!(result.is_ok(), "valid wiring must assemble");
    let Ok(engine) = result else { return };
    // Production resolves secure cookies on, and the derived HMAC key is present.
    assert!(engine.config().secure_cookies());
    assert_eq!(engine.config().hmac_key().len(), 32);
    assert_eq!(engine.config().config().route_prefix, "auth");
}

/// Enabling the platform domain without a platform repository fails fast with the matching
/// `ConfigError`, rather than panicking.
#[test]
fn rejects_platform_enabled_without_a_platform_repository() {
    let mut config = base_config();
    config.platform.enabled = true;
    config.roles.platform_hierarchy = Some(HashMap::from([("SUPER".to_owned(), Vec::new())]));
    let users: Arc<dyn UserRepository> = Arc::new(InMemoryUserRepository::new());
    let result = AuthEngine::builder()
        .config(config)
        .user_repository(users)
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build();
    assert!(matches!(
        result,
        Err(ConfigError::MissingPlatformRepository)
    ));
}

/// The platform domain assembles once a platform repository is supplied.
#[test]
fn assembles_with_platform_domain_enabled() {
    let mut config = base_config();
    config.platform.enabled = true;
    config.roles.platform_hierarchy = Some(HashMap::from([("SUPER".to_owned(), Vec::new())]));
    let users: Arc<dyn UserRepository> = Arc::new(InMemoryUserRepository::new());
    let platform: Arc<dyn PlatformUserRepository> = Arc::new(InMemoryPlatformUserRepository::new());
    let result = AuthEngine::builder()
        .config(config)
        .user_repository(users)
        .platform_user_repository(platform)
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build();
    assert!(result.is_ok(), "platform wiring must assemble");
    let Ok(engine) = result else { return };
    assert!(engine.platform_user_repository().is_some());
    assert!(engine.config().config().controllers.platform);
}
