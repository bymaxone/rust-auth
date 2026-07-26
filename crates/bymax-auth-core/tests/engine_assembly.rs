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
    assert_eq!(engine.config().hmac_key().len(), 64);
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

/// A breach checker that reports one specific password as breached.
struct RejectsOnePassword(&'static str);

#[async_trait::async_trait]
impl bymax_auth_core::traits::PasswordBreachChecker for RejectsOnePassword {
    async fn is_breached(&self, password: &str) -> bool {
        password == self.0
    }
}

/// A wired breach checker refuses the password before it is ever hashed and stored, and a
/// clean password is untouched.
///
/// The check has to sit on the path that *sets* a password. Wiring that only takes effect at
/// some later verification would be worthless: the breached credential would already be the
/// account's.
#[tokio::test]
async fn a_wired_breach_checker_refuses_a_compromised_password_at_registration() {
    let users: Arc<dyn UserRepository> = Arc::new(InMemoryUserRepository::new());
    let engine = AuthEngine::builder()
        .config(base_config())
        .environment(Environment::Test)
        .user_repository(users)
        .redis_stores(Arc::new(InMemoryStores::new()))
        .breach_checker(Arc::new(RejectsOnePassword("password123")))
        .build();
    assert!(engine.is_ok(), "valid wiring must assemble");
    let Ok(engine) = engine else { return };
    let ctx = bymax_auth_core::context::RequestContext::new(
        "203.0.113.4",
        "tests",
        std::collections::BTreeMap::new(),
    );

    let refused = engine
        .register(
            bymax_auth_core::services::auth::RegisterInput {
                email: "breached@example.com".to_owned(),
                password: "password123".to_owned(),
                name: "Ada".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &ctx,
        )
        .await;
    assert!(matches!(
        refused,
        Err(bymax_auth_types::AuthError::PasswordCompromised)
    ));

    // A password the corpus does not know registers normally — the check adds no behaviour
    // when it has nothing to report.
    let accepted = engine
        .register(
            bymax_auth_core::services::auth::RegisterInput {
                email: "clean@example.com".to_owned(),
                password: "a-long-unique-passphrase".to_owned(),
                name: "Ada".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &ctx,
        )
        .await;
    assert!(accepted.is_ok());
}
