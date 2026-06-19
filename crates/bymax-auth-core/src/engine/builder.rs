//! The fluent [`AuthEngineBuilder`]: it gathers the configuration and the host-supplied
//! collaborators and runs one fallible `build()` that validates the configuration, applies
//! the collaborator-presence rules, and assembles an immutable [`AuthEngine`].

use std::collections::HashMap;
use std::sync::Arc;

use super::AuthEngine;
use crate::ConfigError;
use crate::config::{AuthConfig, Environment, ResolvedConfig};
use crate::traits::{
    AuthHooks, BruteForceStore, EmailProvider, HttpClient, NoOpAuthHooks, NoOpEmailProvider,
    OAuthProvider, OtpStore, PlatformUserRepository, SessionStore, UserRepository, WsTicketStore,
};

/// Assembles an [`AuthEngine`] from a configuration plus the host's trait implementations.
/// Required collaborators (a [`UserRepository`] and the session/OTP/brute-force stores) are
/// enforced at `build()`; optional ones default to a no-op or unconfigured state.
pub struct AuthEngineBuilder {
    config: Option<AuthConfig>,
    environment: Environment,
    user_repository: Option<Arc<dyn UserRepository>>,
    platform_user_repository: Option<Arc<dyn PlatformUserRepository>>,
    email_provider: Option<Arc<dyn EmailProvider>>,
    hooks: Option<Arc<dyn AuthHooks>>,
    session_store: Option<Arc<dyn SessionStore>>,
    otp_store: Option<Arc<dyn OtpStore>>,
    brute_force_store: Option<Arc<dyn BruteForceStore>>,
    ws_ticket_store: Option<Arc<dyn WsTicketStore>>,
    oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>,
    http_client: Option<Arc<dyn HttpClient>>,
}

impl Default for AuthEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEngineBuilder {
    /// Create an empty builder. The environment defaults to [`Environment::Production`]
    /// (secure by default).
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: None,
            environment: Environment::Production,
            user_repository: None,
            platform_user_repository: None,
            email_provider: None,
            hooks: None,
            session_store: None,
            otp_store: None,
            brute_force_store: None,
            ws_ticket_store: None,
            oauth_providers: HashMap::new(),
            http_client: None,
        }
    }

    /// Set the configuration. When unset, `build()` uses [`AuthConfig::default`], whose
    /// empty secret then fails validation — so a real config is effectively required.
    #[must_use]
    pub fn config(mut self, config: AuthConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the deployment environment, which drives `secure_cookies` resolution and the
    /// production-gated OAuth-redirect checks.
    #[must_use]
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = environment;
        self
    }

    /// Set the dashboard/tenant user repository (required).
    #[must_use]
    pub fn user_repository(mut self, repository: Arc<dyn UserRepository>) -> Self {
        self.user_repository = Some(repository);
        self
    }

    /// Set the platform-admin repository (required only when the platform domain is enabled).
    #[must_use]
    pub fn platform_user_repository(mut self, repository: Arc<dyn PlatformUserRepository>) -> Self {
        self.platform_user_repository = Some(repository);
        self
    }

    /// Set the email provider (defaults to [`NoOpEmailProvider`]).
    #[must_use]
    pub fn email_provider(mut self, provider: Arc<dyn EmailProvider>) -> Self {
        self.email_provider = Some(provider);
        self
    }

    /// Set the lifecycle hooks (defaults to [`NoOpAuthHooks`]).
    #[must_use]
    pub fn hooks(mut self, hooks: Arc<dyn AuthHooks>) -> Self {
        self.hooks = Some(hooks);
        self
    }

    /// Set the refresh-session store (required).
    #[must_use]
    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Set the OTP store (required).
    #[must_use]
    pub fn otp_store(mut self, store: Arc<dyn OtpStore>) -> Self {
        self.otp_store = Some(store);
        self
    }

    /// Set the brute-force store (required).
    #[must_use]
    pub fn brute_force_store(mut self, store: Arc<dyn BruteForceStore>) -> Self {
        self.brute_force_store = Some(store);
        self
    }

    /// Set the single-use WebSocket-ticket store (optional).
    #[must_use]
    pub fn ws_ticket_store(mut self, store: Arc<dyn WsTicketStore>) -> Self {
        self.ws_ticket_store = Some(store);
        self
    }

    /// Register the session, OTP, and brute-force stores from a single backend that
    /// implements all three (the common case — one Redis handle behind every store trait).
    #[must_use]
    pub fn redis_stores<S>(mut self, stores: Arc<S>) -> Self
    where
        S: SessionStore + OtpStore + BruteForceStore + 'static,
    {
        self.session_store = Some(stores.clone());
        self.otp_store = Some(stores.clone());
        self.brute_force_store = Some(stores);
        self
    }

    /// Register an OAuth provider, keyed by its [`OAuthProvider::name`].
    #[must_use]
    pub fn oauth_provider(mut self, provider: Arc<dyn OAuthProvider>) -> Self {
        self.oauth_providers
            .insert(provider.name().to_owned(), provider);
        self
    }

    /// Register every provider in an [`OAuthProviders`](crate::traits::OAuthProviders)
    /// registry in one call, each keyed by its [`OAuthProvider::name`].
    #[must_use]
    pub fn oauth_providers(mut self, providers: crate::traits::OAuthProviders) -> Self {
        for provider in providers.0 {
            self.oauth_providers
                .insert(provider.name().to_owned(), provider);
        }
        self
    }

    /// Set the OAuth HTTP transport. With the `oauth-reqwest` feature, `build()` defaults
    /// this to the bundled `ReqwestHttpClient` when it is left unset. That bundled client
    /// carries no TLS backend (the workspace forbids `ring`); a deployment that needs HTTPS
    /// OAuth exchanges must install a RustCrypto rustls provider or supply its own
    /// `HttpClient` here, otherwise an HTTPS request fails with a transport error.
    #[must_use]
    pub fn http_client(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http_client = Some(http);
        self
    }

    /// Validate the configuration and assemble the engine.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] for any config-intrinsic violation (via
    /// [`AuthConfig::validate`]) or any missing required collaborator: no user repository
    /// ([`ConfigError::MissingUserRepository`]), an incomplete store set
    /// ([`ConfigError::MissingStores`]), the platform domain enabled without a platform
    /// repository ([`ConfigError::MissingPlatformRepository`]), or the OAuth controller
    /// enabled without a registered provider ([`ConfigError::OAuthToggleWithoutProvider`]).
    pub fn build(self) -> Result<AuthEngine, ConfigError> {
        let AuthEngineBuilder {
            config,
            environment,
            user_repository,
            platform_user_repository,
            email_provider,
            hooks,
            session_store,
            otp_store,
            brute_force_store,
            ws_ticket_store,
            oauth_providers,
            http_client,
        } = self;

        let mut config = config.unwrap_or_default();

        // Auto-promote the router toggles whose feature config is enabled, mirroring
        // nest-auth's "default true when X.enabled" behavior.
        if config.sessions.enabled {
            config.controllers.sessions = true;
        }
        if config.platform.enabled {
            config.controllers.platform = true;
        }
        if config.invitations.enabled {
            config.controllers.invitations = true;
        }

        // Config-intrinsic validation, resolving `secure_cookies` from the environment.
        let secure_cookies = config.validate(environment)?;

        // Collaborator-presence rules.
        let user_repository = user_repository.ok_or(ConfigError::MissingUserRepository)?;
        let (session_store, otp_store, brute_force_store) =
            match (session_store, otp_store, brute_force_store) {
                (Some(session), Some(otp), Some(brute_force)) => (session, otp, brute_force),
                _ => return Err(ConfigError::MissingStores),
            };
        if config.platform.enabled && platform_user_repository.is_none() {
            return Err(ConfigError::MissingPlatformRepository);
        }
        if config.controllers.oauth && oauth_providers.is_empty() {
            return Err(ConfigError::OAuthToggleWithoutProvider);
        }

        let http_client = match http_client {
            Some(client) => Some(client),
            None => default_http_client(),
        };

        let config = Arc::new(ResolvedConfig::new(config, environment, secure_cookies));

        Ok(AuthEngine {
            config,
            user_repository,
            platform_user_repository,
            email_provider: email_provider
                .unwrap_or_else(|| Arc::new(NoOpEmailProvider) as Arc<dyn EmailProvider>),
            hooks: hooks.unwrap_or_else(|| Arc::new(NoOpAuthHooks) as Arc<dyn AuthHooks>),
            session_store,
            otp_store,
            brute_force_store,
            ws_ticket_store,
            oauth_providers,
            http_client,
        })
    }
}

/// The default OAuth transport when none is supplied: the bundled `ReqwestHttpClient` under
/// the `oauth-reqwest` feature, otherwise none (the host must supply its own).
#[cfg(feature = "oauth-reqwest")]
fn default_http_client() -> Option<Arc<dyn HttpClient>> {
    Some(Arc::new(crate::traits::ReqwestHttpClient::new()) as Arc<dyn HttpClient>)
}

/// The default OAuth transport when the `oauth-reqwest` feature is off: none.
#[cfg(not(feature = "oauth-reqwest"))]
fn default_http_client() -> Option<Arc<dyn HttpClient>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Environment};
    use crate::testing::{
        InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository, MockOAuthProvider,
    };
    use secrecy::SecretString;
    use std::collections::HashMap as Map;

    /// A configuration that passes validation, for the assembly tests.
    fn valid_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = Map::from([("ADMIN".to_owned(), Vec::new())]);
        cfg
    }

    fn user_repo() -> Arc<dyn UserRepository> {
        Arc::new(InMemoryUserRepository::new())
    }

    fn stores() -> Arc<InMemoryStores> {
        Arc::new(InMemoryStores::new())
    }

    #[test]
    fn builds_with_noop_defaults_and_exposes_every_accessor() {
        // A minimal valid wiring assembles, defaulting the email provider and hooks to the
        // NoOp implementations, and every accessor returns the wired collaborator.
        let result = AuthEngine::builder()
            .config(valid_config())
            .environment(Environment::Development)
            .user_repository(user_repo())
            .redis_stores(stores())
            .build();
        assert!(result.is_ok(), "valid config must assemble");
        let Ok(engine) = result else { return };
        // Development resolves secure_cookies to false.
        assert!(!engine.config().secure_cookies());
        assert_eq!(engine.config().environment(), Environment::Development);
        assert_eq!(engine.config().config().jwt.refresh_expires_in_days, 7);
        assert_eq!(engine.config().hmac_key().len(), 32);
        // Required + defaulted collaborators are all reachable.
        let _ = engine.user_repository();
        assert!(engine.platform_user_repository().is_none());
        let _ = engine.email_provider();
        let _ = engine.hooks();
        let _ = engine.session_store();
        let _ = engine.otp_store();
        let _ = engine.brute_force_store();
        assert!(engine.ws_ticket_store().is_none());
        assert!(engine.oauth_providers().is_empty());
        // Without `oauth-reqwest`, no default transport is wired.
        #[cfg(not(feature = "oauth-reqwest"))]
        assert!(engine.http_client().is_none());
        #[cfg(feature = "oauth-reqwest")]
        assert!(engine.http_client().is_some());
    }

    #[test]
    fn build_accepts_explicit_optional_collaborators() {
        // Supplying the optional collaborators exercises the non-default branches and the
        // individual store setters + ws-ticket + oauth-provider + http-client wiring.
        use crate::testing::MockHttpClient;
        use crate::traits::{NoOpAuthHooks, NoOpEmailProvider};
        let stores = stores();
        let result = AuthEngine::builder()
            .config(valid_config())
            .user_repository(user_repo())
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores.clone())
            .ws_ticket_store(stores)
            .email_provider(Arc::new(NoOpEmailProvider))
            .hooks(Arc::new(NoOpAuthHooks))
            .http_client(Arc::new(MockHttpClient::ok()))
            .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
            .build();
        assert!(result.is_ok(), "explicit collaborators must assemble");
        let Ok(engine) = result else { return };
        assert!(engine.ws_ticket_store().is_some());
        assert!(engine.http_client().is_some());
        assert!(engine.oauth_providers().contains_key("google"));
    }

    #[test]
    fn oauth_providers_registry_registers_every_provider() {
        // The batch setter wires an `OAuthProviders` registry, keying each by name.
        use crate::traits::OAuthProviders;
        let registry = OAuthProviders::new()
            .with(Arc::new(MockOAuthProvider::new("google")))
            .with(Arc::new(MockOAuthProvider::new("github")));
        let mut cfg = valid_config();
        cfg.controllers.oauth = true;
        let result = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(stores())
            .oauth_providers(registry)
            .build();
        assert!(result.is_ok(), "registry wiring must assemble");
        let Ok(engine) = result else { return };
        assert!(engine.oauth_providers().contains_key("google"));
        assert!(engine.oauth_providers().contains_key("github"));
    }

    #[test]
    fn auto_promotes_toggles_when_feature_config_enabled() {
        // sessions/platform/invitations toggles are promoted to true from their config.
        let mut cfg = valid_config();
        cfg.sessions.enabled = true;
        cfg.invitations.enabled = true;
        cfg.platform.enabled = true;
        cfg.roles.platform_hierarchy = Some(Map::from([("SUPER".to_owned(), Vec::new())]));
        let result = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .platform_user_repository(Arc::new(InMemoryPlatformUserRepository::new()))
            .redis_stores(stores())
            .build();
        assert!(result.is_ok(), "platform wiring must assemble");
        let Ok(engine) = result else { return };
        let toggles = engine.config().config().controllers;
        assert!(toggles.sessions);
        assert!(toggles.platform);
        assert!(toggles.invitations);
    }

    #[test]
    fn rejects_missing_user_repository() {
        let err = AuthEngine::builder()
            .config(valid_config())
            .redis_stores(stores())
            .build();
        assert!(matches!(err, Err(ConfigError::MissingUserRepository)));
    }

    #[test]
    fn rejects_missing_stores() {
        // Only one of the three stores is supplied.
        let err = AuthEngine::builder()
            .config(valid_config())
            .user_repository(user_repo())
            .session_store(stores())
            .build();
        assert!(matches!(err, Err(ConfigError::MissingStores)));
    }

    #[test]
    fn rejects_platform_without_repository() {
        let mut cfg = valid_config();
        cfg.platform.enabled = true;
        cfg.roles.platform_hierarchy = Some(Map::from([("SUPER".to_owned(), Vec::new())]));
        let err = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(stores())
            .build();
        assert!(matches!(err, Err(ConfigError::MissingPlatformRepository)));
    }

    #[test]
    fn rejects_oauth_toggle_without_provider() {
        let mut cfg = valid_config();
        cfg.controllers.oauth = true;
        let err = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(stores())
            .build();
        assert!(matches!(err, Err(ConfigError::OAuthToggleWithoutProvider)));
    }

    #[test]
    fn missing_config_fails_validation_on_the_empty_secret() {
        // With no config, the default (empty secret) is used and rejected by validation.
        let err = AuthEngine::builder()
            .user_repository(user_repo())
            .redis_stores(stores())
            .build();
        assert!(matches!(
            err,
            Err(ConfigError::JwtSecretTooShort { len: 0 })
        ));
    }

    #[test]
    fn default_builder_matches_new() {
        // The `Default` impl is the empty builder; building it fails the same way.
        let err = AuthEngineBuilder::default()
            .config(valid_config())
            .user_repository(user_repo())
            .build();
        assert!(matches!(err, Err(ConfigError::MissingStores)));
    }
}
