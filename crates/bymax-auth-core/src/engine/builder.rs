//! The fluent [`AuthEngineBuilder`]: it gathers the configuration and the host-supplied
//! collaborators and runs one fallible `build()` that validates the configuration, applies
//! the collaborator-presence rules, and assembles an immutable [`AuthEngine`].

use std::collections::HashMap;
use std::sync::Arc;

use bymax_auth_jwt::keys::HsKey;
use secrecy::ExposeSecret;

use super::AuthEngine;
use crate::ConfigError;
use crate::config::{AuthConfig, Environment, ResolvedConfig};
use crate::services::brute_force::BruteForceService;
use crate::services::otp::OtpService;
use crate::services::password::PasswordService;
use crate::services::session::SessionService;
use crate::services::token_manager::TokenManagerService;
#[cfg(feature = "mfa")]
use crate::traits::MfaStore;
use crate::traits::{
    AuthHooks, BruteForceStore, EmailProvider, HttpClient, InvitationStore, NoOpAuthHooks,
    NoOpEmailProvider, OAuthProvider, OtpStore, PasswordResetStore, PlatformUserRepository,
    SessionStore, UserRepository, WsTicketStore,
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
    password_reset_store: Option<Arc<dyn PasswordResetStore>>,
    invitation_store: Option<Arc<dyn InvitationStore>>,
    oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>,
    http_client: Option<Arc<dyn HttpClient>>,
    #[cfg(feature = "oauth")]
    oauth_state_store: Option<Arc<dyn crate::traits::OAuthStateStore>>,
    #[cfg(feature = "mfa")]
    mfa_store: Option<Arc<dyn MfaStore>>,
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
            password_reset_store: None,
            invitation_store: None,
            oauth_providers: HashMap::new(),
            http_client: None,
            #[cfg(feature = "oauth")]
            oauth_state_store: None,
            #[cfg(feature = "mfa")]
            mfa_store: None,
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

    /// Set the password-reset proof store (`pr:`/`prv:` single-use tokens). Required only when
    /// the password-reset flow uses the token method or the OTP verified-token bridge.
    #[must_use]
    pub fn password_reset_store(mut self, store: Arc<dyn PasswordResetStore>) -> Self {
        self.password_reset_store = Some(store);
        self
    }

    /// Set the invitation store (`inv:` single-use tokens). Required only when the invitation
    /// domain is enabled.
    #[must_use]
    pub fn invitation_store(mut self, store: Arc<dyn InvitationStore>) -> Self {
        self.invitation_store = Some(store);
        self
    }

    /// Set the MFA store (`mfa_setup:`/`mfa:`/`tu:` keyspaces). Required only when the MFA
    /// lifecycle is used; wired automatically by [`AuthEngineBuilder::redis_stores`] when the
    /// backend also implements [`MfaStore`].
    #[cfg(feature = "mfa")]
    #[must_use]
    pub fn mfa_store(mut self, store: Arc<dyn MfaStore>) -> Self {
        self.mfa_store = Some(store);
        self
    }

    /// Register the session, OTP, and brute-force stores from a single backend that
    /// implements all three (the common case — one Redis handle behind every store trait).
    /// When the same backend also implements the WebSocket-ticket, password-reset, and
    /// invitation stores, those are wired too, so one handle satisfies every store seam.
    #[cfg(not(feature = "mfa"))]
    #[must_use]
    pub fn redis_stores<S>(mut self, stores: Arc<S>) -> Self
    where
        S: SessionStore
            + OtpStore
            + BruteForceStore
            + WsTicketStore
            + PasswordResetStore
            + InvitationStore
            + 'static,
    {
        self.session_store = Some(stores.clone());
        self.otp_store = Some(stores.clone());
        self.brute_force_store = Some(stores.clone());
        self.ws_ticket_store = Some(stores.clone());
        self.password_reset_store = Some(stores.clone());
        self.invitation_store = Some(stores);
        self
    }

    /// Register every store seam from a single backend (the common one-Redis-handle case).
    /// Under the `mfa` feature the backend must also implement [`MfaStore`], so the MFA
    /// lifecycle's `mfa_setup:`/`mfa:`/`tu:` keyspaces are wired from the same handle.
    #[cfg(feature = "mfa")]
    #[must_use]
    pub fn redis_stores<S>(mut self, stores: Arc<S>) -> Self
    where
        S: SessionStore
            + OtpStore
            + BruteForceStore
            + WsTicketStore
            + PasswordResetStore
            + InvitationStore
            + MfaStore
            + 'static,
    {
        self.session_store = Some(stores.clone());
        self.otp_store = Some(stores.clone());
        self.brute_force_store = Some(stores.clone());
        self.ws_ticket_store = Some(stores.clone());
        self.password_reset_store = Some(stores.clone());
        self.invitation_store = Some(stores.clone());
        self.mfa_store = Some(stores);
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

    /// Set the OAuth HTTP transport. The consumer supplies an [`HttpClient`]; the bundled
    /// `reqwest`-backed transport is wired alongside the OAuth flow that performs the real
    /// HTTPS exchange.
    #[must_use]
    pub fn http_client(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http_client = Some(http);
        self
    }

    /// Set the single-use OAuth `state` + PKCE store (the `os:` keyspace). Required when the
    /// OAuth controller is enabled; the same Redis backend that satisfies the other store
    /// seams implements it, so this is typically `engine.oauth_state_store(stores.clone())`.
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn oauth_state_store(mut self, store: Arc<dyn crate::traits::OAuthStateStore>) -> Self {
        self.oauth_state_store = Some(store);
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
            password_reset_store,
            invitation_store,
            oauth_providers,
            http_client,
            #[cfg(feature = "oauth")]
            oauth_state_store,
            #[cfg(feature = "mfa")]
            mfa_store,
        } = self;

        // Capture whether the consumer supplied custom hooks before the NoOp default is
        // applied below, so the OAuth-misconfiguration warning can distinguish "OAuth enabled
        // with a real `on_oauth_login`" from "OAuth enabled while the hook is the secure-deny
        // default" (which makes every callback fail).
        let hooks_supplied = hooks.is_some();

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
        // OAuth needs the single-use `state` + PKCE store to persist and consume the CSRF
        // nonce; an enabled controller without it could never complete a callback.
        #[cfg(feature = "oauth")]
        if config.controllers.oauth && oauth_state_store.is_none() {
            return Err(ConfigError::OAuthStateStoreMissing);
        }
        // OAuth sign-in stays disabled by default: when the controller is enabled but the
        // `on_oauth_login` hook is still the secure-deny NoOp default, every callback will
        // `OAuthFailed` (§24 invariant 12). Make that loud rather than silent at startup.
        if oauth_enabled_without_custom_hook(config.controllers.oauth, hooks_supplied) {
            tracing::warn!(
                "OAuth controller enabled but no custom AuthHooks supplied: on_oauth_login \
                 defaults to a secure deny, so every OAuth sign-in will fail until it is \
                 implemented"
            );
        }
        // The invitation domain is gated by both its config toggle and a backing store: an
        // enabled domain with no `inv:` store could never persist or consume an invitation.
        if config.invitations.enabled && invitation_store.is_none() {
            return Err(ConfigError::MissingInvitationStore);
        }

        // Build the password service (and its startup sentinel hash) from the validated
        // password config before it is moved into the resolved bundle.
        let passwords = Arc::new(PasswordService::new(&config.password)?);

        // Capture the scalar token/brute-force settings and the signing key before the
        // config is consumed by `ResolvedConfig::new`.
        let access_ttl = config.jwt.access_expires_in;
        let refresh_days = config.jwt.refresh_expires_in_days;
        let grace_window = config.jwt.refresh_grace_window;
        let brute_max_attempts = config.brute_force.max_attempts;
        let brute_window_secs = config.brute_force.window.as_secs();
        let refresh_ttl_secs = u64::from(refresh_days) * 86_400;
        let session_config = config.sessions.clone();
        let signing_key = HsKey::from_bytes(config.jwt.secret.expose_secret().as_bytes());

        // Default the email provider and hooks before they are shared with both the engine and
        // the session service, so the session service holds the same instances the engine does.
        let email_provider =
            email_provider.unwrap_or_else(|| Arc::new(NoOpEmailProvider) as Arc<dyn EmailProvider>);
        let hooks = hooks.unwrap_or_else(|| Arc::new(NoOpAuthHooks) as Arc<dyn AuthHooks>);

        #[cfg(feature = "mfa")]
        let sessions_enabled = session_config.enabled;
        let config = Arc::new(ResolvedConfig::new(config, environment, secure_cookies));

        let tokens = TokenManagerService::new(
            signing_key,
            session_store.clone(),
            access_ttl,
            refresh_days,
            grace_window,
        );
        // Wire the MFA temp-token single-use support when an MFA store is supplied, so the
        // challenge token planted at login is store-backed and brute-force-capped.
        #[cfg(feature = "mfa")]
        let tokens = match &mfa_store {
            Some(store) => {
                tokens.with_mfa_support(crate::services::token_manager::MfaTokenSupport::new(
                    store.clone(),
                    brute_force_store.clone(),
                    config.hmac_key(),
                ))
            }
            None => tokens,
        };
        let tokens = Arc::new(tokens);
        let brute_force = Arc::new(BruteForceService::new(
            brute_force_store.clone(),
            brute_max_attempts,
            brute_window_secs,
        ));
        let otp = OtpService::new(otp_store.clone());
        let sessions = Arc::new(SessionService::new(
            session_store.clone(),
            user_repository.clone(),
            hooks.clone(),
            session_config,
            refresh_ttl_secs,
        ));

        // The MFA lifecycle service is constructed only when `config.mfa` is present and an MFA
        // store is wired; otherwise the engine exposes no MFA surface.
        #[cfg(feature = "mfa")]
        let mfa = build_mfa_service(MfaWiring {
            config: &config,
            mfa_store: mfa_store.as_ref(),
            user_repository: &user_repository,
            platform_user_repository: platform_user_repository.as_ref(),
            tokens: &tokens,
            sessions: &sessions,
            session_store: &session_store,
            brute_force: &brute_force,
            email_provider: &email_provider,
            hooks: &hooks,
            sessions_enabled,
        });

        Ok(AuthEngine {
            config,
            user_repository,
            platform_user_repository,
            email_provider,
            hooks,
            session_store,
            otp_store,
            brute_force_store,
            ws_ticket_store,
            password_reset_store,
            invitation_store,
            oauth_providers,
            http_client,
            #[cfg(feature = "oauth")]
            oauth_state_store,
            passwords,
            tokens,
            brute_force,
            otp,
            sessions,
            #[cfg(feature = "mfa")]
            mfa,
        })
    }
}

/// Whether OAuth sign-in is enabled while `on_oauth_login` is still the secure-deny default
/// (no custom hooks supplied). In that state every callback fails until the deployer
/// implements the hook, so the builder emits a startup warning. Kept as a tiny pure helper so
/// the decision is directly unit-testable without inspecting `tracing` output.
fn oauth_enabled_without_custom_hook(oauth_enabled: bool, hooks_supplied: bool) -> bool {
    oauth_enabled && !hooks_supplied
}

/// The collaborators [`build_mfa_service`] reads to assemble the optional MFA service, grouped
/// so the helper takes one borrow rather than a long positional list.
#[cfg(feature = "mfa")]
struct MfaWiring<'a> {
    config: &'a Arc<ResolvedConfig>,
    mfa_store: Option<&'a Arc<dyn MfaStore>>,
    user_repository: &'a Arc<dyn UserRepository>,
    platform_user_repository: Option<&'a Arc<dyn PlatformUserRepository>>,
    tokens: &'a Arc<TokenManagerService>,
    sessions: &'a Arc<SessionService>,
    session_store: &'a Arc<dyn SessionStore>,
    brute_force: &'a Arc<BruteForceService>,
    email_provider: &'a Arc<dyn EmailProvider>,
    hooks: &'a Arc<dyn AuthHooks>,
    sessions_enabled: bool,
}

/// Construct the [`crate::services::mfa::MfaService`] when both `config.mfa` and an MFA store
/// are present; otherwise the engine has no MFA surface (returns `None`).
#[cfg(feature = "mfa")]
fn build_mfa_service(wiring: MfaWiring<'_>) -> Option<crate::services::mfa::MfaService> {
    let mfa_config = wiring.config.config().mfa.as_ref()?;
    let mfa_store = wiring.mfa_store?.clone();
    let encryption_key = wiring.config.mfa_encryption_key()?;
    let deps = crate::services::mfa::MfaServiceDeps {
        mfa_store,
        user_repo: wiring.user_repository.clone(),
        platform_repo: wiring.platform_user_repository.cloned(),
        tokens: wiring.tokens.clone(),
        sessions: wiring.sessions.clone(),
        session_store: wiring.session_store.clone(),
        brute_force: wiring.brute_force.clone(),
        email: wiring.email_provider.clone(),
        hooks: wiring.hooks.clone(),
        encryption_key,
        identifier_key: zeroize::Zeroizing::new(*wiring.config.hmac_key()),
        issuer: mfa_config.issuer.clone(),
        totp_window: mfa_config.totp_window,
        recovery_code_count: mfa_config.recovery_code_count,
        sessions_enabled: wiring.sessions_enabled,
    };
    Some(crate::services::mfa::MfaService::new(deps))
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
        // The single backend handle satisfies every store seam, so `redis_stores` wires the
        // ws-ticket, password-reset, and invitation stores from it too.
        assert!(engine.ws_ticket_store().is_some());
        assert!(engine.password_reset_store().is_some());
        assert!(engine.invitation_store().is_some());
        assert!(engine.oauth_providers().is_empty());
        // No transport is wired unless the consumer supplies one.
        assert!(engine.http_client().is_none());
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
            .ws_ticket_store(stores.clone())
            .password_reset_store(stores.clone())
            .invitation_store(stores)
            .email_provider(Arc::new(NoOpEmailProvider))
            .hooks(Arc::new(NoOpAuthHooks))
            .http_client(Arc::new(MockHttpClient::ok()))
            .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
            .build();
        assert!(result.is_ok(), "explicit collaborators must assemble");
        let Ok(engine) = result else { return };
        assert!(engine.ws_ticket_store().is_some());
        assert!(engine.password_reset_store().is_some());
        assert!(engine.invitation_store().is_some());
        assert!(engine.http_client().is_some());
        assert!(engine.oauth_providers().contains_key("google"));
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn build_wires_the_mfa_service_via_the_explicit_mfa_store_setter() {
        // With `config.mfa` present and the MFA store supplied through its dedicated setter, the
        // engine exposes a constructed MFA service.
        use crate::config::MfaConfig;
        use base64::Engine as _;
        let mut cfg = valid_config();
        cfg.mfa = Some(MfaConfig {
            encryption_key: SecretString::from(
                base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
            ),
            issuer: "Bymax One".to_owned(),
            recovery_code_count: 8,
            totp_window: 1,
        });
        let s = stores();
        let result = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .session_store(s.clone())
            .otp_store(s.clone())
            .brute_force_store(s.clone())
            .mfa_store(s)
            .build();
        assert!(matches!(&result, Ok(engine) if engine.mfa().is_some()));
    }

    #[test]
    fn rejects_invitations_enabled_without_an_invitation_store() {
        // Enabling the invitation domain without a backing `inv:` store fails fast, rather
        // than assembling an engine that could never persist or consume an invitation.
        let mut cfg = valid_config();
        cfg.invitations.enabled = true;
        let err = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .session_store(stores())
            .otp_store(stores())
            .brute_force_store(stores())
            .build();
        assert!(matches!(err, Err(ConfigError::MissingInvitationStore)));
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
        let mut builder = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(stores())
            .oauth_providers(registry);
        #[cfg(feature = "oauth")]
        {
            builder = builder.oauth_state_store(stores());
        }
        let result = builder.build();
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

    #[cfg(feature = "oauth")]
    #[test]
    fn rejects_oauth_toggle_without_a_state_store() {
        // OAuth enabled with a provider but no `OAuthStateStore` fails fast: the single-use
        // `state` + PKCE record could never be persisted or consumed.
        let mut cfg = valid_config();
        cfg.controllers.oauth = true;
        let err = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(stores())
            .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
            .build();
        assert!(matches!(err, Err(ConfigError::OAuthStateStoreMissing)));
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn oauth_enabled_with_a_state_store_and_default_hooks_assembles_and_warns() {
        // OAuth on, a provider and a state store wired, but no custom hooks: the engine still
        // assembles (the secure-deny default applies) and the startup-warning branch runs.
        let s = stores();
        let mut cfg = valid_config();
        cfg.controllers.oauth = true;
        let result = AuthEngine::builder()
            .config(cfg)
            .user_repository(user_repo())
            .redis_stores(s.clone())
            .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
            .oauth_state_store(s)
            .build();
        assert!(matches!(&result, Ok(engine) if engine.oauth_state_store().is_some()));
    }

    #[test]
    fn oauth_enabled_without_custom_hook_flags_only_the_default_hook_case() {
        // The warning predicate fires exactly when OAuth is enabled AND no custom hooks were
        // supplied; the other three combinations stay silent.
        assert!(oauth_enabled_without_custom_hook(true, false));
        assert!(!oauth_enabled_without_custom_hook(true, true));
        assert!(!oauth_enabled_without_custom_hook(false, false));
        assert!(!oauth_enabled_without_custom_hook(false, true));
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
