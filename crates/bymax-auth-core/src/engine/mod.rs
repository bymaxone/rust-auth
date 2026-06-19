//! The composition root: the [`AuthEngine`] that owns the resolved configuration and the
//! host-supplied trait objects, and the [`AuthEngineBuilder`] that validates and assembles
//! it in one fallible step.
//!
//! This module owns engine assembly, the field accessors, and validation wiring. The
//! engine holds the resolved config and every collaborator as `Arc<dyn _>`; the
//! authentication flow methods are defined in separate `impl AuthEngine` blocks alongside
//! each flow's implementation.

mod builder;

use std::collections::HashMap;
use std::sync::Arc;

pub use builder::AuthEngineBuilder;

use crate::config::ResolvedConfig;
use crate::services::brute_force::BruteForceService;
use crate::services::otp::OtpService;
use crate::services::password::PasswordService;
use crate::services::token_manager::TokenManagerService;
use crate::traits::{
    AuthHooks, BruteForceStore, EmailProvider, HttpClient, OAuthProvider, OtpStore,
    PlatformUserRepository, SessionStore, UserRepository, WsTicketStore,
};

/// The single composition root. It owns the resolved configuration and the trait objects
/// supplied by the host, and is shared as `Arc<AuthEngine>` — immutable after `build()`, so
/// the only synchronization in the hot path is `Arc` reference counting.
///
/// Construct it with [`AuthEngine::builder`]. The fields are assembled by the builder after
/// validation succeeds.
pub struct AuthEngine {
    config: Arc<ResolvedConfig>,
    user_repository: Arc<dyn UserRepository>,
    platform_user_repository: Option<Arc<dyn PlatformUserRepository>>,
    email_provider: Arc<dyn EmailProvider>,
    hooks: Arc<dyn AuthHooks>,
    session_store: Arc<dyn SessionStore>,
    otp_store: Arc<dyn OtpStore>,
    brute_force_store: Arc<dyn BruteForceStore>,
    ws_ticket_store: Option<Arc<dyn WsTicketStore>>,
    oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>,
    http_client: Option<Arc<dyn HttpClient>>,
    passwords: Arc<PasswordService>,
    tokens: TokenManagerService,
    brute_force: BruteForceService,
    otp: OtpService,
}

impl AuthEngine {
    /// Start assembling an engine. Equivalent to [`AuthEngineBuilder::new`].
    #[must_use]
    pub fn builder() -> AuthEngineBuilder {
        AuthEngineBuilder::new()
    }

    /// The password service (hash/verify off the runtime, rehash-on-verify, sentinel). The
    /// `Arc` is returned so a fire-and-forget rehash task can clone an owned handle.
    pub(crate) fn passwords(&self) -> &Arc<PasswordService> {
        &self.passwords
    }

    /// The token manager (access JWT + opaque refresh, rotation, JTI blacklist).
    pub(crate) fn tokens(&self) -> &TokenManagerService {
        &self.tokens
    }

    /// The brute-force service (HMAC-identifier fixed-window lockout).
    pub(crate) fn brute_force(&self) -> &BruteForceService {
        &self.brute_force
    }

    /// The OTP service (CSPRNG generation, attempt-bounded verify, resend cooldown).
    pub(crate) fn otp(&self) -> &OtpService {
        &self.otp
    }

    /// The resolved configuration (validated `AuthConfig`, resolved `secure_cookies`, the
    /// deployment environment, and the derived identifier-hashing key).
    #[must_use]
    pub fn config(&self) -> &ResolvedConfig {
        &self.config
    }

    /// The dashboard/tenant user repository.
    #[must_use]
    pub fn user_repository(&self) -> &Arc<dyn UserRepository> {
        &self.user_repository
    }

    /// The platform-admin repository, present only when the platform domain is enabled.
    #[must_use]
    pub fn platform_user_repository(&self) -> Option<&Arc<dyn PlatformUserRepository>> {
        self.platform_user_repository.as_ref()
    }

    /// The email provider (`NoOpEmailProvider` when the host supplied none).
    #[must_use]
    pub fn email_provider(&self) -> &Arc<dyn EmailProvider> {
        &self.email_provider
    }

    /// The lifecycle hooks (`NoOpAuthHooks` when the host supplied none).
    #[must_use]
    pub fn hooks(&self) -> &Arc<dyn AuthHooks> {
        &self.hooks
    }

    /// The refresh-session store.
    #[must_use]
    pub fn session_store(&self) -> &Arc<dyn SessionStore> {
        &self.session_store
    }

    /// The OTP store.
    #[must_use]
    pub fn otp_store(&self) -> &Arc<dyn OtpStore> {
        &self.otp_store
    }

    /// The brute-force store.
    #[must_use]
    pub fn brute_force_store(&self) -> &Arc<dyn BruteForceStore> {
        &self.brute_force_store
    }

    /// The single-use WebSocket-ticket store, if one was supplied.
    #[must_use]
    pub fn ws_ticket_store(&self) -> Option<&Arc<dyn WsTicketStore>> {
        self.ws_ticket_store.as_ref()
    }

    /// The registered OAuth providers, keyed by [`OAuthProvider::name`].
    #[must_use]
    pub fn oauth_providers(&self) -> &HashMap<String, Arc<dyn OAuthProvider>> {
        &self.oauth_providers
    }

    /// The OAuth HTTP transport, if one was supplied or defaulted.
    #[must_use]
    pub fn http_client(&self) -> Option<&Arc<dyn HttpClient>> {
        self.http_client.as_ref()
    }
}
