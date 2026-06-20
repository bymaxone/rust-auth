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
use crate::services::session::SessionService;
use crate::services::token_manager::TokenManagerService;
use crate::traits::{
    AuthHooks, BruteForceStore, EmailProvider, HttpClient, InvitationStore, OAuthProvider,
    OtpStore, PasswordResetStore, PlatformUserRepository, SessionStore, UserRepository,
    WsTicketStore,
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
    password_reset_store: Option<Arc<dyn PasswordResetStore>>,
    invitation_store: Option<Arc<dyn InvitationStore>>,
    oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>,
    http_client: Option<Arc<dyn HttpClient>>,
    /// The single-use OAuth `state` + PKCE store, wired only when the OAuth flow is enabled.
    #[cfg(feature = "oauth")]
    oauth_state_store: Option<Arc<dyn crate::traits::OAuthStateStore>>,
    passwords: Arc<PasswordService>,
    tokens: Arc<TokenManagerService>,
    brute_force: Arc<BruteForceService>,
    otp: OtpService,
    sessions: Arc<SessionService>,
    /// The MFA lifecycle service, constructed only when `config.mfa` is present.
    #[cfg(feature = "mfa")]
    mfa: Option<crate::services::mfa::MfaService>,
    /// The platform-admin authentication service, constructed only when
    /// `config.platform.enabled`.
    #[cfg(feature = "platform")]
    platform_auth: Option<crate::services::platform::PlatformAuthService>,
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

    /// The session service (concurrent-session tracking, FIFO eviction, ownership-checked
    /// revoke, atomic detail rotation).
    pub(crate) fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    /// The MFA lifecycle service, present only when `config.mfa` is configured. Returns
    /// `None` when MFA is not set up for the deployment.
    #[cfg(feature = "mfa")]
    #[must_use]
    pub fn mfa(&self) -> Option<&crate::services::mfa::MfaService> {
        self.mfa.as_ref()
    }

    /// The platform-admin authentication service (login/MFA-challenge, me, logout, refresh,
    /// revoke-all), present only when `config.platform.enabled`. Returns `None` when the
    /// platform identity domain is not enabled for the deployment.
    #[cfg(feature = "platform")]
    #[must_use]
    pub fn platform_auth(&self) -> Option<&crate::services::platform::PlatformAuthService> {
        self.platform_auth.as_ref()
    }

    /// The password-reset proof store (`pr:`/`prv:` single-use tokens), present only when the
    /// password-reset flow is wired.
    pub(crate) fn password_reset_store(&self) -> Option<&Arc<dyn PasswordResetStore>> {
        self.password_reset_store.as_ref()
    }

    /// The invitation store (`inv:` single-use tokens), present only when the invitation flow
    /// is enabled and wired.
    pub(crate) fn invitation_store(&self) -> Option<&Arc<dyn InvitationStore>> {
        self.invitation_store.as_ref()
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

    /// The single-use OAuth `state` + PKCE store, present only when the OAuth flow is wired.
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn oauth_state_store(&self) -> Option<&Arc<dyn crate::traits::OAuthStateStore>> {
        self.oauth_state_store.as_ref()
    }
}
