//! The strongly-typed configuration model: [`AuthConfig`] and its nested groups, the
//! two default profiles, the [`Environment`] input that drives production-only checks,
//! the resolver traits, and the startup validation that produces typed
//! [`crate::ConfigError`]s.
//!
//! Every library-owned, closed choice is a named enum ([`JwtAlgorithm`],
//! [`PasswordAlgorithm`], [`TokenDelivery`], [`SameSite`], [`EvictionStrategy`],
//! [`ResetMethod`]) so a magic string or boolean trap can never reach the engine. Secrets
//! ([`JwtConfig::secret`], [`MfaConfig::encryption_key`], [`GoogleOAuthConfig::client_secret`])
//! are `secrecy::SecretString`, redacted in `Debug`/`Display` and zeroized on drop.

mod profiles;
pub mod resolvers;
mod validate;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

pub use resolvers::{
    CookieDomainResolver, MaxSessionsResolver, RequestParts, TenantIdResolver, TenantResolveError,
};
pub use validate::ResolvedConfig;

/// The JWT signing algorithm. A single-variant enum so an asymmetric algorithm is
/// *unrepresentable* — algorithm confusion is impossible by construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256, the only supported (and pinned) algorithm.
    #[default]
    Hs256,
}

/// The algorithm used to hash NEW passwords. Verification accepts either algorithm via the
/// self-describing PHC format, so a deployment can migrate lazily.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// scrypt — parity with nest-auth's stored corpus. Always representable, so this
    /// `#[default]` compiles even in an argon2-only build; selecting it without the
    /// `scrypt` feature is a [`crate::ConfigError`] at `build()`.
    #[default]
    Scrypt,
    /// Argon2id — OWASP first choice; recommended for new projects. Compile-gated behind
    /// the `argon2` feature, so it is only selectable once that feature is enabled.
    #[cfg(feature = "argon2")]
    Argon2id,
}

impl PasswordAlgorithm {
    /// The lowercase algorithm name, used in diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scrypt => "scrypt",
            #[cfg(feature = "argon2")]
            Self::Argon2id => "argon2id",
        }
    }
}

/// scrypt cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScryptParams {
    /// CPU/memory cost N — a power of two, default 32768 (2^15), minimum 16384 (2^14).
    pub cost_factor: u32,
    /// Block size r, default 8.
    pub block_size: u32,
    /// Parallelization p, default 1.
    pub parallelization: u32,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            cost_factor: 1 << 15,
            block_size: 8,
            parallelization: 1,
        }
    }
}

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB, default and minimum 19456 (the OWASP production floor).
    pub memory_kib: u32,
    /// Iterations (time cost), default and minimum 2 (OWASP production floor).
    pub iterations: u32,
    /// Degree of parallelism (lanes), default 1.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Password-hashing configuration: which algorithm writes new hashes, whether to rehash on
/// verify, and the per-algorithm cost parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordConfig {
    /// Algorithm used to hash new passwords. Verification accepts either.
    pub active_algorithm: PasswordAlgorithm,
    /// When true, a successful verify whose stored hash is not the active algorithm — or
    /// is weaker than current params — triggers a transparent rehash.
    pub rehash_on_verify: bool,
    /// scrypt parameters.
    pub scrypt: ScryptParams,
    /// Argon2id parameters.
    pub argon2: Argon2Params,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            active_algorithm: PasswordAlgorithm::Scrypt,
            rehash_on_verify: true,
            scrypt: ScryptParams::default(),
            argon2: Argon2Params::default(),
        }
    }
}

/// JWT configuration. The signing secret is required and validated at startup (length +
/// entropy); it is never logged.
#[derive(Clone, Debug)]
pub struct JwtConfig {
    /// Signing secret. Required. Redacted in `Debug`, zeroized on drop.
    pub secret: SecretString,
    /// Access-token lifetime, default 15m.
    pub access_expires_in: Duration,
    /// Access-token cookie `Max-Age`, default 15m.
    pub access_cookie_max_age: Duration,
    /// Refresh-token lifetime in days, default 7.
    pub refresh_expires_in_days: u32,
    /// Pinned to HS256.
    pub algorithm: JwtAlgorithm,
    /// Grace window during which a rotated refresh token stays valid, default 30s.
    pub refresh_grace_window: Duration,
}

impl Default for JwtConfig {
    /// Default JWT settings with an **empty** secret placeholder. The secret must be set
    /// explicitly — an empty secret is rejected by startup validation — so this default
    /// only supplies the non-secret fields (the form used with `..JwtConfig::default()`).
    fn default() -> Self {
        Self {
            secret: SecretString::from(String::new()),
            access_expires_in: Duration::from_secs(15 * 60),
            access_cookie_max_age: Duration::from_secs(15 * 60),
            refresh_expires_in_days: 7,
            algorithm: JwtAlgorithm::Hs256,
            refresh_grace_window: Duration::from_secs(30),
        }
    }
}

/// The dashboard/tenant and platform role hierarchies. Each hierarchy is fully
/// denormalized: a role lists ALL roles it transitively includes (single-level lookup).
#[derive(Clone, Debug, Default)]
pub struct RolesConfig {
    /// Dashboard/tenant hierarchy. Required, non-empty.
    pub hierarchy: HashMap<String, Vec<String>>,
    /// Platform-admin hierarchy. Required when `platform.enabled`.
    pub platform_hierarchy: Option<HashMap<String, Vec<String>>>,
}

/// Where tokens are delivered (and which credential the guards read).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenDelivery {
    /// HttpOnly cookies. Recommended for same-origin web/SPA.
    #[default]
    Cookie,
    /// Tokens in the response body; guards read `Authorization: Bearer`.
    Bearer,
    /// Both cookies AND body; guards accept either.
    Both,
}

/// The cookie `SameSite` attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SameSite {
    /// `SameSite=Lax`.
    #[default]
    Lax,
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=None` — requires `secure_cookies = true`.
    None,
}

/// Cookie names, paths, and the `SameSite`/domain policy.
#[derive(Clone)]
pub struct CookieConfig {
    /// Access-token cookie name, default `access_token`.
    pub access_token_name: String,
    /// Refresh-token cookie name, default `refresh_token`.
    pub refresh_token_name: String,
    /// Non-HttpOnly login-signal cookie name, default `has_session`.
    pub session_signal_name: String,
    /// Path the refresh cookie is scoped to, default `/auth`.
    pub refresh_cookie_path: String,
    /// Path the OAuth-MFA temp cookie is scoped to, default `/auth/mfa`.
    pub mfa_temp_cookie_path: String,
    /// `SameSite` attribute, default `Lax`.
    pub same_site: SameSite,
    /// Optional resolver for the cookie `Domain`(s), derived from the request host.
    pub resolve_domains: Option<Arc<dyn CookieDomainResolver>>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            access_token_name: "access_token".to_owned(),
            refresh_token_name: "refresh_token".to_owned(),
            session_signal_name: "has_session".to_owned(),
            refresh_cookie_path: "/auth".to_owned(),
            mfa_temp_cookie_path: "/auth/mfa".to_owned(),
            same_site: SameSite::Lax,
            resolve_domains: None,
        }
    }
}

/// The deployment environment, supplied explicitly to the builder. It is the *only* input
/// that drives "is this production": the library never reads the ambient process env. It
/// is secure-by-default (`Production`), so an unset `secure_cookies` resolves to `true` and
/// the production-gated OAuth-redirect checks apply unless the host opts into
/// `Development`/`Test`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Environment {
    /// A production deployment (the secure default).
    #[default]
    Production,
    /// A development deployment.
    Development,
    /// A test deployment.
    Test,
}

/// TOTP MFA configuration. Modeled as `Option<MfaConfig>` on [`AuthConfig`], so a present
/// value structurally guarantees the encryption key and issuer are set.
#[derive(Clone, Debug)]
pub struct MfaConfig {
    /// AES-256-GCM key for TOTP-secret encryption. Must decode (base64 standard or
    /// url-safe) to exactly 32 bytes. Redacted in `Debug`, zeroized on drop.
    pub encryption_key: SecretString,
    /// Issuer shown in authenticator apps. Required, non-empty.
    pub issuer: String,
    /// Recovery codes generated on enable, default 8.
    pub recovery_code_count: u8,
    /// Accepted ± periods of 30s drift, default 1.
    pub totp_window: u8,
}

/// Concurrent-session tracking and eviction policy.
#[derive(Clone)]
pub struct SessionConfig {
    /// Whether session tracking is enabled, default false.
    pub enabled: bool,
    /// Fallback per-user session cap when no resolver is set or it fails, default 5.
    pub default_max_sessions: u32,
    /// Eviction strategy when the cap is reached, default FIFO.
    pub eviction_strategy: EvictionStrategy,
    /// Optional per-user limit override (plan/role aware).
    pub max_sessions_resolver: Option<Arc<dyn MaxSessionsResolver>>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_max_sessions: 5,
            eviction_strategy: EvictionStrategy::Fifo,
            max_sessions_resolver: None,
        }
    }
}

/// The session-eviction strategy when the concurrent-session cap is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvictionStrategy {
    /// Evict the oldest session first.
    #[default]
    Fifo,
}

/// Brute-force lockout policy (a fixed window that does not extend on each failure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BruteForceConfig {
    /// Failures before lockout, default 5.
    pub max_attempts: u32,
    /// The fixed window, default 900s.
    pub window: Duration,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window: Duration::from_secs(900),
        }
    }
}

/// Password-reset policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordResetConfig {
    /// Reset method (link token vs. OTP), default `Token`.
    pub method: ResetMethod,
    /// Reset-token TTL, default 600s.
    pub token_ttl: Duration,
    /// Reset-OTP TTL, default 600s.
    pub otp_ttl: Duration,
    /// OTP length, default 6; valid range `4..=8`.
    pub otp_length: u8,
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self {
            method: ResetMethod::Token,
            token_ttl: Duration::from_secs(600),
            otp_ttl: Duration::from_secs(600),
            otp_length: 6,
        }
    }
}

/// The password-reset delivery method.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResetMethod {
    /// A reset link carrying an opaque token.
    #[default]
    Token,
    /// A short-lived numeric OTP.
    Otp,
}

/// Email-verification policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmailVerificationConfig {
    /// Whether verification is required to log in, default true (secure by default).
    pub required: bool,
    /// Verification-OTP TTL, default 600s.
    pub otp_ttl: Duration,
}

impl Default for EmailVerificationConfig {
    fn default() -> Self {
        Self {
            required: true,
            otp_ttl: Duration::from_secs(600),
        }
    }
}

/// Platform-admin domain toggle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlatformConfig {
    /// Whether the platform-admin domain is enabled, default false. Requires a platform
    /// hierarchy and repository.
    pub enabled: bool,
}

/// Invitation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationConfig {
    /// Whether invitations are enabled, default false.
    pub enabled: bool,
    /// Invitation-token TTL, default 172800s (48h).
    pub token_ttl: Duration,
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_ttl: Duration::from_secs(172_800),
        }
    }
}

/// OAuth redirect/flow knobs and the built-in Google provider credentials.
#[derive(Clone, Debug, Default)]
pub struct OAuthConfig {
    /// 302 target after a successful callback. Requires `Cookie`/`Both` delivery.
    pub success_redirect_url: Option<String>,
    /// 302 target when the callback completes for an MFA-enabled user (before tokens).
    pub mfa_redirect_url: Option<String>,
    /// 302 target on a callback failure; `?error=<code>` is appended.
    pub error_redirect_url: Option<String>,
    /// Allow-list of permitted redirect/callback hosts; empty = no host restriction beyond
    /// the https/relative checks.
    pub redirect_allowlist: Vec<String>,
    /// Built-in Google provider credentials. `Some` enables Google.
    pub google: Option<GoogleOAuthConfig>,
}

/// Built-in Google OAuth provider credentials.
#[derive(Clone, Debug)]
pub struct GoogleOAuthConfig {
    /// Google OAuth client id.
    pub client_id: String,
    /// Google OAuth client secret. Redacted in `Debug`, zeroized on drop.
    pub client_secret: SecretString,
    /// Absolute redirect URI registered with Google.
    pub callback_url: String,
    /// Requested scopes, default `["openid", "email", "profile"]`.
    pub scope: Vec<String>,
}

impl Default for GoogleOAuthConfig {
    /// The canonical OpenID Connect scopes with empty credential placeholders. The
    /// `client_id`, `client_secret`, and `callback_url` must be set explicitly — startup
    /// validation rejects them when empty — so this default only supplies the standard
    /// scope list (the form used with `..GoogleOAuthConfig::default()`).
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: SecretString::from(String::new()),
            callback_url: String::new(),
            scope: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        }
    }
}

/// Which route groups the Axum router mounts. The data-side mirror of nest-auth's
/// `controllers.*`. `sessions`/`platform`/`invitations` are auto-promoted to `true` during
/// `build()` when their feature config is enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerToggles {
    /// The always-on auth flow group (opt-out), default true.
    pub auth: bool,
    /// The password-reset group (opt-out), default true.
    pub password_reset: bool,
    /// The MFA group (opt-in; requires `mfa` config), default false.
    pub mfa: bool,
    /// The sessions group (auto-true when `sessions.enabled`), default false.
    pub sessions: bool,
    /// The platform group (auto-true when `platform.enabled`), default false.
    pub platform: bool,
    /// The OAuth group (opt-in; requires an OAuth provider), default false.
    pub oauth: bool,
    /// The invitations group (auto-true when `invitations.enabled`), default false.
    pub invitations: bool,
}

impl Default for ControllerToggles {
    fn default() -> Self {
        Self {
            auth: true,
            password_reset: true,
            mfa: false,
            sessions: false,
            platform: false,
            oauth: false,
            invitations: false,
        }
    }
}

/// The top-level, owned configuration consumed by `AuthEngineBuilder::build`. Static knobs
/// only — consumer collaborators (repositories, stores, providers, hooks) are supplied to
/// the builder, not embedded here.
///
/// Construct it from one of the two profiles ([`AuthConfig::nest_compat_defaults`] /
/// [`AuthConfig::secure_defaults`]) and override field-by-field.
#[derive(Clone)]
pub struct AuthConfig {
    /// JWT configuration (required secret).
    pub jwt: JwtConfig,
    /// Role hierarchies (required, non-empty dashboard hierarchy).
    pub roles: RolesConfig,
    /// Password-hashing configuration.
    pub password: PasswordConfig,
    /// Token-delivery mode.
    pub token_delivery: TokenDelivery,
    /// Explicit secure-cookie override; `None` resolves from [`Environment`] at `build()`.
    pub secure_cookies: Option<bool>,
    /// Cookie names, paths, and policy.
    pub cookies: CookieConfig,
    /// Optional MFA configuration; `Some` enables MFA.
    pub mfa: Option<MfaConfig>,
    /// Session tracking configuration.
    pub sessions: SessionConfig,
    /// Brute-force lockout configuration.
    pub brute_force: BruteForceConfig,
    /// Password-reset configuration.
    pub password_reset: PasswordResetConfig,
    /// Email-verification configuration.
    pub email_verification: EmailVerificationConfig,
    /// Platform-admin domain configuration.
    pub platform: PlatformConfig,
    /// Invitation configuration.
    pub invitations: InvitationConfig,
    /// OAuth configuration.
    pub oauth: OAuthConfig,
    /// Route prefix, default `auth`.
    pub route_prefix: String,
    /// Redis namespace, default `auth`; all keys prefixed `{ns}:`.
    pub redis_namespace: String,
    /// Statuses that block login, default `["BANNED", "INACTIVE", "SUSPENDED"]`.
    pub blocked_statuses: Vec<String>,
    /// User-status cache TTL (status-revocation latency), default 60s.
    pub user_status_cache_ttl: Duration,
    /// Router-mounting toggles.
    pub controllers: ControllerToggles,
    /// Optional tenant-id resolver. When `Some`, its value is authoritative and any
    /// body-supplied `tenant_id` is ignored entirely (anti-spoofing).
    pub tenant_id_resolver: Option<Arc<dyn TenantIdResolver>>,
}
