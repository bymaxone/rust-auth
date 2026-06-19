//! The engine's two non-flow error types: [`ConfigError`], raised once at startup by
//! the builder when a cross-field configuration invariant is violated, and
//! [`RepositoryError`], the opaque seam a host maps its datastore failures into.
//!
//! Flow errors (`auth.*`) are [`bymax_auth_types::AuthError`]; these two types cover
//! the boundaries `AuthError` does not: configuration resolution and the storage layer.

/// A configuration invariant violated during [`crate::AuthEngineBuilder::build`]. Each
/// variant names one cross-field rule from the startup-validation set, so a misconfigured
/// deployment fails fast at boot with a precise, actionable message.
///
/// The signing secret itself is never embedded in any variant — only its measured
/// properties (length, entropy) appear, so a `ConfigError` is safe to log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// `jwt.secret` is shorter than the 32-character minimum.
    #[error("jwt.secret must be at least 32 characters (got {len})")]
    JwtSecretTooShort {
        /// The measured secret length in characters.
        len: usize,
    },
    /// `jwt.secret` Shannon entropy is below the 3.5 bits/char floor (a first-order
    /// filter that rejects extreme low-diversity secrets such as a repeated character).
    #[error("jwt.secret entropy {entropy:.2} bits/char is below the 3.5 minimum")]
    JwtSecretLowEntropy {
        /// The measured Shannon entropy in bits per character.
        entropy: f64,
    },
    /// `jwt.refresh_grace_window` is not strictly less than the refresh lifetime.
    #[error("jwt.refresh_grace_window ({grace}s) must be < refresh lifetime ({lifetime}s)")]
    RefreshGraceTooLarge {
        /// The configured grace window, in seconds.
        grace: u64,
        /// The refresh-token lifetime, in seconds.
        lifetime: u64,
    },
    /// `jwt.refresh_expires_in_days` is zero (it must be a positive number of days).
    #[error("jwt.refresh_expires_in_days must be a positive value (got {got})")]
    RefreshLifetimeInvalid {
        /// The rejected value.
        got: u32,
    },
    /// `roles.hierarchy` is empty (at least one role must be declared).
    #[error("roles.hierarchy must not be empty")]
    EmptyRoleHierarchy,
    /// A role lists a child that is itself not declared as a key — a dangling reference
    /// that would make a hierarchy lookup silently incomplete.
    #[error("roles.hierarchy['{role}'] references unknown role '{child}'")]
    UnknownRoleReference {
        /// The parent role whose list contains the dangling reference.
        role: String,
        /// The undeclared child role.
        child: String,
    },
    /// `platform.enabled` is set but `roles.platform_hierarchy` is absent.
    #[error("roles.platform_hierarchy is required when platform.enabled")]
    MissingPlatformHierarchy,
    /// `platform.enabled` is set but no `PlatformUserRepository` was supplied.
    #[error("platform.enabled requires a PlatformUserRepository")]
    MissingPlatformRepository,
    /// `password.scrypt.cost_factor` is not a power of two or is below the 16384 floor.
    #[error("password.scrypt.cost_factor must be a power of two >= 16384 (got {got})")]
    ScryptCostFactor {
        /// The rejected cost factor.
        got: u32,
    },
    /// `password.argon2.memory_kib` is below the OWASP production floor of 19456 KiB.
    #[error("password.argon2.memory_kib must be >= 19456 (OWASP floor; got {got})")]
    Argon2Memory {
        /// The rejected memory cost, in KiB.
        got: u32,
    },
    /// `password.argon2.iterations` is below the OWASP production floor of 2.
    #[error("password.argon2.iterations must be >= 2 (OWASP floor; got {got})")]
    Argon2Iterations {
        /// The rejected iteration count.
        got: u32,
    },
    /// `password.active_algorithm` names an algorithm whose hasher feature is not
    /// compiled in (e.g. `Scrypt` selected in a build without the `scrypt` feature).
    #[error("password.active_algorithm '{algorithm}' requires its hasher feature to be enabled")]
    HasherNotEnabled {
        /// The name of the selected-but-uncompiled algorithm.
        algorithm: &'static str,
    },
    /// `mfa.encryption_key` is not valid base64 (standard or url-safe), so it cannot be
    /// decoded to the 32 raw bytes AES-256-GCM requires.
    #[error("mfa.encryption_key is not valid base64 (standard or url-safe)")]
    MfaKeyInvalidBase64,
    /// `mfa.encryption_key` decodes but not to exactly 32 bytes — the size AES-256-GCM
    /// requires.
    #[error("mfa.encryption_key must decode to exactly 32 bytes (got {got})")]
    MfaKeyLength {
        /// The decoded key length in bytes.
        got: usize,
    },
    /// `mfa` is configured but `mfa.issuer` is empty.
    #[error("mfa.issuer is required when mfa is configured")]
    MfaIssuerMissing,
    /// `controllers.mfa` is enabled but no `mfa` config was provided.
    #[error("controllers.mfa is enabled but no mfa config was provided")]
    MfaToggleWithoutConfig,
    /// `password_reset.otp_length` is outside the accepted `4..=8` range.
    #[error("password_reset.otp_length must be within 4..=8 (got {got})")]
    OtpLengthRange {
        /// The rejected OTP length.
        got: u8,
    },
    /// A configured OAuth provider is missing a required credential field.
    #[error("oauth.{provider}.{field} is required when the provider is configured")]
    OAuthFieldMissing {
        /// The provider whose credential is incomplete.
        provider: String,
        /// The missing field name.
        field: String,
    },
    /// An OAuth provider's `callback_url` is not `https` in a production environment.
    #[error("oauth.{provider}.callback_url must use https in production (got {got})")]
    OAuthCallbackInsecure {
        /// The provider with the insecure callback.
        provider: String,
        /// The rejected callback URL.
        got: String,
    },
    /// `oauth.success_redirect_url` is set but token delivery is not `Cookie`/`Both`,
    /// so the redirected browser would carry no session.
    #[error("oauth.success_redirect_url requires token_delivery Cookie or Both")]
    OAuthRedirectNeedsCookie,
    /// A configured OAuth redirect URL is neither `https` nor a same-origin path in a
    /// production environment.
    #[error(
        "oauth.{kind}_redirect_url must be https or a same-origin path in production (got {got})"
    )]
    OAuthRedirectInsecure {
        /// The redirect kind (`success` / `mfa` / `error`).
        kind: String,
        /// The rejected URL.
        got: String,
    },
    /// A configured redirect/callback URL resolves to a host absent from a non-empty
    /// `oauth.redirect_allowlist`.
    #[error("oauth redirect/callback URL {url} is not in oauth.redirect_allowlist")]
    OAuthRedirectNotAllowlisted {
        /// The URL whose host is not allow-listed.
        url: String,
    },
    /// `cookies.same_site = None` was resolved without `secure_cookies = true`, which
    /// browsers reject.
    #[error("cookies.same_site = None requires secure_cookies = true")]
    SameSiteNoneRequiresSecure,
    /// `route_prefix` was changed from its default without an explicit
    /// `cookies.refresh_cookie_path`, so the refresh cookie would no longer be scoped to
    /// the refresh endpoint.
    #[error("route_prefix '{prefix}' requires cookies.refresh_cookie_path to be set explicitly")]
    RefreshPathMismatch {
        /// The non-default route prefix.
        prefix: String,
    },
    /// `controllers.oauth` is enabled but no `OAuthProvider` was registered.
    #[error("controllers.oauth is enabled but no OAuth provider was registered")]
    OAuthToggleWithoutProvider,
    /// No `UserRepository` was supplied — it is mandatory.
    #[error("a UserRepository is required")]
    MissingUserRepository,
    /// One or more of the session / OTP / brute-force stores was not supplied.
    #[error("a SessionStore/OtpStore/BruteForceStore is required")]
    MissingStores,
    /// The anti-enumeration sentinel hash could not be computed from the validated
    /// password parameters during engine assembly — effectively unreachable once the
    /// password floors have passed validation, but reported rather than panicked.
    #[error("failed to compute the password sentinel hash from the configured parameters")]
    SentinelHashFailed,
}

/// A failure crossing the storage seam. The host maps its concrete datastore errors
/// into these two cases; the engine maps them onward to the appropriate
/// [`bymax_auth_types::AuthError`].
///
/// "Not found" is intentionally absent — a missing row is the non-error `Ok(None)` on
/// the read methods, keeping the common case out of the error channel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepositoryError {
    /// A unique-constraint violation (e.g. a duplicate email within a tenant). The
    /// engine maps this to `auth.email_already_exists`.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Any other datastore failure (connection loss, timeout, serialization). The engine
    /// maps this to an internal error and logs the cause via `tracing`.
    #[error("repository backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
