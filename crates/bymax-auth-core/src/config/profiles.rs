//! The two named default profiles. Both seed every group with the same already-secure
//! operational defaults (the verified nest-auth set) and differ **only** in the password
//! hasher: [`AuthConfig::nest_compat_defaults`] writes scrypt (drop-in behavioral parity),
//! [`AuthConfig::secure_defaults`] writes Argon2id (hardened greenfield, requires the
//! `argon2` feature). `AuthConfig::default()` is the scrypt profile.
//!
//! A profile leaves the two structurally-required inputs unset — `jwt.secret` is empty and
//! `roles.hierarchy` is empty — so the deployment fills them in and startup validation
//! enforces their presence.

use std::time::Duration;

use super::{
    AuthConfig, BruteForceConfig, ControllerToggles, CookieConfig, EmailVerificationConfig,
    InvitationConfig, JwtConfig, OAuthConfig, PasswordAlgorithm, PasswordConfig,
    PasswordResetConfig, PlatformConfig, RolesConfig, SessionConfig, TokenDelivery,
};

impl AuthConfig {
    /// Build the shared profile base with the given active password algorithm. Every group
    /// uses its secure operational default; only the hasher differs between profiles.
    fn base(active_algorithm: PasswordAlgorithm) -> Self {
        Self {
            jwt: JwtConfig::default(),
            roles: RolesConfig::default(),
            password: PasswordConfig {
                active_algorithm,
                ..PasswordConfig::default()
            },
            token_delivery: TokenDelivery::default(),
            secure_cookies: None,
            cookies: CookieConfig::default(),
            mfa: None,
            sessions: SessionConfig::default(),
            brute_force: BruteForceConfig::default(),
            password_reset: PasswordResetConfig::default(),
            email_verification: EmailVerificationConfig::default(),
            platform: PlatformConfig::default(),
            invitations: InvitationConfig::default(),
            oauth: OAuthConfig::default(),
            route_prefix: "auth".to_owned(),
            redis_namespace: "auth".to_owned(),
            blocked_statuses: vec![
                "BANNED".to_owned(),
                "INACTIVE".to_owned(),
                "SUSPENDED".to_owned(),
            ],
            user_status_cache_ttl: Duration::from_secs(60),
            controllers: ControllerToggles::default(),
            tenant_id_resolver: None,
        }
    }

    /// The drop-in, behaviorally-compatible profile: scrypt writer plus the verified
    /// nest-auth operational defaults. Works out of the box because the `default` feature
    /// set enables `scrypt`; it never references an uncompiled algorithm.
    #[must_use]
    pub fn nest_compat_defaults() -> Self {
        Self::base(PasswordAlgorithm::Scrypt)
    }

    /// The hardened greenfield profile: Argon2id writer with the same operational defaults.
    /// Requires the `argon2` feature and is simply absent from the API without it; existing
    /// scrypt hashes still verify and migrate lazily via rehash-on-verify.
    #[cfg(feature = "argon2")]
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self::base(PasswordAlgorithm::Argon2id)
    }
}

impl Default for AuthConfig {
    /// Equivalent to [`AuthConfig::nest_compat_defaults`].
    fn default() -> Self {
        Self::nest_compat_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn default_equals_nest_compat_and_uses_the_verified_operational_values() {
        // `default()` must be the scrypt profile carrying the verified nest-auth values, so
        // a bare deployment is secure-by-default.
        let cfg = AuthConfig::default();
        assert_eq!(cfg.password.active_algorithm, PasswordAlgorithm::Scrypt);
        assert_eq!(cfg.password.active_algorithm.as_str(), "scrypt");
        assert!(cfg.password.rehash_on_verify);
        assert!(cfg.email_verification.required);
        assert_eq!(cfg.brute_force.max_attempts, 5);
        assert_eq!(cfg.password_reset.token_ttl, Duration::from_secs(600));
        assert_eq!(cfg.invitations.token_ttl, Duration::from_secs(172_800));
        assert_eq!(cfg.password.scrypt.cost_factor, 1 << 15);
        assert_eq!(cfg.sessions.default_max_sessions, 5);
        assert_eq!(cfg.route_prefix, "auth");
        assert_eq!(cfg.redis_namespace, "auth");
        assert_eq!(cfg.user_status_cache_ttl, Duration::from_secs(60));
        assert_eq!(
            cfg.blocked_statuses,
            vec![
                "BANNED".to_string(),
                "INACTIVE".to_string(),
                "SUSPENDED".to_string()
            ]
        );
        // The profile leaves the two required inputs unset for the deployment to fill.
        assert!(cfg.jwt.secret.expose_secret().is_empty());
        assert!(cfg.roles.hierarchy.is_empty());
        // Default cookie/JWT settings.
        assert_eq!(cfg.cookies.refresh_cookie_path, "/auth");
        assert_eq!(cfg.jwt.refresh_expires_in_days, 7);
        assert!(cfg.controllers.auth);
        assert!(cfg.controllers.password_reset);
        assert!(!cfg.controllers.mfa);
    }

    #[cfg(feature = "argon2")]
    #[test]
    fn secure_defaults_only_differs_in_the_hasher() {
        // `secure_defaults()` is the hardened profile: same operational defaults, Argon2id
        // writer. Available only under the `argon2` feature.
        let cfg = AuthConfig::secure_defaults();
        assert_eq!(cfg.password.active_algorithm, PasswordAlgorithm::Argon2id);
        assert_eq!(cfg.password.active_algorithm.as_str(), "argon2id");
        assert!(cfg.email_verification.required);
        assert_eq!(cfg.brute_force.max_attempts, 5);
        assert_eq!(cfg.password.argon2.memory_kib, 19_456);
    }
}
