//! Startup validation and config resolution. [`AuthConfig::validate`] checks every
//! config-intrinsic invariant and resolves `secure_cookies` from the [`Environment`]; the
//! builder layers the collaborator-presence checks on top and assembles a
//! [`ResolvedConfig`], which also carries the derived identifier-hashing key.

use std::collections::HashMap;

use base64::Engine;
use bymax_auth_crypto::mac::sha256;
use secrecy::{ExposeSecret, SecretBox};

use super::{AuthConfig, Environment, PasswordConfig, SameSite, TokenDelivery};
use crate::ConfigError;

/// Domain-separation label for the derived identifier-hashing key. Changing it invalidates
/// every existing keyed identifier and is therefore a breaking change.
const HMAC_KEY_LABEL: &[u8] = b"bymax-auth:hmac-key:v1";

/// The minimum Shannon entropy, in bits per character, accepted for the JWT secret.
const MIN_SECRET_ENTROPY: f64 = 3.5;

/// The minimum JWT-secret length, in characters.
const MIN_SECRET_LEN: usize = 32;

/// The fully-resolved configuration stored on the engine after a successful `build()`. It
/// owns the validated [`AuthConfig`], the resolved `secure_cookies` bool, the deployment
/// [`Environment`], and the derived identifier-hashing key — none of which are surfaced on
/// `AuthConfig` itself.
pub struct ResolvedConfig {
    config: AuthConfig,
    environment: Environment,
    secure_cookies: bool,
    hmac_key: SecretBox<[u8; 32]>,
}

impl ResolvedConfig {
    /// Assemble a resolved config, deriving the identifier-hashing key from the JWT secret.
    /// Callers pass the already-validated config, the resolved environment, and the
    /// resolved `secure_cookies` value.
    pub(crate) fn new(config: AuthConfig, environment: Environment, secure_cookies: bool) -> Self {
        let hmac_key = derive_hmac_key(config.jwt.secret.expose_secret());
        Self {
            config,
            environment,
            secure_cookies,
            hmac_key,
        }
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// The deployment environment supplied to the builder.
    #[must_use]
    pub fn environment(&self) -> Environment {
        self.environment
    }

    /// The resolved `secure_cookies` flag.
    #[must_use]
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    /// The derived identifier-hashing key (`SHA-256(label || jwt.secret)`), used to HMAC
    /// low-entropy Redis identifiers so the signing key and the identifier-hashing key are
    /// cryptographically independent.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8; 32] {
        self.hmac_key.expose_secret()
    }
}

/// Derive the identifier-hashing key as `SHA-256(label || secret)`.
fn derive_hmac_key(secret: &str) -> SecretBox<[u8; 32]> {
    let mut input = Vec::with_capacity(HMAC_KEY_LABEL.len() + secret.len());
    input.extend_from_slice(HMAC_KEY_LABEL);
    input.extend_from_slice(secret.as_bytes());
    SecretBox::new(Box::new(sha256(&input)))
}

impl AuthConfig {
    /// Resolve `secure_cookies`: the explicit value if set, otherwise `true` only in a
    /// production environment.
    #[must_use]
    pub(crate) fn resolve_secure_cookies(&self, environment: Environment) -> bool {
        self.secure_cookies
            .unwrap_or(environment == Environment::Production)
    }

    /// Validate every config-intrinsic invariant against the deployment `environment` and
    /// return the resolved `secure_cookies` value. The collaborator-presence rules
    /// (user repository, stores, platform repository, OAuth provider) are applied by the
    /// builder on top of this.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant as a [`ConfigError`]: secret length/entropy,
    /// refresh-lifetime/grace coherence, role-hierarchy non-emptiness and referential
    /// integrity, the platform-hierarchy requirement, password-hasher parameters and
    /// availability, the MFA key size and issuer, the MFA-toggle prerequisite, the OTP
    /// length range, the OAuth provider-field and redirect rules (production-gated), the
    /// `SameSite=None ⇒ Secure` rule, and the route-prefix/refresh-path coherence rule.
    pub fn validate(&self, environment: Environment) -> Result<bool, ConfigError> {
        let secure_cookies = self.resolve_secure_cookies(environment);

        // Rule 1-2: JWT secret length + entropy.
        let secret = self.jwt.secret.expose_secret();
        let len = secret.chars().count();
        if len < MIN_SECRET_LEN {
            return Err(ConfigError::JwtSecretTooShort { len });
        }
        let entropy = shannon_entropy(secret);
        if entropy < MIN_SECRET_ENTROPY {
            return Err(ConfigError::JwtSecretLowEntropy { entropy });
        }

        // Rule 3-4: refresh lifetime positive + grace window strictly smaller.
        if self.jwt.refresh_expires_in_days == 0 {
            return Err(ConfigError::RefreshLifetimeInvalid { got: 0 });
        }
        let grace = self.jwt.refresh_grace_window.as_secs();
        let lifetime = u64::from(self.jwt.refresh_expires_in_days) * 86_400;
        if grace >= lifetime {
            return Err(ConfigError::RefreshGraceTooLarge { grace, lifetime });
        }

        // Rule 5-7: role hierarchies.
        if self.roles.hierarchy.is_empty() {
            return Err(ConfigError::EmptyRoleHierarchy);
        }
        validate_referential(&self.roles.hierarchy)?;
        if let Some(platform_hierarchy) = &self.roles.platform_hierarchy {
            validate_referential(platform_hierarchy)?;
        }
        if self.platform.enabled && self.roles.platform_hierarchy.is_none() {
            return Err(ConfigError::MissingPlatformHierarchy);
        }

        // Rule 8 (platform.enabled requires a PlatformUserRepository) is a collaborator-
        // presence rule, so the builder enforces it rather than this config-only pass.

        // Rule 9-10 + hasher availability.
        validate_password(&self.password)?;

        // Rule 11-12: MFA key size + issuer.
        if let Some(mfa) = &self.mfa {
            let decoded = decode_base64_any(mfa.encryption_key.expose_secret())
                .ok_or(ConfigError::MfaKeyInvalidBase64)?;
            if decoded.len() != 32 {
                return Err(ConfigError::MfaKeyLength { got: decoded.len() });
            }
            if mfa.issuer.trim().is_empty() {
                return Err(ConfigError::MfaIssuerMissing);
            }
        }

        // Rule 13: MFA toggle requires MFA config.
        if self.controllers.mfa && self.mfa.is_none() {
            return Err(ConfigError::MfaToggleWithoutConfig);
        }

        // Rule 14: OTP length range.
        let otp_length = self.password_reset.otp_length;
        if !(4..=8).contains(&otp_length) {
            return Err(ConfigError::OtpLengthRange { got: otp_length });
        }

        // Rule 15-18: OAuth provider fields and redirect safety.
        self.validate_oauth(environment)?;

        // Rule 19: SameSite=None requires resolved secure cookies.
        if self.cookies.same_site == SameSite::None && !secure_cookies {
            return Err(ConfigError::SameSiteNoneRequiresSecure);
        }

        // Rule 20: a non-default route prefix requires an explicit refresh cookie path.
        if self.route_prefix != "auth" && self.cookies.refresh_cookie_path == "/auth" {
            return Err(ConfigError::RefreshPathMismatch {
                prefix: self.route_prefix.clone(),
            });
        }

        Ok(secure_cookies)
    }

    /// Validate the OAuth provider fields (rule 15), the production callback-https rule
    /// (16), the success-redirect delivery rule (17), and the production redirect
    /// https/relative + allow-list rules (18).
    fn validate_oauth(&self, environment: Environment) -> Result<(), ConfigError> {
        if let Some(google) = &self.oauth.google {
            if google.client_id.trim().is_empty() {
                return Err(ConfigError::OAuthFieldMissing {
                    provider: "google".to_owned(),
                    field: "client_id".to_owned(),
                });
            }
            if google.client_secret.expose_secret().trim().is_empty() {
                return Err(ConfigError::OAuthFieldMissing {
                    provider: "google".to_owned(),
                    field: "client_secret".to_owned(),
                });
            }
            if google.callback_url.trim().is_empty() {
                return Err(ConfigError::OAuthFieldMissing {
                    provider: "google".to_owned(),
                    field: "callback_url".to_owned(),
                });
            }
            if environment == Environment::Production && !is_secure_https(&google.callback_url) {
                return Err(ConfigError::OAuthCallbackInsecure {
                    provider: "google".to_owned(),
                    got: google.callback_url.clone(),
                });
            }
        }

        if self.oauth.success_redirect_url.is_some()
            && !matches!(
                self.token_delivery,
                TokenDelivery::Cookie | TokenDelivery::Both
            )
        {
            return Err(ConfigError::OAuthRedirectNeedsCookie);
        }

        if environment == Environment::Production {
            for (kind, url) in [
                ("success", &self.oauth.success_redirect_url),
                ("mfa", &self.oauth.mfa_redirect_url),
                ("error", &self.oauth.error_redirect_url),
            ] {
                if let Some(url) = url
                    && !is_https_or_relative(url)
                {
                    return Err(ConfigError::OAuthRedirectInsecure {
                        kind: kind.to_owned(),
                        got: url.clone(),
                    });
                }
            }
            if !self.oauth.redirect_allowlist.is_empty() {
                for url in self.allowlist_candidate_urls() {
                    if !host_allowlisted(&url, &self.oauth.redirect_allowlist) {
                        return Err(ConfigError::OAuthRedirectNotAllowlisted { url });
                    }
                }
            }
        }

        Ok(())
    }

    /// The redirect/callback URLs subject to the host allow-list: the configured redirect
    /// URLs plus each provider callback.
    fn allowlist_candidate_urls(&self) -> Vec<String> {
        let mut urls = Vec::new();
        for url in [
            &self.oauth.success_redirect_url,
            &self.oauth.mfa_redirect_url,
            &self.oauth.error_redirect_url,
        ]
        .into_iter()
        .flatten()
        {
            urls.push(url.clone());
        }
        if let Some(google) = &self.oauth.google {
            urls.push(google.callback_url.clone());
        }
        urls
    }
}

/// Validate that every child role in `hierarchy` is itself declared as a key. Roles are
/// visited in sorted order so a malformed hierarchy reports the same dangling reference on
/// every run (deterministic diagnostics, independent of `HashMap` iteration order).
fn validate_referential(hierarchy: &HashMap<String, Vec<String>>) -> Result<(), ConfigError> {
    let mut roles: Vec<&String> = hierarchy.keys().collect();
    roles.sort();
    for role in roles {
        for child in &hierarchy[role] {
            if !hierarchy.contains_key(child) {
                return Err(ConfigError::UnknownRoleReference {
                    role: role.clone(),
                    child: child.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Validate the password hasher parameters (rule 9-10) and the active-hasher availability.
fn validate_password(password: &PasswordConfig) -> Result<(), ConfigError> {
    #[cfg(feature = "scrypt")]
    if !password.scrypt.cost_factor.is_power_of_two() || password.scrypt.cost_factor < 16_384 {
        return Err(ConfigError::ScryptCostFactor {
            got: password.scrypt.cost_factor,
        });
    }

    #[cfg(feature = "argon2")]
    {
        if password.argon2.memory_kib < 19_456 {
            return Err(ConfigError::Argon2Memory {
                got: password.argon2.memory_kib,
            });
        }
        if password.argon2.iterations < 2 {
            return Err(ConfigError::Argon2Iterations {
                got: password.argon2.iterations,
            });
        }
    }

    // The active algorithm must be backed by a compiled-in hasher. `Argon2id` is only
    // representable under the `argon2` feature, so the only unavailable case is `Scrypt`
    // selected without the `scrypt` feature.
    #[cfg(not(feature = "scrypt"))]
    if password.active_algorithm == super::PasswordAlgorithm::Scrypt {
        return Err(ConfigError::HasherNotEnabled {
            algorithm: "scrypt",
        });
    }

    Ok(())
}

/// The Shannon entropy of `s` in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Decode `s` as base64 (standard or url-safe, padded or not), returning the bytes on the
/// first variant that succeeds.
fn decode_base64_any(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| URL_SAFE.decode(s).ok())
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}

/// Whether `url` is an absolute `https` URL with a non-empty host. An empty authority
/// (`https:///path`) is rejected — it is not a usable absolute target.
fn is_secure_https(url: &str) -> bool {
    url.starts_with("https://") && url_host(url).is_some()
}

/// Whether `url` is a genuinely same-origin path: `/`-rooted, but NOT `//host` or `/\host`.
/// Browsers resolve a second `/` or `\` after the leading slash to a foreign authority
/// (WHATWG treats `\` as `/` for special schemes), so both forms are rejected.
fn is_same_origin_path(url: &str) -> bool {
    url.starts_with('/') && !matches!(url.as_bytes().get(1), Some(b'/') | Some(b'\\'))
}

/// Whether `url` is an absolute `https` URL (with a host) or a same-origin path.
fn is_https_or_relative(url: &str) -> bool {
    is_secure_https(url) || is_same_origin_path(url)
}

/// The host component of an absolute or protocol-relative URL, or `None` for a same-origin
/// path. Strips userinfo and port, and keeps a bracketed IPv6 literal intact. A backslash
/// terminates the authority (browsers treat `\` as `/` for special schemes), so
/// `evil.com\@allowed.com` resolves to host `evil.com`, not `allowed.com`.
fn url_host(url: &str) -> Option<String> {
    // Accept both `scheme://authority/...` and protocol-relative `//authority/...`.
    let after_scheme = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url.strip_prefix("//")?,
    };
    let authority = after_scheme
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or(after_scheme);
    let without_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    // A bracketed IPv6 literal (`[::1]:8443`) keeps everything up to and including `]`;
    // otherwise the host ends at the port separator.
    let host = if without_userinfo.starts_with('[') {
        without_userinfo
            .find(']')
            .map_or(without_userinfo, |close| &without_userinfo[..=close])
    } else {
        without_userinfo
            .split(':')
            .next()
            .unwrap_or(without_userinfo)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// Whether `url`'s host is allow-listed. A relative (host-less) URL is same-origin and is
/// always allowed. The host comparison is ASCII-case-insensitive (DNS hostnames are
/// case-insensitive); allow-list entries are bare hostnames — the URL's port is stripped
/// before comparison, so an entry that includes a port never matches.
fn host_allowlisted(url: &str, allowlist: &[String]) -> bool {
    match url_host(url) {
        None => true,
        Some(host) => allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&host)),
    }
}

// These tests construct a configuration that must pass the password-hasher availability
// check, so they require at least one compiled hasher. A no-hasher build (`scrypt` and
// `argon2` both off) is degenerate — it cannot validate any config — and is exercised only
// by the build-compiles checks.
#[cfg(all(test, any(feature = "scrypt", feature = "argon2")))]
mod tests {
    use super::*;
    use crate::config::{GoogleOAuthConfig, MfaConfig};
    use secrecy::SecretString;
    use std::collections::HashMap;

    /// A configuration that passes every config-intrinsic rule, used as the base for the
    /// one-rule-at-a-time negative tests. The active algorithm is whichever hasher is
    /// compiled in, so the base clears the hasher-availability check.
    fn valid_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        // In an argon2-only build the default `Scrypt` algorithm has no compiled hasher, so
        // select the available one.
        #[cfg(not(feature = "scrypt"))]
        {
            cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
        }
        // A 32-char, 16-symbol secret: length 32, entropy 4.0 bits/char.
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = HashMap::from([
            ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
            ("MEMBER".to_owned(), Vec::new()),
        ]);
        cfg
    }

    #[test]
    fn valid_config_passes_in_production_and_development() {
        // The base must validate cleanly so the negative tests isolate exactly one rule.
        assert!(matches!(
            valid_config().validate(Environment::Production),
            Ok(true)
        ));
        assert!(matches!(
            valid_config().validate(Environment::Development),
            Ok(false)
        ));
    }

    #[test]
    fn secure_cookies_resolves_from_environment_and_override() {
        // None resolves to prod-only; an explicit value always wins.
        let cfg = valid_config();
        assert!(cfg.resolve_secure_cookies(Environment::Production));
        assert!(!cfg.resolve_secure_cookies(Environment::Development));
        assert!(!cfg.resolve_secure_cookies(Environment::Test));
        let mut overridden = valid_config();
        overridden.secure_cookies = Some(false);
        assert!(!overridden.resolve_secure_cookies(Environment::Production));
        overridden.secure_cookies = Some(true);
        assert!(overridden.resolve_secure_cookies(Environment::Development));
    }

    #[test]
    fn rejects_short_secret() {
        let mut cfg = valid_config();
        cfg.jwt.secret = SecretString::from("too-short".to_owned());
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::JwtSecretTooShort { len: 9 })
        ));
    }

    #[test]
    fn rejects_low_entropy_secret() {
        let mut cfg = valid_config();
        // 32 identical characters: length passes, entropy is 0.
        cfg.jwt.secret = SecretString::from("a".repeat(32));
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::JwtSecretLowEntropy { .. })
        ));
    }

    #[test]
    fn rejects_zero_refresh_lifetime_and_oversized_grace() {
        let mut zero = valid_config();
        zero.jwt.refresh_expires_in_days = 0;
        assert!(matches!(
            zero.validate(Environment::Production),
            Err(ConfigError::RefreshLifetimeInvalid { got: 0 })
        ));

        let mut grace = valid_config();
        grace.jwt.refresh_expires_in_days = 1;
        grace.jwt.refresh_grace_window = std::time::Duration::from_secs(90_000); // > 86400
        assert!(matches!(
            grace.validate(Environment::Production),
            Err(ConfigError::RefreshGraceTooLarge {
                grace: 90_000,
                lifetime: 86_400
            })
        ));
    }

    #[test]
    fn rejects_empty_and_dangling_role_hierarchies() {
        let mut empty = valid_config();
        empty.roles.hierarchy = HashMap::new();
        assert!(matches!(
            empty.validate(Environment::Production),
            Err(ConfigError::EmptyRoleHierarchy)
        ));

        let mut dangling = valid_config();
        dangling.roles.hierarchy = HashMap::from([("ADMIN".to_owned(), vec!["GHOST".to_owned()])]);
        assert!(matches!(
            dangling.validate(Environment::Production),
            Err(ConfigError::UnknownRoleReference { role, child })
                if role == "ADMIN" && child == "GHOST"
        ));

        // A dangling reference in the platform hierarchy is rejected the same way.
        let mut platform_dangling = valid_config();
        platform_dangling.roles.platform_hierarchy = Some(HashMap::from([(
            "SUPER".to_owned(),
            vec!["GHOST".to_owned()],
        )]));
        assert!(matches!(
            platform_dangling.validate(Environment::Production),
            Err(ConfigError::UnknownRoleReference { .. })
        ));
    }

    #[test]
    fn rejects_platform_without_hierarchy() {
        let mut cfg = valid_config();
        cfg.platform.enabled = true;
        cfg.roles.platform_hierarchy = None;
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::MissingPlatformHierarchy)
        ));
    }

    #[cfg(feature = "scrypt")]
    #[test]
    fn rejects_bad_scrypt_cost_factor() {
        let mut not_power = valid_config();
        not_power.password.scrypt.cost_factor = 30_000; // not a power of two
        assert!(matches!(
            not_power.validate(Environment::Production),
            Err(ConfigError::ScryptCostFactor { got: 30_000 })
        ));

        let mut too_small = valid_config();
        too_small.password.scrypt.cost_factor = 8_192; // power of two but below floor
        assert!(matches!(
            too_small.validate(Environment::Production),
            Err(ConfigError::ScryptCostFactor { got: 8_192 })
        ));
    }

    #[cfg(feature = "argon2")]
    #[test]
    fn rejects_weak_argon2_params() {
        // The OWASP production floors (memory >= 19456 KiB, iterations >= 2) are enforced
        // whenever the argon2 hasher is compiled in.
        let mut low_mem = valid_config();
        low_mem.password.argon2.memory_kib = 1_024;
        assert!(matches!(
            low_mem.validate(Environment::Production),
            Err(ConfigError::Argon2Memory { got: 1_024 })
        ));
        let mut low_iter = valid_config();
        low_iter.password.argon2.iterations = 1;
        assert!(matches!(
            low_iter.validate(Environment::Production),
            Err(ConfigError::Argon2Iterations { got: 1 })
        ));
    }

    #[cfg(not(feature = "scrypt"))]
    #[test]
    fn rejects_scrypt_selection_without_the_scrypt_feature() {
        // In a build without the scrypt feature, selecting `Scrypt` is not backed by a
        // compiled hasher, so validation directs the deployer to the argon2 profile.
        let mut cfg = valid_config();
        cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Scrypt;
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::HasherNotEnabled {
                algorithm: "scrypt"
            })
        ));
    }

    fn mfa_with_key(key: &str) -> MfaConfig {
        MfaConfig {
            encryption_key: SecretString::from(key.to_owned()),
            issuer: "Acme".to_owned(),
            recovery_code_count: 8,
            totp_window: 1,
        }
    }

    #[test]
    fn rejects_bad_mfa_key_and_empty_issuer() {
        // A 32-byte key, base64-encoded, is the accepted case.
        let good_key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut ok = valid_config();
        ok.mfa = Some(mfa_with_key(&good_key));
        assert!(ok.validate(Environment::Production).is_ok());

        // A 16-byte key decodes to the wrong length.
        let short_key = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let mut wrong_len = valid_config();
        wrong_len.mfa = Some(mfa_with_key(&short_key));
        assert!(matches!(
            wrong_len.validate(Environment::Production),
            Err(ConfigError::MfaKeyLength { got: 16 })
        ));

        // A non-base64 key is a distinct, clearer diagnostic than a wrong length.
        let mut garbage = valid_config();
        garbage.mfa = Some(mfa_with_key("!!!not base64!!!"));
        assert!(matches!(
            garbage.validate(Environment::Production),
            Err(ConfigError::MfaKeyInvalidBase64)
        ));

        // A good key but an empty issuer.
        let mut no_issuer = valid_config();
        let mut mfa = mfa_with_key(&good_key);
        mfa.issuer = "   ".to_owned();
        no_issuer.mfa = Some(mfa);
        assert!(matches!(
            no_issuer.validate(Environment::Production),
            Err(ConfigError::MfaIssuerMissing)
        ));
    }

    #[test]
    fn rejects_mfa_toggle_without_config() {
        let mut cfg = valid_config();
        cfg.controllers.mfa = true;
        cfg.mfa = None;
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::MfaToggleWithoutConfig)
        ));
    }

    #[test]
    fn rejects_out_of_range_otp_length() {
        let mut cfg = valid_config();
        cfg.password_reset.otp_length = 3;
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::OtpLengthRange { got: 3 })
        ));
        cfg.password_reset.otp_length = 9;
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::OtpLengthRange { got: 9 })
        ));
    }

    fn google(callback: &str) -> GoogleOAuthConfig {
        GoogleOAuthConfig {
            client_id: "id".to_owned(),
            client_secret: SecretString::from("secret".to_owned()),
            callback_url: callback.to_owned(),
            scope: vec!["openid".to_owned()],
        }
    }

    #[test]
    fn google_oauth_config_default_carries_the_openid_scopes() {
        // The default supplies the canonical OpenID Connect scopes with empty credential
        // placeholders (which validation then rejects until set).
        let cfg = GoogleOAuthConfig::default();
        assert_eq!(cfg.scope, ["openid", "email", "profile"]);
        assert!(cfg.client_id.is_empty());
        assert!(cfg.callback_url.is_empty());
        assert!(cfg.client_secret.expose_secret().is_empty());
    }

    /// The `OAuthFieldMissing` field name reported for the given Google config, if any
    /// (provider asserted to be `google`).
    fn missing_field(google: GoogleOAuthConfig) -> Option<String> {
        let mut cfg = valid_config();
        cfg.oauth.google = Some(google);
        match cfg.validate(Environment::Production) {
            Err(ConfigError::OAuthFieldMissing { provider, field }) => {
                assert_eq!(provider, "google");
                Some(field)
            }
            _ => None,
        }
    }

    #[test]
    fn rejects_missing_oauth_provider_fields() {
        // Each required Google credential, when blank, is reported by name.
        let mut no_id = google("https://app.example.com/callback");
        no_id.client_id.clear();
        assert_eq!(missing_field(no_id).as_deref(), Some("client_id"));

        let mut no_secret = google("https://app.example.com/callback");
        no_secret.client_secret = SecretString::from(String::new());
        assert_eq!(missing_field(no_secret).as_deref(), Some("client_secret"));

        let mut no_callback = google("https://app.example.com/callback");
        no_callback.callback_url.clear();
        assert_eq!(missing_field(no_callback).as_deref(), Some("callback_url"));

        // A fully-populated provider produces no field error.
        assert_eq!(
            missing_field(google("https://app.example.com/callback")),
            None
        );
    }

    #[test]
    fn rejects_insecure_oauth_callback_in_production_only() {
        let mut cfg = valid_config();
        cfg.oauth.google = Some(google("http://app.example.com/callback"));
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::OAuthCallbackInsecure { .. })
        ));
        // The same insecure callback is accepted outside production.
        assert!(cfg.validate(Environment::Development).is_ok());
    }

    #[test]
    fn rejects_success_redirect_without_cookie_delivery() {
        let mut cfg = valid_config();
        cfg.token_delivery = TokenDelivery::Bearer;
        cfg.oauth.success_redirect_url = Some("https://app.example.com/done".to_owned());
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectNeedsCookie)
        ));
    }

    #[test]
    fn rejects_insecure_and_unallowlisted_redirects_in_production() {
        let mut insecure = valid_config();
        insecure.oauth.error_redirect_url = Some("http://app.example.com/err".to_owned());
        assert!(matches!(
            insecure.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectInsecure { kind, .. }) if kind == "error"
        ));
        // A relative redirect is accepted (same-origin).
        let mut relative = valid_config();
        relative.oauth.error_redirect_url = Some("/error".to_owned());
        assert!(relative.validate(Environment::Production).is_ok());

        // A protocol-relative URL (`//host`) is NOT same-origin and is rejected.
        let mut protocol_relative = valid_config();
        protocol_relative.oauth.error_redirect_url = Some("//evil.example.com/err".to_owned());
        assert!(matches!(
            protocol_relative.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectInsecure { kind, .. }) if kind == "error"
        ));

        // A backslash-after-slash URL (`/\host`) is resolved to a foreign authority by
        // browsers, so it is rejected too.
        let mut backslash_path = valid_config();
        backslash_path.oauth.error_redirect_url = Some("/\\evil.example.com".to_owned());
        assert!(matches!(
            backslash_path.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectInsecure { kind, .. }) if kind == "error"
        ));

        // The backslash-authority trick cannot smuggle a foreign host past the allow-list.
        let mut backslash_authority = valid_config();
        backslash_authority.oauth.success_redirect_url =
            Some("https://evil.example.com\\@app.example.com/done".to_owned());
        backslash_authority.oauth.redirect_allowlist = vec!["app.example.com".to_owned()];
        assert!(matches!(
            backslash_authority.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectNotAllowlisted { url }) if url.contains("evil.example.com")
        ));

        let mut not_allowed = valid_config();
        not_allowed.oauth.success_redirect_url = Some("https://evil.example.com/done".to_owned());
        not_allowed.oauth.redirect_allowlist = vec!["app.example.com".to_owned()];
        assert!(matches!(
            not_allowed.validate(Environment::Production),
            Err(ConfigError::OAuthRedirectNotAllowlisted { url }) if url.contains("evil.example.com")
        ));
        // An allow-listed host passes; the provider callback is also checked against the
        // allow-list, and relative URLs are exempt from the host check.
        let mut allowed = valid_config();
        allowed.oauth.success_redirect_url = Some("https://app.example.com/done".to_owned());
        allowed.oauth.google = Some(google("https://app.example.com/callback"));
        allowed.oauth.redirect_allowlist = vec!["app.example.com".to_owned()];
        assert!(allowed.validate(Environment::Production).is_ok());
    }

    #[test]
    fn rejects_samesite_none_without_secure() {
        let mut cfg = valid_config();
        cfg.cookies.same_site = SameSite::None;
        cfg.secure_cookies = Some(false);
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::SameSiteNoneRequiresSecure)
        ));
        // SameSite=None is fine once cookies are secure.
        cfg.secure_cookies = Some(true);
        assert!(cfg.validate(Environment::Production).is_ok());
    }

    #[test]
    fn rejects_non_default_prefix_without_explicit_refresh_path() {
        let mut cfg = valid_config();
        cfg.route_prefix = "api-auth".to_owned();
        // refresh_cookie_path left at the "/auth" default.
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::RefreshPathMismatch { prefix }) if prefix == "api-auth"
        ));
        // Setting an explicit refresh path clears the mismatch.
        cfg.cookies.refresh_cookie_path = "/api-auth".to_owned();
        assert!(cfg.validate(Environment::Production).is_ok());
    }

    #[test]
    fn resolved_config_derives_a_deterministic_independent_hmac_key() {
        // The derived key must be a deterministic function of the secret and differ when
        // the secret differs, so rotating the JWT secret rotates the identifier key.
        let cfg = valid_config();
        let resolved = ResolvedConfig::new(cfg, Environment::Production, true);
        assert!(resolved.secure_cookies());
        assert_eq!(resolved.environment(), Environment::Production);
        assert_eq!(resolved.config().jwt.refresh_expires_in_days, 7);

        // Recompute the key independently and compare.
        let secret = "0123456789abcdef0123456789abcdef";
        let mut expected_input = HMAC_KEY_LABEL.to_vec();
        expected_input.extend_from_slice(secret.as_bytes());
        assert_eq!(resolved.hmac_key(), &sha256(&expected_input));

        let mut other = valid_config();
        other.jwt.secret = SecretString::from("fedcba9876543210fedcba9876543210".to_owned());
        let other_resolved = ResolvedConfig::new(other, Environment::Test, false);
        assert_ne!(resolved.hmac_key(), other_resolved.hmac_key());
        assert!(!other_resolved.secure_cookies());
    }

    #[test]
    fn url_host_extracts_authority_and_treats_relative_as_same_origin() {
        // Drives the host-extraction helper across absolute, port/userinfo, and relative
        // forms — the basis of the allow-list check.
        assert_eq!(
            url_host("https://app.example.com/path"),
            Some("app.example.com".to_owned())
        );
        assert_eq!(
            url_host("https://user@host.example.com:8443/p"),
            Some("host.example.com".to_owned())
        );
        assert_eq!(url_host("/relative/path"), None);
        assert_eq!(url_host("https://"), None);
        // A protocol-relative URL resolves to its authority, so its host is extracted (not
        // treated as same-origin) — the basis for rejecting `//evil.com` redirects.
        assert_eq!(
            url_host("//evil.example.com/path"),
            Some("evil.example.com".to_owned())
        );
        // Userinfo tricks resolve to the real (rightmost) authority host.
        assert_eq!(
            url_host("https://app.example.com@evil.example.com/"),
            Some("evil.example.com".to_owned())
        );
        // A bracketed IPv6 literal is preserved intact (port stripped).
        assert_eq!(url_host("https://[::1]:8443/p"), Some("[::1]".to_owned()));
        // A backslash terminates the authority (browsers treat `\` as `/`), so the host is
        // `evil.example.com`, not the trailing `@allowed.example.com`.
        assert_eq!(
            url_host("https://evil.example.com\\@allowed.example.com"),
            Some("evil.example.com".to_owned())
        );
        // An empty authority is not a usable host.
        assert_eq!(url_host("https:///path"), None);
        assert!(host_allowlisted(
            "/relative",
            &["app.example.com".to_owned()]
        ));
        // A protocol-relative host is checked against the allow-list, never auto-allowed.
        assert!(!host_allowlisted(
            "//evil.example.com",
            &["app.example.com".to_owned()]
        ));
        // The backslash-authority trick does not slip a foreign host past the allow-list.
        assert!(!host_allowlisted(
            "https://evil.example.com\\@allowed.example.com",
            &["allowed.example.com".to_owned()]
        ));
        // Host comparison is ASCII-case-insensitive (DNS hostnames are case-insensitive).
        assert!(host_allowlisted(
            "https://APP.Example.COM/x",
            &["app.example.com".to_owned()]
        ));
        // `/`-rooted same-origin detection rejects the `//` and `/\` foreign-authority forms.
        assert!(is_same_origin_path("/error"));
        assert!(!is_same_origin_path("//evil.example.com"));
        assert!(!is_same_origin_path("/\\evil.example.com"));
        // An empty-host https URL is not a valid secure absolute target.
        assert!(!is_secure_https("https:///path"));
        assert!(is_secure_https("https://app.example.com/done"));
        // The entropy of an empty string is zero (the secret-length rule fires first in
        // `validate`, so this guards the standalone helper).
        assert_eq!(shannon_entropy(""), 0.0);
    }
}
