//! Startup validation and config resolution. [`AuthConfig::validate`] checks every
//! config-intrinsic invariant and resolves `secure_cookies` from the [`Environment`]; the
//! builder layers the collaborator-presence checks on top and assembles a
//! [`ResolvedConfig`], which also carries the derived identifier-hashing key.

use std::collections::HashMap;

use base64::Engine;
use bymax_auth_crypto::mac::sha256;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::{AuthConfig, Environment, PasswordConfig, SameSite, TokenDelivery};
use crate::ConfigError;
use crate::traits::TOKEN_EPOCH_RETENTION_SECS;

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
    hmac_key: SecretBox<[u8; 64]>,
    /// The same derivation over each retired secret, for verification-only reads during a
    /// rotation. Empty unless one is in progress.
    previous_hmac_keys: Vec<SecretBox<[u8; 64]>>,
}

impl ResolvedConfig {
    /// Assemble a resolved config, deriving the identifier-hashing key from the JWT secret.
    /// Callers pass the already-validated config, the resolved environment, and the
    /// resolved `secure_cookies` value.
    pub(crate) fn new(config: AuthConfig, environment: Environment, secure_cookies: bool) -> Self {
        let hmac_key = derive_hmac_key(config.jwt.secret.expose_secret());
        let previous_hmac_keys = config
            .jwt
            .previous_secrets
            .iter()
            .map(|secret| derive_hmac_key(secret.expose_secret()))
            .collect();
        Self {
            config,
            environment,
            secure_cookies,
            hmac_key,
            previous_hmac_keys,
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

    /// The derived identifier-hashing key — the ASCII hex of `SHA-256("{label}:{jwt.secret}")`
    /// — used to HMAC low-entropy Redis identifiers so the signing key and the
    /// identifier-hashing key are cryptographically independent. The 64-byte ASCII-hex
    /// encoding is part of the cross-implementation contract, not an implementation detail:
    /// `nest-auth` derives the same key the same way, so a key derived from the raw digest
    /// would silently hash every identifier differently and split the shared keyspace.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8; 64] {
        self.hmac_key.expose_secret()
    }

    /// The identifier-hashing keys derived from `jwt.previous_secrets`, in the order given.
    /// Empty unless a rotation is in progress.
    ///
    /// Read-only, like the secrets they come from: a recovery-code digest written under a
    /// retired key still verifies, so rotating the signing secret does not lock users out of
    /// the codes they printed and filed. Nothing is ever newly written under one — a code that
    /// matches here is consumed and the set is regenerated under the current key.
    #[must_use]
    pub fn previous_hmac_keys(&self) -> Vec<[u8; 64]> {
        self.previous_hmac_keys
            .iter()
            .map(|key| *key.expose_secret())
            .collect()
    }

    /// Whether `held_role` satisfies a required dashboard/tenant role under the dashboard
    /// hierarchy: a role satisfies itself, or any role it transitively includes (the hierarchy
    /// is fully denormalized, so this is a single-level membership test). A role absent from the
    /// hierarchy satisfies only itself. This consults ONLY [`crate::config::RolesConfig::hierarchy`],
    /// never the platform hierarchy, so a platform role can never satisfy a dashboard-role check.
    #[must_use]
    pub fn dashboard_role_satisfies(&self, held_role: &str, required_role: &str) -> bool {
        role_satisfies(&self.config.roles.hierarchy, held_role, required_role)
    }

    /// Whether `held_role` satisfies a required platform role under the platform hierarchy.
    /// Returns `false` when no platform hierarchy is configured (the platform domain is then
    /// disabled, so no platform role is grantable). This consults ONLY
    /// [`crate::config::RolesConfig::platform_hierarchy`], never the dashboard hierarchy, so a
    /// dashboard/tenant role can never satisfy a platform-role check — the domains are isolated.
    #[must_use]
    pub fn platform_role_satisfies(&self, held_role: &str, required_role: &str) -> bool {
        match self.config.roles.platform_hierarchy.as_ref() {
            Some(hierarchy) => role_satisfies(hierarchy, held_role, required_role),
            None => false,
        }
    }

    /// Decode the configured MFA encryption key into its 32-byte AES-256-GCM form. `None` when
    /// MFA is not configured. Startup validation already proved a configured key decodes to
    /// exactly 32 bytes, so a present `config.mfa` always yields `Some`. The transient decoded
    /// buffer is zeroized on drop.
    #[cfg(feature = "mfa")]
    #[must_use]
    pub(crate) fn mfa_encryption_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let mfa = self.config.mfa.as_ref()?;
        decode_aes256_key(mfa.encryption_key.expose_secret())
    }

    /// The MFA keys retired by a rotation, decoded, in the order configured. Empty unless a
    /// rotation is in progress.
    ///
    /// Decrypt-only: a stored TOTP secret records no key identifier, so without these a change
    /// of `mfa.encryption_key` makes every stored secret undecryptable at once.
    #[cfg(feature = "mfa")]
    #[must_use]
    pub(crate) fn previous_mfa_encryption_keys(&self) -> Vec<Zeroizing<[u8; 32]>> {
        self.config
            .mfa
            .as_ref()
            .map(|mfa| {
                mfa.previous_encryption_keys
                    .iter()
                    .filter_map(|key| decode_aes256_key(key.expose_secret()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Decode a base64 AES-256 key, returning `None` unless it is exactly 32 bytes.
fn decode_aes256_key(encoded: &str) -> Option<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(decode_base64_any(encoded)?);
    <[u8; 32]>::try_from(decoded.as_slice())
        .ok()
        .map(Zeroizing::new)
}

/// Lowercase hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Derive the identifier-hashing key as the lowercase hex encoding of
/// `SHA-256("{label}:{secret}")`, in its 64-byte ASCII form.
///
/// Two details are load-bearing and must not drift, because nest-auth derives the same key
/// and the two backends key the same Redis identifiers with it:
///
/// - the `:` between label and secret is explicit domain separation. Concatenating them
///   directly makes the preimage ambiguous, so a different label/secret split could produce
///   the same key.
/// - the key is the **hex text**, not the raw digest. A raw-byte key would be equally sound
///   cryptographically, but it would not match what nest-auth already uses, and every
///   HMAC-derived key — brute-force lockout, OTP, resend cooldown, MFA setup, anti-replay —
///   would land in a different Redis slot on each backend.
///
/// The buffer holding the secret and the intermediate digest are both zeroized on drop, and
/// the hex is written straight into the fixed-size key so no heap copy of the key material
/// outlives this call.
fn derive_hmac_key(secret: &str) -> SecretBox<[u8; 64]> {
    let mut input = Zeroizing::new(Vec::with_capacity(HMAC_KEY_LABEL.len() + 1 + secret.len()));
    input.extend_from_slice(HMAC_KEY_LABEL);
    input.push(b':');
    input.extend_from_slice(secret.as_bytes());

    let digest = Zeroizing::new(sha256(&input));
    let mut key = [0u8; 64];
    for (pair, byte) in key.chunks_exact_mut(2).zip(digest.iter()) {
        pair[0] = HEX_ALPHABET[usize::from(byte >> 4)];
        pair[1] = HEX_ALPHABET[usize::from(byte & 0x0f)];
    }
    SecretBox::new(Box::new(key))
}

/// Hard ceiling on `jwt.refresh_grace_window`, in seconds (five minutes). Deliberately far
/// above the 30-second default and far below anything that could be mistaken for a session
/// policy. `nest-auth` enforces the identical bound.
const MAX_REFRESH_GRACE_WINDOW_SECS: u64 = 300;

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

        // Rule 2b: every retired secret is held to the same bar. They still verify tokens and
        // still read recovery-code digests, so a weak entry is exactly as forgeable as a weak
        // current secret would be — the rotation list is not a place where the bar drops. A
        // retired secret equal to the current one is rejected too: it means the rotation never
        // happened, and a configuration that reads as rotated while nothing changed is worse
        // than one that never claimed to.
        let mut seen: Vec<&str> = vec![secret];
        for previous in &self.jwt.previous_secrets {
            let previous = previous.expose_secret();
            let len = previous.chars().count();
            if len < MIN_SECRET_LEN {
                return Err(ConfigError::JwtSecretTooShort { len });
            }
            let entropy = shannon_entropy(previous);
            if entropy < MIN_SECRET_ENTROPY {
                return Err(ConfigError::JwtSecretLowEntropy { entropy });
            }
            if seen.contains(&previous) {
                return Err(ConfigError::PreviousSecretRepeated);
            }
            seen.push(previous);
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
        // The relative bound above is not enough on its own: a 6-day window under a 7-day
        // refresh passes it. This window is the span in which an already-consumed refresh
        // token still buys a session, so it is the replay window for a stolen one — it exists
        // to cover a single network retry, measured in seconds, not a policy knob measured in
        // days. `nest-auth` enforces the identical ceiling.
        if grace > MAX_REFRESH_GRACE_WINDOW_SECS {
            return Err(ConfigError::RefreshGraceCeiling {
                got: grace,
                max: MAX_REFRESH_GRACE_WINDOW_SECS,
            });
        }

        // Rule 3c: the two values that decide whether the account lockout exists at all.
        // `window` is handed to the store as the counter's EXPIRE, and Redis DELETES a key on
        // `EXPIRE key 0` — a zero window destroys every failure counter as it is created, the
        // count never exceeds one, and the lockout silently never engages while the config
        // still reads as enabled. `max_attempts` of 0 is the opposite failure: a fresh counter
        // already satisfies `count >= 0`, so every account is locked out permanently.
        if self.brute_force.window.as_secs() == 0 {
            return Err(ConfigError::BruteForceWindowInvalid);
        }
        if !(1..=100).contains(&self.brute_force.max_attempts) {
            return Err(ConfigError::BruteForceAttemptsRange {
                got: self.brute_force.max_attempts,
            });
        }

        // Rule 4b: the access-token lifetime must fit inside the token-epoch retention window.
        // A longer-lived access token could outlive the stored epoch that revokes it, so
        // `current_epoch` would fall back to `0` and a reset-revoked token would verify again.
        let access = self.jwt.access_expires_in.as_secs();
        if access > TOKEN_EPOCH_RETENTION_SECS {
            return Err(ConfigError::AccessLifetimeExceedsEpochRetention {
                access,
                retention: TOKEN_EPOCH_RETENTION_SECS,
            });
        }

        // Rule 4c: every retired MFA key is held to the same bar as the current one. They still
        // decrypt stored secrets, so a malformed entry would throw at the first challenge
        // instead of at startup — and a key equal to the current one means the rotation being
        // described did not happen.
        if let Some(mfa) = self.mfa.as_ref() {
            let mut seen: Vec<&str> = vec![mfa.encryption_key.expose_secret()];
            for previous in &mfa.previous_encryption_keys {
                let previous = previous.expose_secret();
                if decode_aes256_key(previous).is_none() {
                    return Err(ConfigError::MfaKeyInvalidBase64);
                }
                if seen.contains(&previous) {
                    return Err(ConfigError::PreviousSecretRepeated);
                }
                seen.push(previous);
            }
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

        // Rule 13b: the two MFA parameters that decide how much a second factor is worth.
        // `totp_window` is counted in 30-second steps on either side of now, so `2n + 1` codes
        // are valid at once: three at the default of 1, but 121 at 60 — a six-digit code a
        // hundred times easier to guess than its length suggests. `recovery_code_count` of
        // zero enrols an account with no way back if the authenticator is lost. Every sibling
        // security parameter carries a bound; these two decide whether MFA is worth anything.
        if let Some(mfa) = self.mfa.as_ref() {
            if mfa.totp_window > 10 {
                return Err(ConfigError::TotpWindowRange {
                    got: mfa.totp_window,
                    valid: u16::from(mfa.totp_window) * 2 + 1,
                });
            }
            if !(1..=50).contains(&mfa.recovery_code_count) {
                return Err(ConfigError::RecoveryCodeCountRange {
                    got: mfa.recovery_code_count,
                });
            }
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

        // Rule 19b: the trusted-origin allow-list and the SameSite posture must agree. The
        // list only ever matters under `None` — the one posture where the browser sends the
        // session cookie on a cross-site request — so either half without the other is a
        // configuration that fails quietly rather than loudly.
        self.validate_trusted_origins()?;

        // Rule 20: a non-default route prefix requires an explicit refresh cookie path.
        if self.route_prefix != "auth" && self.cookies.refresh_cookie_path == "/auth" {
            return Err(ConfigError::RefreshPathMismatch {
                prefix: self.route_prefix.clone(),
            });
        }

        Ok(secure_cookies)
    }

    /// Validate that `cookies.trusted_origins` and `cookies.same_site` agree, and that every
    /// entry is a bare absolute origin.
    ///
    /// The shape check is deliberately strict: an entry must be exactly scheme, host and an
    /// optional port, with nothing after the authority. A trailing slash, a path, or a naked
    /// hostname would all be silently blocked at request time instead — an `Origin` header is
    /// never any of those — so they are refused here where the message can say why.
    fn validate_trusted_origins(&self) -> Result<(), ConfigError> {
        let cross_site = self.cookies.same_site == SameSite::None;
        let listed = !self.cookies.trusted_origins.is_empty();

        if cross_site && !listed {
            return Err(ConfigError::TrustedOriginsRequired);
        }
        if !cross_site && listed {
            return Err(ConfigError::TrustedOriginsUnused);
        }
        for origin in &self.cookies.trusted_origins {
            if !is_bare_origin(origin) {
                return Err(ConfigError::TrustedOriginMalformed {
                    origin: origin.clone(),
                });
            }
        }
        Ok(())
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

/// Whether `held_role` satisfies `required_role` under a denormalized role `hierarchy`: a role
/// always satisfies itself, and otherwise satisfies any role listed among the roles it
/// transitively includes. A `held_role` absent from the hierarchy satisfies only itself, so an
/// unknown or cross-domain role can never satisfy a check against a different domain's roles.
/// The membership test is a single-level lookup because the hierarchy is fully denormalized.
fn role_satisfies(
    hierarchy: &HashMap<String, Vec<String>>,
    held_role: &str,
    required_role: &str,
) -> bool {
    if held_role == required_role {
        return true;
    }
    hierarchy
        .get(held_role)
        .is_some_and(|included| included.iter().any(|role| role == required_role))
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

    // scrypt's memory cost is `128 * N * r`, so the block size is a multiplier on the hardness
    // the cost-factor floor exists to guarantee: at `r = 1` the same N buys an eighth of the
    // memory and the floor quietly stops meaning what it says. The weakening is invisible
    // precisely because the parameter that IS bounded is still intact.
    #[cfg(feature = "scrypt")]
    if password.scrypt.block_size < 8 {
        return Err(ConfigError::ScryptBlockSize {
            got: password.scrypt.block_size,
        });
    }

    // Below 1 is not a weaker setting but an invalid one — the hasher rejects it at the first
    // password, which is a credential path failing at runtime over something startup could
    // have caught.
    #[cfg(feature = "scrypt")]
    if password.scrypt.parallelization < 1 {
        return Err(ConfigError::ScryptParallelization {
            got: password.scrypt.parallelization,
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

/// Whether `value` is exactly an origin: `scheme://host` with an optional `:port` and
/// nothing after the authority.
///
/// The `Origin` header a browser sends is always in this form, and the comparison against it
/// is verbatim, so anything else configured here can never match. Userinfo is rejected too —
/// it never appears in an `Origin`, and `https://evil.com@app.example.com` reading as
/// "app.example.com" to a careless parser is precisely the confusion worth refusing outright.
fn is_bare_origin(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return false;
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '\\', '@']) {
        return false;
    }
    url_host(value).is_some()
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
    fn admits_a_secret_whose_entropy_sits_exactly_on_the_floor() {
        // The floor is inclusive: 3.5 bits/char is *acceptable*, not rejected. Built to land
        // on the constant exactly — eight symbols twice (4 bits each) and four symbols four
        // times (3 bits each) sum to 3.5 with no rounding — because only a secret at the
        // boundary can tell `<` from `<=`, and rejecting one at the floor would refuse a
        // configuration the documented rule admits.
        let mut cfg = valid_config();
        cfg.jwt.secret = SecretString::from("aabbccddeeffgghhiiiijjjjkkkkllll".to_owned());
        assert!((shannon_entropy("aabbccddeeffgghhiiiijjjjkkkkllll") - 3.5).abs() < f64::EPSILON);
        assert!(cfg.validate(Environment::Production).is_ok());
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
    fn rejects_an_access_lifetime_that_outlives_the_token_epoch_retention_window() {
        // An access token allowed to outlive the stored epoch would let the epoch key expire
        // while a pre-bump token is still inside its own `exp`, so `current_epoch` would read
        // `0`, the staleness test would stop firing, and a reset-revoked token would verify
        // again. The boundary itself is legal — only strictly longer is rejected.
        let mut over = valid_config();
        over.jwt.access_expires_in = std::time::Duration::from_secs(TOKEN_EPOCH_RETENTION_SECS + 1);
        assert!(matches!(
            over.validate(Environment::Production),
            Err(ConfigError::AccessLifetimeExceedsEpochRetention {
                access,
                retention
            }) if access == TOKEN_EPOCH_RETENTION_SECS + 1
                && retention == TOKEN_EPOCH_RETENTION_SECS
        ));

        let mut exact = valid_config();
        exact.jwt.access_expires_in = std::time::Duration::from_secs(TOKEN_EPOCH_RETENTION_SECS);
        assert!(exact.validate(Environment::Production).is_ok());
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

        // The floor is inclusive: 16384 is the documented minimum, not the first rejected
        // value. Only a config sitting exactly on it can tell the two apart, and refusing it
        // would reject the very parameters the error message tells an operator to use.
        let mut at_floor = valid_config();
        at_floor.password.scrypt.cost_factor = 16_384;
        assert!(at_floor.validate(Environment::Production).is_ok());
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

        // Both floors are inclusive — a deployment configured at exactly the OWASP minimum
        // is compliant, and rejecting it would contradict the error the rule raises.
        let mut at_floor = valid_config();
        at_floor.password.argon2.memory_kib = 19_456;
        at_floor.password.argon2.iterations = 2;
        assert!(at_floor.validate(Environment::Production).is_ok());
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
            previous_encryption_keys: Vec::new(),
            encryption_key: SecretString::from(key.to_owned()),
            issuer: "Acme".to_owned(),
            recovery_code_count: 8,
            totp_window: 1,
        }
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn the_mfa_parameters_that_decide_a_second_factor_are_bounded() {
        // `totp_window` is counted in 30-second steps on either side of now, so `2n + 1` codes
        // are valid at once. At 60 that is 121, and a six-digit code is a hundred times easier
        // to guess than its length suggests — the second factor is worth almost nothing while
        // the config still reads as "MFA enabled". Every sibling parameter carries a bound.
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut wide = valid_config();
        wide.mfa = Some(MfaConfig {
            totp_window: 60,
            ..mfa_with_key(&key)
        });
        assert!(matches!(
            wide.validate(Environment::Test),
            Err(ConfigError::TotpWindowRange {
                got: 60,
                valid: 121
            })
        ));

        // The edges are accepted: 0 is a deliberate hardening (no tolerance at all), 10 is the
        // generous ceiling. A bound that refused a legitimate tolerance would be an outage.
        for window in [0u8, 1, 10] {
            let mut ok = valid_config();
            ok.mfa = Some(MfaConfig {
                totp_window: window,
                ..mfa_with_key(&key)
            });
            assert!(ok.validate(Environment::Test).is_ok());
        }

        // Zero recovery codes enrols an account with no way back if the authenticator is lost,
        // and nothing in the flow reports anything wrong — the user finds out at the worst
        // possible moment.
        let mut none = valid_config();
        none.mfa = Some(MfaConfig {
            recovery_code_count: 0,
            ..mfa_with_key(&key)
        });
        assert!(matches!(
            none.validate(Environment::Test),
            Err(ConfigError::RecoveryCodeCountRange { got: 0 })
        ));

        let mut many = valid_config();
        many.mfa = Some(MfaConfig {
            recovery_code_count: 51,
            ..mfa_with_key(&key)
        });
        assert!(matches!(
            many.validate(Environment::Test),
            Err(ConfigError::RecoveryCodeCountRange { got: 51 })
        ));
    }

    #[test]
    fn the_grace_window_and_lockout_knobs_are_bounded() {
        // The grace window is the span in which an ALREADY-CONSUMED refresh token still buys a
        // session, so it is precisely the replay window for a stolen one. The relative bound
        // ("< refresh lifetime") lets a 6-day window under a 7-day refresh through, which is a
        // days-long replay window wearing the name of a network retry.
        let mut wide = valid_config();
        wide.jwt.refresh_grace_window = std::time::Duration::from_secs(6 * 86_400);
        wide.jwt.refresh_expires_in_days = 7;
        assert!(matches!(
            wide.validate(Environment::Test),
            Err(ConfigError::RefreshGraceCeiling { max: 300, .. })
        ));

        // The edges hold: the default, the ceiling, and 0 (grace disabled outright).
        for secs in [0u64, 30, 300] {
            let mut ok = valid_config();
            ok.jwt.refresh_grace_window = std::time::Duration::from_secs(secs);
            assert!(
                ok.validate(Environment::Test).is_ok(),
                "grace of {secs}s must be accepted"
            );
        }

        // A zero brute-force window reaches the store as `EXPIRE key 0`, which DELETES the key:
        // every failure counter is destroyed as it is created, the count never exceeds one, and
        // the lockout silently never engages while the config still reads as enabled.
        let mut no_window = valid_config();
        no_window.brute_force.window = std::time::Duration::from_secs(0);
        assert!(matches!(
            no_window.validate(Environment::Test),
            Err(ConfigError::BruteForceWindowInvalid)
        ));

        // Zero attempts is the opposite failure: a fresh counter already satisfies
        // `count >= 0`, so every account is locked out permanently. A huge threshold disables
        // the lockout as thoroughly as switching it off.
        for got in [0u32, 101, 1_000_000] {
            let mut bad = valid_config();
            bad.brute_force.max_attempts = got;
            let refused = matches!(
                bad.validate(Environment::Test),
                Err(ConfigError::BruteForceAttemptsRange { got: reported }) if reported == got
            );
            assert!(refused, "max_attempts of {got} must be refused");
        }

        for got in [1u32, 5, 100] {
            let mut ok = valid_config();
            ok.brute_force.max_attempts = got;
            assert!(ok.validate(Environment::Test).is_ok());
        }
    }

    #[cfg(feature = "scrypt")]
    #[test]
    fn the_scrypt_parameters_that_carry_the_memory_hardness_are_bounded() {
        // The memory cost is `128 * N * r`. Bounding N alone is not enough: at `r = 1` the same
        // cost factor buys an eighth of the memory, and the floor quietly stops meaning what it
        // says — invisibly, because the parameter that IS bounded is still intact.
        let mut thin = valid_config();
        thin.password.scrypt.block_size = 1;
        assert!(matches!(
            thin.validate(Environment::Test),
            Err(ConfigError::ScryptBlockSize { got: 1 })
        ));

        // Below 1 is not weaker but invalid: the hasher rejects it at the first password, which
        // is a credential path failing at runtime over something startup could have caught.
        let mut zero = valid_config();
        zero.password.scrypt.parallelization = 0;
        assert!(matches!(
            zero.validate(Environment::Test),
            Err(ConfigError::ScryptParallelization { got: 0 })
        ));

        // The defaults sit at the floor and are accepted.
        let mut ok = valid_config();
        ok.password.scrypt.block_size = 8;
        ok.password.scrypt.parallelization = 1;
        assert!(ok.validate(Environment::Test).is_ok());
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn resolves_the_configured_mfa_key_and_none_without_mfa() {
        // The key that comes back is the configured one, byte for byte — the stored TOTP
        // secrets are sealed with it, so a resolver that answered with a fixed or zeroed key
        // would seal every deployment's secrets under the same one and none of the MFA tests
        // would notice: they only ever round-trip through the same resolver.
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut cfg = valid_config();
        cfg.mfa = Some(mfa_with_key(&key));
        let resolved = ResolvedConfig::new(cfg, Environment::Test, false);
        let got = resolved.mfa_encryption_key();
        assert!(matches!(&got, Some(k) if **k == [7u8; 32]));

        // No MFA configured: no key at all, rather than a default one.
        let plain = ResolvedConfig::new(valid_config(), Environment::Test, false);
        assert!(plain.mfa_encryption_key().is_none());
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
        cfg.cookies.trusted_origins = vec!["https://app.example.com".to_owned()];
        cfg.secure_cookies = Some(false);
        assert!(matches!(
            cfg.validate(Environment::Production),
            Err(ConfigError::SameSiteNoneRequiresSecure)
        ));
        // SameSite=None is fine once cookies are secure and an origin is named.
        cfg.secure_cookies = Some(true);
        assert!(cfg.validate(Environment::Production).is_ok());
    }

    #[test]
    fn the_trusted_origin_list_and_the_same_site_posture_must_agree() {
        // The list only matters under `None`: that is the one posture where the browser sends
        // the session cookie cross-site, so it is the only one with a cross-origin caller to
        // authorize. Either half without the other fails quietly — `None` with no list rejects
        // every cross-site call, a list under `Lax` is never consulted — so both are refused.
        let mut none_without_list = valid_config();
        none_without_list.cookies.same_site = SameSite::None;
        none_without_list.secure_cookies = Some(true);
        assert!(matches!(
            none_without_list.validate(Environment::Production),
            Err(ConfigError::TrustedOriginsRequired)
        ));

        let mut list_without_none = valid_config();
        list_without_none.cookies.trusted_origins = vec!["https://app.example.com".to_owned()];
        assert!(matches!(
            list_without_none.validate(Environment::Production),
            Err(ConfigError::TrustedOriginsUnused)
        ));
    }

    #[test]
    fn rejects_a_trusted_origin_that_is_not_a_bare_origin() {
        // Every entry is compared verbatim against the `Origin` header, which is always
        // `scheme://host[:port]`. A trailing slash, a path, a naked hostname or embedded
        // userinfo can never match, so the origin they were meant to allow would be silently
        // blocked — refused here instead, where the message can say why.
        for malformed in [
            "https://app.example.com/",
            "https://app.example.com/callback",
            "app.example.com",
            "https://evil.example.com@app.example.com",
            "https://",
            "not a url",
            "://app.example.com",
            // Punctuation the scheme grammar does not admit — accepting it would widen what
            // counts as an origin beyond what a browser can ever send.
            "ht!tp://app.example.com",
        ] {
            let mut cfg = valid_config();
            cfg.cookies.same_site = SameSite::None;
            cfg.secure_cookies = Some(true);
            cfg.cookies.trusted_origins = vec![malformed.to_owned()];
            assert!(
                matches!(
                    cfg.validate(Environment::Production),
                    Err(ConfigError::TrustedOriginMalformed { ref origin }) if origin == malformed
                ),
                "expected {malformed} to be rejected"
            );
        }

        // A port and an IPv6 literal are both part of an origin and must survive, and so do
        // the punctuation-bearing schemes a browser really sends: an extension page's
        // `Origin` is `chrome-extension://<id>`, and the scheme grammar admits `+`, `-` and
        // `.` alongside the alphanumerics.
        for accepted in [
            "http://localhost:3000",
            "https://[::1]:8443",
            "chrome-extension://abcdefghijklmnop",
            "coap+tcp://gateway.example.com",
            "web.socket://relay.example.com",
        ] {
            let mut cfg = valid_config();
            cfg.cookies.same_site = SameSite::None;
            cfg.secure_cookies = Some(true);
            cfg.cookies.trusted_origins = vec![accepted.to_owned()];
            assert!(
                cfg.validate(Environment::Production).is_ok(),
                "expected {accepted} to be accepted"
            );
        }
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
    fn role_hierarchies_are_provably_isolated_in_both_directions() {
        // A config wiring a dashboard hierarchy (ADMIN ⊇ MEMBER) and a DISJOINT platform
        // hierarchy (SUPER_ADMIN ⊇ SUPPORT) proves the two domains never cross-satisfy.
        let mut cfg = valid_config();
        cfg.roles.hierarchy = HashMap::from([
            ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
            ("MEMBER".to_owned(), Vec::new()),
        ]);
        cfg.roles.platform_hierarchy = Some(HashMap::from([
            ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
            ("SUPPORT".to_owned(), Vec::new()),
        ]));
        let resolved = ResolvedConfig::new(cfg, Environment::Test, false);

        // Dashboard hierarchy: a role satisfies itself and the roles it includes.
        assert!(resolved.dashboard_role_satisfies("ADMIN", "ADMIN"));
        assert!(resolved.dashboard_role_satisfies("ADMIN", "MEMBER"));
        assert!(!resolved.dashboard_role_satisfies("MEMBER", "ADMIN"));

        // Platform hierarchy: likewise within its own domain.
        assert!(resolved.platform_role_satisfies("SUPER_ADMIN", "SUPER_ADMIN"));
        assert!(resolved.platform_role_satisfies("SUPER_ADMIN", "SUPPORT"));
        assert!(!resolved.platform_role_satisfies("SUPPORT", "SUPER_ADMIN"));

        // Direction 1 — a tenant role can NEVER satisfy a platform-role check: the dashboard
        // ADMIN/MEMBER roles do not satisfy any platform role, even one named identically were
        // it absent from the platform set.
        assert!(!resolved.platform_role_satisfies("ADMIN", "SUPER_ADMIN"));
        assert!(!resolved.platform_role_satisfies("ADMIN", "SUPPORT"));
        assert!(!resolved.platform_role_satisfies("MEMBER", "SUPPORT"));

        // Direction 2 — a platform role can NEVER satisfy a tenant-role check.
        assert!(!resolved.dashboard_role_satisfies("SUPER_ADMIN", "ADMIN"));
        assert!(!resolved.dashboard_role_satisfies("SUPER_ADMIN", "MEMBER"));
        assert!(!resolved.dashboard_role_satisfies("SUPPORT", "MEMBER"));

        // MEMBER lives only in the dashboard hierarchy: a platform check for it is satisfied
        // only reflexively (role-equals-itself), never via inclusion — and crucially a dashboard
        // MEMBER cannot reach any *other* platform role, which is the isolation that matters.
        assert!(!resolved.platform_role_satisfies("MEMBER", "SUPER_ADMIN"));
    }

    #[test]
    fn platform_role_check_is_false_without_a_platform_hierarchy() {
        // With no platform hierarchy configured the platform domain is off, so no platform role
        // is grantable — every platform-role check is false, even a role-equals-itself query.
        let mut cfg = valid_config();
        cfg.roles.platform_hierarchy = None;
        let resolved = ResolvedConfig::new(cfg, Environment::Test, false);
        assert!(!resolved.platform_role_satisfies("SUPER_ADMIN", "SUPER_ADMIN"));
        assert!(!resolved.platform_role_satisfies("ADMIN", "ADMIN"));
    }

    #[test]
    fn role_satisfies_self_for_a_role_absent_from_the_hierarchy() {
        // A role not present as a key still satisfies itself (reflexive) but nothing else.
        let hierarchy = HashMap::from([("ADMIN".to_owned(), vec!["MEMBER".to_owned()])]);
        assert!(role_satisfies(&hierarchy, "GHOST", "GHOST"));
        assert!(!role_satisfies(&hierarchy, "GHOST", "ADMIN"));
        assert!(!role_satisfies(&hierarchy, "GHOST", "MEMBER"));
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

        // Recompute the key independently and compare, including the ':' separator and the
        // hex encoding that make up the contract.
        let secret = "0123456789abcdef0123456789abcdef";
        let mut expected_input = HMAC_KEY_LABEL.to_vec();
        expected_input.push(b':');
        expected_input.extend_from_slice(secret.as_bytes());
        let expected_hex = to_hex_string(&sha256(&expected_input));
        assert_eq!(resolved.hmac_key().as_slice(), expected_hex.as_bytes());

        let mut other = valid_config();
        other.jwt.secret = SecretString::from("fedcba9876543210fedcba9876543210".to_owned());
        let other_resolved = ResolvedConfig::new(other, Environment::Test, false);
        assert_ne!(resolved.hmac_key(), other_resolved.hmac_key());
        assert!(!other_resolved.secure_cookies());
    }

    /// The first HMAC vector from the shared cross-implementation wire contract, as
    /// `(secret, derived key hex, identifier message, identifier hex)`.
    ///
    /// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
    /// derives the same key and reads the same Redis identifiers. Sourcing the vector from it
    /// keeps one copy of the truth instead of two that can drift apart silently.
    fn contract_hmac_vector() -> (String, String, String, String) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        let field = |name: &str| -> String {
            root.get("hmacKeyDerivation")
                .and_then(|d| d.get("vectors"))
                .and_then(serde_json::Value::as_array)
                .and_then(|v| v.first())
                .and_then(|v| v.get(name))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        (
            field("secret"),
            field("derivedKeyHex"),
            field("identifierMessage"),
            field("identifierHex"),
        )
    }

    /// Hex-encode for the test's independent recomputation of the derived key.
    fn to_hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hmac_key_matches_the_nest_auth_known_answer() {
        // CROSS-IMPLEMENTATION KNOWN-ANSWER TEST. The two backends key the same Redis
        // identifiers with this value, so the derivation is a wire contract, not an internal
        // detail. The constants below were produced by nest-auth's own primitives:
        //
        //   createHash('sha256').update(`${LABEL}:${secret}`, 'utf8').digest('hex')
        //   createHmac('sha256', thatHexString).update(message, 'utf8').digest('hex')
        //
        // nest-auth carries the identical vectors. If either side changes its separator, its
        // hash, or the encoding it feeds the HMAC, exactly one of the two suites goes red
        // instead of the split appearing later as sessions and lockouts that silently miss
        // each other in production.
        // Read from the shared contract rather than repeating it: nest-auth holds the same file
        // byte-identical, so a change to the derivation on either side turns that side red here.
        let vector = contract_hmac_vector();
        let secret = vector.0.as_str();
        let expected_key = vector.1.as_str();
        let identifier_message = vector.2.as_str();
        let expected_identifier = vector.3.as_str();

        let mut cfg = valid_config();
        cfg.jwt.secret = SecretString::from(secret.to_owned());
        let resolved = ResolvedConfig::new(cfg, Environment::Production, true);

        // The key itself is the 64-character hex text, not the raw 32-byte digest.
        assert_eq!(resolved.hmac_key().as_slice(), expected_key.as_bytes());

        // And an identifier keyed with it matches byte for byte what nest-auth writes.
        let identifier = to_hex_string(&bymax_auth_crypto::mac::hmac_sha256(
            resolved.hmac_key(),
            identifier_message.as_bytes(),
        ));
        assert_eq!(identifier, expected_identifier);
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

    #[test]
    fn retired_secrets_are_held_to_the_same_bar_as_the_current_one() {
        // They still verify tokens and still read recovery-code digests, so a weak entry is
        // exactly as forgeable as a weak current secret. The rotation list is not a place where
        // the bar drops.
        let strong = "kR7pQw9zTr4XmVn2PsB6yLdG3hJ8fCxZ5aNeU1oIqW0M";
        let mut cfg = valid_config();
        cfg.jwt.secret = SecretString::from(strong.to_owned());

        // A well-formed rotation is accepted, and derives one identifier key per retired secret
        // — the keys that keep pre-rotation recovery-code digests readable.
        let mut rotating = cfg.clone();
        rotating.jwt.previous_secrets = vec![SecretString::from(
            "Zx4mQ7wLpR2nT9yB6vKdH3sJfCgA5eU8iO1rXwNqYtM0".to_owned(),
        )];
        assert!(rotating.validate(Environment::Test).is_ok());
        let resolved = ResolvedConfig::new(rotating.clone(), Environment::Test, true);
        assert_eq!(resolved.previous_hmac_keys().len(), 1);
        assert_ne!(resolved.previous_hmac_keys()[0], *resolved.hmac_key());

        // With no rotation in progress there are no retired keys at all.
        let none = ResolvedConfig::new(cfg.clone(), Environment::Test, true);
        assert!(none.previous_hmac_keys().is_empty());

        // Too short, and too repetitive: rejected by the same two rules the current secret faces.
        let mut short = cfg.clone();
        short.jwt.previous_secrets = vec![SecretString::from("too-short".to_owned())];
        assert!(matches!(
            short.validate(Environment::Test),
            Err(ConfigError::JwtSecretTooShort { .. })
        ));

        let mut flat = cfg.clone();
        flat.jwt.previous_secrets = vec![SecretString::from("a".repeat(40))];
        assert!(matches!(
            flat.validate(Environment::Test),
            Err(ConfigError::JwtSecretLowEntropy { .. })
        ));

        // The current secret repeated, and a duplicate entry: both mean the rotation being
        // described did not happen, and a config that reads as rotated while nothing changed is
        // worse than one that never claimed to.
        let mut echoed = cfg.clone();
        echoed.jwt.previous_secrets = vec![SecretString::from(strong.to_owned())];
        assert!(matches!(
            echoed.validate(Environment::Test),
            Err(ConfigError::PreviousSecretRepeated)
        ));

        let other = "Zx4mQ7wLpR2nT9yB6vKdH3sJfCgA5eU8iO1rXwNqYtM0";
        let mut duplicated = cfg;
        duplicated.jwt.previous_secrets = vec![
            SecretString::from(other.to_owned()),
            SecretString::from(other.to_owned()),
        ];
        assert!(matches!(
            duplicated.validate(Environment::Test),
            Err(ConfigError::PreviousSecretRepeated)
        ));
    }

    #[test]
    fn retired_mfa_keys_are_held_to_the_same_bar_as_the_current_one() {
        // They still decrypt stored TOTP secrets, so a malformed entry would throw at the first
        // challenge instead of at startup — and a key equal to the current one means the
        // rotation being described did not happen.
        let key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let retired = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let mut cfg = valid_config();
        cfg.mfa = Some(mfa_with_key(&key));

        // A well-formed rotation is accepted and decodes one key per entry.
        let mut rotating = cfg.clone();
        if let Some(mfa) = rotating.mfa.as_mut() {
            mfa.previous_encryption_keys = vec![SecretString::from(retired.clone())];
        }
        assert!(rotating.validate(Environment::Test).is_ok());
        let resolved = ResolvedConfig::new(rotating, Environment::Test, true);
        assert_eq!(resolved.previous_mfa_encryption_keys().len(), 1);
        assert!(matches!(
            resolved.mfa_encryption_key(),
            Some(current) if *current != *resolved.previous_mfa_encryption_keys()[0]
        ));

        // With no rotation in progress there are no retired keys at all.
        let none = ResolvedConfig::new(cfg.clone(), Environment::Test, true);
        assert!(none.previous_mfa_encryption_keys().is_empty());

        // A key that is not 32 bytes is refused at startup, not at the first challenge.
        let mut short = cfg.clone();
        if let Some(mfa) = short.mfa.as_mut() {
            mfa.previous_encryption_keys = vec![SecretString::from("dG9vLXNob3J0".to_owned())];
        }
        assert!(matches!(
            short.validate(Environment::Test),
            Err(ConfigError::MfaKeyInvalidBase64)
        ));

        // Neither is a value that is not base64 at all — the two rejections are separate
        // branches, and only one of them being wired would let the other reach a challenge.
        let mut garbage = cfg.clone();
        if let Some(mfa) = garbage.mfa.as_mut() {
            mfa.previous_encryption_keys =
                vec![SecretString::from("!!!!not base64!!!!".to_owned())];
        }
        assert!(matches!(
            garbage.validate(Environment::Test),
            Err(ConfigError::MfaKeyInvalidBase64)
        ));

        // The current key repeated, and a duplicate entry: both describe a rotation that did
        // not happen.
        let mut echoed = cfg.clone();
        if let Some(mfa) = echoed.mfa.as_mut() {
            mfa.previous_encryption_keys = vec![SecretString::from(key)];
        }
        assert!(matches!(
            echoed.validate(Environment::Test),
            Err(ConfigError::PreviousSecretRepeated)
        ));

        let mut duplicated = cfg;
        if let Some(mfa) = duplicated.mfa.as_mut() {
            mfa.previous_encryption_keys = vec![
                SecretString::from(retired.clone()),
                SecretString::from(retired),
            ];
        }
        assert!(matches!(
            duplicated.validate(Environment::Test),
            Err(ConfigError::PreviousSecretRepeated)
        ));
    }
}
