//! Domain user model: the canonical `AuthUser` / `AuthPlatformUser` records, their
//! credential-free `SafeAuthUser` / `SafeAuthPlatformUser` projections, and the
//! `Create*` / `Update*` write payloads passed into the repository contracts.
//!
//! # Secrets are isolated, not projected
//!
//! `password_hash`, `mfa_secret`, and `mfa_recovery_codes` live only on the full
//! records ([`AuthUser`] / [`AuthPlatformUser`]). The [`SafeAuthUser`] /
//! [`SafeAuthPlatformUser`] projections are **distinct structs** (not aliases) that
//! omit those three fields, so the compiler — not discipline — prevents credential
//! material from reaching a hook, a response body, or a log. The full records and the
//! write payloads are server-internal and are therefore deliberately **excluded** from
//! the generated TypeScript surface (only the `Safe*` projections derive `ts_rs::TS`),
//! so the shape of secret storage never ships to the frontend bundle.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Maps any present secret value to a fixed redaction marker for `Debug` output, so the
/// raw value never reaches a formatter while its `Option` presence stays visible.
fn redacted<T: ?Sized>(_value: &T) -> &'static str {
    "[REDACTED]"
}

/// Authenticated dashboard/tenant user — the library's view of one row in the
/// consumer's user table. Returned by every authentication operation and projected
/// (minus secrets, via [`SafeAuthUser`]) into JWT access-token payloads.
///
/// Server-internal: it carries credential material and is never serialized to a
/// client or exported to TypeScript.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    /// Unique internal identifier (UUID or similar).
    pub id: String,
    /// Primary email. Used for login and verification.
    pub email: String,
    /// Display name.
    pub name: String,
    /// PHC password hash (scrypt or argon2id). `None` for OAuth-only users who never
    /// set a local password. Never holds plaintext.
    pub password_hash: Option<String>,
    /// Authorization role (application-defined; keys into the role hierarchy).
    pub role: String,
    /// Account lifecycle status (application-defined; compared against `blocked_statuses`).
    pub status: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Whether the email has been verified.
    pub email_verified: bool,
    /// Whether TOTP MFA is currently enabled.
    pub mfa_enabled: bool,
    /// AES-256-GCM-encrypted TOTP secret. `None` until MFA is configured.
    pub mfa_secret: Option<String>,
    /// HMAC-SHA-256-keyed recovery-code hashes. `None` until MFA is configured.
    /// Compared in constant time — never with `==` on the raw value.
    pub mfa_recovery_codes: Option<Vec<String>>,
    /// Primary OAuth provider id (e.g. "google"). `None` for local-only accounts.
    pub oauth_provider: Option<String>,
    /// User's id within the OAuth provider. `None` for local-only accounts.
    pub oauth_provider_id: Option<String>,
    /// Most recent successful login, or `None` if never logged in.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    /// Record creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// [`AuthUser`] with every credential/secret field removed. Safe to serialize and to
/// pass to consumer hooks. Produced via `SafeAuthUser::from(auth_user)`.
///
/// This is the type handed to hooks, returned to callers, and serialized into API
/// responses — the Rust analogue of nest-auth's
/// `Omit<AuthUser, 'passwordHash' | 'mfaSecret' | 'mfaRecoveryCodes'>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "auth-user.types.ts", rename = "AuthUserClient")
)]
#[serde(rename_all = "camelCase")]
pub struct SafeAuthUser {
    /// Unique internal identifier.
    pub id: String,
    /// Primary email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Authorization role.
    pub role: String,
    /// Account lifecycle status.
    pub status: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Whether the email has been verified.
    pub email_verified: bool,
    /// Whether TOTP MFA is currently enabled.
    pub mfa_enabled: bool,
    /// Primary OAuth provider id, or `None` for local-only accounts.
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub oauth_provider: Option<String>,
    /// User's id within the OAuth provider, or `None` for local-only accounts.
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub oauth_provider_id: Option<String>,
    /// Most recent successful login, or `None` if never logged in.
    #[serde(with = "time::serde::rfc3339::option")]
    #[cfg_attr(feature = "ts-export", ts(as = "Option::<String>"))]
    pub last_login_at: Option<OffsetDateTime>,
    /// Record creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "ts-export", ts(as = "String"))]
    pub created_at: OffsetDateTime,
}

impl From<AuthUser> for SafeAuthUser {
    /// Project an [`AuthUser`] to its credential-free form, dropping `password_hash`,
    /// `mfa_secret`, and `mfa_recovery_codes` by construction (they have no field to
    /// land in on the target type).
    fn from(user: AuthUser) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            status: user.status,
            tenant_id: user.tenant_id,
            email_verified: user.email_verified,
            mfa_enabled: user.mfa_enabled,
            oauth_provider: user.oauth_provider,
            oauth_provider_id: user.oauth_provider_id,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
        }
    }
}

impl fmt::Debug for AuthUser {
    /// Redacts `password_hash`, `mfa_secret`, and `mfa_recovery_codes` so a stray `{:?}`
    /// in a log line or panic message can never leak credential material. The `Option`
    /// presence is preserved (a redacted `Some` vs `None`) for debugging without
    /// exposing the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthUser")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("password_hash", &self.password_hash.as_ref().map(redacted))
            .field("role", &self.role)
            .field("status", &self.status)
            .field("tenant_id", &self.tenant_id)
            .field("email_verified", &self.email_verified)
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(redacted))
            .field(
                "mfa_recovery_codes",
                &self.mfa_recovery_codes.as_ref().map(redacted),
            )
            .field("oauth_provider", &self.oauth_provider)
            .field("oauth_provider_id", &self.oauth_provider_id)
            .field("last_login_at", &self.last_login_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Authenticated platform administrator (operator/super-admin layer).
///
/// Differs from [`AuthUser`]: `password_hash` is **non-optional** (admins always have
/// a local credential and never use OAuth), there is no `email_verified` field
/// (accounts are provisioned by operators), and an `updated_at` field supports audit
/// and status-cache invalidation. Server-internal — never serialized to a client.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPlatformUser {
    /// Unique internal identifier.
    pub id: String,
    /// Primary email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// PHC password hash (scrypt or argon2id). Never `None` — platform admins always
    /// have a password.
    pub password_hash: String,
    /// Authorization role within the platform hierarchy.
    pub role: String,
    /// Account lifecycle status.
    pub status: String,
    /// Whether TOTP MFA is currently enabled.
    pub mfa_enabled: bool,
    /// AES-256-GCM-encrypted TOTP secret. `None` until MFA is configured.
    pub mfa_secret: Option<String>,
    /// HMAC-SHA-256-keyed recovery-code hashes. `None` until MFA is configured.
    pub mfa_recovery_codes: Option<Vec<String>>,
    /// Logical platform id for multi-platform deployments. `None` when single-platform.
    pub platform_id: Option<String>,
    /// Most recent successful login, or `None` if never logged in.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    /// Last modification time — supports audit and status-cache invalidation.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Record creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for AuthPlatformUser {
    /// Redacts `password_hash`, `mfa_secret`, and `mfa_recovery_codes` so credential
    /// material can never leak through a `{:?}` in a log or panic message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthPlatformUser")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("password_hash", &redacted(&self.password_hash))
            .field("role", &self.role)
            .field("status", &self.status)
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(redacted))
            .field(
                "mfa_recovery_codes",
                &self.mfa_recovery_codes.as_ref().map(redacted),
            )
            .field("platform_id", &self.platform_id)
            .field("last_login_at", &self.last_login_at)
            .field("updated_at", &self.updated_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// [`AuthPlatformUser`] with every credential/secret field removed. Safe to serialize
/// and to return to callers. Produced via `SafeAuthPlatformUser::from(admin)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "auth-user.types.ts", rename = "AuthPlatformUserClient")
)]
#[serde(rename_all = "camelCase")]
pub struct SafeAuthPlatformUser {
    /// Unique internal identifier.
    pub id: String,
    /// Primary email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Authorization role within the platform hierarchy.
    pub role: String,
    /// Account lifecycle status.
    pub status: String,
    /// Whether TOTP MFA is currently enabled.
    pub mfa_enabled: bool,
    /// Logical platform id, or `None` when single-platform.
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub platform_id: Option<String>,
    /// Most recent successful login, or `None` if never logged in.
    #[serde(with = "time::serde::rfc3339::option")]
    #[cfg_attr(feature = "ts-export", ts(as = "Option::<String>"))]
    pub last_login_at: Option<OffsetDateTime>,
    /// Last modification time.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "ts-export", ts(as = "String"))]
    pub updated_at: OffsetDateTime,
    /// Record creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "ts-export", ts(as = "String"))]
    pub created_at: OffsetDateTime,
}

impl From<AuthPlatformUser> for SafeAuthPlatformUser {
    /// Project an [`AuthPlatformUser`] to its credential-free form, dropping
    /// `password_hash`, `mfa_secret`, and `mfa_recovery_codes` by construction.
    fn from(admin: AuthPlatformUser) -> Self {
        Self {
            id: admin.id,
            email: admin.email,
            name: admin.name,
            role: admin.role,
            status: admin.status,
            mfa_enabled: admin.mfa_enabled,
            platform_id: admin.platform_id,
            last_login_at: admin.last_login_at,
            updated_at: admin.updated_at,
            created_at: admin.created_at,
        }
    }
}

/// Payload to create a new local (email + password) user. `password_hash` is always a
/// crypto-layer hash — the contract forbids plaintext. Optional fields fall back to
/// engine/application defaults when `None`.
///
/// Server-internal repository input, constructed by the engine — not a wire DTO.
#[derive(Clone)]
pub struct CreateUserData {
    /// Primary email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// PHC hash from the crypto layer. `None` for OAuth-only accounts. Never plaintext.
    pub password_hash: Option<String>,
    /// Authorization role; defaults to the application base role when `None`.
    pub role: Option<String>,
    /// Lifecycle status; defaults to "pending" when `None`.
    pub status: Option<String>,
    /// Tenant scope.
    pub tenant_id: String,
    /// Email-verified flag; defaults to `false` when `None`.
    pub email_verified: Option<bool>,
}

impl fmt::Debug for CreateUserData {
    /// Redacts `password_hash` (a PHC hash is still credential material) while keeping
    /// the rest of the repository input visible for diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserData")
            .field("email", &self.email)
            .field("name", &self.name)
            .field("password_hash", &self.password_hash.as_ref().map(redacted))
            .field("role", &self.role)
            .field("status", &self.status)
            .field("tenant_id", &self.tenant_id)
            .field("email_verified", &self.email_verified)
            .finish()
    }
}

/// Payload to create a user originating from an OAuth provider. Such users have no
/// local password (`password_hash` is implicitly `None`); one may be added later via
/// `update_password`.
#[derive(Clone, Debug)]
pub struct CreateWithOAuthData {
    /// Primary email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Authorization role; defaults to the application base role when `None`.
    pub role: Option<String>,
    /// Lifecycle status; defaults to "active" when `None`.
    pub status: Option<String>,
    /// Tenant scope.
    pub tenant_id: String,
    /// Set `true` when the provider guarantees a verified email.
    pub email_verified: Option<bool>,
    /// OAuth provider id (e.g. "google").
    pub oauth_provider: String,
    /// User's id within the OAuth provider.
    pub oauth_provider_id: String,
}

/// Payload to update a user's TOTP MFA configuration. `None` for the secret/codes
/// clears them (disabling MFA).
#[derive(Clone)]
pub struct UpdateMfaData {
    /// Whether MFA is enabled after this update.
    pub mfa_enabled: bool,
    /// AES-256-GCM-encrypted secret, or `None` to clear.
    pub mfa_secret: Option<String>,
    /// HMAC-SHA-256-keyed code hashes, or `None` to clear.
    pub mfa_recovery_codes: Option<Vec<String>>,
}

impl fmt::Debug for UpdateMfaData {
    /// Redacts the encrypted secret and the keyed recovery-code hashes from `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateMfaData")
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(redacted))
            .field(
                "mfa_recovery_codes",
                &self.mfa_recovery_codes.as_ref().map(redacted),
            )
            .finish()
    }
}

/// Platform-side counterpart of [`UpdateMfaData`]. Structurally identical but kept a
/// distinct type so the dashboard and platform MFA flows can diverge without a
/// breaking change.
#[derive(Clone)]
pub struct UpdatePlatformMfaData {
    /// Whether MFA is enabled after this update.
    pub mfa_enabled: bool,
    /// AES-256-GCM-encrypted secret, or `None` to clear.
    pub mfa_secret: Option<String>,
    /// HMAC-SHA-256-keyed code hashes, or `None` to clear.
    pub mfa_recovery_codes: Option<Vec<String>>,
}

impl fmt::Debug for UpdatePlatformMfaData {
    /// Redacts the encrypted secret and the keyed recovery-code hashes from `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdatePlatformMfaData")
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(redacted))
            .field(
                "mfa_recovery_codes",
                &self.mfa_recovery_codes.as_ref().map(redacted),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, always-valid instant used across the fixtures so the no-`unwrap`
    /// lint is satisfied without a fallible conversion in the assertions.
    fn fixed_instant() -> OffsetDateTime {
        // 2023-11-14T22:13:20Z. The fallback is unreachable for this literal but keeps
        // the constructor total under the workspace's no-`unwrap`/`expect` lints.
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn sample_auth_user() -> AuthUser {
        AuthUser {
            id: "u_1".to_owned(),
            email: "user@example.com".to_owned(),
            name: "Ada".to_owned(),
            password_hash: Some("$scrypt$ph".to_owned()),
            role: "member".to_owned(),
            status: "ACTIVE".to_owned(),
            tenant_id: "t_1".to_owned(),
            email_verified: true,
            mfa_enabled: true,
            mfa_secret: Some("enc-secret".to_owned()),
            mfa_recovery_codes: Some(vec!["hash-a".to_owned(), "hash-b".to_owned()]),
            oauth_provider: Some("google".to_owned()),
            oauth_provider_id: Some("g-123".to_owned()),
            last_login_at: Some(fixed_instant()),
            created_at: fixed_instant(),
        }
    }

    fn sample_platform_user() -> AuthPlatformUser {
        AuthPlatformUser {
            id: "p_1".to_owned(),
            email: "admin@example.com".to_owned(),
            name: "Grace".to_owned(),
            password_hash: "$argon2id$ph".to_owned(),
            role: "super_admin".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            platform_id: Some("plat_1".to_owned()),
            last_login_at: None,
            updated_at: fixed_instant(),
            created_at: fixed_instant(),
        }
    }

    /// Round-trip identity check that stays total under the no-`unwrap` lints: a value
    /// serialized, parsed back, and re-serialized must equal its first serialization.
    /// The `Err` arm of the parse lives in `Result::ok` (std), so an unreachable
    /// deserialization failure costs no coverage in this file.
    fn json_round_trip<T>(value: &T) -> (serde_json::Value, serde_json::Value)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let first = serde_json::to_value(value).unwrap_or_default();
        let again = serde_json::from_value::<T>(first.clone())
            .ok()
            .map(|parsed| serde_json::to_value(parsed).unwrap_or_default())
            .unwrap_or_default();
        (first, again)
    }

    #[test]
    fn auth_user_round_trips_through_json_with_camel_case_wire() {
        // The full record must (de)serialize losslessly and emit camelCase keys — the
        // nest-auth wire convention the whole contract layer preserves.
        let user = sample_auth_user();
        let json = serde_json::to_string(&user).unwrap_or_default();
        assert!(json.contains("\"passwordHash\""));
        assert!(json.contains("\"emailVerified\""));
        assert!(json.contains("\"tenantId\""));
        assert!(json.contains("\"lastLoginAt\""));
        assert!(json.contains("\"createdAt\""));
        let (first, again) = json_round_trip(&user);
        assert_eq!(first, again);
    }

    #[test]
    fn safe_auth_user_drops_every_credential_field() {
        // The credential-stripping projection is the central security property: a
        // serialized SafeAuthUser must contain none of the three secret fields.
        let safe = SafeAuthUser::from(sample_auth_user());
        let json = serde_json::to_string(&safe).unwrap_or_default();
        assert!(!json.contains("passwordHash"));
        assert!(!json.contains("mfaSecret"));
        assert!(!json.contains("mfaRecoveryCodes"));
        // …while the non-secret fields survive the projection unchanged.
        assert!(json.contains("\"oauthProvider\""));
        assert_eq!(safe.id, "u_1");
        assert!(safe.email_verified);
    }

    #[test]
    fn safe_auth_user_round_trips_through_json() {
        // The client-facing projection must itself (de)serialize cleanly so a response
        // body and a re-parse agree.
        let safe = SafeAuthUser::from(sample_auth_user());
        let (first, again) = json_round_trip(&safe);
        assert_eq!(first, again);
    }

    #[test]
    fn safe_platform_user_drops_credentials_and_omits_email_verified() {
        // The platform projection drops the same three secrets and (by type) has no
        // email_verified field — the platform record never carries one.
        let safe = SafeAuthPlatformUser::from(sample_platform_user());
        let json = serde_json::to_string(&safe).unwrap_or_default();
        assert!(!json.contains("passwordHash"));
        assert!(!json.contains("mfaSecret"));
        assert!(!json.contains("mfaRecoveryCodes"));
        assert!(!json.contains("emailVerified"));
        assert!(json.contains("\"updatedAt\""));
        assert_eq!(safe.platform_id.as_deref(), Some("plat_1"));
        assert_eq!(safe.last_login_at, None);
    }

    #[test]
    fn platform_user_round_trips_through_json() {
        // Full platform record (de)serialization round-trip, including the null
        // last_login_at and the platform-only updated_at field.
        let admin = sample_platform_user();
        let json = serde_json::to_string(&admin).unwrap_or_default();
        assert!(json.contains("\"updatedAt\""));
        assert!(json.contains("\"lastLoginAt\":null"));
        let (first, again) = json_round_trip(&admin);
        assert_eq!(first, again);
    }

    #[test]
    fn auth_user_debug_redacts_every_credential_field() {
        // A stray `{:?}` on a full user must never print the PHC hash, the encrypted
        // TOTP secret, or the recovery-code hashes — only a redaction marker — so a log
        // line or panic message cannot leak credential material.
        let dbg = format!("{:?}", sample_auth_user());
        assert!(dbg.starts_with("AuthUser {"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("$scrypt$ph"));
        assert!(!dbg.contains("enc-secret"));
        assert!(!dbg.contains("hash-a"));
        // Non-secret fields stay visible for diagnostics.
        assert!(dbg.contains("user@example.com"));
    }

    #[test]
    fn auth_platform_user_debug_redacts_every_credential_field() {
        // The platform record's non-optional password hash and its MFA secrets must all
        // be redacted in Debug output, just like the dashboard user.
        let mut admin = sample_platform_user();
        admin.mfa_secret = Some("enc-platform-secret".to_owned());
        admin.mfa_recovery_codes = Some(vec!["plat-hash".to_owned()]);
        let dbg = format!("{admin:?}");
        assert!(dbg.starts_with("AuthPlatformUser {"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("$argon2id$ph"));
        assert!(!dbg.contains("enc-platform-secret"));
        assert!(!dbg.contains("plat-hash"));
        assert!(dbg.contains("admin@example.com"));
    }

    #[test]
    fn write_payloads_clone_and_debug_redacting_secrets() {
        // The repository-input payloads are plain data; exercise their derived Clone and
        // their redacting Debug. The credential-bearing fields must never print their
        // value, while the non-secret payload (no credentials) Debugs in full.
        let create = CreateUserData {
            email: "a@b.c".to_owned(),
            name: "A".to_owned(),
            password_hash: Some("PHC-SECRET".to_owned()),
            role: None,
            status: None,
            tenant_id: "t".to_owned(),
            email_verified: Some(false),
        };
        let create_dbg = format!("{:?}", create.clone());
        assert_eq!(create.email, "a@b.c");
        assert!(create_dbg.contains("CreateUserData"));
        assert!(create_dbg.contains("[REDACTED]"));
        assert!(!create_dbg.contains("PHC-SECRET"));

        let oauth = CreateWithOAuthData {
            email: "a@b.c".to_owned(),
            name: "A".to_owned(),
            role: Some("member".to_owned()),
            status: None,
            tenant_id: "t".to_owned(),
            email_verified: Some(true),
            oauth_provider: "google".to_owned(),
            oauth_provider_id: "g-1".to_owned(),
        };
        assert!(format!("{:?}", oauth.clone()).contains("CreateWithOAuthData"));
        assert_eq!(oauth.oauth_provider, "google");

        let mfa = UpdateMfaData {
            mfa_enabled: true,
            mfa_secret: Some("MFA-ENC-SECRET".to_owned()),
            mfa_recovery_codes: Some(vec!["RECOVERY-HASH".to_owned()]),
        };
        let mfa_dbg = format!("{:?}", mfa.clone());
        assert!(mfa_dbg.contains("UpdateMfaData"));
        assert!(mfa.mfa_enabled);
        assert!(mfa_dbg.contains("[REDACTED]"));
        assert!(!mfa_dbg.contains("MFA-ENC-SECRET"));
        assert!(!mfa_dbg.contains("RECOVERY-HASH"));

        let platform_mfa = UpdatePlatformMfaData {
            mfa_enabled: true,
            mfa_secret: Some("PLAT-ENC-SECRET".to_owned()),
            mfa_recovery_codes: Some(vec!["PLAT-RECOVERY-HASH".to_owned()]),
        };
        let platform_dbg = format!("{:?}", platform_mfa.clone());
        assert!(platform_dbg.contains("UpdatePlatformMfaData"));
        assert!(platform_mfa.mfa_enabled);
        assert!(platform_dbg.contains("[REDACTED]"));
        assert!(!platform_dbg.contains("PLAT-ENC-SECRET"));
        assert!(!platform_dbg.contains("PLAT-RECOVERY-HASH"));
        // The cleared-secret case still Debugs (both secrets `None`).
        let cleared = UpdatePlatformMfaData {
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
        };
        assert!(format!("{cleared:?}").contains("UpdatePlatformMfaData"));
    }
}
