//! Framework-neutral per-request context and the credential-dropping user projections.
//!
//! [`RequestContext`] is the transport-derived, security-relevant metadata every public
//! engine operation receives — the adapter builds it from the HTTP request, and the
//! core never sees a `Request`, header map, or cookie type. The [`to_safe_user`] /
//! [`to_safe_platform_user`] projections strip `password_hash`, `mfa_secret`, and
//! `mfa_recovery_codes` before a user object is returned to a caller, passed to a hook,
//! or handed to an email provider, so credential material never leaves the service layer.

use std::collections::BTreeMap;

use bymax_auth_types::{AuthPlatformUser, AuthUser, SafeAuthPlatformUser, SafeAuthUser};

/// Transport-derived, security-relevant request metadata passed into every public engine
/// operation. The adapter constructs it; the core consumes it verbatim (e.g. to build a
/// [`crate::traits::HookContext`]).
#[derive(Clone, Debug)]
pub struct RequestContext {
    /// The trusted client IP. The adapter is responsible for resolving it from a
    /// trusted-proxy configuration — never raw `X-Forwarded-For` — so brute-force
    /// counting and alerting cannot be spoofed.
    pub ip: String,
    /// The raw `User-Agent` value.
    pub user_agent: String,
    /// Request headers with sensitive entries (`authorization`, `cookie`, CSRF/access
    /// tokens, secrets) already removed and keys lowercased. A `BTreeMap` keeps the
    /// ordering deterministic, so anything derived from it (audit logs, hashes) is
    /// reproducible. Safe to log or persist for audit.
    pub sanitized_headers: BTreeMap<String, String>,
}

impl RequestContext {
    /// Construct a context from its parts.
    #[must_use]
    pub fn new(
        ip: impl Into<String>,
        user_agent: impl Into<String>,
        sanitized_headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            ip: ip.into(),
            user_agent: user_agent.into(),
            sanitized_headers,
        }
    }
}

/// Project an [`AuthUser`] to its credential-free [`SafeAuthUser`], dropping
/// `password_hash`, `mfa_secret`, and `mfa_recovery_codes`. The borrow is cloned so the
/// caller keeps ownership of the source row.
#[must_use]
pub fn to_safe_user(user: &AuthUser) -> SafeAuthUser {
    SafeAuthUser::from(user.clone())
}

/// Project an [`AuthPlatformUser`] to its credential-free [`SafeAuthPlatformUser`],
/// dropping `password_hash`, `mfa_secret`, and `mfa_recovery_codes`.
#[must_use]
pub fn to_safe_platform_user(user: &AuthPlatformUser) -> SafeAuthPlatformUser {
    SafeAuthPlatformUser::from(user.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    /// A fully-populated `AuthUser` (including every secret field) used to prove the
    /// projection drops the credential material.
    fn sample_user() -> AuthUser {
        AuthUser {
            id: "u1".into(),
            email: "user@example.com".into(),
            name: "User".into(),
            password_hash: Some("$scrypt$secret".into()),
            role: "MEMBER".into(),
            status: "ACTIVE".into(),
            tenant_id: "t1".into(),
            email_verified: true,
            mfa_enabled: true,
            mfa_secret: Some("ENCRYPTED".into()),
            mfa_recovery_codes: Some(vec!["HASH".into()]),
            oauth_provider: Some("google".into()),
            oauth_provider_id: Some("google-123".into()),
            last_login_at: Some(OffsetDateTime::UNIX_EPOCH),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn sample_platform_user() -> AuthPlatformUser {
        AuthPlatformUser {
            id: "p1".into(),
            email: "admin@example.com".into(),
            name: "Admin".into(),
            password_hash: "$scrypt$secret".into(),
            role: "PLATFORM_ADMIN".into(),
            status: "ACTIVE".into(),
            mfa_enabled: true,
            mfa_secret: Some("ENCRYPTED".into()),
            mfa_recovery_codes: Some(vec!["HASH".into()]),
            platform_id: Some("plat".into()),
            last_login_at: Some(OffsetDateTime::UNIX_EPOCH),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn request_context_new_sets_fields() {
        // The constructor wires every part through unchanged so the engine sees exactly
        // what the adapter resolved.
        let mut headers = BTreeMap::new();
        headers.insert("x-trace".to_string(), "abc".to_string());
        let ctx = RequestContext::new("203.0.113.4", "agent/1.0", headers.clone());
        assert_eq!(ctx.ip, "203.0.113.4");
        assert_eq!(ctx.user_agent, "agent/1.0");
        assert_eq!(ctx.sanitized_headers, headers);
    }

    #[test]
    fn to_safe_user_drops_credentials_and_keeps_identity() {
        // The safe projection must preserve identity/profile fields while removing every
        // secret — the type system already forbids the secret fields on `SafeAuthUser`,
        // so this asserts the surviving fields round-trip.
        let user = sample_user();
        let safe = to_safe_user(&user);
        assert_eq!(safe.id, user.id);
        assert_eq!(safe.email, user.email);
        assert_eq!(safe.role, user.role);
        assert_eq!(safe.mfa_enabled, user.mfa_enabled);
        assert_eq!(safe.oauth_provider, user.oauth_provider);
        // The source row is untouched (projection cloned), so its secret survives here.
        assert!(user.password_hash.is_some());
    }

    #[test]
    fn to_safe_platform_user_drops_credentials_and_keeps_identity() {
        // Same guarantee for the operator layer: identity preserved, credentials gone.
        let user = sample_platform_user();
        let safe = to_safe_platform_user(&user);
        assert_eq!(safe.id, user.id);
        assert_eq!(safe.email, user.email);
        assert_eq!(safe.role, user.role);
        assert_eq!(safe.platform_id, user.platform_id);
        assert_eq!(safe.mfa_enabled, user.mfa_enabled);
    }
}
