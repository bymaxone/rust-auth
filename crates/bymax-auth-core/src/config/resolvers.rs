//! The three function-valued configuration options, modeled as object-safe traits so they
//! can be stored as `Arc<dyn _>` inside [`super::AuthConfig`] and stay `Send + Sync`.
//!
//! [`TenantIdResolver`] and [`MaxSessionsResolver`] genuinely await, so they carry
//! `#[async_trait]`; [`CookieDomainResolver`] is purely synchronous and is object-safe
//! without any macro.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bymax_auth_types::AuthUser;

/// A framework-neutral view of the request, owned by `bymax-auth-core`. The Axum adapter
/// constructs it from `http::request::Parts`, keeping the resolver traits free of any
/// web-framework type.
#[derive(Clone, Debug, Default)]
pub struct RequestParts {
    /// The request method (e.g. `"POST"`).
    pub method: String,
    /// The request URI/path.
    pub uri: String,
    /// The request host, if present.
    pub host: Option<String>,
    /// Request headers, keys lowercased. A `BTreeMap` keeps lookups deterministic.
    pub headers: BTreeMap<String, String>,
}

/// A failure resolving the tenant id from the request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantResolveError {
    /// The resolver returned an empty tenant id — treated as misconfiguration, so the
    /// request is rejected rather than silently degrading to "no tenant".
    #[error("tenant resolver returned an empty tenant id")]
    Empty,
    /// The resolver failed for an implementation-specific reason.
    #[error("tenant resolution failed: {0}")]
    Internal(String),
}

/// Resolves the tenant id from request parts. When configured, the value it returns is the
/// **only** tenant id the engine uses for that request — any `tenant_id` in the request
/// body is ignored entirely (anti-spoofing).
///
/// # Errors
///
/// Returns [`TenantResolveError::Empty`] when the resolver yields an empty id (a
/// misconfiguration), or [`TenantResolveError::Internal`] for any other failure.
#[async_trait]
pub trait TenantIdResolver: Send + Sync {
    /// Resolve a non-empty tenant id from the request, or an error.
    async fn resolve(&self, parts: &RequestParts) -> Result<String, TenantResolveError>;
}

/// Resolves the cookie `Domain` attribute(s) to set, derived from the request host
/// (multi-domain support). Purely synchronous, so it is object-safe without `#[async_trait]`.
pub trait CookieDomainResolver: Send + Sync {
    /// Return the `Domain` attribute(s) to set for the given request host.
    fn resolve(&self, request_host: &str) -> Vec<String>;
}

/// Resolves a per-user concurrent-session limit (plan/role aware). When it returns
/// successfully, the value overrides `sessions.default_max_sessions`.
#[async_trait]
pub trait MaxSessionsResolver: Send + Sync {
    /// Resolve the session limit for the given user.
    async fn resolve(&self, user: &AuthUser) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use time::OffsetDateTime;

    struct StaticTenant;

    #[async_trait]
    impl TenantIdResolver for StaticTenant {
        async fn resolve(&self, parts: &RequestParts) -> Result<String, TenantResolveError> {
            match parts.host.as_deref() {
                Some("") | None => Err(TenantResolveError::Empty),
                Some(host) => Ok(host.to_owned()),
            }
        }
    }

    struct SuffixDomain;

    impl CookieDomainResolver for SuffixDomain {
        fn resolve(&self, request_host: &str) -> Vec<String> {
            vec![format!(".{request_host}")]
        }
    }

    struct PlanLimit;

    #[async_trait]
    impl MaxSessionsResolver for PlanLimit {
        async fn resolve(&self, user: &AuthUser) -> u32 {
            if user.role == "OWNER" { 100 } else { 3 }
        }
    }

    fn user(role: &str) -> AuthUser {
        AuthUser {
            id: "u1".into(),
            email: "e@x.io".into(),
            name: "E".into(),
            password_hash: None,
            role: role.into(),
            status: "ACTIVE".into(),
            tenant_id: "t1".into(),
            email_verified: true,
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn tenant_resolver_is_object_safe_and_rejects_empty() {
        // Held as `Arc<dyn _>` the resolver must be object-safe; an absent host is the
        // misconfiguration path that yields `Empty`.
        let resolver: Arc<dyn TenantIdResolver> = Arc::new(StaticTenant);
        let parts = RequestParts {
            host: Some("acme.example.com".into()),
            ..Default::default()
        };
        assert!(matches!(resolver.resolve(&parts).await, Ok(t) if t == "acme.example.com"));
        let empty = RequestParts::default();
        assert!(matches!(
            resolver.resolve(&empty).await,
            Err(TenantResolveError::Empty)
        ));
    }

    #[test]
    fn cookie_domain_resolver_is_object_safe_without_a_macro() {
        // The sync resolver is dyn-compatible directly; it derives the cookie domain.
        let resolver: Arc<dyn CookieDomainResolver> = Arc::new(SuffixDomain);
        assert_eq!(
            resolver.resolve("app.example.com"),
            vec![".app.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn max_sessions_resolver_is_object_safe() {
        // The async resolver dispatches per user, overriding the default cap.
        let resolver: Arc<dyn MaxSessionsResolver> = Arc::new(PlanLimit);
        assert_eq!(resolver.resolve(&user("OWNER")).await, 100);
        assert_eq!(resolver.resolve(&user("MEMBER")).await, 3);
    }

    #[test]
    fn tenant_resolve_error_messages_are_stable() {
        // These feed `tracing`; pin them against accidental rewording.
        assert_eq!(
            TenantResolveError::Empty.to_string(),
            "tenant resolver returned an empty tenant id"
        );
        assert_eq!(
            TenantResolveError::Internal("db down".into()).to_string(),
            "tenant resolution failed: db down"
        );
    }
}
