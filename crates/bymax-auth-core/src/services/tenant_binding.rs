//! Tenant binding for authenticated requests (layer: engine surface used by the HTTP adapter).
//!
//! A verified token is trusted for the tenant baked into it, so a token minted for one tenant is
//! accepted when it is presented under another tenant's host. When the host is the tenant
//! boundary, `enforce_tenant_binding` re-resolves the request's tenant with the configured
//! resolver and refuses a mismatch.

use bymax_auth_types::AuthError;

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::auth::{map_tenant_error, request_parts_from_context};

impl AuthEngine {
    /// Refuse a request whose token tenant differs from the tenant the resolver names for it.
    ///
    /// A no-op unless `enforce_tenant_binding` is set (startup rejects the flag without a
    /// resolver, so an enforcing engine always has one). A mismatch is reported as
    /// [`AuthError::TokenInvalid`], like every other refusal of a token, so the answer reveals
    /// nothing about which tenant the token belongs to.
    ///
    /// # Errors
    ///
    /// [`AuthError::TokenInvalid`] when the tenants differ, [`AuthError::Forbidden`] when the
    /// resolver yields an empty id, or [`AuthError::Internal`] when the resolver fails.
    pub async fn assert_tenant_binding(
        &self,
        token_tenant: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let config = self.config().config();
        // Startup rejects the flag without a resolver, so an enforcing engine always has one.
        let Some(resolver) = config
            .tenant_id_resolver
            .as_ref()
            .filter(|_| config.enforce_tenant_binding)
        else {
            return Ok(());
        };
        let request_tenant = resolver
            .resolve(&request_parts_from_context(ctx))
            .await
            .map_err(map_tenant_error)?;
        if request_tenant == token_tenant {
            Ok(())
        } else {
            Err(AuthError::TokenInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::config::{RequestParts, TenantIdResolver, TenantResolveError};
    use crate::services::auth::test_support::{base_config, harness};

    /// Resolves the tenant from the request host, failing on a missing or empty one.
    struct HostResolver;

    #[async_trait]
    impl TenantIdResolver for HostResolver {
        async fn resolve(&self, parts: &RequestParts) -> Result<String, TenantResolveError> {
            match parts.host.as_deref() {
                Some("") | None => Err(TenantResolveError::Empty),
                Some(host) => Ok(host.to_owned()),
            }
        }
    }

    fn ctx_for_host(host: &str) -> RequestContext {
        let headers = BTreeMap::from([("host".to_owned(), host.to_owned())]);
        RequestContext::new("203.0.113.9", "agent/1.0", headers)
    }

    fn enforcing_config() -> crate::config::AuthConfig {
        let mut config = base_config();
        config.tenant_id_resolver = Some(Arc::new(HostResolver));
        config.enforce_tenant_binding = true;
        config
    }

    #[tokio::test]
    async fn a_token_from_another_tenant_is_refused_and_its_own_tenant_is_accepted() {
        let Some(h) = harness(enforcing_config(), None) else { return };

        let own = h
            .engine
            .assert_tenant_binding("acme", &ctx_for_host("acme"))
            .await;
        assert!(own.is_ok(), "{own:?}");

        let foreign = h
            .engine
            .assert_tenant_binding("globex", &ctx_for_host("acme"))
            .await;
        assert!(
            matches!(foreign, Err(AuthError::TokenInvalid)),
            "a token minted for another tenant was accepted: {foreign:?}"
        );
    }

    #[tokio::test]
    async fn a_resolver_that_cannot_name_a_tenant_refuses_instead_of_waving_the_token_through() {
        let Some(h) = harness(enforcing_config(), None) else { return };
        let ctx = RequestContext::new("203.0.113.9", "agent/1.0", BTreeMap::new());
        let refused = h.engine.assert_tenant_binding("acme", &ctx).await;
        assert!(matches!(refused, Err(AuthError::Forbidden)), "{refused:?}");
    }

    #[tokio::test]
    async fn binding_is_off_by_default_even_with_a_resolver() {
        let mut config = base_config();
        config.tenant_id_resolver = Some(Arc::new(HostResolver));
        let Some(h) = harness(config, None) else { return };
        let answer = h
            .engine
            .assert_tenant_binding("globex", &ctx_for_host("acme"))
            .await;
        assert!(answer.is_ok(), "{answer:?}");
    }

    #[test]
    fn enforcing_without_a_resolver_is_a_startup_error() {
        let mut config = base_config();
        config.enforce_tenant_binding = true;
        let result = config.validate(crate::config::Environment::Test);
        assert!(matches!(
            result,
            Err(crate::error::ConfigError::TenantBindingWithoutResolver)
        ));
    }
}
