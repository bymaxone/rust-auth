//! The dashboard arm of the combined verifier: the chain's order, each refusal's code, the
//! opt-outs and the tenant binding. Layer: unit tests over the in-memory doubles.

use std::sync::Arc;

use async_trait::async_trait;
use bymax_auth_types::{AuthError, DashboardClaims, DashboardType};

use super::super::{AuthPlane, VerifiedAccessToken, VerifyAccessOptions};
use crate::config::{RequestParts, TenantIdResolver, TenantResolveError};
use crate::context::RequestContext;
use crate::services::auth::test_support::{Harness, SeedUser, base_config, harness};
use crate::services::{new_uuid_v4, now_unix};
use crate::traits::{SessionStore, UserRepository};

const TENANT: &str = "t1";

/// Claims for the account `sub`, signed by nothing yet.
pub(super) fn claims_for(sub: &str) -> DashboardClaims {
    DashboardClaims {
        iss: None,
        aud: None,
        sub: sub.to_owned(),
        jti: new_uuid_v4(),
        tenant_id: TENANT.to_owned(),
        role: "USER".to_owned(),
        token_type: DashboardType::Dashboard,
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_verified: false,
        iat: now_unix(),
        exp: now_unix() + 900,
        epoch: 0,
    }
}

/// A seeded active account and a signed token for `claims` naming it.
async fn token_for(h: &Harness, edit: impl FnOnce(&mut DashboardClaims)) -> (String, String) {
    // A fresh address per call: seeding the same one twice fails and yields an empty id.
    static SEEDED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEEDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = h
        .seed(SeedUser::active(&format!("v{n}@example.com"), "pw123456"))
        .await;
    assert!(!id.is_empty(), "the account must be seeded");
    let mut claims = claims_for(&id);
    edit(&mut claims);
    let token = h.engine.tokens().issue_access(&claims).unwrap_or_default();
    (id, token)
}

fn dashboard() -> VerifyAccessOptions<'static> {
    VerifyAccessOptions::new(AuthPlane::Dashboard)
}

#[tokio::test]
async fn a_live_token_verifies_and_is_tagged_with_its_plane() {
    let Some(h) = harness(base_config(), None) else { return };
    let (id, token) = token_for(&h, |_| {}).await;
    let verified = h.engine.verify_access(&token, &dashboard()).await;
    assert!(
        matches!(&verified, Ok(VerifiedAccessToken::Dashboard(c)) if c.sub == id),
        "{verified:?}"
    );
}

#[tokio::test]
async fn garbage_an_expired_token_and_a_revoked_one_all_answer_token_invalid() {
    let Some(h) = harness(base_config(), None) else { return };
    let (_, expired) = token_for(&h, |c| c.exp = now_unix() - 60).await;
    let (_, revoked) = token_for(&h, |_| {}).await;
    let Ok(VerifiedAccessToken::Dashboard(live)) =
        h.engine.verify_access(&revoked, &dashboard()).await
    else {
        return;
    };
    assert!(h.stores.blacklist_access(&live.jti, 600).await.is_ok());
    for presented in ["not-a-jwt", expired.as_str(), revoked.as_str()] {
        let refused = h.engine.verify_access(presented, &dashboard()).await;
        assert!(
            matches!(refused, Err(AuthError::TokenInvalid)),
            "{presented}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_malformed_jti_subject_or_tenant_is_refused_even_when_signed() {
    // The status check is waived so that an account that does not exist cannot be what refuses
    // the token: only the shape check can, and each operand of it has a case of its own.
    let Some(h) = harness(base_config(), None) else { return };
    let (_, bad_jti) = token_for(&h, |c| c.jti = "abc".to_owned()).await;
    let (_, long_sub) = token_for(&h, |c| c.sub = "x".repeat(257)).await;
    let (_, long_tenant) = token_for(&h, |c| c.tenant_id = "t".repeat(257)).await;
    for presented in [bad_jti, long_sub, long_tenant] {
        let refused = h
            .engine
            .verify_access(&presented, &dashboard().check_status(false))
            .await;
        assert!(
            matches!(refused, Err(AuthError::TokenInvalid)),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn a_blocked_account_is_told_so_even_while_a_challenge_is_pending() {
    // Status is judged before the second factor: a banned account must not be asked for a
    // challenge it could not use.
    let Some(h) = harness(base_config(), None) else { return };
    let (id, token) = token_for(&h, |c| c.mfa_enabled = true).await;
    assert!(h.users.update_status(&id, TENANT, "BANNED").await.is_ok());
    let refused = h.engine.verify_access(&token, &dashboard()).await;
    assert!(
        matches!(refused, Err(AuthError::AccountBanned)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_pending_challenge_is_refused_unless_the_caller_waives_it() {
    let Some(h) = harness(base_config(), None) else { return };
    let (_, token) = token_for(&h, |c| c.mfa_enabled = true).await;
    let refused = h.engine.verify_access(&token, &dashboard()).await;
    assert!(
        matches!(refused, Err(AuthError::MfaRequired)),
        "{refused:?}"
    );
    let waived = h
        .engine
        .verify_access(&token, &dashboard().require_mfa(false))
        .await;
    assert!(waived.is_ok(), "{waived:?}");
}

#[tokio::test]
async fn a_completed_challenge_passes() {
    let Some(h) = harness(base_config(), None) else { return };
    let (_, token) = token_for(&h, |c| {
        c.mfa_enabled = true;
        c.mfa_verified = true;
    })
    .await;
    assert!(h.engine.verify_access(&token, &dashboard()).await.is_ok());
}

#[tokio::test]
async fn waiving_the_status_check_trusts_the_token_snapshot() {
    let Some(h) = harness(base_config(), None) else { return };
    let (id, token) = token_for(&h, |_| {}).await;
    assert!(h.users.update_status(&id, TENANT, "BANNED").await.is_ok());
    let waived = h
        .engine
        .verify_access(&token, &dashboard().check_status(false))
        .await;
    assert!(waived.is_ok(), "{waived:?}");
}

#[tokio::test]
async fn an_unverified_address_is_refused_where_verification_is_required() {
    let mut cfg = base_config();
    cfg.email_verification.required = true;
    let Some(h) = harness(cfg, None) else { return };
    let id = h
        .seed(SeedUser {
            email_verified: false,
            ..SeedUser::active("u@example.com", "pw123456")
        })
        .await;
    let token = h
        .engine
        .tokens()
        .issue_access(&claims_for(&id))
        .unwrap_or_default();
    let refused = h.engine.verify_access(&token, &dashboard()).await;
    assert!(
        matches!(refused, Err(AuthError::EmailNotVerified)),
        "{refused:?}"
    );
}

/// Resolves the tenant from the request host, failing on a missing one.
struct HostResolver;

#[async_trait]
impl TenantIdResolver for HostResolver {
    async fn resolve(&self, parts: &RequestParts) -> Result<String, TenantResolveError> {
        parts.host.clone().ok_or(TenantResolveError::Empty)
    }
}

fn request_for(host: Option<&str>) -> RequestContext {
    let headers = host
        .map(|h| std::collections::BTreeMap::from([("host".to_owned(), h.to_owned())]))
        .unwrap_or_default();
    RequestContext::new("203.0.113.9", "agent/1.0", headers)
}

#[tokio::test]
async fn the_tenant_binding_follows_the_request_and_every_failure_is_token_invalid() {
    let mut cfg = base_config();
    cfg.tenant_id_resolver = Some(Arc::new(HostResolver));
    cfg.enforce_tenant_binding = true;
    let Some(h) = harness(cfg, None) else { return };
    let (_, token) = token_for(&h, |_| {}).await;

    let own = request_for(Some(TENANT));
    assert!(
        h.engine
            .verify_access(&token, &dashboard().request(&own))
            .await
            .is_ok()
    );

    // Another tenant's host, and a request the resolver cannot name a tenant for.
    for host in [Some("globex"), None] {
        let request = request_for(host);
        let refused = h
            .engine
            .verify_access(&token, &dashboard().request(&request))
            .await;
        assert!(
            matches!(refused, Err(AuthError::TokenInvalid)),
            "{host:?}: {refused:?}"
        );
    }

    // No request: the binding cannot be applied, and the call still verifies.
    assert!(h.engine.verify_access(&token, &dashboard()).await.is_ok());
}

#[tokio::test]
async fn a_request_is_ignored_when_the_binding_is_off() {
    let mut cfg = base_config();
    cfg.tenant_id_resolver = Some(Arc::new(HostResolver));
    let Some(h) = harness(cfg, None) else { return };
    let (_, token) = token_for(&h, |_| {}).await;
    let foreign = request_for(Some("globex"));
    assert!(
        h.engine
            .verify_access(&token, &dashboard().request(&foreign))
            .await
            .is_ok()
    );
}
