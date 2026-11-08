//! The access decision: route configuration first, then the key, then its scopes, then the audit;
//! every refusal is audited with its operator-facing reason while the caller gets one answer, and
//! a `Required` audit that cannot be written refuses the request it audits.

use std::time::Duration;

use bymax_auth_types::AuthError;

use super::ApiKeyRoute;
use super::access::run_required_audit;
use super::test_support::{Fixture, TestResult, fixture, request_context};
use crate::config::ApiKeyAuditMode;
use crate::traits::{ApiKeyDenyReason, ApiKeyOutcome, HookError, HookPlane};

const ROUTE: &str = "/reports/{id}";

async fn authorize(
    f: &Fixture,
    header: Option<&str>,
    scopes: &[&str],
) -> Result<crate::traits::ApiKeyPrincipal, AuthError> {
    let route = ApiKeyRoute {
        method: "GET",
        pattern: ROUTE,
        required_scopes: scopes,
    };
    f.engine
        .authorize_api_key(header, &route, &request_context())
        .await
}

#[tokio::test]
async fn a_key_holding_every_declared_scope_is_admitted_and_audited() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["reports:read", "reports:write", "admin"]).await?;

    let principal = authorize(&f, Some(&issued.key), &["reports:read", "reports:write"]).await?;

    assert_eq!(principal.id, issued.record.id);
    assert_eq!(principal.label, "billing");
    assert_eq!(principal.scopes, issued.record.scopes);
    let calls = f.hooks.wait_for(1).await;
    let (event, ctx) = calls.first().ok_or("no audit event")?;
    assert_eq!(event.outcome, ApiKeyOutcome::Allowed);
    assert_eq!(event.reason, None);
    assert_eq!(event.key_id.as_deref(), Some(issued.record.id.as_str()));
    assert_eq!(event.label.as_deref(), Some("billing"));
    assert_eq!(
        (event.method.as_str(), event.route.as_str()),
        ("GET", ROUTE)
    );
    assert_eq!(event.required_scopes, ["reports:read", "reports:write"]);
    assert_eq!(event.ip, "203.0.113.9");
    assert_eq!(ctx.plane, HookPlane::ApiKey);
    assert!(ctx.user_id.is_none() && ctx.tenant_id.is_none() && ctx.email.is_none());
    Ok(())
}

#[tokio::test]
async fn the_key_header_never_reaches_the_audit_context() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;

    authorize(&f, Some(&issued.key), &["admin"]).await?;

    let calls = f.hooks.wait_for(1).await;
    let (event, ctx) = calls.first().ok_or("no audit event")?;
    assert!(!ctx.sanitized_headers.contains_key("x-api-key"));
    assert_eq!(
        ctx.sanitized_headers
            .get("x-request-id")
            .map(String::as_str),
        Some("req-1")
    );
    let rendered = format!("{event:?} {ctx:?}");
    assert!(!rendered.contains(&issued.key));
    assert!(!rendered.contains("must-not-reach-the-audit"));
    Ok(())
}

#[tokio::test]
async fn a_key_missing_one_declared_scope_is_refused_with_its_own_error() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["reports:read"]).await?;

    let error = authorize(&f, Some(&issued.key), &["reports:read", "reports:write"])
        .await
        .err();

    assert!(matches!(error, Some(AuthError::ApiKeyScopeInsufficient)));
    let calls = f.hooks.wait_for(1).await;
    let (event, _) = calls.first().ok_or("no audit event")?;
    assert_eq!(event.outcome, ApiKeyOutcome::Denied);
    assert_eq!(event.reason, Some(ApiKeyDenyReason::ScopeInsufficient));
    assert_eq!(event.key_id.as_deref(), Some(issued.record.id.as_str()));
    Ok(())
}

#[tokio::test]
async fn every_bad_credential_gets_one_answer_and_its_own_audit_reason() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let live = f.issue(&["admin"]).await?;
    let revoked = f.issue(&["admin"]).await?;
    f.engine.revoke_api_key(&revoked.record.id).await?;
    let mut lapsing = super::IssueApiKeyInput::new("billing", vec!["admin".to_owned()]);
    lapsing.expires_at = Some(f.clock_now() + time::Duration::seconds(30));
    let lapsed = f.engine.issue_api_key(lapsing).await?;
    f.clock.advance(time::Duration::seconds(30));
    let wrong_secret = bymax_auth_crypto::api_key::format(
        "bak",
        &live.record.id,
        &bymax_auth_crypto::api_key::generate_secret(),
    );
    let cases = [
        (None, ApiKeyDenyReason::Missing, None),
        (Some("junk".to_owned()), ApiKeyDenyReason::Malformed, None),
        (
            Some(bymax_auth_crypto::api_key::format(
                "bak",
                "00000000-0000-4000-8000-0000000000aa",
                &bymax_auth_crypto::api_key::generate_secret(),
            )),
            ApiKeyDenyReason::Unknown,
            None,
        ),
        (
            Some(wrong_secret),
            ApiKeyDenyReason::WrongSecret,
            Some(live.record.id.clone()),
        ),
        (
            Some(revoked.key.clone()),
            ApiKeyDenyReason::Revoked,
            Some(revoked.record.id.clone()),
        ),
        (
            Some(lapsed.key.clone()),
            ApiKeyDenyReason::Expired,
            Some(lapsed.record.id.clone()),
        ),
    ];

    for (index, (header, reason, identified)) in cases.iter().enumerate() {
        let error = authorize(&f, header.as_deref(), &["admin"]).await.err();
        assert!(
            matches!(error, Some(AuthError::ApiKeyInvalid)),
            "{reason:?}"
        );
        let calls = f.hooks.wait_for(index + 1).await;
        let (event, _) = calls.get(index).ok_or("no audit event")?;
        assert_eq!(event.outcome, ApiKeyOutcome::Denied);
        assert_eq!(event.reason, Some(*reason));
        assert_eq!(&event.key_id, identified);
    }
    Ok(())
}

#[tokio::test]
async fn a_route_without_scopes_is_refused_before_any_credential_work() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    let reads = f.repo.reads();

    let with_key = authorize(&f, Some(&issued.key), &[]).await.err();
    let without_key = authorize(&f, None, &[]).await.err();

    assert!(matches!(with_key, Some(AuthError::Forbidden)));
    assert!(matches!(without_key, Some(AuthError::Forbidden)));
    assert_eq!(
        f.repo.reads(),
        reads,
        "no row may be read for an undeclared route"
    );
    let calls = f.hooks.wait_for(2).await;
    assert!(calls.iter().all(|(event, _)| {
        event.reason == Some(ApiKeyDenyReason::RouteUndeclared) && event.key_id.is_none()
    }));
    Ok(())
}

#[tokio::test]
async fn a_store_outage_is_an_internal_error_audited_as_such() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.repo.set_failing(true);

    let error = authorize(&f, Some(&issued.key), &["admin"]).await.err();

    assert!(matches!(error, Some(AuthError::Internal(_))));
    let calls = f.hooks.wait_for(1).await;
    let (event, _) = calls.first().ok_or("no audit event")?;
    assert_eq!(event.reason, Some(ApiKeyDenyReason::StoreError));
    Ok(())
}

#[tokio::test]
async fn a_failing_hook_never_changes_the_answer_in_best_effort_mode() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.hooks.set_failing(true);

    let admitted = authorize(&f, Some(&issued.key), &["admin"]).await;
    let refused = authorize(&f, None, &["admin"]).await.err();

    assert!(admitted.is_ok());
    assert!(matches!(refused, Some(AuthError::ApiKeyInvalid)));
    assert_eq!(f.hooks.wait_for(2).await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_failing_hook_refuses_an_admitted_request_in_required_mode() -> TestResult {
    let f = fixture(ApiKeyAuditMode::Required)?;
    let issued = f.issue(&["admin"]).await?;

    assert!(authorize(&f, Some(&issued.key), &["admin"]).await.is_ok());
    f.hooks.set_failing(true);
    let admitted = authorize(&f, Some(&issued.key), &["admin"]).await.err();
    // A request that was refused anyway keeps its own answer whatever the hook does.
    let refused = authorize(&f, None, &["admin"]).await.err();
    let scope = authorize(&f, Some(&issued.key), &["reports:read"])
        .await
        .err();

    assert!(matches!(admitted, Some(AuthError::Internal(_))));
    assert!(matches!(refused, Some(AuthError::ApiKeyInvalid)));
    assert!(matches!(scope, Some(AuthError::ApiKeyScopeInsufficient)));
    Ok(())
}

#[tokio::test]
async fn the_required_audit_is_awaited_so_its_event_exists_when_the_answer_does() -> TestResult {
    let f = fixture(ApiKeyAuditMode::Required)?;
    let issued = f.issue(&["admin"]).await?;

    authorize(&f, Some(&issued.key), &["admin"]).await?;

    assert_eq!(f.hooks.calls().len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_required_audit_that_never_returns_is_a_refusal() {
    let hangs = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok::<(), HookError>(())
    };
    let fails = async { Err::<(), HookError>(HookError::Rejected("no".to_owned())) };

    assert!(run_required_audit(Duration::from_millis(20), async { Ok(()) }).await);
    assert!(!run_required_audit(Duration::from_millis(20), hangs).await);
    assert!(!run_required_audit(Duration::from_millis(20), fails).await);
}

#[tokio::test]
async fn authorizing_with_api_keys_off_is_an_internal_error() -> TestResult {
    let engine = crate::engine::AuthEngine::builder()
        .config(crate::services::auth::test_support::base_config())
        .environment(crate::config::Environment::Test)
        .user_repository(std::sync::Arc::new(
            crate::testing::InMemoryUserRepository::new(),
        ))
        .redis_stores(std::sync::Arc::new(crate::testing::InMemoryStores::new()))
        .build()?;
    let route = ApiKeyRoute {
        method: "GET",
        pattern: ROUTE,
        required_scopes: &["admin"],
    };

    let error = engine
        .authorize_api_key(None, &route, &request_context())
        .await
        .err();

    assert!(matches!(error, Some(AuthError::Internal(_))));
    Ok(())
}
