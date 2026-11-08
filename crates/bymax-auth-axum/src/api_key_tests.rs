//! The API-key layer over a real router: what a caller sees for each credential, how the route is
//! named in the audit, how the key is read, and what the flush task does.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::routing::get;
use bymax_auth_core::config::{ApiKeyAuditMode, TokenDelivery};
use bymax_auth_core::services::api_key::IssueApiKeyInput;
use bymax_auth_core::testing::{
    InMemoryApiKeyRepository, InMemoryStores, InMemoryUserRepository, ManualApiKeyClock,
};
use bymax_auth_core::traits::{
    ApiKeyAccessEvent, ApiKeyDenyReason, AuthHooks, HookContext, HookError,
};
use bymax_auth_core::{AuthConfig, AuthEngine, ConfigError, Environment};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use secrecy::SecretString;
use time::OffsetDateTime;
use tower::ServiceExt;

use crate::api_key::{
    ApiKeyScopesLayer, CurrentApiKey, require_api_key_scopes, spawn_api_key_flush,
};
use crate::state::AuthState;
use crate::test_support::{SECRET, resolved_config_with};

/// 43 base64url characters: a strong pepper distinct from the JWT secret.
const PEPPER: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[derive(Default)]
struct Audit {
    events: Mutex<Vec<ApiKeyAccessEvent>>,
}

#[async_trait]
impl AuthHooks for Audit {
    async fn on_api_key_request(
        &self,
        event: &ApiKeyAccessEvent,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}

impl Audit {
    fn events(&self) -> Vec<ApiKeyAccessEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn wait_for(&self, count: usize) -> Vec<ApiKeyAccessEvent> {
        for _ in 0..200 {
            if self.events().len() >= count {
                break;
            }
            tokio::task::yield_now().await;
        }
        self.events()
    }
}

struct Harness {
    state: AuthState,
    engine: Arc<AuthEngine>,
    repo: Arc<InMemoryApiKeyRepository>,
    audit: Arc<Audit>,
}

fn harness(tweak: impl FnOnce(&mut AuthConfig)) -> Result<Harness, ConfigError> {
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(SECRET.to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.api_keys.enabled = true;
    config.api_keys.pepper = SecretString::from(PEPPER.to_owned());
    config.api_keys.scopes = vec!["reports:read".to_owned(), "reports:write".to_owned()];
    config.api_keys.audit_mode = ApiKeyAuditMode::BestEffort;
    tweak(&mut config);
    let repo = Arc::new(InMemoryApiKeyRepository::new());
    let audit = Arc::new(Audit::default());
    let engine = Arc::new(
        AuthEngine::builder()
            .config(config)
            .environment(Environment::Test)
            .user_repository(Arc::new(InMemoryUserRepository::new()))
            .redis_stores(Arc::new(InMemoryStores::new()))
            .hooks(audit.clone())
            .api_key_repository(repo.clone())
            .api_key_clock(Arc::new(ManualApiKeyClock::new(OffsetDateTime::now_utc())))
            .build()?,
    );
    let state = AuthState::new(
        engine.clone(),
        Arc::new(resolved_config_with(
            TokenDelivery::Bearer,
            bymax_auth_core::config::SameSite::Lax,
        )),
    );
    Ok(Harness {
        state,
        engine,
        repo,
        audit,
    })
}

async fn issue(h: &Harness, scopes: &[&str]) -> Result<String, bymax_auth_types::AuthError> {
    let scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    let issued = h
        .engine
        .issue_api_key(IssueApiKeyInput::new("billing", scopes))
        .await?;
    Ok(issued.key)
}

async fn label(CurrentApiKey(principal): CurrentApiKey) -> String {
    principal.label
}

async fn sensitivity(headers: HeaderMap) -> String {
    let values: Vec<_> = headers.get_all("x-service-key").iter().collect();
    format!(
        "{}",
        !values.is_empty() && values.iter().all(|v| v.is_sensitive())
    )
}

fn guarded(layer: ApiKeyScopesLayer) -> Router {
    Router::new()
        .route("/reports/{id}", get(label))
        .route("/sensitive", get(sensitivity))
        .route_layer(layer)
}

fn request(path: &str, key: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .unwrap_or_default();
    if let Some(key) = key.and_then(|k| http::HeaderValue::from_str(k).ok()) {
        request.headers_mut().insert("x-api-key", key);
    }
    request
}

async fn answer(router: &Router, request: Request<Body>) -> (StatusCode, String) {
    match router.clone().oneshot(request).await {
        Ok(response) => {
            let status = response.status();
            let bytes = response
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
        Err(never) => match never {},
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn a_valid_key_with_the_scope_is_admitted_and_audited_by_route_pattern() -> TestResult {
    let h = harness(|_| {})?;
    let key = issue(&h, &["reports:read"]).await?;
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);

    let (status, body) = answer(&router, request("/reports/42", Some(&key))).await;

    assert_eq!((status, body.as_str()), (StatusCode::OK, "billing"));
    let events = h.audit.wait_for(1).await;
    let event = events.first().ok_or("no audit event")?;
    assert_eq!(event.route, "/reports/{id}");
    assert_eq!(event.method, "GET");
    assert_eq!(event.required_scopes, ["reports:read"]);
    Ok(())
}

#[tokio::test]
async fn every_bad_credential_gets_the_same_answer_byte_for_byte() -> TestResult {
    let h = harness(|_| {})?;
    let live = issue(&h, &["reports:read"]).await?;
    let revoked = issue(&h, &["reports:read"]).await?;
    let revoked_id = revoked.split('_').nth(1).ok_or("no id")?;
    h.engine.revoke_api_key(revoked_id).await?;
    let forged = live.replacen(&live[live.len() - 5..], "AAAAA", 1);
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);

    let mut bodies = Vec::new();
    for presented in [
        None,
        Some("junk"),
        Some(forged.as_str()),
        Some(revoked.as_str()),
    ] {
        let (status, body) = answer(&router, request("/reports/1", presented)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{presented:?}");
        bodies.push(body);
    }

    assert!(bodies.iter().all(|b| b == &bodies[0]));
    assert!(bodies[0].contains("auth.api_key_invalid"));
    Ok(())
}

#[tokio::test]
async fn a_repeated_header_a_query_key_and_a_non_ascii_value_are_not_keys() -> TestResult {
    let h = harness(|_| {})?;
    let key = issue(&h, &["reports:read"]).await?;
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);

    let twice = Request::builder()
        .uri("/reports/1")
        .header("x-api-key", &key)
        .header("x-api-key", &key)
        .body(Body::empty())?;
    let in_query = request(&format!("/reports/1?x-api-key={key}"), None);
    let mut non_ascii = request("/reports/1", None);
    non_ascii
        .headers_mut()
        .insert("x-api-key", http::HeaderValue::from_bytes(b"bak_\xff")?);

    for bad in [twice, in_query, non_ascii] {
        let (status, body) = answer(&router, bad).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("auth.api_key_invalid"));
    }
    let (single, _) = answer(&router, request("/reports/1", Some(&key))).await;
    assert_eq!(single, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn a_valid_key_missing_a_declared_scope_is_forbidden_with_its_own_code() -> TestResult {
    let h = harness(|_| {})?;
    let key = issue(&h, &["reports:read"]).await?;
    let router = guarded(require_api_key_scopes(
        &h.state,
        &["reports:read", "reports:write"],
    )?);

    let (status, body) = answer(&router, request("/reports/1", Some(&key))).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("auth.api_key_scope_insufficient"));
    Ok(())
}

#[tokio::test]
async fn a_layer_built_with_no_scopes_refuses_everything_before_reading_a_key() -> TestResult {
    let h = harness(|_| {})?;
    let key = issue(&h, &["reports:read", "reports:write"]).await?;
    let reads = h.repo.reads();
    let router = guarded(require_api_key_scopes(&h.state, &[])?);

    for presented in [Some(key.as_str()), None] {
        let (status, body) = answer(&router, request("/reports/1", presented)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("auth.forbidden"));
    }

    assert_eq!(h.repo.reads(), reads, "no row may be read");
    let events = h.audit.wait_for(2).await;
    assert!(
        events
            .iter()
            .all(|e| e.reason == Some(ApiKeyDenyReason::RouteUndeclared))
    );
    Ok(())
}

#[tokio::test]
async fn a_store_outage_is_a_500_not_a_refusal_of_the_key() -> TestResult {
    let h = harness(|_| {})?;
    let key = issue(&h, &["reports:read"]).await?;
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);
    h.repo.set_failing(true);

    let (status, body) = answer(&router, request("/reports/1", Some(&key))).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("auth.internal"));
    Ok(())
}

#[tokio::test]
async fn the_configured_header_is_the_only_one_read_and_is_marked_sensitive() -> TestResult {
    let h = harness(|cfg| cfg.api_keys.header = "x-service-key".to_owned())?;
    let key = issue(&h, &["reports:read"]).await?;
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);

    let default_header = request("/reports/1", Some(&key));
    let configured = Request::builder()
        .uri("/reports/1")
        .header("x-service-key", &key)
        .body(Body::empty())?;
    let sensitive = Request::builder()
        .uri("/sensitive")
        .header("x-service-key", &key)
        .body(Body::empty())?;

    assert_eq!(
        answer(&router, default_header).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(answer(&router, configured).await.0, StatusCode::OK);
    let (status, body) = answer(&router, sensitive).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "true"));
    Ok(())
}

#[tokio::test]
async fn the_extractor_without_the_layer_is_a_wiring_error_not_a_missing_credential() {
    let router = Router::new().route("/open", get(label));

    let (status, body) = answer(&router, request("/open", None)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("auth.internal"));
}

#[tokio::test]
async fn a_guard_or_a_flush_task_over_an_engine_without_api_keys_is_refused_at_startup()
-> TestResult {
    let plain = AuthEngine::builder()
        .config({
            let mut config = AuthConfig::default();
            config.jwt.secret = SecretString::from(SECRET.to_owned());
            config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
            config
        })
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build()?;
    let state = AuthState::new(
        Arc::new(plain),
        Arc::new(resolved_config_with(
            TokenDelivery::Bearer,
            bymax_auth_core::config::SameSite::Lax,
        )),
    );

    assert!(matches!(
        require_api_key_scopes(&state, &["reports:read"]),
        Err(ConfigError::ApiKeyGuardWithoutApiKeys)
    ));
    assert!(matches!(
        spawn_api_key_flush(state.engine().clone()),
        Err(ConfigError::ApiKeyGuardWithoutApiKeys)
    ));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_flush_task_writes_on_its_period_and_once_more_on_shutdown() -> TestResult {
    let h = harness(|cfg| cfg.api_keys.last_used_flush = Duration::from_secs(30))?;
    let key = issue(&h, &["reports:read"]).await?;
    let id = key.split('_').nth(1).ok_or("no id")?.to_owned();
    let router = guarded(require_api_key_scopes(&h.state, &["reports:read"])?);
    let task = spawn_api_key_flush(h.engine.clone())?;

    answer(&router, request("/reports/1", Some(&key))).await;
    assert!(h.repo.row(&id).and_then(|r| r.last_used_at).is_none());
    tokio::time::sleep(Duration::from_secs(31)).await;
    let after_period = h.repo.row(&id).and_then(|r| r.last_used_at);
    assert!(after_period.is_some(), "the period flush wrote the instant");

    h.repo.set_failing(true);
    answer(&router, request("/reports/1", Some(&key))).await;
    tokio::time::sleep(Duration::from_secs(31)).await;
    h.repo.set_failing(false);
    assert!(task.shutdown().await, "the task ends normally");
    assert!(h.repo.row(&id).and_then(|r| r.last_used_at) >= after_period);
    Ok(())
}
