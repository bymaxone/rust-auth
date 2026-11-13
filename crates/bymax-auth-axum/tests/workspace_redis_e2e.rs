//! The workspace guard against a **real Redis** (via `testcontainers`): the membership a route
//! admits is resolved through the versioned cache `RedisStores` holds, an unbumped change is still
//! answered from it, and the bump the writer makes after its change takes the entry out (layer:
//! HTTP adapter, end-to-end tests).
//!
//! The single legitimate skip is Docker being unavailable; once a container runs, every step
//! asserts a real outcome.

#[path = "../../bymax-auth-redis/tests/common/docker_gate.rs"]
mod docker_gate;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bymax_auth_axum::{AuthRouter, AxumAuthConfig, ClientIpSource};
use bymax_auth_core::services::membership_cache::bump_membership;
use bymax_auth_core::testing::{InMemoryUserRepository, InMemoryWorkspaces};
use bymax_auth_core::traits::UserRepository;
use bymax_auth_core::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceStatus,
};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::CreateUserData;
use http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::{Value, json};
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use time::OffsetDateTime;
use tower::ServiceExt;

const TENANT: &str = "t1";
const PASSWORD: &str = "glidingwalnut42";

/// Start a `redis:8` container and return it with its URL, `None` when Docker is unavailable.
async fn try_start() -> Option<(ContainerAsync<Redis>, String)> {
    let container = match Redis::default().with_tag("8").start().await {
        Ok(container) => container,
        Err(error) => return docker_gate::docker_unavailable("redis:8", error),
    };
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    Some((container, format!("redis://{host}:{port}")))
}

/// What the test holds of the engine it built.
struct Built {
    engine: Arc<AuthEngine>,
    users: Arc<InMemoryUserRepository>,
    stores: Arc<RedisStores>,
    repo: Arc<InMemoryWorkspaces>,
}

/// An engine with the workspace layer on, its membership cache in the real Redis.
fn build(url: &str) -> Option<Built> {
    let stores = Arc::new(RedisStores::connect(url, "auth").ok()?);
    let users = Arc::new(InMemoryUserRepository::new());
    let repo = Arc::new(InMemoryWorkspaces::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.workspaces.enabled = true;
    config.workspaces.roles.hierarchy = BTreeMap::from([("owner".to_owned(), Vec::new())]);
    config.workspaces.roles.owner_role = "owner".to_owned();
    config.controllers.workspaces = true;
    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .workspace_repositories(repo.clone(), repo.clone())
        .membership_cache_store(stores.clone())
        .build()
        .ok()?;
    Some(Built {
        engine: Arc::new(engine),
        users,
        stores,
        repo,
    })
}

/// Sends a request with an optional JSON body and access cookie: the status and the JSON body,
/// with the access cookie the response set, if any.
async fn send(
    app: &Router,
    (method, path): (Method, &str),
    body: Option<Value>,
    access: &str,
) -> (StatusCode, Value, String) {
    let body = body.map_or_else(Body::empty, |value| Body::from(value.to_string()));
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("access_token={access}"))
        .body(body)
        .unwrap_or_default();
    if let Ok(peer) = "203.0.113.4:5555".parse::<SocketAddr>() {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    let Ok(response) = app.clone().oneshot(request).await;
    let status = response.status();
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix("access_token="))
        .and_then(|rest| rest.split(';').next())
        .unwrap_or_default()
        .to_owned();
    let bytes = response.into_body().collect().await.map(|c| c.to_bytes());
    let json = bytes.map_or(Value::Null, |b| {
        serde_json::from_slice(&b).unwrap_or(Value::Null)
    });
    (status, json, cookie)
}

/// An account with the test password; returns its id.
async fn seed_user(users: &InMemoryUserRepository) -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    let hash = bymax_auth_crypto::password::hash(PASSWORD.as_bytes(), &params).unwrap_or_default();
    let created = users
        .create(CreateUserData {
            email: "w@e.com".to_owned(),
            name: "Member".to_owned(),
            password_hash: Some(hash),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    created.map(|user| user.id).unwrap_or_default()
}

/// The active workspace `w1`, and `user` owning it in `status`.
fn seed_seat(repo: &InMemoryWorkspaces, user: &str, status: MembershipStatus) {
    let at = OffsetDateTime::UNIX_EPOCH;
    repo.seed_workspace(Workspace {
        id: "w1".to_owned(),
        tenant_id: TENANT.to_owned(),
        name: "One".to_owned(),
        status: WorkspaceStatus::Active,
        created_at: at,
        deletion_scheduled_at: None,
    });
    repo.seed_membership(Membership {
        tenant_id: TENANT.to_owned(),
        workspace_id: "w1".to_owned(),
        user_id: user.to_owned(),
        role: "owner".to_owned(),
        status,
        invited_by_user_id: None,
        created_at: at,
        updated_at: at,
    });
}

#[tokio::test]
async fn the_workspace_guard_resolves_through_the_cache_in_real_redis() {
    let Some((_container, url)) = try_start().await else { return };
    let built = build(&url);
    assert!(
        built.is_some(),
        "setup must succeed once the container runs"
    );
    let Some(b) = built else { return };
    let router = AuthRouter::from_engine(
        b.engine.clone(),
        AxumAuthConfig::new(ClientIpSource::PeerAddr),
    );
    let Ok(app) = router.map(AuthRouter::into_router) else { return };
    let user = seed_user(&b.users).await;
    let credentials = json!({ "email": "w@e.com", "password": PASSWORD, "tenantId": TENANT });
    let (_, _, access) = send(&app, (Method::POST, "/auth/login"), Some(credentials), "").await;
    assert!(!access.is_empty());
    seed_seat(&b.repo, &user, MembershipStatus::Active);
    let read = (Method::GET, "/auth/workspaces/w1/access");
    let (status, body, _) = send(&app, read.clone(), None, &access).await;
    assert_eq!((status, &body["role"]), (StatusCode::OK, &json!("owner")));
    // A change the writer has not bumped is still answered from the entry Redis holds.
    seed_seat(&b.repo, &user, MembershipStatus::Suspended);
    let (status, _, _) = send(&app, read.clone(), None, &access).await;
    assert_eq!(status, StatusCode::OK);
    let member = MembershipRef {
        tenant_id: TENANT,
        workspace_id: "w1",
        user_id: &user,
    };
    let bumped = bump_membership(b.stores.as_ref(), b.engine.config().hmac_key(), member).await;
    assert!(bumped.is_ok());
    let (status, body, _) = send(&app, read, None, &access).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "auth.workspace_not_found");
    let (status, body, _) = send(&app, (Method::GET, "/auth/workspaces"), None, &access).await;
    assert_eq!((status, &body["items"]), (StatusCode::OK, &json!([])));
}
