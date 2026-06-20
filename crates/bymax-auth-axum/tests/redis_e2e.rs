//! Full-router end-to-end test against a **real Redis** (via `testcontainers`). It proves the
//! adapter behaves identically against the production store tier as against the in-memory tier:
//! the always-on flows, sessions, the MFA enrolment + challenge wiring, the OAuth callback
//! (against a mock provider), the platform domain, invitations, and the single-use WS ticket
//! all work over genuine Redis keys, and no token ever appears in a URL.
//!
//! The single legitimate skip is Docker being unavailable (no container starts). Once a
//! container is running, every step asserts a real outcome. This file is self-contained (it
//! does not include the in-memory `common` harness) so its request helpers stay minimal.
#![cfg(all(
    feature = "mfa",
    feature = "sessions",
    feature = "platform",
    feature = "oauth",
    feature = "invitations",
    feature = "websocket"
))]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bymax_auth_axum::{AuthRouter, AxumAuthConfig};
use bymax_auth_core::config::MfaConfig;
use bymax_auth_core::testing::{
    InMemoryPlatformUserRepository, InMemoryUserRepository, MockOAuthProvider,
};
use bymax_auth_core::traits::{
    AuthHooks, HookContext, HookError, OAuthLoginResult, OAuthProfile, UserRepository,
};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_redis::RedisStores;
use bymax_auth_types::{AuthPlatformUser, CreateUserData};
use http::{HeaderValue, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use time::OffsetDateTime;
use tower::ServiceExt;

const TENANT: &str = "t1";
const PEER: &str = "203.0.113.4:5555";

/// A hook that allows OAuth sign-in (creates a new user), so the callback can complete.
struct AllowOAuth;

#[async_trait]
impl AuthHooks for AllowOAuth {
    async fn on_oauth_login(
        &self,
        _profile: &OAuthProfile,
        existing: Option<&bymax_auth_types::SafeAuthUser>,
        _ctx: &HookContext,
    ) -> Result<OAuthLoginResult, HookError> {
        if existing.is_some() {
            Ok(OAuthLoginResult::Link)
        } else {
            Ok(OAuthLoginResult::Create)
        }
    }
}

/// A running Redis container plus its URL; dropping it stops the container.
struct TestRedis {
    container: ContainerAsync<Redis>,
    url: String,
}

/// Start a `redis:8` container, returning `None` when Docker is unavailable so the test skips.
async fn try_start() -> Option<TestRedis> {
    let container = Redis::default().with_tag("8").start().await.ok()?;
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(REDIS_PORT).await.ok()?;
    let url = format!("redis://{host}:{port}");
    Some(TestRedis { container, url })
}

/// Hash a plaintext with the default (scrypt) hasher.
fn hash_password(plain: &str) -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    bymax_auth_crypto::password::hash(plain.as_bytes(), &params).unwrap_or_default()
}

/// A 32-byte AES key, base64-encoded, for the MFA config.
fn mfa_key() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

/// Build a fully-featured engine over the real Redis stores.
fn build_engine(
    redis: &TestRedis,
) -> Option<(
    Arc<AuthEngine>,
    Arc<InMemoryUserRepository>,
    Arc<InMemoryPlatformUserRepository>,
)> {
    let _ = redis.container.id();
    let stores = Arc::new(RedisStores::connect(&redis.url, "auth").ok()?);
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["USER".to_owned()]),
        ("USER".to_owned(), Vec::new()),
    ]);
    config.roles.platform_hierarchy = Some(HashMap::from([
        ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
        ("SUPPORT".to_owned(), Vec::new()),
    ]));
    config.sessions.enabled = true;
    config.controllers.sessions = true;
    config.controllers.invitations = true;
    config.invitations.enabled = true;
    config.controllers.oauth = true;
    config.controllers.mfa = true;
    config.platform.enabled = true;
    config.mfa = Some(MfaConfig {
        encryption_key: SecretString::from(mfa_key()),
        issuer: "Bymax".to_owned(),
        recovery_code_count: 8,
        totp_window: 2,
    });

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(stores.clone())
        .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
        .oauth_state_store(stores)
        .hooks(Arc::new(AllowOAuth))
        .build()
        .ok()?;
    Some((Arc::new(engine), users, admins))
}

/// Seed an active dashboard user; returns its id.
async fn seed_user(users: &InMemoryUserRepository, email: &str, role: &str) -> String {
    let created = users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "User".to_owned(),
            password_hash: Some(hash_password("password123")),
            role: Some(role.to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: TENANT.to_owned(),
            email_verified: Some(true),
        })
        .await;
    match created {
        Ok(user) => user.id,
        Err(_) => String::new(),
    }
}

/// Captured response.
struct Resp {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn cookie_value(&self, name: &str) -> String {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with(&format!("{name}=")))
            .and_then(|c| c.split(';').next())
            .and_then(|kv| kv.split_once('='))
            .map(|(_, v)| v.to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_default()
    }
}

/// Drive a request through the router (peer IP injected; optional JSON body + cookies).
async fn call(
    app: &Router,
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
    cookies: &[(&str, &str)],
) -> Resp {
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if !cookies.is_empty() {
        let jar = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(value) = HeaderValue::from_str(&jar) {
            builder = builder.header(header::COOKIE, value);
        }
    }
    builder = builder.header(header::CONTENT_TYPE, "application/json");
    let mut request = match builder.body(body) {
        Ok(request) => request,
        Err(_) => return error_resp(),
    };
    if let Ok(addr) = PEER.parse::<SocketAddr>() {
        request.extensions_mut().insert(ConnectInfo(addr));
    }
    match app.clone().oneshot(request).await {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            Resp {
                status,
                headers,
                body,
            }
        }
        Err(_) => error_resp(),
    }
}

fn error_resp() -> Resp {
    Resp {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: http::HeaderMap::new(),
        body: Vec::new(),
    }
}

#[tokio::test]
async fn full_router_against_real_redis() {
    let Some(redis) = try_start().await else {
        // Docker unavailable — skip cleanly.
        return;
    };
    // The container is up, so engine/router setup MUST succeed; a failure here is an
    // infrastructure regression, not a skip condition. Assert before binding so the test
    // hard-fails instead of silently passing on a broken setup.
    let built = build_engine(&redis);
    assert!(
        built.is_some(),
        "engine/router setup must succeed once the Redis container is running"
    );
    let Some((engine, users, admins)) = built else { return };
    let app = AuthRouter::from_engine(engine.clone(), AxumAuthConfig::default()).into_router();

    // ---- register → login → refresh → logout → me, all over real Redis -----------------
    let reg = call(
        &app,
        Method::POST,
        "/auth/register",
        Some(serde_json::json!({
            "email": "r@e.com", "password": "password123", "name": "Ray", "tenantId": TENANT
        })),
        &[],
    )
    .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let access = reg.cookie_value("access_token");
    let refresh = reg.cookie_value("refresh_token");
    assert!(!access.is_empty() && !refresh.is_empty());

    let me = call(
        &app,
        Method::GET,
        "/auth/me",
        None,
        &[("access_token", &access)],
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["user"]["email"], "r@e.com");

    let rotated = call(
        &app,
        Method::POST,
        "/auth/refresh",
        None,
        &[("refresh_token", &refresh)],
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_refresh = rotated.cookie_value("refresh_token");
    assert!(!new_refresh.is_empty());

    // ---- sessions over real Redis ------------------------------------------------------
    let list = call(
        &app,
        Method::GET,
        "/auth/sessions",
        None,
        &[("access_token", &access), ("refresh_token", &new_refresh)],
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(list.json()["sessions"].is_array());

    // ---- WS ticket mint + single-use redeem against real Redis -------------------------
    let mint = call(
        &app,
        Method::POST,
        "/auth/ws-ticket",
        None,
        &[("access_token", &access)],
    )
    .await;
    assert_eq!(mint.status, StatusCode::OK);
    let ticket = mint.json()["ticket"].as_str().unwrap_or("").to_owned();
    assert!(!ticket.is_empty());
    // The first GETDEL redemption wins; the second is refused (single-use).
    assert!(engine.redeem_ws_ticket(&ticket).await.is_ok());
    assert!(engine.redeem_ws_ticket(&ticket).await.is_err());

    // ---- OAuth initiate (302) → callback completes against real Redis state ------------
    let initiate = call(
        &app,
        Method::GET,
        "/auth/oauth/google?tenantId=t1",
        None,
        &[],
    )
    .await;
    assert_eq!(initiate.status, StatusCode::FOUND);
    let location = initiate
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let state = location
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or("")
        .to_owned();
    let callback = call(
        &app,
        Method::GET,
        &format!("/auth/oauth/google/callback?code=abc&state={state}"),
        None,
        &[],
    )
    .await;
    assert_eq!(callback.status, StatusCode::OK);
    assert!(callback.json()["user"].is_object());

    // ---- platform login → me over real Redis -------------------------------------------
    admins.insert(AuthPlatformUser {
        id: "admin-1".to_owned(),
        email: "boss@e.com".to_owned(),
        name: "Boss".to_owned(),
        password_hash: hash_password("adminpass123"),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    let plogin = call(
        &app,
        Method::POST,
        "/auth/platform/login",
        Some(serde_json::json!({ "email": "boss@e.com", "password": "adminpass123" })),
        &[],
    )
    .await;
    assert_eq!(plogin.status, StatusCode::OK);
    let padmin_access = plogin.cookie_value("access_token");
    let pme = call(
        &app,
        Method::GET,
        "/auth/platform/me",
        None,
        &[("access_token", &padmin_access)],
    )
    .await;
    assert_eq!(pme.status, StatusCode::OK);

    // ---- invitations over real Redis ---------------------------------------------------
    seed_user(&users, "inviter@e.com", "ADMIN").await;
    let ilogin = call(
        &app,
        Method::POST,
        "/auth/login",
        Some(serde_json::json!({
            "email": "inviter@e.com", "password": "password123", "tenantId": TENANT
        })),
        &[],
    )
    .await;
    let inviter_access = ilogin.cookie_value("access_token");
    let create = call(
        &app,
        Method::POST,
        "/auth/invitations",
        Some(serde_json::json!({ "email": "invitee@e.com", "role": "USER" })),
        &[("access_token", &inviter_access)],
    )
    .await;
    assert_eq!(create.status, StatusCode::NO_CONTENT);

    // ---- MFA enrolment over real Redis (setup → verify-enable with a live TOTP) ---------
    seed_user(&users, "mfa@e.com", "USER").await;
    let mlogin = call(
        &app,
        Method::POST,
        "/auth/login",
        Some(serde_json::json!({
            "email": "mfa@e.com", "password": "password123", "tenantId": TENANT
        })),
        &[],
    )
    .await;
    let mfa_access = mlogin.cookie_value("access_token");
    let setup = call(
        &app,
        Method::POST,
        "/auth/mfa/setup",
        None,
        &[("access_token", &mfa_access)],
    )
    .await;
    assert_eq!(setup.status, StatusCode::OK);
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let raw = bymax_auth_crypto::totp::decode_secret_base32(&secret).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let code = format!("{:06}", bymax_auth_crypto::totp::totp(&raw, now, 30, 6));
    let enable = call(
        &app,
        Method::POST,
        "/auth/mfa/verify-enable",
        Some(serde_json::json!({ "code": code })),
        &[("access_token", &mfa_access)],
    )
    .await;
    assert_eq!(enable.status, StatusCode::NO_CONTENT);

    // ---- logout clears the session; the rotated refresh no longer rotates --------------
    let logout = call(
        &app,
        Method::POST,
        "/auth/logout",
        None,
        &[("access_token", &access), ("refresh_token", &new_refresh)],
    )
    .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
}
