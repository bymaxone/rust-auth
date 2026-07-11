//! Shared test harness for the Axum adapter: build a fully-wired engine over the in-memory
//! trait doubles (the fast, Docker-free tier), assemble the router, and drive it with
//! `tower::ServiceExt::oneshot`. The testcontainers tier (real Redis) lives in its own file
//! and reuses the request/response helpers here.
//!
//! Every helper here is exercised by the single integration test file that includes this
//! module, so the crate's no-suppression lint posture holds without a `dead_code` allow.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bymax_auth_axum::AxumAuthConfig;
use bymax_auth_core::config::{MfaConfig, TokenDelivery as DeliveryMode};
use bymax_auth_core::testing::{
    InMemoryPlatformUserRepository, InMemoryStores, InMemoryUserRepository, MockOAuthProvider,
};
use bymax_auth_core::traits::{
    AuthHooks, HookContext, HookError, OAuthLoginResult, OAuthProfile, UserRepository,
};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_types::{CreateUserData, SafeAuthUser as HookSafeUser, UpdateMfaData};
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use tower::ServiceExt;

/// A 32-byte JWT secret used across the tests.
pub const JWT_SECRET: &str = "0123456789abcdef0123456789abcdef";
/// The default tenant used in tests.
pub const TENANT: &str = "t1";
/// The socket address injected as the peer IP for `oneshot` requests (no real socket).
pub const PEER: &str = "203.0.113.4:5555";

/// A hook that allows OAuth sign-in by creating a new account from the profile, so the OAuth
/// callback E2E can complete (the default `NoOpAuthHooks` rejects, disabling OAuth).
pub struct AllowOAuthHooks;

#[async_trait]
impl AuthHooks for AllowOAuthHooks {
    async fn on_oauth_login(
        &self,
        _profile: &OAuthProfile,
        existing: Option<&HookSafeUser>,
        _ctx: &HookContext,
    ) -> Result<OAuthLoginResult, HookError> {
        // Create when there is no existing user, otherwise link to it.
        if existing.is_some() {
            Ok(OAuthLoginResult::Link)
        } else {
            Ok(OAuthLoginResult::Create)
        }
    }
}

/// Knobs for building a test engine: which optional surfaces are enabled and the delivery mode.
pub struct EngineSpec {
    pub delivery: DeliveryMode,
    pub mfa: bool,
    pub platform: bool,
    pub oauth: bool,
    pub invitations: bool,
    pub sessions: bool,
    pub verification_required: bool,
    pub allow_oauth: bool,
}

impl Default for EngineSpec {
    fn default() -> Self {
        Self {
            delivery: DeliveryMode::Cookie,
            mfa: false,
            platform: false,
            oauth: false,
            invitations: false,
            sessions: false,
            verification_required: false,
            allow_oauth: false,
        }
    }
}

/// A base AES key (32 bytes) for the MFA config, base64-encoded.
fn mfa_key_b64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

/// The compiled-hasher PHC for a plaintext password (scrypt is the default test hasher).
pub fn hash_password(plain: &str) -> String {
    let params = bymax_auth_crypto::password::PasswordParams::default();
    bymax_auth_crypto::password::hash(plain.as_bytes(), &params).unwrap_or_default()
}

/// The built engine plus the concrete in-memory collaborators a test seeds/inspects.
pub struct Harness {
    pub engine: Arc<AuthEngine>,
    pub users: Arc<InMemoryUserRepository>,
    pub admins: Arc<InMemoryPlatformUserRepository>,
    pub stores: Arc<InMemoryStores>,
}

/// Build an engine + router over in-memory stores per `spec`.
pub fn build(spec: EngineSpec) -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(JWT_SECRET.to_owned());
    config.token_delivery = spec.delivery;
    config.email_verification.required = spec.verification_required;
    config.password_reset.method = bymax_auth_core::config::ResetMethod::Otp;
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["USER".to_owned()]),
        ("USER".to_owned(), Vec::new()),
    ]);
    config.sessions.enabled = spec.sessions;
    config.controllers.sessions = spec.sessions;
    config.controllers.invitations = spec.invitations;
    config.invitations.enabled = spec.invitations;
    config.controllers.oauth = spec.oauth;

    if spec.mfa {
        config.mfa = Some(MfaConfig {
            encryption_key: SecretString::from(mfa_key_b64()),
            issuer: "Bymax".to_owned(),
            recovery_code_count: 8,
            totp_window: 2,
        });
        config.controllers.mfa = true;
    }
    if spec.platform {
        config.platform.enabled = true;
        config.roles.platform_hierarchy = Some(HashMap::from([
            ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
            ("SUPPORT".to_owned(), Vec::new()),
        ]));
    }

    let mut builder = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(stores.clone());

    if spec.oauth {
        builder = builder
            .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
            .oauth_state_store(stores.clone());
    }
    if spec.allow_oauth {
        builder = builder.hooks(Arc::new(AllowOAuthHooks));
    }

    let engine = Arc::new(builder.build().ok()?);
    Some(Harness {
        engine,
        users,
        admins,
        stores,
    })
}

/// Build an OAuth-enabled engine with the three redirect URLs configured (so the callback
/// redirect branches are exercised), under the Test environment that permits http localhost.
pub fn build_oauth_with_redirects() -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(JWT_SECRET.to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.controllers.oauth = true;
    config.oauth.success_redirect_url = Some("http://localhost/app".to_owned());
    config.oauth.mfa_redirect_url = Some("http://localhost/mfa".to_owned());
    config.oauth.error_redirect_url = Some("http://localhost/error".to_owned());
    config.oauth.redirect_allowlist = vec!["localhost".to_owned()];

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Development)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(stores.clone())
        .oauth_provider(Arc::new(MockOAuthProvider::new("google")))
        .oauth_state_store(stores.clone())
        .hooks(Arc::new(AllowOAuthHooks))
        .build()
        .ok()?;
    Some(Harness {
        engine: Arc::new(engine),
        users,
        admins,
        stores,
    })
}

/// Assemble the adapter router for the harness engine with default adapter config.
pub fn router(harness: &Harness) -> Router {
    bymax_auth_axum::AuthRouter::from_engine(harness.engine.clone(), AxumAuthConfig::default())
        .into_router()
}

/// Seed an active, verified dashboard user with the given role; returns the id.
pub async fn seed_user(harness: &Harness, email: &str, password: &str, role: &str) -> String {
    let created = harness
        .users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "Seed User".to_owned(),
            password_hash: Some(hash_password(password)),
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

/// Sign a dashboard access token for an arbitrary `sub`/`role`/`status` with the shared test
/// secret, so a test can present a token whose subject does not exist (driving the handler
/// error arms that fetch the user and fail). The token is HS256-signed and temporally valid.
pub fn mint_dashboard_token(sub: &str, role: &str, status: &str) -> String {
    use bymax_auth_types::{DashboardClaims, DashboardType};
    let claims = DashboardClaims {
        sub: sub.to_owned(),
        jti: "jti-mint".to_owned(),
        tenant_id: TENANT.to_owned(),
        role: role.to_owned(),
        token_type: DashboardType::Dashboard,
        status: status.to_owned(),
        mfa_enabled: false,
        mfa_verified: false,
        iat: 1_700_000_000,
        exp: 4_700_000_000,
        epoch: 0,
    };
    let key = bymax_auth_jwt::HsKey::from_bytes(JWT_SECRET.as_bytes());
    bymax_auth_jwt::sign(&claims, &key).unwrap_or_default()
}

/// Sign a platform access token for an arbitrary `sub`/`role` with the shared test secret.
pub fn mint_platform_token(sub: &str, role: &str) -> String {
    use bymax_auth_types::{PlatformClaims, PlatformType};
    let claims = PlatformClaims {
        sub: sub.to_owned(),
        jti: "jti-mint-p".to_owned(),
        role: role.to_owned(),
        token_type: PlatformType::Platform,
        mfa_enabled: false,
        mfa_verified: false,
        iat: 1_700_000_000,
        exp: 4_700_000_000,
        epoch: 0,
    };
    let key = bymax_auth_jwt::HsKey::from_bytes(JWT_SECRET.as_bytes());
    bymax_auth_jwt::sign(&claims, &key).unwrap_or_default()
}

/// A store backend whose every operation fails with an internal error, so the handler error
/// arms that surface a store failure (session list/revoke, the WS-ticket mint, platform
/// revoke-all) are reachable in a test. Built into an engine via the `redis_stores` seam.
/// A store backend that delegates everything to a real in-memory store EXCEPT the session
/// `list_sessions` / `revoke_all` and the WS-ticket `mint`, which fail with an internal error.
/// This lets the auth extractors pass (the blacklist check delegates and succeeds) while the
/// session/WS handlers hit their store-failure error arms.
pub struct FailingStores {
    inner: Arc<InMemoryStores>,
    /// When set, `is_blacklisted` itself fails (simulating Redis down during the `rv:{jti}`
    /// revocation check), so a test can drive the auth-extractor's internal-error path rather
    /// than the handler error arms. Default `false` keeps the auth extractors passing.
    blacklist_fails: bool,
}

impl FailingStores {
    fn new() -> Self {
        Self {
            inner: Arc::new(InMemoryStores::new()),
            blacklist_fails: false,
        }
    }

    fn with_failing_blacklist() -> Self {
        Self {
            inner: Arc::new(InMemoryStores::new()),
            blacklist_fails: true,
        }
    }
}

/// A fresh internal error for the failing-store methods.
fn fail() -> bymax_auth_types::AuthError {
    bymax_auth_types::AuthError::Internal(Box::new(std::io::Error::other("store unavailable")))
}

#[async_trait]
impl bymax_auth_core::traits::SessionStore for FailingStores {
    async fn create_session(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        token_hash: &str,
        detail: &bymax_auth_core::traits::SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner
            .create_session(kind, token_hash, detail, ttl_secs)
            .await
    }
    async fn rotate(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        rotation: &bymax_auth_core::traits::SessionRotation,
    ) -> Result<bymax_auth_core::traits::RotateOutcome, bymax_auth_types::AuthError> {
        self.inner.rotate(kind, rotation).await
    }
    async fn find_session(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        token_hash: &str,
    ) -> Result<Option<bymax_auth_core::traits::SessionRecord>, bymax_auth_types::AuthError> {
        self.inner.find_session(kind, token_hash).await
    }
    async fn list_sessions(
        &self,
        _kind: bymax_auth_core::traits::SessionKind,
        _user_id: &str,
    ) -> Result<Vec<bymax_auth_core::traits::SessionDetail>, bymax_auth_types::AuthError> {
        Err(fail())
    }
    async fn revoke_session(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        user_id: &str,
        session_hash: &str,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.revoke_session(kind, user_id, session_hash).await
    }
    async fn delete_grace_pointer(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        session_hash: &str,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.delete_grace_pointer(kind, session_hash).await
    }
    async fn revoke_all(
        &self,
        _kind: bymax_auth_core::traits::SessionKind,
        _user_id: &str,
    ) -> Result<(), bymax_auth_types::AuthError> {
        Err(fail())
    }
    async fn revoke_family(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        family_id: &str,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.revoke_family(kind, family_id).await
    }
    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner
            .blacklist_access(jti_or_hash, remaining_ttl_secs)
            .await
    }
    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, bymax_auth_types::AuthError> {
        if self.blacklist_fails {
            return Err(fail());
        }
        self.inner.is_blacklisted(jti_or_hash).await
    }
    async fn current_epoch(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        user_id: &str,
    ) -> Result<u64, bymax_auth_types::AuthError> {
        self.inner.current_epoch(kind, user_id).await
    }
    async fn bump_epoch(
        &self,
        kind: bymax_auth_core::traits::SessionKind,
        user_id: &str,
    ) -> Result<u64, bymax_auth_types::AuthError> {
        self.inner.bump_epoch(kind, user_id).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::OtpStore for FailingStores {
    async fn put(
        &self,
        purpose: bymax_auth_core::traits::OtpPurpose,
        identifier: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put(purpose, identifier, code, ttl_secs).await
    }
    async fn verify(
        &self,
        purpose: bymax_auth_core::traits::OtpPurpose,
        identifier: &str,
        code: &str,
        max_attempts: u32,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner
            .verify(purpose, identifier, code, max_attempts)
            .await
    }
    async fn try_begin_resend(
        &self,
        purpose: bymax_auth_core::traits::OtpPurpose,
        identifier: &str,
        cooldown_secs: u64,
    ) -> Result<bool, bymax_auth_types::AuthError> {
        self.inner
            .try_begin_resend(purpose, identifier, cooldown_secs)
            .await
    }
}

#[async_trait]
impl bymax_auth_core::traits::BruteForceStore for FailingStores {
    async fn is_locked(
        &self,
        identifier: &str,
        max_attempts: u32,
    ) -> Result<bool, bymax_auth_types::AuthError> {
        self.inner.is_locked(identifier, max_attempts).await
    }
    async fn record_failure(
        &self,
        identifier: &str,
        window_secs: u64,
    ) -> Result<i64, bymax_auth_types::AuthError> {
        self.inner.record_failure(identifier, window_secs).await
    }
    async fn reset(&self, identifier: &str) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.reset(identifier).await
    }
    async fn remaining_lockout_secs(
        &self,
        identifier: &str,
    ) -> Result<u64, bymax_auth_types::AuthError> {
        self.inner.remaining_lockout_secs(identifier).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::WsTicketStore for FailingStores {
    async fn mint(
        &self,
        _snapshot: &bymax_auth_core::traits::WsTicketSnapshot,
        _ttl_secs: u64,
    ) -> Result<String, bymax_auth_types::AuthError> {
        Err(fail())
    }
    async fn redeem(
        &self,
        ticket: &str,
    ) -> Result<Option<bymax_auth_core::traits::WsTicketSnapshot>, bymax_auth_types::AuthError>
    {
        self.inner.redeem(ticket).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::PasswordResetStore for FailingStores {
    async fn put_token(
        &self,
        token: &str,
        context: &bymax_auth_core::traits::ResetContext,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put_token(token, context, ttl_secs).await
    }
    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<bymax_auth_core::traits::ResetContext>, bymax_auth_types::AuthError> {
        self.inner.consume_token(token).await
    }
    async fn delete_token(&self, token: &str) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.delete_token(token).await
    }
    async fn put_verified(
        &self,
        token: &str,
        context: &bymax_auth_core::traits::ResetContext,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put_verified(token, context, ttl_secs).await
    }
    async fn consume_verified(
        &self,
        token: &str,
    ) -> Result<Option<bymax_auth_core::traits::ResetContext>, bymax_auth_types::AuthError> {
        self.inner.consume_verified(token).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::InvitationStore for FailingStores {
    async fn put_invitation(
        &self,
        token: &str,
        invitation: &bymax_auth_core::traits::StoredInvitation,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put_invitation(token, invitation, ttl_secs).await
    }
    async fn consume_invitation(
        &self,
        token: &str,
    ) -> Result<Option<bymax_auth_core::traits::StoredInvitation>, bymax_auth_types::AuthError>
    {
        self.inner.consume_invitation(token).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::MfaStore for FailingStores {
    async fn put_setup_nx(
        &self,
        user_id_hash: &str,
        value: &str,
        ttl: u64,
    ) -> Result<bool, bymax_auth_types::AuthError> {
        self.inner.put_setup_nx(user_id_hash, value, ttl).await
    }
    async fn get_setup(
        &self,
        user_id_hash: &str,
    ) -> Result<Option<String>, bymax_auth_types::AuthError> {
        self.inner.get_setup(user_id_hash).await
    }
    async fn take_setup(
        &self,
        user_id_hash: &str,
    ) -> Result<Option<String>, bymax_auth_types::AuthError> {
        self.inner.take_setup(user_id_hash).await
    }
    async fn put_temp(
        &self,
        jti_hash: &str,
        user_id: &str,
        ttl: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put_temp(jti_hash, user_id, ttl).await
    }
    async fn get_temp(
        &self,
        jti_hash: &str,
    ) -> Result<Option<String>, bymax_auth_types::AuthError> {
        self.inner.get_temp(jti_hash).await
    }
    async fn del_temp(&self, jti_hash: &str) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.del_temp(jti_hash).await
    }
    async fn mark_totp_used(
        &self,
        replay_id: &str,
        ttl: u64,
    ) -> Result<bool, bymax_auth_types::AuthError> {
        self.inner.mark_totp_used(replay_id, ttl).await
    }
    async fn challenge_consume(
        &self,
        replay_id: &str,
        jti_hash: &str,
        ttl: u64,
    ) -> Result<bool, bymax_auth_types::AuthError> {
        self.inner.challenge_consume(replay_id, jti_hash, ttl).await
    }
}

#[async_trait]
impl bymax_auth_core::traits::OAuthStateStore for FailingStores {
    async fn put_state(
        &self,
        state_hash: &str,
        payload: &str,
        ttl_secs: u64,
    ) -> Result<(), bymax_auth_types::AuthError> {
        self.inner.put_state(state_hash, payload, ttl_secs).await
    }
    async fn take_state(
        &self,
        state_hash: &str,
    ) -> Result<Option<String>, bymax_auth_types::AuthError> {
        self.inner.take_state(state_hash).await
    }
}

/// Build an engine whose store backend always fails, with the sessions + platform groups on,
/// so a test can drive the store-failure error arms of the session/platform/WS handlers.
pub fn build_failing() -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let failing = Arc::new(FailingStores::new());
    // The stores field is unused by the failing-store tests, but the Harness shape needs one.
    let inert = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(JWT_SECRET.to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.roles.platform_hierarchy = Some(HashMap::from([("SUPER_ADMIN".to_owned(), Vec::new())]));
    // Mount the sessions group but keep session tracking off, so register does not trigger the
    // (failing) `list_sessions` eviction path — the handlers still reach the failing store.
    config.sessions.enabled = false;
    config.controllers.sessions = true;
    config.platform.enabled = true;

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(failing)
        .build()
        .ok()?;
    Some(Harness {
        engine: Arc::new(engine),
        users,
        admins,
        stores: inert,
    })
}

/// Build a platform-enabled engine whose `is_blacklisted` check always fails with an internal
/// error, so a test can confirm the platform auth extractor PROPAGATES that infrastructure
/// failure as a 500 rather than masking it as a 401. Everything else delegates to the in-memory
/// stores, so a well-formed platform token reaches the revocation check before it fails.
pub fn build_failing_blacklist() -> Option<Harness> {
    let users = Arc::new(InMemoryUserRepository::new());
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let failing = Arc::new(FailingStores::with_failing_blacklist());
    let inert = Arc::new(InMemoryStores::new());

    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from(JWT_SECRET.to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.roles.platform_hierarchy = Some(HashMap::from([("SUPER_ADMIN".to_owned(), Vec::new())]));
    config.sessions.enabled = false;
    config.controllers.sessions = true;
    config.platform.enabled = true;

    let engine = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .platform_user_repository(admins.clone())
        .redis_stores(failing)
        .build()
        .ok()?;
    Some(Harness {
        engine: Arc::new(engine),
        users,
        admins,
        stores: inert,
    })
}

/// Peek the engine-generated OTP for a `(tenant, email)` pair under a purpose (the in-memory
/// store keeps the plaintext code so the reset/verify flows can be driven end to end).
pub fn peek_otp(
    harness: &Harness,
    purpose: bymax_auth_core::traits::OtpPurpose,
    email: &str,
) -> Option<String> {
    let identifier = harness.engine.hashed_identifier_for(TENANT, email);
    harness.stores.peek_otp(purpose, &identifier)
}

/// Seed an active platform admin with the given role; returns its id.
pub async fn seed_admin(harness: &Harness, email: &str, role: &str) -> String {
    use bymax_auth_types::AuthPlatformUser;
    use time::OffsetDateTime;
    let id = format!("admin-{email}");
    harness.admins.insert(AuthPlatformUser {
        id: id.clone(),
        email: email.to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password("adminpass123"),
        role: role.to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });
    id
}

/// Compute the current 6-digit TOTP for a Base32 secret (for the MFA happy-path tests).
pub fn current_totp(secret_b32: &str) -> String {
    totp_at(secret_b32, 0)
}

/// Compute the 6-digit TOTP for a Base32 secret at `now + offset_secs`. A caller that performs
/// several TOTP-gated operations in one test uses distinct window offsets (0, 30, 60, …) so the
/// per-window anti-replay never rejects a reused code. The configured `totp_window` (2) accepts
/// codes a couple of steps away from the verifier's clock, so a near-future offset still validates.
pub fn totp_at(secret_b32: &str, offset_secs: u64) -> String {
    let raw = bymax_auth_crypto::totp::decode_secret_base32(secret_b32).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + offset_secs;
    format!("{:06}", bymax_auth_crypto::totp::totp(&raw, now, 30, 6))
}

/// Mark a seeded user as MFA-enabled with a stored (encrypted-placeholder) secret.
pub async fn enable_mfa_flag(harness: &Harness, user_id: &str) {
    let _ = harness
        .users
        .update_mfa(
            user_id,
            UpdateMfaData {
                mfa_enabled: true,
                mfa_secret: Some("encrypted-secret".to_owned()),
                mfa_recovery_codes: None,
            },
        )
        .await;
}

/// Set a user's status (e.g. to a blocked value) for the status-gate tests.
pub async fn set_status(harness: &Harness, user_id: &str, status: &str) {
    let _ = harness.users.update_status(user_id, status).await;
}

// ---- request / response helpers --------------------------------------------------------

/// A response captured as its status, headers, and decoded body bytes.
pub struct Captured {
    pub status: StatusCode,
    pub set_cookies: Vec<String>,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

impl Captured {
    /// Parse the body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// The value of a `Set-Cookie` whose name matches `name`, if present.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .cloned()
    }

    /// Whether a `Set-Cookie` for `name` exists with a non-empty value (set, not cleared).
    pub fn has_cookie_value(&self, name: &str) -> bool {
        self.cookie(name)
            .map(|c| {
                let value = c
                    .split(';')
                    .next()
                    .and_then(|kv| kv.split_once('='))
                    .map(|(_, v)| v)
                    .unwrap_or("");
                !value.is_empty()
            })
            .unwrap_or(false)
    }

    /// The raw access-token cookie value, if set with a value.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookie(name).and_then(|c| {
            c.split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v.to_owned())
                .filter(|v| !v.is_empty())
        })
    }

    /// The `Retry-After` header value, if any.
    pub fn retry_after(&self) -> Option<String> {
        self.headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

/// Builder for a oneshot request against the adapter router.
pub struct Req {
    method: Method,
    path: String,
    body: Option<Vec<u8>>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Req {
    /// A new request with the given method + path.
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.to_owned(),
            body: None,
            headers: Vec::new(),
        }
    }

    /// A GET request.
    pub fn get(path: &str) -> Self {
        Self::new(Method::GET, path)
    }

    /// A POST request.
    pub fn post(path: &str) -> Self {
        Self::new(Method::POST, path)
    }

    /// A DELETE request.
    pub fn delete(path: &str) -> Self {
        Self::new(Method::DELETE, path)
    }

    /// Attach a JSON body (sets the content-type).
    pub fn json(mut self, value: serde_json::Value) -> Self {
        self.body = Some(value.to_string().into_bytes());
        self.headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ));
        self
    }

    /// Attach a raw body with the given content-type.
    pub fn raw_body(mut self, bytes: Vec<u8>, content_type: &'static str) -> Self {
        self.body = Some(bytes);
        self.headers
            .push((header::CONTENT_TYPE, HeaderValue::from_static(content_type)));
        self
    }

    /// Add a bearer `Authorization` header.
    pub fn bearer(mut self, token: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
            self.headers.push((header::AUTHORIZATION, value));
        }
        self
    }

    /// Add a `Cookie` header pair.
    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(&format!("{name}={value}")) {
            self.headers.push((header::COOKIE, value));
        }
        self
    }

    /// Add an arbitrary header.
    pub fn header(mut self, name: HeaderName, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.push((name, value));
        }
        self
    }

    /// Send the request through `router` and capture the response.
    pub async fn send(self, router: &Router) -> Captured {
        let body = match self.body {
            Some(bytes) => Body::from(bytes),
            None => Body::empty(),
        };
        let mut builder = Request::builder().method(self.method).uri(self.path);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        let mut request = match builder.body(body) {
            Ok(request) => request,
            Err(_) => return empty_captured(),
        };
        // Inject the peer address so the `PeerIpKeyExtractor` and the engine context have a
        // client IP without a real socket.
        if let Ok(addr) = PEER.parse::<SocketAddr>() {
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        let response = match router.clone().oneshot(request).await {
            Ok(response) => response,
            Err(_) => return empty_captured(),
        };
        capture(response).await
    }
}

/// Capture a response into status/cookies/headers/body.
async fn capture(response: http::Response<Body>) -> Captured {
    let status = response.status();
    let headers = response.headers().clone();
    let set_cookies = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    Captured {
        status,
        set_cookies,
        headers,
        body,
    }
}

/// An empty captured response for the (unreachable in practice) builder-error path.
fn empty_captured() -> Captured {
    Captured {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        set_cookies: Vec::new(),
        headers: http::HeaderMap::new(),
        body: Vec::new(),
    }
}
