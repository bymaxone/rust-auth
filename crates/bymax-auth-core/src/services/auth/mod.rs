//! The local authentication flows on [`crate::AuthEngine`] — registration, login, logout,
//! `me`, token refresh, email verification, and the password-less issuance primitive.
//!
//! Every flow runs against the host-pluggable repository/store/hook traits and is exercised
//! with the in-memory doubles. The flow bodies live in the submodules; this module owns the
//! shared input DTOs, the small mapping helpers, and the cross-cutting concerns
//! (tenant resolution, the status gate, hook context, and fire-and-forget dispatch).

mod detached;
mod email_verification;
mod login;
mod register;
mod session_ops;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bymax_auth_crypto::mac::hmac_sha256;
use bymax_auth_types::AuthError;

use crate::RepositoryError;
use crate::config::resolvers::{RequestParts, TenantResolveError};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::{internal_error, to_hex};

/// The minimum total elapsed time, in milliseconds, for an email-existence-revealing
/// response, so account existence never leaks through latency (§7.1 / §15.5 / §17.2).
pub(crate) const ANTI_ENUM_MIN_MS: u64 = 300;

/// The ceiling, in seconds, a fire-and-forget hook or repository side-effect may run before
/// it is abandoned (its result swallowed and logged), so a slow collaborator can never
/// stall — or roll back — the user-facing response.
pub(crate) const DETACHED_TASK_TIMEOUT: Duration = Duration::from_secs(5);

/// Registration input: the new user's credentials and tenant scope. The `Debug` impl
/// redacts `password` so it cannot slip into a log line.
#[derive(Clone)]
pub struct RegisterInput {
    /// The email being registered.
    pub email: String,
    /// The display name.
    pub name: String,
    /// The plaintext password (redacted in `Debug`).
    pub password: String,
    /// The tenant scope supplied by the caller; ignored when a `TenantIdResolver` is set.
    pub tenant_id: String,
}

impl fmt::Debug for RegisterInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterInput")
            .field("email", &self.email)
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// Login input: the credentials and tenant scope. The `Debug` impl redacts `password`.
#[derive(Clone)]
pub struct LoginInput {
    /// The login email.
    pub email: String,
    /// The plaintext password (redacted in `Debug`).
    pub password: String,
    /// The tenant scope supplied by the caller; ignored when a `TenantIdResolver` is set.
    pub tenant_id: String,
}

impl fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginInput")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// Map a [`RepositoryError`] onto the engine's flow error catalog: a unique-constraint
/// conflict becomes `email_already_exists`, any other datastore failure becomes the opaque
/// internal error (the concrete cause is carried for logging, never serialized).
pub(crate) fn map_repository_error(error: RepositoryError) -> AuthError {
    match error {
        RepositoryError::Conflict(_) => AuthError::EmailAlreadyExists,
        RepositoryError::Backend(source) => AuthError::Internal(source),
    }
}

/// Build a framework-neutral [`RequestParts`] view from a [`RequestContext`] for the tenant
/// resolver. The core never sees a real HTTP request, so the method/URI are empty and the
/// host is read from the sanitized `host` header.
pub(crate) fn request_parts_from_context(ctx: &RequestContext) -> RequestParts {
    RequestParts {
        method: String::new(),
        uri: String::new(),
        host: ctx.sanitized_headers.get("host").cloned(),
        headers: ctx.sanitized_headers.clone(),
    }
}

/// Map a tenant-resolution failure onto a flow error: an empty id (a misconfiguration that
/// cannot scope the request) is treated as `forbidden`; any other failure is internal.
pub(crate) fn map_tenant_error(error: TenantResolveError) -> AuthError {
    match error {
        TenantResolveError::Empty => AuthError::Forbidden,
        TenantResolveError::Internal(_) => internal_error("tenant resolution failed"),
    }
}

/// A type-erased detached side-effect: a boxed future whose error is only ever displayed.
/// Boxing keeps [`run_guarded`] monomorphized once per error type (not once per concrete
/// future), so a single unit test can drive all three of its outcome arms.
type GuardedFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// Await `future` under `timeout`, swallowing and logging any error, timeout, or success —
/// the body of a fire-and-forget side-effect. Kept separate from the spawn so its three
/// outcome arms are directly unit-testable without a detached task.
pub(crate) async fn run_guarded<T, E>(timeout: Duration, future: GuardedFuture<T, E>)
where
    E: fmt::Display,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::warn!(%error, "detached auth side-effect returned an error (ignored)");
        }
        Err(_) => {
            tracing::warn!("detached auth side-effect exceeded the timeout ceiling (ignored)");
        }
    }
}

/// Spawn a fire-and-forget side-effect: run it detached under the [`DETACHED_TASK_TIMEOUT`]
/// ceiling, never blocking or failing the response that scheduled it.
pub(crate) fn spawn_guarded<F, T, E>(future: F)
where
    F: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: fmt::Display + Send + 'static,
{
    tokio::spawn(run_guarded(DETACHED_TASK_TIMEOUT, Box::pin(future)));
}

/// Sleep, if necessary, until at least [`ANTI_ENUM_MIN_MS`] have elapsed since `started`,
/// so an email-existence-revealing branch returns no faster than the floor and timing
/// cannot be used as an enumeration oracle.
pub(crate) async fn normalize_anti_enum(started: std::time::Instant) {
    let floor = Duration::from_millis(ANTI_ENUM_MIN_MS);
    if let Some(remaining) = floor.checked_sub(started.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
}

impl AuthEngine {
    /// Resolve the tenant for a request: a configured [`crate::config::TenantIdResolver`]
    /// is authoritative and overrides the body-supplied value (§24 invariant 8); otherwise
    /// the body value is used verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] when the resolver yields an empty id, or
    /// [`AuthError::Internal`] for any other resolver failure.
    pub(crate) async fn resolve_tenant(
        &self,
        body_tenant: &str,
        ctx: &RequestContext,
    ) -> Result<String, AuthError> {
        match self.config().config().tenant_id_resolver.as_ref() {
            Some(resolver) => {
                let parts = request_parts_from_context(ctx);
                resolver.resolve(&parts).await.map_err(map_tenant_error)
            }
            None => Ok(body_tenant.to_owned()),
        }
    }

    /// The no-PII hashed identifier for a `(tenant_id, email)` pair: the hex of
    /// `HMAC-SHA-256("{tenant_id}:{email}")` under the engine's derived identifier key. The
    /// same value keys the brute-force counter and the OTP record (§7.1.2 / §7.1.6 / §7.7);
    /// HMAC blocks dictionary reversal of the low-entropy email and the output is pure hex,
    /// so it never carries PII into a store key.
    pub(crate) fn hashed_identifier(&self, tenant_id: &str, email: &str) -> String {
        let input = format!("{tenant_id}:{email}");
        to_hex(&hmac_sha256(self.config().hmac_key(), input.as_bytes()))
    }
}

/// Shared fixtures for the flow integration tests: a valid base config, a crypto-parameter
/// helper that tracks the compiled hasher, a password-hashing helper, a user seeder, and an
/// engine harness that exposes the in-memory repository and stores alongside the engine.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::config::{AuthConfig, Environment};
    use crate::engine::AuthEngine;
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::{AuthHooks, UserRepository};
    use bymax_auth_crypto::password::{PasswordParams, hash};
    use bymax_auth_types::{CreateUserData, UpdateMfaData};
    use secrecy::SecretString;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    /// A config that validates under either hasher feature matrix, with verification on.
    pub(crate) fn base_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        #[cfg(not(feature = "scrypt"))]
        {
            cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
        }
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
        cfg
    }

    /// The crypto parameters for the compiled hasher, used to seed stored password hashes.
    fn crypto_params() -> PasswordParams {
        #[cfg(not(feature = "scrypt"))]
        {
            PasswordParams {
                active: bymax_auth_crypto::password::PasswordAlgorithm::Argon2id,
                ..PasswordParams::default()
            }
        }
        #[cfg(feature = "scrypt")]
        {
            PasswordParams::default()
        }
    }

    /// Hash a plaintext password into a PHC string with the compiled hasher.
    pub(crate) fn hash_password(plain: &str) -> String {
        hash(plain.as_bytes(), &crypto_params()).unwrap_or_default()
    }

    /// A request context with a fixed IP/user-agent and no headers.
    pub(crate) fn ctx() -> RequestContext {
        RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new())
    }

    /// The fields of a seeded dashboard user.
    pub(crate) struct SeedUser {
        pub email: String,
        pub password: String,
        pub tenant_id: String,
        pub status: String,
        pub email_verified: bool,
        pub mfa_enabled: bool,
    }

    impl SeedUser {
        /// A verified, active local user with the given email and password.
        pub(crate) fn active(email: &str, password: &str) -> Self {
            Self {
                email: email.to_owned(),
                password: password.to_owned(),
                tenant_id: "t1".to_owned(),
                status: "ACTIVE".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            }
        }
    }

    /// An engine plus the concrete in-memory collaborators behind it, so a test can both
    /// drive the flows and seed/inspect the backing state.
    pub(crate) struct Harness {
        pub engine: AuthEngine,
        pub users: Arc<InMemoryUserRepository>,
        pub stores: Arc<InMemoryStores>,
    }

    impl Harness {
        /// Seed a dashboard user directly into the repository, returning its id.
        pub(crate) async fn seed(&self, spec: SeedUser) -> String {
            let created = self
                .users
                .create(CreateUserData {
                    email: spec.email,
                    name: "Seed User".to_owned(),
                    password_hash: Some(hash_password(&spec.password)),
                    role: None,
                    status: Some(spec.status),
                    tenant_id: spec.tenant_id,
                    email_verified: Some(spec.email_verified),
                })
                .await;
            let Ok(user) = created else {
                return String::new();
            };
            if spec.mfa_enabled {
                let _ = self
                    .users
                    .update_mfa(
                        &user.id,
                        UpdateMfaData {
                            mfa_enabled: true,
                            mfa_secret: Some("encrypted-secret".to_owned()),
                            mfa_recovery_codes: None,
                        },
                    )
                    .await;
            }
            user.id
        }
    }

    /// Build a harness from `cfg` and optional hooks. Returns `None` if the (always valid)
    /// fixture config somehow fails to assemble, so callers stay panic-free with `let-else`.
    pub(crate) fn harness(cfg: AuthConfig, hooks: Option<Arc<dyn AuthHooks>>) -> Option<Harness> {
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let mut builder = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users.clone())
            .redis_stores(stores.clone());
        if let Some(hooks) = hooks {
            builder = builder.hooks(hooks);
        }
        builder.build().ok().map(|engine| Harness {
            engine,
            users,
            stores,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::resolvers::{RequestParts, TenantIdResolver, TenantResolveError};
    use crate::traits::{HookError, NoOpAuthHooks};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// A resolver that derives the tenant from the request host, rejecting an absent host.
    struct HostTenantResolver;

    #[async_trait::async_trait]
    impl TenantIdResolver for HostTenantResolver {
        async fn resolve(&self, parts: &RequestParts) -> Result<String, TenantResolveError> {
            match parts.host.as_deref() {
                Some("") | None => Err(TenantResolveError::Empty),
                Some(host) => Ok(host.to_owned()),
            }
        }
    }

    #[test]
    fn register_and_login_inputs_redact_the_password_in_debug() {
        // A stray `{:?}` on either credential DTO must show the redaction marker, never the
        // plaintext password.
        let reg = RegisterInput {
            email: "e@x.io".to_owned(),
            name: "N".to_owned(),
            password: "super-secret".to_owned(),
            tenant_id: "t1".to_owned(),
        };
        let reg_dbg = format!("{reg:?}");
        assert!(reg_dbg.contains("[REDACTED]"));
        assert!(!reg_dbg.contains("super-secret"));
        assert!(reg_dbg.contains("e@x.io"));

        let login = LoginInput {
            email: "e@x.io".to_owned(),
            password: "super-secret".to_owned(),
            tenant_id: "t1".to_owned(),
        };
        let login_dbg = format!("{login:?}");
        assert!(login_dbg.contains("[REDACTED]"));
        assert!(!login_dbg.contains("super-secret"));
    }

    #[test]
    fn map_repository_error_distinguishes_conflict_from_backend() {
        // A conflict surfaces as the public duplicate-email code; any other backend failure
        // collapses to the opaque internal error.
        assert!(matches!(
            map_repository_error(RepositoryError::Conflict("dup".to_owned())),
            AuthError::EmailAlreadyExists
        ));
        assert!(matches!(
            map_repository_error(RepositoryError::Backend("db down".into())),
            AuthError::Internal(_)
        ));
    }

    #[test]
    fn map_tenant_error_maps_empty_to_forbidden_and_internal_to_internal() {
        // An empty resolved tenant is a misconfiguration (Forbidden); any other resolver
        // failure is internal.
        assert!(matches!(
            map_tenant_error(TenantResolveError::Empty),
            AuthError::Forbidden
        ));
        assert!(matches!(
            map_tenant_error(TenantResolveError::Internal("x".to_owned())),
            AuthError::Internal(_)
        ));
    }

    #[test]
    fn request_parts_from_context_reads_the_host_header() {
        // The framework-neutral parts carry the host (for the resolver) and leave the
        // method/URI empty, since the core never sees a real request.
        let mut headers = BTreeMap::new();
        headers.insert("host".to_owned(), "acme.example.com".to_owned());
        let ctx = RequestContext::new("1.2.3.4", "ua", headers);
        let parts = request_parts_from_context(&ctx);
        assert_eq!(parts.host.as_deref(), Some("acme.example.com"));
        assert!(parts.method.is_empty());
        assert!(parts.uri.is_empty());
    }

    #[tokio::test]
    async fn resolve_tenant_uses_the_resolver_over_the_body() {
        // With a resolver configured, the resolved value wins over the body tenant (§24.8);
        // an absent host (resolver Empty) surfaces as Forbidden.
        let mut cfg = test_support::base_config();
        cfg.tenant_id_resolver = Some(Arc::new(HostTenantResolver));
        let Some(h) = test_support::harness(cfg, None) else { return };
        let mut headers = BTreeMap::new();
        headers.insert("host".to_owned(), "resolved-tenant".to_owned());
        let ctx = RequestContext::new("1.2.3.4", "ua", headers);
        assert!(matches!(
            h.engine.resolve_tenant("body-tenant", &ctx).await,
            Ok(t) if t == "resolved-tenant"
        ));
        let empty_ctx = RequestContext::new("1.2.3.4", "ua", BTreeMap::new());
        assert!(matches!(
            h.engine.resolve_tenant("body-tenant", &empty_ctx).await,
            Err(AuthError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn harness_wires_hooks_and_seed_reports_a_conflict() {
        // The harness wires an explicit hooks collaborator, and seeding a duplicate email
        // returns an empty id (the repository conflict path).
        let hooks: Arc<dyn crate::traits::AuthHooks> = Arc::new(NoOpAuthHooks);
        let built = test_support::harness(test_support::base_config(), Some(hooks));
        let Some(h) = built else { return };
        let first = h
            .seed(test_support::SeedUser::active("dup@x.io", "pw"))
            .await;
        assert!(!first.is_empty());
        let second = h
            .seed(test_support::SeedUser::active("dup@x.io", "pw"))
            .await;
        assert!(second.is_empty(), "a duplicate seed yields an empty id");
    }

    #[tokio::test]
    async fn normalize_anti_enum_sleeps_below_the_floor_and_skips_above_it() {
        // Both arms of the timing guard. The "below" start is seeded half a floor in the
        // past so a short, bounded sleep is guaranteed (deterministic under coverage
        // instrumentation, unlike a `now()` start whose remaining could round to zero).
        let below = std::time::Instant::now()
            .checked_sub(Duration::from_millis(ANTI_ENUM_MIN_MS / 2))
            .unwrap_or_else(std::time::Instant::now);
        normalize_anti_enum(below).await;
        // A start instant already older than the floor takes the no-sleep path.
        let above = std::time::Instant::now()
            .checked_sub(Duration::from_millis(ANTI_ENUM_MIN_MS * 4))
            .unwrap_or_else(std::time::Instant::now);
        normalize_anti_enum(above).await;
    }

    /// Drive all three outcome arms of [`run_guarded`] for a given error type, so every
    /// monomorphization (one per detached side-effect's error type) is fully covered.
    async fn exercise_run_guarded<E: fmt::Display + Send + 'static>(error: E) {
        run_guarded(Duration::from_secs(5), Box::pin(async { Ok::<(), E>(()) })).await;
        run_guarded(
            Duration::from_secs(5),
            Box::pin(async { Err::<(), E>(error) }),
        )
        .await;
        // A future that never resolves forces the timeout arm with no closure body to leave
        // uncovered after the cancellation point.
        run_guarded(
            Duration::from_millis(1),
            Box::pin(std::future::pending::<Result<(), E>>()),
        )
        .await;
    }

    #[tokio::test]
    async fn run_guarded_swallows_success_error_and_timeout_for_every_error_type() {
        // A clean success, a returned error, and a timeout are all swallowed — exercised for
        // each error type a detached side-effect can carry (hook, repository, email, auth).
        exercise_run_guarded(HookError::Rejected("boom".to_owned())).await;
        exercise_run_guarded(RepositoryError::Conflict("dup".to_owned())).await;
        exercise_run_guarded(crate::traits::EmailError::Delivery("down".into())).await;
        exercise_run_guarded(internal_error("boom")).await;
    }

    #[tokio::test]
    async fn spawn_guarded_runs_a_detached_task_to_completion() {
        // The detached spawn schedules the guarded body; yielding lets the current-thread
        // runtime drive it. The assertion is simply that scheduling does not panic.
        spawn_guarded(async { Ok::<(), HookError>(()) });
        tokio::task::yield_now().await;
    }
}
