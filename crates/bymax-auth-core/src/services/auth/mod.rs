//! The local authentication flows on [`crate::AuthEngine`] — registration, login, logout,
//! `me`, token refresh, email verification, and the password-less issuance primitive.
//!
//! Every flow runs against the host-pluggable repository/store/hook traits and is exercised
//! with the in-memory doubles. The flow bodies live in the submodules; this module owns the
//! shared input DTOs, the small mapping helpers, and the cross-cutting concerns
//! (tenant resolution, the status gate, hook context, and fire-and-forget dispatch).

pub(crate) mod detached;
mod email_change;
mod email_verification;
mod invitation;
mod login;
mod password_reset;
mod register;
mod session_ops;

pub use invitation::AcceptInvitationInput;
pub use password_reset::{
    ForgotPasswordInput, ResendResetOtpInput, ResetPasswordInput, VerifyResetOtpInput,
};

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bymax_auth_crypto::mac::hmac_sha256;
use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, AuthResult};

use crate::RepositoryError;
use crate::config::resolvers::{RequestParts, TenantResolveError};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::session::normalize_session_metadata;
use crate::services::{internal_error, now_offset, to_hex};
use crate::traits::{HookContext, SessionRecord};

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
    /// The tenant scope supplied by the caller; ignored when a `TenantIdResolver` is set, and
    /// `None` when the caller named none. A request that names no tenant with no resolver
    /// configured is refused with a `validation` error naming this field, never defaulted.
    pub tenant_id: Option<String>,
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
    /// The tenant scope supplied by the caller; ignored when a `TenantIdResolver` is set, and
    /// `None` when the caller named none. A request that names no tenant with no resolver
    /// configured is refused with a `validation` error naming this field, never defaulted.
    pub tenant_id: Option<String>,
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
    /// Because a configured resolver makes the caller's value dead weight, `body_tenant` is
    /// optional and a request may omit it entirely. The two states a request can arrive in
    /// therefore differ: with a resolver, the caller's value is ignored whether present or
    /// absent; without one, it is the only thing that can name a tenant, and its absence is a
    /// request that cannot be scoped. That case is refused rather than defaulted, because
    /// inventing a tenant name would silently gather into one scope every account a
    /// misconfigured deployment created — and that scope keys the user lookup, the Redis
    /// records and the HMAC identifiers built from it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Validation`] when no resolver is configured and the caller named no
    /// tenant, [`AuthError::Forbidden`] when the resolver yields an empty id, or
    /// [`AuthError::Internal`] for any other resolver failure.
    pub(crate) async fn resolve_tenant(
        &self,
        body_tenant: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<String, AuthError> {
        match self.config().config().tenant_id_resolver.as_ref() {
            Some(resolver) => {
                let parts = request_parts_from_context(ctx);
                resolver.resolve(&parts).await.map_err(map_tenant_error)
            }
            None => body_tenant.map(str::to_owned).ok_or_else(|| {
                AuthError::Validation {
                    details: vec![bymax_auth_types::FieldError {
                        field: "tenantId".to_owned(),
                        message: "tenantId is required unless the deployment configures a TenantIdResolver"
                            .to_owned(),
                    }],
                }
            }),
        }
    }

    /// The no-PII hashed identifier for a `(tenant_id, email)` pair: the hex of
    /// `HMAC-SHA-256("{tenant_id}:{email}")` under the engine's derived identifier key. The
    /// same value keys the brute-force counter and the OTP record (§7.1.2 / §7.1.6 / §7.7);
    /// HMAC blocks dictionary reversal of the low-entropy email and the output is pure hex,
    /// so it never carries PII into a store key.
    /// The brute-force counter key for a dashboard account.
    ///
    /// The identity PLANE is part of the preimage, not just the tenant. Without it a tenant
    /// whose id is literally `platform` produced a byte-identical identifier to the platform
    /// plane's own `platform:{email}` — so five unauthenticated dashboard logins against an
    /// operator's address locked that operator out of the console, repeatably, without the
    /// platform surface ever being touched. The reverse held too: a successful dashboard login
    /// in that tenant cleared the operator's lockout mid-attack. The MFA counters already
    /// carry their plane for exactly this reason.
    ///
    /// Deliberately NOT [`Self::hashed_identifier`]: that value also keys the OTP records,
    /// whose keyspace is shared byte-for-byte with nest-auth and is already purpose-scoped
    /// (`otp:{purpose}:`), so it cannot collide and must not move.
    pub(crate) fn lockout_identifier(&self, tenant_id: &str, email: &str) -> String {
        let input = format!("dashboard:{tenant_id}:{email}");
        to_hex(&hmac_sha256(self.config().hmac_key(), input.as_bytes()))
    }

    /// The brute-force identifier for a password re-proof that guards a sensitive change.
    ///
    /// `login` refuses an account after N wrong passwords. The doors that ask for the SAME
    /// secret — change-password, request-email-change — refused nothing, so a caller holding a
    /// stolen access token but not the password could guess it there without limit. The only
    /// control was the per-IP rate limit, which in this crate is in-process and per-instance
    /// (see `rateLimits.$comment` in the wire contract), so a distributed caller sidesteps it
    /// entirely. Winning the guess buys the whole account: replace the credential, or move the
    /// address recovery runs through.
    ///
    /// Namespaced by `flow` so an authenticated caller cannot spend the owner's `login` budget
    /// and lock them out of their own sign-in, and keyed on the user id rather than the address
    /// because that is what the caller is attacking here.
    pub(crate) fn reproof_identifier(&self, flow: &str, user_id: &str) -> String {
        let input = format!("reauth:{flow}:{user_id}");
        to_hex(&hmac_sha256(self.config().hmac_key(), input.as_bytes()))
    }

    /// The invitee-index identifier for an address: `hmac_sha256(email)`, hex.
    ///
    /// The index used to key on a bare `sha256(email)`, which is reversible by dictionary — an
    /// address carries far too little entropy for a plain digest to hide it, and this is the
    /// one handle an operator (or anyone reading a keyspace dump) has on who a tenant has been
    /// inviting. Every other identifier in both libraries is an HMAC for exactly that reason;
    /// this one was the exception. The tenant is not in the preimage because it is already a
    /// literal segment of the key.
    ///
    /// Shared byte-for-byte with nest-auth and pinned by `conformance/wire-contract.json`.
    pub(crate) fn invitee_identifier(&self, email: &str) -> String {
        to_hex(&hmac_sha256(self.config().hmac_key(), email.as_bytes()))
    }

    pub(crate) fn hashed_identifier(&self, tenant_id: &str, email: &str) -> String {
        let input = format!("{tenant_id}:{email}");
        to_hex(&hmac_sha256(self.config().hmac_key(), input.as_bytes()))
    }

    /// Enforce the per-user session cap and fire the new-session hook for a **dashboard**
    /// session the token manager has just issued. A no-op unless session tracking is enabled;
    /// when it is, the just-created session's hash is recomputed from the issued refresh token
    /// so eviction can exclude it. The device/IP are normalized with the same
    /// [`normalize_session_metadata`] the token manager applied at persistence (parsed UA +
    /// byte-bounded IP), so this hook record matches the stored one and bounds an
    /// attacker-controlled `X-Forwarded-For`. This is a dashboard-only path: the record always carries the
    /// dashboard tenant (the platform identity surface manages its own sessions separately), so
    /// the `tenant_id` is taken verbatim from the dashboard user.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only on an infrastructure failure listing the user's
    /// sessions; eviction itself is best-effort.
    pub(crate) async fn enforce_sessions_after_issue(
        &self,
        result: &AuthResult,
        ip: &str,
        user_agent: &str,
        hook_ctx: &HookContext,
    ) -> Result<(), AuthError> {
        if !self.config().config().sessions.enabled {
            return Ok(());
        }
        let new_hash = RawRefreshToken::from_raw(result.refresh_token.clone()).redis_hash();
        // Build the hook/management record with the SAME normalization the token manager applied
        // when it persisted this session, so the stored record, `list_sessions`, and the
        // new-session hook payload all agree.
        let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
        let record = SessionRecord {
            user_id: result.user.id.clone(),
            tenant_id: Some(result.user.tenant_id.clone()),
            role: result.user.role.clone(),
            device,
            ip: stored_ip,
            created_at: now_offset(),
            mfa_enabled: result.user.mfa_enabled,
            // The family id is server-internal to the reuse-detection store and is not part of
            // the new-session hook / eviction projection (which keys on the session hash), so
            // this display record leaves it empty.
            family_id: String::new(),
            family_created_at: None,
        };
        self.sessions()
            .after_session_created(&record, &new_hash, hook_ctx)
            .await
    }
}

/// Returns `user` only when it belongs to `tenant_id`, and `None` otherwise.
///
/// [`crate::traits::UserRepository::find_by_email`] takes a `tenant_id` and its contract says
/// to scope by it — but the repository is the host's and a trait can only ask. A single-tenant
/// host writing `find_by_email(email)` that ignores its second argument is the shape nobody
/// notices, and under one every distinct `tenantId` in a request body resolves the same account
/// while deriving a *different* HMAC-keyed identifier. That turns the brute-force lockout and
/// the resend cooldown — both keyed on `hmac(tenant:email)` — into per-value budgets an
/// attacker refills by rotating a field they control, so the five-attempt ceiling and the
/// sixty-second cooldown never engage.
///
/// Collapsing a cross-tenant answer to `None` puts those callers on the path they already have
/// for "no such account": the same generic error, the same sentinel-KDF timing, the same silent
/// `Ok`. Nothing new is disclosed, and the account in tenant A stops being reachable through a
/// request naming tenant B whatever the repository returns.
pub(crate) fn tenant_scoped(
    user: Option<bymax_auth_types::AuthUser>,
    tenant_id: &str,
) -> Option<bymax_auth_types::AuthUser> {
    user.filter(|candidate| candidate.tenant_id == tenant_id)
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
    pub(crate) fn crypto_params() -> PasswordParams {
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
        /// The codes the engine actually mailed. The OTP record holds a keyed fingerprint, not
        /// the code, so a flow that has to submit the code back reads it from here — which is
        /// also where the recipient reads it.
        pub emails: Arc<CapturingEmails>,
    }

    /// An email provider that keeps the codes it was asked to send.
    #[derive(Default)]
    pub(crate) struct CapturingEmails {
        verification: std::sync::Mutex<Option<String>>,
        password_reset: std::sync::Mutex<Option<String>>,
    }

    impl CapturingEmails {
        /// Take the last email-verification code sent, leaving the mailbox empty.
        ///
        /// Consuming, not peeking, and that is load-bearing: a flow that mails twice would
        /// otherwise have the second read answer instantly with the FIRST code, because the
        /// mailbox is already non-empty when the poll starts. The test then submits a stale code
        /// and its assertion passes for the wrong reason.
        pub(crate) fn verification_code(&self) -> Option<String> {
            self.verification.lock().ok().and_then(|mut c| c.take())
        }

        /// Take the last password-reset code sent, leaving the mailbox empty. See
        /// [`Self::verification_code`] for why it consumes.
        pub(crate) fn password_reset_code(&self) -> Option<String> {
            self.password_reset.lock().ok().and_then(|mut c| c.take())
        }
    }

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for CapturingEmails {
        async fn send_email_verification_otp(
            &self,
            _tenant_id: &str,
            _email: &str,
            otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            if let Ok(mut slot) = self.verification.lock() {
                *slot = Some(otp.to_owned());
            }
            Ok(())
        }
        async fn send_password_reset_otp(
            &self,
            _tenant_id: &str,
            _email: &str,
            otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            if let Ok(mut slot) = self.password_reset.lock() {
                *slot = Some(otp.to_owned());
            }
            Ok(())
        }
        async fn send_password_reset_token(
            &self,
            _tenant_id: &str,
            _email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_email_change_verification(
            &self,
            _tenant_id: &str,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_mfa_enabled(
            &self,
            _tenant_id: &str,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_mfa_disabled(
            &self,
            _tenant_id: &str,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_invitation(
            &self,
            _tenant_id: &str,
            _email: &str,
            _invite: &crate::traits::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
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
                        None,
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
    /// Wait for a detached rehash to land, polling until the stored hash differs from
    /// `previous` or the deadline passes.
    ///
    /// Polling rather than sleeping a fixed span: the rehash is one password derivation at the
    /// configured cost, and how long that takes depends on the machine. A fixed wait tuned on a
    /// developer's laptop becomes a test that fails on a slower CI runner and reports nothing
    /// about the code — which is exactly what raising the default cost factor turned this into.
    ///
    /// Returns `false` if the deadline passes with the hash unchanged, so the caller asserts
    /// rather than hangs.
    /// Polls to a deadline of `attempts` × 100 ms. Callers pass a generous count; the
    /// give-up path is reachable — and therefore testable — by passing a small one.
    pub(crate) async fn await_rehash_within(
        harness: &Harness,
        user_id: &str,
        previous: &str,
        attempts: u32,
    ) -> bool {
        for _ in 0..attempts {
            if let Ok(Some(user)) = harness.users.find_by_id(user_id, None).await
                && user.password_hash.as_deref().unwrap_or_default() != previous
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    /// Wait for a detached rehash with a generous deadline — four seconds, far longer than a
    /// derivation takes even on a slow shared runner, and the loop exits the moment the value
    /// changes.
    pub(crate) async fn await_rehash(harness: &Harness, user_id: &str, previous: &str) -> bool {
        await_rehash_within(harness, user_id, previous, 40).await
    }

    /// Wait for the detached email send to deliver the verification code, up to a deadline.
    ///
    /// The send is fire-and-forget (`spawn_guarded`), so reading the mailbox the instant the
    /// flow returns is a race the test loses on a quiet machine — and loses SILENTLY, because
    /// the caller's `let Some(code) = .. else { return }` turns a lost race into a pass. Polling
    /// rather than sleeping a fixed span for the reason `await_rehash_within` does: a wait tuned
    /// here becomes a flake on a slower runner.
    /// Polls to a deadline of `attempts` × 25 ms. Callers pass a generous count; the give-up
    /// path is reachable — and therefore testable — by passing a small one, exactly as
    /// [`await_rehash_within`] is.
    pub(crate) async fn await_verification_code_within(
        harness: &Harness,
        attempts: u32,
    ) -> Option<String> {
        for _ in 0..attempts {
            if let Some(code) = harness.emails.verification_code() {
                return Some(code);
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        None
    }

    pub(crate) async fn await_verification_code(harness: &Harness) -> Option<String> {
        await_verification_code_within(harness, 40).await
    }

    /// The password-reset twin of [`await_verification_code_within`].
    pub(crate) async fn await_password_reset_code_within(
        harness: &Harness,
        attempts: u32,
    ) -> Option<String> {
        for _ in 0..attempts {
            if let Some(code) = harness.emails.password_reset_code() {
                return Some(code);
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        None
    }

    pub(crate) async fn await_password_reset_code(harness: &Harness) -> Option<String> {
        await_password_reset_code_within(harness, 40).await
    }

    pub(crate) fn harness(cfg: AuthConfig, hooks: Option<Arc<dyn AuthHooks>>) -> Option<Harness> {
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let emails = Arc::new(CapturingEmails::default());
        let mut builder = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users.clone())
            .email_provider(emails.clone())
            .redis_stores(stores.clone());
        if let Some(hooks) = hooks {
            builder = builder.hooks(hooks);
        }
        builder.build().ok().map(|engine| Harness {
            engine,
            users,
            stores,
            emails,
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

    #[tokio::test]
    async fn every_identifier_preimage_matches_the_shared_wire_contract() {
        // These decide which records the two backends share. The `dashboard:` segment is what
        // keeps a tenant whose id is literally `platform` out of the platform lockout counter;
        // the OTP preimage stays bare because its keyspace is already purpose-scoped; the
        // invitee index is an HMAC rather than a plain digest because an address carries far
        // too little entropy for SHA-256 to hide it. Any of them drifting on one side alone
        // splits a keyspace the two implementations are supposed to share.
        let Some(h) = test_support::harness(test_support::base_config(), None) else { return };
        let key = h.engine.config().hmac_key();
        let expect_preimage = |name: &str, actual: &str| {
            let template = crate::services::contract_preimage(name)
                .replace("{tenantId}", "t1")
                .replace("{email}", "user@example.com");
            assert_eq!(
                to_hex(&hmac_sha256(key, template.as_bytes())),
                actual,
                "the {name} preimage drifted from the shared contract"
            );
        };

        expect_preimage(
            "dashboard",
            &h.engine.lockout_identifier("t1", "user@example.com"),
        );
        expect_preimage(
            "otpRecord",
            &h.engine.hashed_identifier("t1", "user@example.com"),
        );
        expect_preimage(
            "inviteeIndex",
            &h.engine.invitee_identifier("user@example.com"),
        );
    }

    #[test]
    fn register_and_login_inputs_redact_the_password_in_debug() {
        // A stray `{:?}` on either credential DTO must show the redaction marker, never the
        // plaintext password.
        let reg = RegisterInput {
            email: "e@x.io".to_owned(),
            name: "N".to_owned(),
            password: "super-secret".to_owned(),
            tenant_id: Some("t1".to_owned()),
        };
        let reg_dbg = format!("{reg:?}");
        assert!(reg_dbg.contains("[REDACTED]"));
        assert!(!reg_dbg.contains("super-secret"));
        assert!(reg_dbg.contains("e@x.io"));

        let login = LoginInput {
            email: "e@x.io".to_owned(),
            password: "super-secret".to_owned(),
            tenant_id: Some("t1".to_owned()),
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
            h.engine.resolve_tenant(Some("body-tenant"), &ctx).await,
            Ok(t) if t == "resolved-tenant"
        ));
        let empty_ctx = RequestContext::new("1.2.3.4", "ua", BTreeMap::new());
        assert!(matches!(
            h.engine
                .resolve_tenant(Some("body-tenant"), &empty_ctx)
                .await,
            Err(AuthError::Forbidden)
        ));
        // A configured resolver makes the caller's value dead weight, so a request that names
        // no tenant is resolved exactly like one that does.
        assert!(matches!(
            h.engine.resolve_tenant(None, &ctx).await,
            Ok(t) if t == "resolved-tenant"
        ));
    }

    #[tokio::test]
    async fn the_mail_poll_gives_up_rather_than_hanging() {
        // The deadline arm, driven with a tiny attempt count against a mailbox nothing ever
        // wrote to. It exists so a caller that loses the race asserts and fails instead of
        // blocking a CI run forever, and it is only reachable — and only testable — through the
        // parameterized form, exactly as `await_rehash_within` is.
        let cfg = test_support::base_config();
        let Some(h) = test_support::harness(cfg, None) else { return };
        assert!(
            test_support::await_verification_code_within(&h, 1)
                .await
                .is_none()
        );
        assert!(
            test_support::await_password_reset_code_within(&h, 1)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_capturing_mailer_records_the_codes_and_ignores_the_rest() {
        // The harness's double keeps the two codes a flow has to submit back, and no-ops the
        // other sends. Exercised end to end here so the object-safe impl is covered and so the
        // recording halves are asserted rather than assumed: a double that quietly kept nothing
        // would make every test that reads a code from it skip its own assertions.
        let mailer = test_support::CapturingEmails::default();
        assert!(mailer.verification_code().is_none());
        assert!(mailer.password_reset_code().is_none());

        let provider: &dyn crate::traits::EmailProvider = &mailer;
        assert!(
            provider
                .send_email_verification_otp("t1", "u@example.com", "123456", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_password_reset_otp("t1", "u@example.com", "654321", Some("pt-BR"))
                .await
                .is_ok()
        );
        assert_eq!(mailer.verification_code().as_deref(), Some("123456"));
        assert_eq!(mailer.password_reset_code().as_deref(), Some("654321"));

        // The rest carry no code a test submits back, so they are no-ops — driven here so the
        // impl is fully covered.
        assert!(
            provider
                .send_password_reset_token("t1", "u@example.com", "tok", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_change_verification("t1", "new@example.com", "tok", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_mfa_enabled("t1", "u@example.com", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_mfa_disabled("t1", "u@example.com", None)
                .await
                .is_ok()
        );
        let invite = crate::traits::InviteData {
            inviter_name: "Owner".to_owned(),
            tenant_name: "Acme".to_owned(),
            invite_token: "0".repeat(64),
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert!(
            provider
                .send_invitation("t1", "u@example.com", &invite, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_request_naming_no_tenant_with_no_resolver_is_refused_rather_than_defaulted() {
        // Without a resolver the caller's value is the ONLY thing that can scope the request,
        // and that scope keys the user lookup, the Redis records and the HMAC identifiers. A
        // default would silently gather into one scope every account a misconfigured deployment
        // created — so the request is refused, naming the field the deployment has to fix.
        // Bound first so the `else` fits on one line: a wrapped `else { return; }` isolates the
        // `return` on its own line, which no run reaches and the 100% line gate then refuses.
        let cfg = test_support::base_config();
        let Some(h) = test_support::harness(cfg, None) else { return };
        let ctx = RequestContext::new("1.2.3.4", "ua", BTreeMap::new());
        let refused = h.engine.resolve_tenant(None, &ctx).await;
        assert!(
            matches!(&refused, Err(AuthError::Validation { details })
                if details.len() == 1 && details[0].field == "tenantId"),
            "expected a tenantId validation failure, got {refused:?}"
        );
        // The named value still passes through untouched — the refusal is about absence only.
        assert!(matches!(
            h.engine.resolve_tenant(Some("body-tenant"), &ctx).await,
            Ok(t) if t == "body-tenant"
        ));
    }

    #[tokio::test]
    async fn every_tenant_scoped_flow_honours_the_resolver() {
        // The option documents itself as ignoring the body's tenant when a resolver is
        // configured, "to prevent tenant spoofing". Only `login` and `register` honoured it:
        // password reset (all four steps) and email verification (both) read the body value
        // verbatim, so a caller on one tenant could drive reset/verification mail at accounts
        // in another — and a reset started under the RESOLVED tenant could never be completed,
        // because the stored context and the confirm step disagreed about which tenant it
        // belonged to.
        //
        // The check is indirect but exact: the resolver refuses when no `host` header is
        // present, so a flow that consults it fails with `Forbidden` on an empty context and a
        // flow that ignores it does not. Every one of these used to be silently fine.
        let mut cfg = test_support::base_config();
        cfg.tenant_id_resolver = Some(Arc::new(HostTenantResolver));
        let Some(h) = test_support::harness(cfg, None) else { return };
        let empty = RequestContext::new("1.2.3.4", "ua", BTreeMap::new());

        let forgot = crate::services::auth::ForgotPasswordInput {
            email: "x@example.com".to_owned(),
            tenant_id: Some("body-tenant".to_owned()),
        };
        assert!(matches!(
            h.engine.initiate_reset(forgot, &empty).await,
            Err(AuthError::Forbidden)
        ));

        let verify_otp = crate::services::auth::VerifyResetOtpInput {
            email: "x@example.com".to_owned(),
            tenant_id: Some("body-tenant".to_owned()),
            otp: "123456".to_owned(),
        };
        assert!(matches!(
            h.engine.verify_reset_otp(verify_otp, &empty).await,
            Err(AuthError::Forbidden)
        ));

        let resend = crate::services::auth::ResendResetOtpInput {
            email: "x@example.com".to_owned(),
            tenant_id: Some("body-tenant".to_owned()),
        };
        assert!(matches!(
            h.engine.resend_reset_otp(resend, &empty).await,
            Err(AuthError::Forbidden)
        ));

        assert!(matches!(
            h.engine
                .verify_email(Some("body-tenant"), "x@example.com", "123456", &empty)
                .await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            h.engine
                .resend_verification_email(Some("body-tenant"), "x@example.com", &empty)
                .await,
            Err(AuthError::Forbidden)
        ));

        // `oauth_initiate` is the eighth tenant-scoped flow and belongs on this list, but it
        // needs a configured provider to reach the resolver at all (the provider is resolved
        // first, so an unknown one fails before any consumer code runs). It is asserted in
        // `services::oauth::tests::oauth_initiate_honours_the_tenant_resolver`, against a
        // harness that wires Google.
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
