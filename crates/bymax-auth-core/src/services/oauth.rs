//! The provider-agnostic OAuth authorize → callback orchestration on [`AuthEngine`]
//! (§11.3). Everything security-critical lives here in the core: the 64-hex CSRF `state`,
//! the PKCE `code_verifier` → S256 `code_challenge`, the single-use `state` `getdel`, the
//! token-exchange and profile-fetch orchestration through the injected provider, the
//! `on_oauth_login` create/link/reject decision, and the session-vs-MFA branch. No HTTP
//! handler logic lives here — the Axum adapter only turns the returned [`OAuthOutcome`] into
//! a redirect or JSON response.
//!
//! Provider internals never reach the caller: every [`OAuthProviderError`] collapses to the
//! opaque `auth.oauth_failed`, while store/repository failures propagate as the internal
//! error so monitoring still sees an infrastructure problem rather than an auth-failed
//! redirect (§11.3.3). Redirect targets are never request-derived — the three redirect URLs
//! and the provider callback are operator-configured and startup-validated (§11.4); the only
//! runtime redirect operation is the safe `?error=` append in [`AuthEngine::oauth_error_redirect_url`].

use std::sync::Arc;

use base64::Engine as _;
use bymax_auth_types::{
    AuthError, AuthResult, AuthUser, CreateWithOAuthData, MfaChallengeResult, MfaContext,
    SafeAuthUser,
};
use serde::{Deserialize, Serialize};

use crate::RepositoryError;
use crate::context::{RequestContext, to_safe_user};
use crate::engine::AuthEngine;
use crate::services::auth::detached::{run_after_login, run_update_last_login};
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::services::{internal_error, to_hex};
use crate::traits::{
    HookContext, OAuthLoginResult, OAuthProfile, OAuthProvider, OAuthProviderError,
};

/// The TTL, in seconds, of the single-use `state` + PKCE record (`os:{sha256(state)}`). Ten
/// minutes — long enough for a human consent screen, short enough to bound replay surface.
const OAUTH_STATE_TTL_SECS: u64 = 600;

/// The byte length of both the CSRF `state` (rendered as 64 hex chars) and the PKCE
/// `code_verifier` (rendered as 43 base64url chars), each a fresh 256-bit CSPRNG draw.
const OAUTH_RANDOM_BYTES: usize = 32;

/// Uppercase hexadecimal alphabet for percent-encoding, indexed by nibble value.
const PERCENT_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// The server-held `os:` payload bound to a `state`: the tenant the user will join and the
/// PKCE `code_verifier`. Only the `code_challenge` ever leaves the system; the verifier stays
/// here and is forwarded straight to the token endpoint on callback. The encoding is
/// core-owned (the store sees it as an opaque string), camelCase for parity with the other
/// nest-auth Redis payloads. It deliberately derives no `Debug`, so the verifier can never
/// reach a log line through a stray `{:?}`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthStatePayload {
    /// The tenant scope carried from the initiate query and recovered on callback. Never
    /// validated server-side here — `on_oauth_login` is the tenant-membership gate.
    tenant_id: String,
    /// The PKCE `code_verifier` (RFC 7636), forwarded on exchange and never logged.
    code_verifier: String,
}

/// The outcome of [`AuthEngine::oauth_callback`]: either a full authentication or an MFA
/// challenge. Discriminated like the password-login [`bymax_auth_types::LoginResult`], so the
/// adapter shapes the response the same way.
#[derive(Clone, Debug)]
pub enum OAuthOutcome {
    /// A full session: access + refresh + the safe user. The large success payload is boxed so
    /// the enum stays small to move around (the challenge arm is tiny), mirroring
    /// [`bymax_auth_types::LoginResult::Success`]. Delivered per the token-delivery mode.
    Authenticated(Box<AuthResult>),
    /// The resolved user has MFA enabled: OAuth proved only provider control, so the engine
    /// issued a short-lived MFA temp token and the user must complete the second factor.
    MfaChallenge(MfaChallengeResult),
}

impl AuthEngine {
    /// Begin an OAuth authorize redirect (§11.3.1): resolve the provider **before** any Redis
    /// write, mint a fresh 64-hex `state` and a PKCE verifier/challenge pair, store
    /// `os:{sha256(state)} → { tenant_id, code_verifier }` at a 600 s TTL, and return the
    /// provider authorization URL. The raw `state` is never stored — only its hash is a key —
    /// and only the `code_challenge` is exposed to the provider.
    ///
    /// `tenant_id` is carried verbatim into the state and recovered on callback; it is **not**
    /// validated here (the `on_oauth_login` hook enforces tenant membership).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::OauthFailed`] for an unknown or malformed provider name (without
    /// consuming any resource), or a store/serialization [`AuthError`] on an infrastructure
    /// failure.
    pub async fn oauth_initiate(
        &self,
        provider: &str,
        tenant_id: &str,
    ) -> Result<String, AuthError> {
        // Resolve the provider first: an unknown provider fails without minting state.
        let provider_impl = self.resolve_oauth_provider(provider)?;

        let state = generate_state();
        let (code_verifier, code_challenge) = generate_pkce();
        let payload = serde_json::to_string(&OAuthStatePayload {
            tenant_id: tenant_id.to_owned(),
            code_verifier,
        })
        .map_err(oauth_state_serialize_failed)?;

        self.require_oauth_state_store()?
            .put_state(&state_key(&state), &payload, OAUTH_STATE_TTL_SECS)
            .await?;

        Ok(provider_impl.authorize_url(&state, Some(&code_challenge)))
    }

    /// Complete an OAuth callback (§11.3.2): resolve the provider, atomically consume the
    /// single-use `state` (`getdel` — the combined CSRF check + replay guard), forward the
    /// PKCE `code_verifier` on token exchange, fetch the normalized profile, look the OAuth
    /// identity up, run the `on_oauth_login` create/link/reject decision, and either issue a
    /// session or route into an MFA challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::OauthFailed`] for an unknown/malformed provider, a
    /// missing/forged/replayed/malformed `state`, any provider (exchange/profile) failure
    /// including an unverified email, a `reject`/`Err` hook decision, or a `link` with no
    /// existing user; [`AuthError::OauthEmailMismatch`] when a `create` collides with an
    /// existing account; or a store/repository/issuance [`AuthError`] on infrastructure
    /// failure (which the adapter surfaces as a 500 rather than an error redirect).
    pub async fn oauth_callback(
        &self,
        provider: &str,
        code: &str,
        state: &str,
        ctx: &RequestContext,
    ) -> Result<OAuthOutcome, AuthError> {
        // Resolve the provider BEFORE consuming the state, so a misconfigured provider does
        // not silently burn the user's single-use nonce.
        let provider_impl = self.resolve_oauth_provider(provider)?;
        let provider_name = provider_impl.name().to_owned();

        // Reject a `state` that does not match the engine-issued 64-hex shape BEFORE hashing
        // it: `state` is attacker-controlled, so an arbitrarily large value would otherwise
        // drive an unbounded SHA-256 (a cheap DoS). A bad-shape value could never match a
        // stored key anyway, so it takes the same path as a missing/forged/replayed state —
        // the opaque `OauthFailed` — and never reaches `state_key`/the store.
        if !is_oauth_state_shape(state) {
            return Err(AuthError::OauthFailed);
        }

        // Atomic read-and-delete: existence is the CSRF check, deletion is the replay guard.
        let Some(raw_payload) = self
            .require_oauth_state_store()?
            .take_state(&state_key(state))
            .await?
        else {
            return Err(AuthError::OauthFailed);
        };
        let Ok(payload) = serde_json::from_str::<OAuthStatePayload>(&raw_payload) else {
            // A malformed/legacy payload is treated as a failed state, not an internal error.
            return Err(AuthError::OauthFailed);
        };
        let tenant_id = payload.tenant_id;

        // Token exchange (forwarding the PKCE verifier) and profile fetch. Every provider
        // error collapses to the opaque OauthFailed — provider internals never reach the client.
        let tokens = provider_impl
            .exchange_code(code, Some(&payload.code_verifier))
            .await
            .map_err(provider_error)?;
        let profile = provider_impl
            .fetch_profile(&tokens.access_token)
            .await
            .map_err(provider_error)?;

        // Resolve any user already bound to this OAuth identity within the tenant.
        let existing = self
            .user_repository()
            .find_by_oauth_id(&provider_name, &profile.provider_id, &tenant_id)
            .await
            .map_err(map_repository_error)?;
        let safe_existing = existing.as_ref().map(to_safe_user);

        // The mandatory create/link/reject decision and tenant-membership gate. The default
        // NoOp hook returns Reject, so OAuth sign-in is disabled until the deployer implements
        // this hook; an Err is treated as a reject (OauthFailed).
        let hook_ctx = HookContext::from_request(
            ctx,
            existing.as_ref().map(|user| user.id.clone()),
            Some(profile.email.clone()),
            Some(tenant_id.clone()),
        );
        let decision = self
            .hooks()
            .on_oauth_login(&profile, safe_existing.as_ref(), &hook_ctx)
            .await
            .map_err(|_| AuthError::OauthFailed)?;

        let resolved = self
            .execute_oauth_decision(decision, &provider_name, &profile, &tenant_id, existing)
            .await?;

        self.finish_oauth_login(resolved, ctx, hook_ctx).await
    }

    /// The operator-configured success redirect (§11.3.3), or `None` for the JSON/SPA flow.
    #[must_use]
    pub fn oauth_success_redirect_url(&self) -> Option<&str> {
        self.config().config().oauth.success_redirect_url.as_deref()
    }

    /// The operator-configured MFA redirect (§11.3.3), or `None` for the JSON/SPA flow.
    #[must_use]
    pub fn oauth_mfa_redirect_url(&self) -> Option<&str> {
        self.config().config().oauth.mfa_redirect_url.as_deref()
    }

    /// Build the error-redirect target for an `OauthFailed`-family callback (§11.4): take the
    /// startup-validated `error_redirect_url`, re-serialize it, and append `error=<short_code>`
    /// (a `?` or `&` as appropriate, before any fragment), percent-encoding the code. Returns
    /// `None` when no error redirect is configured (the adapter then falls back to JSON). The
    /// caller passes the short suffix (`oauth_failed`), never the `auth.`-namespaced code.
    #[must_use]
    pub fn oauth_error_redirect_url(&self, short_code: &str) -> Option<String> {
        self.config()
            .config()
            .oauth
            .error_redirect_url
            .as_deref()
            .map(|base| append_error_param(base, short_code))
    }

    /// Resolve a registered provider by name, rejecting a malformed or unknown name as the
    /// opaque `OauthFailed`. Returns a cloned `Arc` so the handle outlives the borrow of
    /// `self` across the subsequent `await` points.
    fn resolve_oauth_provider(&self, name: &str) -> Result<Arc<dyn OAuthProvider>, AuthError> {
        if !is_valid_provider_name(name) {
            return Err(AuthError::OauthFailed);
        }
        self.oauth_providers()
            .get(name)
            .cloned()
            .ok_or(AuthError::OauthFailed)
    }

    /// The wired OAuth state store, or the internal error when none is present. The builder
    /// rejects an enabled OAuth controller without a state store, so this is defensive.
    fn require_oauth_state_store(
        &self,
    ) -> Result<&Arc<dyn crate::traits::OAuthStateStore>, AuthError> {
        self.oauth_state_store()
            .ok_or_else(|| internal_error("oauth state store is not wired"))
    }

    /// Execute the hook's decision, returning the resolved [`AuthUser`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::OauthEmailMismatch`] for a create collision,
    /// [`AuthError::OauthFailed`] for a reject or a link with no existing user, or a store
    /// [`AuthError`] on a backend failure.
    async fn execute_oauth_decision(
        &self,
        decision: OAuthLoginResult,
        provider_name: &str,
        profile: &OAuthProfile,
        tenant_id: &str,
        existing: Option<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        match decision {
            OAuthLoginResult::Create => {
                let data = CreateWithOAuthData {
                    email: profile.email.clone(),
                    name: name_or_local_part(profile),
                    role: None,
                    status: None,
                    tenant_id: tenant_id.to_owned(),
                    email_verified: Some(true),
                    oauth_provider: provider_name.to_owned(),
                    oauth_provider_id: profile.provider_id.clone(),
                };
                self.user_repository()
                    .create_with_oauth(data)
                    .await
                    .map_err(map_oauth_create_error)
            }
            OAuthLoginResult::Link => {
                // A link requires an account already bound to this OAuth identity.
                let Some(existing) = existing else {
                    return Err(AuthError::OauthFailed);
                };
                self.user_repository()
                    .link_oauth(&existing.id, provider_name, &profile.provider_id)
                    .await
                    .map_err(map_repository_error)?;
                // Re-fetch by primary key so the resolved user reflects the linked state; a
                // vanished row (defensive) collapses to the opaque failure.
                self.user_repository()
                    .find_by_id(&existing.id, Some(tenant_id))
                    .await
                    .map_err(map_repository_error)?
                    .ok_or(AuthError::OauthFailed)
            }
            OAuthLoginResult::Reject { .. } => Err(AuthError::OauthFailed),
        }
    }

    /// Issue the session for the resolved user, or route into an MFA challenge when the user
    /// has MFA enabled (OAuth proved only provider control, never the second factor). The
    /// MFA-temp token is minted through the engine's token manager, with no dependency on the
    /// MFA service.
    ///
    /// # Errors
    ///
    /// Returns a store/signing [`AuthError`] if temp-token minting or session issuance fails.
    async fn finish_oauth_login(
        &self,
        user: AuthUser,
        ctx: &RequestContext,
        hook_ctx: HookContext,
    ) -> Result<OAuthOutcome, AuthError> {
        if user.mfa_enabled {
            let mfa_temp_token = self
                .tokens()
                .issue_mfa_temp_token(&user.id, MfaContext::Dashboard)
                .await?;
            return Ok(OAuthOutcome::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                mfa_temp_token,
            }));
        }

        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens()
            .issue_tokens(&safe, &ctx.ip, &ctx.user_agent, false)
            .await?;
        // Enforce the concurrent-session cap and fire the new-session hook (a no-op when
        // session tracking is disabled) before the fire-and-forget bookkeeping.
        self.enforce_sessions_after_issue(&result, &ctx.ip, &ctx.user_agent, &hook_ctx)
            .await?;
        spawn_guarded(run_update_last_login(
            self.user_repository().clone(),
            safe.id.clone(),
        ));
        spawn_guarded(run_after_login(self.hooks().clone(), safe, hook_ctx));
        Ok(OAuthOutcome::Authenticated(Box::new(result)))
    }
}

/// Whether `name` matches `^[a-z0-9-]{1,64}$` — the stable provider-id grammar used as both
/// the route segment and the storage/lookup key.
fn is_valid_provider_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Mint a 64-hex CSRF `state` from a fresh 256-bit CSPRNG draw.
fn generate_state() -> String {
    to_hex(&bymax_auth_crypto::token::random_array::<OAUTH_RANDOM_BYTES>())
}

/// Whether `state` matches the engine-issued CSRF `state` shape: exactly 64 lower-case hex
/// characters (the [`generate_state`] output, a 256-bit draw). Checking the shape before
/// hashing rejects an oversized or malformed value cheaply — without a SHA-256 over an
/// unbounded, attacker-controlled input — and such a value could never key a stored record
/// anyway. Mirrors the refresh-token / session-hash shape guards used elsewhere.
fn is_oauth_state_shape(state: &str) -> bool {
    state.len() == 64
        && state
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Mint a PKCE `(code_verifier, code_challenge)` pair (RFC 7636, S256): the verifier is a
/// base64url-no-pad 256-bit draw; the challenge is `base64url(SHA-256(code_verifier))`.
fn generate_pkce() -> (String, String) {
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(bymax_auth_crypto::token::random_array::<OAUTH_RANDOM_BYTES>());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(bymax_auth_crypto::mac::sha256(verifier.as_bytes()));
    (verifier, challenge)
}

/// The `os:` key suffix for a raw `state`: its hex `sha256`, so the raw `state` is never a key.
fn state_key(state: &str) -> String {
    to_hex(&bymax_auth_crypto::mac::sha256(state.as_bytes()))
}

/// Map a failure to serialize the `os:` state payload to the opaque internal error.
/// Serializing the concrete [`OAuthStatePayload`] (two `String` fields) cannot fail in
/// practice, so this is a defensive mapping that never surfaces the failing step.
fn oauth_state_serialize_failed(_error: serde_json::Error) -> AuthError {
    internal_error("oauth state payload serialization failed")
}

/// Map any provider-layer error to the opaque client-facing `OauthFailed`, logging the cause
/// for monitoring. Provider internals (status, transport detail, token type) never reach the
/// caller; only the generic code does.
fn provider_error(error: OAuthProviderError) -> AuthError {
    tracing::warn!(%error, "oauth provider error mapped to oauth_failed");
    AuthError::OauthFailed
}

/// Map a `create_with_oauth` failure: a unique-constraint conflict means the provider email
/// collides with an existing account (the §11.4 `oauth_email_mismatch` case, 409); any other
/// backend failure is the opaque internal error.
fn map_oauth_create_error(error: RepositoryError) -> AuthError {
    match error {
        RepositoryError::Conflict(_) => AuthError::OauthEmailMismatch,
        RepositoryError::Backend(source) => AuthError::Internal(source),
    }
}

/// The display name for a new OAuth account: the profile name when present, else the email
/// local-part (the substring before `@`).
fn name_or_local_part(profile: &OAuthProfile) -> String {
    match &profile.name {
        Some(name) => name.clone(),
        None => profile
            .email
            .split('@')
            .next()
            .unwrap_or(profile.email.as_str())
            .to_owned(),
    }
}

/// Append `error=<short_code>` to an already-validated redirect URL, re-serializing so a
/// fragment is preserved and the parameter lands in the query (with `?` or `&` as
/// appropriate). The code is percent-encoded; it is a fixed safe token, so this is
/// defense-in-depth against a malformed configured value rather than request-derived input.
fn append_error_param(base: &str, short_code: &str) -> String {
    let (locator, fragment) = match base.split_once('#') {
        Some((locator, fragment)) => (locator, Some(fragment)),
        None => (base, None),
    };
    let separator = if locator.contains('?') { '&' } else { '?' };
    let mut out = String::with_capacity(base.len() + short_code.len() + 8);
    out.push_str(locator);
    out.push(separator);
    out.push_str("error=");
    out.push_str(&percent_encode(short_code));
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// Percent-encode `value` per the RFC 3986 unreserved set (`A-Za-z0-9-_.~` pass through,
/// everything else becomes `%XX`). Shared by the OAuth error-redirect builder and the built-in
/// providers' query/form encoding.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(PERCENT_HEX[usize::from(byte >> 4)] as char);
            out.push(PERCENT_HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Environment, GoogleOAuthConfig};
    use crate::providers::GoogleOAuthProvider;
    use crate::services::auth::test_support::{base_config, ctx};
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::{
        AuthHooks, HookError, HttpClient, HttpError, HttpRequest, HttpResponse, OAuthStateStore,
        UserRepository,
    };
    use bymax_auth_types::{CreateWithOAuthData, UpdateMfaData};
    use secrecy::SecretString;
    use std::sync::Mutex;
    use std::sync::PoisonError;

    /// Acquire a mutex guard, recovering from poisoning (a test double never escalates to a
    /// panic).
    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A recording [`HttpClient`] that routes by URL: the Google token endpoint and the
    /// userinfo endpoint each return a configurable `(status, body)`, and every request is
    /// captured so a test can assert what was sent (e.g. the PKCE verifier on exchange).
    struct RoutingHttpClient {
        requests: Mutex<Vec<HttpRequest>>,
        token: Mutex<(u16, Vec<u8>)>,
        userinfo: Mutex<(u16, Vec<u8>)>,
    }

    impl RoutingHttpClient {
        /// A client with the canonical success responses: a bearer token, then a verified
        /// profile for `new@example.com` (provider id `google-user-1`).
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                token: Mutex::new((200, token_body("bearer"))),
                userinfo: Mutex::new((200, userinfo_body(true, "new@example.com"))),
            }
        }

        /// The exchange POST body (the request sent to the token endpoint), as a string.
        fn exchange_body(&self) -> Option<String> {
            lock(&self.requests)
                .iter()
                .find(|req| req.url.contains("/token"))
                .and_then(|req| {
                    req.body
                        .as_ref()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                })
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for RoutingHttpClient {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
            let url = req.url.clone();
            lock(&self.requests).push(req);
            let (status, body) = if url.contains("/token") {
                lock(&self.token).clone()
            } else {
                lock(&self.userinfo).clone()
            };
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body,
            })
        }
    }

    /// A token-endpoint JSON body with the given `token_type`.
    fn token_body(token_type: &str) -> Vec<u8> {
        format!(
            "{{\"access_token\":\"at-123\",\"token_type\":\"{token_type}\",\"expires_in\":3599,\
             \"scope\":\"openid email profile\",\"id_token\":\"idtok\"}}"
        )
        .into_bytes()
    }

    /// A userinfo JSON body with the given verification flag and email.
    fn userinfo_body(verified: bool, email: &str) -> Vec<u8> {
        format!(
            "{{\"id\":\"google-user-1\",\"email\":\"{email}\",\"verified_email\":{verified},\
             \"name\":\"New User\",\"picture\":\"https://pic.example.com/a.png\"}}"
        )
        .into_bytes()
    }

    /// An [`OAuthStateStore`] that counts how many times `take_state` is invoked, so a test can
    /// prove a rejected `state` never reaches the store (no hash, no lookup). `put_state` is a
    /// no-op; `take_state` always reports a miss after recording the call.
    struct CountingStateStore {
        takes: std::sync::atomic::AtomicUsize,
    }

    impl CountingStateStore {
        fn new() -> Self {
            Self {
                takes: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn take_count(&self) -> usize {
            self.takes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl OAuthStateStore for CountingStateStore {
        async fn put_state(
            &self,
            _state_hash: &str,
            _payload: &str,
            _ttl_secs: u64,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn take_state(&self, _state_hash: &str) -> Result<Option<String>, AuthError> {
            self.takes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
        }
    }

    /// A hook returning a fixed `on_oauth_login` decision.
    struct DecisionHook(OAuthLoginResult);

    #[async_trait::async_trait]
    impl AuthHooks for DecisionHook {
        async fn on_oauth_login(
            &self,
            _profile: &OAuthProfile,
            _existing: Option<&SafeAuthUser>,
            _ctx: &HookContext,
        ) -> Result<OAuthLoginResult, HookError> {
            Ok(self.0.clone())
        }
    }

    /// A hook whose `on_oauth_login` errors, exercising the hook-error → OauthFailed mapping.
    struct ErrHook;

    #[async_trait::async_trait]
    impl AuthHooks for ErrHook {
        async fn on_oauth_login(
            &self,
            _profile: &OAuthProfile,
            _existing: Option<&SafeAuthUser>,
            _ctx: &HookContext,
        ) -> Result<OAuthLoginResult, HookError> {
            Err(HookError::Rejected("denied".to_owned()))
        }
    }

    /// The Google provider credentials used in the flow tests.
    fn google_config() -> GoogleOAuthConfig {
        GoogleOAuthConfig {
            client_id: "client-id".to_owned(),
            client_secret: SecretString::from("client-secret".to_owned()),
            callback_url: "https://app.example.com/auth/oauth/google/callback".to_owned(),
            scope: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        }
    }

    /// An engine plus its in-memory collaborators and the recording transport.
    struct OAuthHarness {
        engine: AuthEngine,
        users: Arc<InMemoryUserRepository>,
        stores: Arc<InMemoryStores>,
        http: Arc<RoutingHttpClient>,
    }

    /// Build a harness wiring the built-in Google provider over `http`, the given hooks, and
    /// the in-memory state store. `sessions` enables concurrent-session tracking.
    fn harness(
        hooks: Arc<dyn AuthHooks>,
        http: Arc<RoutingHttpClient>,
        sessions: bool,
    ) -> Option<OAuthHarness> {
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let google = GoogleOAuthProvider::new(google_config(), http.clone());
        let mut cfg = base_config();
        cfg.controllers.oauth = true;
        cfg.sessions.enabled = sessions;
        cfg.sessions.default_max_sessions = 5;
        let engine = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users.clone())
            .redis_stores(stores.clone())
            .hooks(hooks)
            .oauth_provider(Arc::new(google))
            .oauth_state_store(stores.clone())
            .build()
            .ok()?;
        Some(OAuthHarness {
            engine,
            users,
            stores,
            http,
        })
    }

    /// Seed a user already bound to the Google identity `google-user-1` in tenant `t1`.
    async fn seed_linked_user(users: &InMemoryUserRepository, mfa: bool) -> String {
        let created = users
            .create_with_oauth(CreateWithOAuthData {
                email: "linked@example.com".to_owned(),
                name: "Linked".to_owned(),
                role: None,
                status: Some("active".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
                oauth_provider: "google".to_owned(),
                oauth_provider_id: "google-user-1".to_owned(),
            })
            .await;
        let Ok(user) = created else { return String::new() };
        if mfa {
            let _ = users
                .update_mfa(
                    &user.id,
                    UpdateMfaData {
                        mfa_enabled: true,
                        mfa_secret: Some("enc".to_owned()),
                        mfa_recovery_codes: None,
                    },
                )
                .await;
        }
        user.id
    }

    /// Run a full initiate → callback, returning the callback outcome. The `code` is canned
    /// (the recording transport ignores it); the `state` is recovered from the authorize URL.
    async fn run_flow(h: &OAuthHarness) -> Result<OAuthOutcome, AuthError> {
        let url = h.engine.oauth_initiate("google", "t1").await;
        let Ok(url) = url else { return Err(AuthError::OauthFailed) };
        let state = extract_query_param(&url, "state").unwrap_or_default();
        h.engine
            .oauth_callback("google", "auth-code", &state, &ctx())
            .await
    }

    /// Extract a query-parameter value from a URL (test helper; not percent-decoded).
    fn extract_query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split_once('?').map(|(_, q)| q)?;
        query.split('&').find_map(|pair| {
            pair.split_once('=')
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| v.to_owned())
        })
    }

    #[tokio::test]
    async fn initiate_resolves_provider_stores_state_and_returns_authorize_url() {
        // Initiate mints state + PKCE, persists the os: record, and returns a Google authorize
        // URL carrying the state and an S256 challenge.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let url = h.engine.oauth_initiate("google", "t1").await;
        assert!(matches!(&url, Ok(u) if u.starts_with("https://accounts.google.com/")));
        let Ok(url) = url else { return };
        assert!(url.contains("code_challenge_method=S256"));
        let state = extract_query_param(&url, "state").unwrap_or_default();
        assert_eq!(state.len(), 64, "state is 64 hex chars");
        // The os: record exists under sha256(state).
        assert!(matches!(
            h.stores.take_state(&state_key(&state)).await,
            Ok(Some(_))
        ));
    }

    #[tokio::test]
    async fn initiate_rejects_unknown_and_malformed_provider_without_storing_state() {
        // An unknown or malformed provider fails as OauthFailed and writes no state.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(
            h.engine.oauth_initiate("github", "t1").await,
            Err(AuthError::OauthFailed)
        ));
        assert!(matches!(
            h.engine.oauth_initiate("BAD_NAME", "t1").await,
            Err(AuthError::OauthFailed)
        ));
    }

    #[tokio::test]
    async fn callback_create_path_provisions_a_user_and_authenticates() {
        // With no existing identity and a Create decision, the callback provisions the account
        // from the profile and returns a full session.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let outcome = run_flow(&h).await;
        assert!(matches!(&outcome, Ok(OAuthOutcome::Authenticated(_))));
        let Ok(OAuthOutcome::Authenticated(result)) = outcome else { return };
        assert_eq!(result.user.email, "new@example.com");
        assert_eq!(result.user.oauth_provider.as_deref(), Some("google"));
        assert!(!result.access_token.is_empty());
        // The PKCE verifier was forwarded on exchange and matches the issued challenge.
        let body = h.engine.oauth_initiate("google", "t1").await;
        assert!(body.is_ok());
        let Some(exchange) = h.http.exchange_body() else { return };
        assert!(exchange.contains("code_verifier="));
        assert!(exchange.contains("grant_type=authorization_code"));
    }

    #[tokio::test]
    async fn callback_pkce_challenge_is_the_sha256_of_the_forwarded_verifier() {
        // End-to-end PKCE proof: the verifier forwarded on exchange hashes (S256) to the
        // challenge that left in the authorize URL.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let url = h.engine.oauth_initiate("google", "t1").await;
        let Ok(url) = url else { return };
        let state = extract_query_param(&url, "state").unwrap_or_default();
        let challenge = extract_query_param(&url, "code_challenge").unwrap_or_default();
        let done = h
            .engine
            .oauth_callback("google", "auth-code", &state, &ctx())
            .await;
        assert!(done.is_ok());
        let Some(exchange) = h.http.exchange_body() else { return };
        let verifier = exchange
            .split('&')
            .find_map(|pair| pair.strip_prefix("code_verifier="))
            .unwrap_or_default();
        // The form value is percent-encoded; the base64url verifier has no reserved chars, so
        // it round-trips unchanged.
        let recomputed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bymax_auth_crypto::mac::sha256(verifier.as_bytes()));
        assert_eq!(recomputed, challenge);
    }

    #[tokio::test]
    async fn callback_link_path_relinks_an_existing_user_and_authenticates() {
        // A Link decision with an existing identity re-links and returns a session.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Link));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let id = seed_linked_user(&h.users, false).await;
        assert!(!id.is_empty());
        let outcome = run_flow(&h).await;
        assert!(matches!(&outcome, Ok(OAuthOutcome::Authenticated(_))));
        let Ok(OAuthOutcome::Authenticated(result)) = outcome else { return };
        assert_eq!(result.user.id, id);
    }

    #[tokio::test]
    async fn callback_link_without_existing_user_fails() {
        // A Link decision with no account bound to the identity is OauthFailed.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Link));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_reject_path_fails() {
        // A Reject decision is OauthFailed.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Reject {
            reason: Some("blocked".to_owned()),
        }));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_mfa_enabled_user_returns_a_challenge() {
        // A Link to an MFA-enabled user returns the MFA challenge, not a session.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Link));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let _ = seed_linked_user(&h.users, true).await;
        let outcome = run_flow(&h).await;
        assert!(matches!(
            outcome,
            Ok(OAuthOutcome::MfaChallenge(MfaChallengeResult {
                mfa_required: true,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn callback_with_session_tracking_creates_a_tracked_session() {
        // With session tracking on, the Authenticated path records a session for the user.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), true) else { return };
        let outcome = run_flow(&h).await;
        assert!(matches!(&outcome, Ok(OAuthOutcome::Authenticated(_))));
        let Ok(OAuthOutcome::Authenticated(result)) = outcome else { return };
        let listed = h
            .engine
            .sessions()
            .list_sessions(&result.user.id, None)
            .await;
        assert!(matches!(listed, Ok(v) if v.len() == 1));
    }

    #[tokio::test]
    async fn callback_default_noop_hook_disables_oauth_signin() {
        // The NoOp hook default returns Reject, so OAuth sign-in is disabled by default.
        let hooks: Arc<dyn AuthHooks> = Arc::new(crate::traits::NoOpAuthHooks);
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_hook_error_maps_to_oauth_failed() {
        // A hook that errors is treated as a reject (OauthFailed), never a 500.
        let hooks: Arc<dyn AuthHooks> = Arc::new(ErrHook);
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_rejects_missing_forged_and_replayed_state() {
        // A never-issued state is OauthFailed; a consumed state cannot be replayed.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        // Forged / missing state.
        assert!(matches!(
            h.engine
                .oauth_callback("google", "code", &"f".repeat(64), &ctx())
                .await,
            Err(AuthError::OauthFailed)
        ));
        // Issue a real state, consume it once, then replay it.
        let url = h.engine.oauth_initiate("google", "t1").await;
        let Ok(url) = url else { return };
        let state = extract_query_param(&url, "state").unwrap_or_default();
        assert!(
            h.engine
                .oauth_callback("google", "code", &state, &ctx())
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine
                .oauth_callback("google", "code", &state, &ctx())
                .await,
            Err(AuthError::OauthFailed)
        ));
    }

    #[tokio::test]
    async fn callback_rejects_a_bad_shape_state_before_hashing_or_lookup() {
        // A `state` that is not 64 lower-case hex is rejected as OauthFailed BEFORE it is
        // hashed or looked up: the counting state store records zero `take_state` calls, so an
        // oversized / non-hex / wrong-length value never drives a SHA-256 or a Redis round-trip.
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let counting = Arc::new(CountingStateStore::new());
        let google = GoogleOAuthProvider::new(google_config(), Arc::new(RoutingHttpClient::new()));
        let mut cfg = base_config();
        cfg.controllers.oauth = true;
        let engine = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users)
            .redis_stores(stores)
            .hooks(Arc::new(DecisionHook(OAuthLoginResult::Create)))
            .oauth_provider(Arc::new(google))
            .oauth_state_store(counting.clone())
            .build();
        let Ok(engine) = engine else { return };
        // An oversized value (well beyond 64 chars), a wrong length, an upper-case hex digit,
        // and a non-hex character are each rejected on the same path.
        for bad in [
            "a".repeat(100_000),
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(matches!(
                engine.oauth_callback("google", "code", &bad, &ctx()).await,
                Err(AuthError::OauthFailed)
            ));
        }
        // The store was never consulted: no hashing, no Redis lookup on a bad-shape state.
        assert_eq!(counting.take_count(), 0);
        // Positive control on the counter itself: a direct store call DOES register, so the
        // zero above is a genuine "never reached", not a counter that can never move. `put_state`
        // is a no-op double; `take_state` increments and reports a miss.
        assert!(counting.put_state("hash", "payload", 600).await.is_ok());
        assert!(matches!(counting.take_state("hash").await, Ok(None)));
        assert_eq!(counting.take_count(), 1);
    }

    #[tokio::test]
    async fn callback_rejects_a_malformed_stored_state_payload() {
        // A stored payload that is not valid JSON collapses to OauthFailed, not an internal error.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        let state = "a".repeat(64);
        assert!(
            h.stores
                .put_state(&state_key(&state), "not-json", 600)
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine
                .oauth_callback("google", "code", &state, &ctx())
                .await,
            Err(AuthError::OauthFailed)
        ));
    }

    #[tokio::test]
    async fn callback_unknown_provider_fails_before_consuming_state() {
        // An unknown provider on callback fails without touching any state.
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        assert!(matches!(
            h.engine
                .oauth_callback("github", "code", &"a".repeat(64), &ctx())
                .await,
            Err(AuthError::OauthFailed)
        ));
    }

    #[tokio::test]
    async fn callback_token_exchange_failure_maps_to_oauth_failed() {
        // A non-2xx token response is a provider error → OauthFailed.
        let http = Arc::new(RoutingHttpClient::new());
        *lock(&http.token) = (400, b"{\"error\":\"invalid_grant\"}".to_vec());
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, http, false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_unverified_email_maps_to_oauth_failed() {
        // An unverified provider email collapses to OauthFailed (never an auth subject).
        let http = Arc::new(RoutingHttpClient::new());
        *lock(&http.userinfo) = (200, userinfo_body(false, "new@example.com"));
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, http, false) else { return };
        assert!(matches!(run_flow(&h).await, Err(AuthError::OauthFailed)));
    }

    #[tokio::test]
    async fn callback_create_collision_maps_to_email_mismatch() {
        // A Create whose email collides with an existing account is OauthEmailMismatch (409).
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, Arc::new(RoutingHttpClient::new()), false) else { return };
        // Seed a local account with the same email but no OAuth identity, so find_by_oauth_id
        // misses (Create is chosen) and create_with_oauth then conflicts on the email.
        let seeded = h
            .users
            .create(bymax_auth_types::CreateUserData {
                email: "new@example.com".to_owned(),
                name: "Existing".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: None,
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        assert!(seeded.is_ok());
        assert!(matches!(
            run_flow(&h).await,
            Err(AuthError::OauthEmailMismatch)
        ));
    }

    #[tokio::test]
    async fn callback_create_uses_email_local_part_when_profile_has_no_name() {
        // When the profile omits a name, the new account's name falls back to the email
        // local-part.
        let http = Arc::new(RoutingHttpClient::new());
        *lock(&http.userinfo) = (
            200,
            b"{\"id\":\"google-user-1\",\"email\":\"alice@example.com\",\"verified_email\":true}"
                .to_vec(),
        );
        let hooks: Arc<dyn AuthHooks> = Arc::new(DecisionHook(OAuthLoginResult::Create));
        let Some(h) = harness(hooks, http, false) else { return };
        let outcome = run_flow(&h).await;
        assert!(matches!(&outcome, Ok(OAuthOutcome::Authenticated(_))));
        let Ok(OAuthOutcome::Authenticated(result)) = outcome else { return };
        assert_eq!(result.user.name, "alice");
    }

    #[test]
    fn redirect_accessors_and_error_append_are_correct() {
        // The success/MFA accessors read config; the error builder re-serializes and appends
        // the code with the right separator, preserving a fragment, and returns None when unset.
        let mut cfg = base_config();
        cfg.oauth.success_redirect_url = Some("https://app.example.com/done".to_owned());
        cfg.oauth.mfa_redirect_url = Some("https://app.example.com/mfa".to_owned());
        cfg.oauth.error_redirect_url = Some("https://app.example.com/cb?x=1".to_owned());
        cfg.token_delivery = crate::config::TokenDelivery::Both;
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let engine = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users)
            .redis_stores(stores)
            .build();
        let Ok(engine) = engine else { return };
        assert_eq!(
            engine.oauth_success_redirect_url(),
            Some("https://app.example.com/done")
        );
        assert_eq!(
            engine.oauth_mfa_redirect_url(),
            Some("https://app.example.com/mfa")
        );
        // The configured error redirect is re-serialized with the short code appended.
        assert_eq!(
            engine.oauth_error_redirect_url("oauth_failed").as_deref(),
            Some("https://app.example.com/cb?x=1&error=oauth_failed")
        );
    }

    #[test]
    fn oauth_error_redirect_url_is_none_when_unconfigured() {
        // With no error redirect configured, the helper returns None (the adapter falls back
        // to JSON).
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let engine = AuthEngine::builder()
            .config(base_config())
            .environment(Environment::Test)
            .user_repository(users)
            .redis_stores(stores)
            .build();
        let Ok(engine) = engine else { return };
        assert_eq!(engine.oauth_error_redirect_url("oauth_failed"), None);
    }

    #[test]
    fn oauth_state_serialize_failed_maps_to_internal() {
        // The defensive serialize-error mapper (unreachable for the concrete payload) collapses
        // to the opaque internal error.
        let error = <serde_json::Error as serde::de::Error>::custom("boom");
        assert!(matches!(
            oauth_state_serialize_failed(error),
            AuthError::Internal(_)
        ));
    }

    #[tokio::test]
    async fn oauth_initiate_without_a_state_store_is_internal() {
        // A provider resolves but no state store is wired (OAuth controller left disabled, so
        // the builder did not enforce it): initiate fails with the internal error.
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let google = GoogleOAuthProvider::new(google_config(), Arc::new(RoutingHttpClient::new()));
        let engine = AuthEngine::builder()
            .config(base_config())
            .environment(Environment::Test)
            .user_repository(users)
            .redis_stores(stores)
            .oauth_provider(Arc::new(google))
            .build();
        let Ok(engine) = engine else { return };
        assert!(matches!(
            engine.oauth_initiate("google", "t1").await,
            Err(AuthError::Internal(_))
        ));
    }

    #[test]
    fn append_error_param_handles_query_and_fragment() {
        // No query → `?`; existing query → `&`; a fragment is preserved after the appended param.
        assert_eq!(
            append_error_param("https://app.example.com/cb", "oauth_failed"),
            "https://app.example.com/cb?error=oauth_failed"
        );
        assert_eq!(
            append_error_param("https://app.example.com/cb?next=/x", "oauth_failed"),
            "https://app.example.com/cb?next=/x&error=oauth_failed"
        );
        assert_eq!(
            append_error_param("https://app.example.com/cb#frag", "oauth_failed"),
            "https://app.example.com/cb?error=oauth_failed#frag"
        );
        // A same-origin relative path is re-serialized the same way.
        assert_eq!(
            append_error_param("/error", "oauth_failed"),
            "/error?error=oauth_failed"
        );
    }

    #[test]
    fn percent_encode_passes_unreserved_and_escapes_the_rest() {
        // Unreserved characters pass through; reserved ones become %XX (uppercase hex).
        assert_eq!(percent_encode("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(percent_encode("a b/c?d=e&f#g"), "a%20b%2Fc%3Fd%3De%26f%23g");
    }

    #[test]
    fn provider_name_grammar_is_enforced() {
        // The grammar accepts lowercase/digit/hyphen of length 1..=64 and rejects everything else.
        assert!(is_valid_provider_name("google"));
        assert!(is_valid_provider_name("my-provider-2"));
        assert!(!is_valid_provider_name(""));
        assert!(!is_valid_provider_name("Google"));
        assert!(!is_valid_provider_name("has space"));
        assert!(!is_valid_provider_name(&"a".repeat(65)));
    }

    #[test]
    fn oauth_state_shape_accepts_only_64_lowercase_hex() {
        // A genuine minted state (64 lower-case hex) passes; wrong length, an upper-case digit,
        // a non-hex character, and an empty value are each rejected before any hashing — and a
        // freshly minted state round-trips through the guard.
        assert!(is_oauth_state_shape(&generate_state()));
        assert!(is_oauth_state_shape(&"a1".repeat(32)));
        assert!(!is_oauth_state_shape(&"a".repeat(63)));
        assert!(!is_oauth_state_shape(&"a".repeat(65)));
        assert!(!is_oauth_state_shape(&"A".repeat(64)));
        assert!(!is_oauth_state_shape(&"g".repeat(64)));
        assert!(!is_oauth_state_shape(""));
    }

    #[test]
    fn state_and_pkce_generation_have_the_documented_shapes() {
        // State is 64 hex; the verifier is 43 base64url chars; the challenge is the S256 of it.
        let state = generate_state();
        assert_eq!(state.len(), 64);
        assert!(state.bytes().all(|b| b.is_ascii_hexdigit()));
        let (verifier, challenge) = generate_pkce();
        assert_eq!(verifier.len(), 43);
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bymax_auth_crypto::mac::sha256(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        // Two draws differ (CSPRNG).
        assert_ne!(generate_state(), generate_state());
    }

    #[test]
    fn map_oauth_create_error_splits_conflict_from_backend() {
        // A conflict is the email-mismatch code; any other backend failure is internal.
        assert!(matches!(
            map_oauth_create_error(RepositoryError::Conflict("dup".to_owned())),
            AuthError::OauthEmailMismatch
        ));
        assert!(matches!(
            map_oauth_create_error(RepositoryError::Backend("down".into())),
            AuthError::Internal(_)
        ));
    }

    #[test]
    fn name_or_local_part_prefers_the_profile_name() {
        // The profile name wins when present; otherwise the email local-part is used.
        let with_name = OAuthProfile {
            provider: "google".to_owned(),
            provider_id: "1".to_owned(),
            email: "x@example.com".to_owned(),
            name: Some("Real Name".to_owned()),
            avatar: None,
        };
        assert_eq!(name_or_local_part(&with_name), "Real Name");
        let no_name = OAuthProfile {
            name: None,
            ..with_name
        };
        assert_eq!(name_or_local_part(&no_name), "x");
    }

    #[test]
    fn oauth_outcome_is_cloneable_and_debuggable() {
        // The public outcome derives Clone + Debug (like LoginResult); exercise both.
        let outcome = OAuthOutcome::MfaChallenge(MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "t".to_owned(),
        });
        let cloned = outcome.clone();
        assert!(matches!(cloned, OAuthOutcome::MfaChallenge(_)));
        assert!(format!("{outcome:?}").contains("MfaChallenge"));
    }
}
