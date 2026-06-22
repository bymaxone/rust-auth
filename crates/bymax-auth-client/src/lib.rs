//! Native Rust HTTP auth client for `bymax-auth`, built on `reqwest`. It is the typed,
//! single-flight-refresh counterpart of the TypeScript `./client` for service-to-service
//! Rust consumers calling a `bymax-auth-axum` backend.
//!
//! # Surface
//!
//! [`AuthClient`] exposes the eight logical operations the TypeScript client mirrors —
//! [`AuthClient::register`], [`AuthClient::login`], [`AuthClient::logout`],
//! [`AuthClient::refresh`], [`AuthClient::me`], [`AuthClient::mfa_challenge`],
//! [`AuthClient::forgot_password`], and [`AuthClient::reset_password`] — over the shared
//! [`bymax_auth_types`] wire contracts, returning a typed [`AuthClientError`] that carries
//! the backend's `auth.*` code, HTTP status, and any structured details.
//!
//! # Token handling
//!
//! The client speaks the `bearer` delivery mode: a successful login/register/MFA-challenge
//! stores the access + refresh pair in memory, and [`AuthClient::me`] /
//! [`AuthClient::logout`] / [`AuthClient::refresh`] use it automatically. On a `401` from
//! [`AuthClient::me`], the client performs a single, serialized refresh (so concurrent
//! `401`s queue behind one rotation rather than stampeding the backend) and retries once.
//!
//! # TLS
//!
//! `reqwest` is pulled with no TLS backend (every reqwest TLS feature reintroduces a
//! workspace-banned crate). As shipped the client speaks plain HTTP; for HTTPS, supply a
//! `reqwest::Client` with a chosen TLS provider via [`AuthClient::with_http_client`].
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Mutex;

use bymax_auth_types::{
    AuthErrorCode, AuthErrorEnvelope, AuthResult, LoginResult, MfaChallengeResult, RotatedTokens,
    SafeAuthUser,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;

/// The lowest 4xx that signals an expired/invalid access token at the edge — the trigger
/// for the single-flight refresh-and-retry in [`AuthClient::me`].
const UNAUTHORIZED: u16 = 401;

/// A typed failure from the auth client: a backend `auth.*` error, an unexpected non-2xx
/// status, a transport failure, a decode failure, or a missing local session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthClientError {
    /// The backend returned a structured `auth.*` error envelope. Carries the HTTP status,
    /// the stable code, the advisory message, and any structured `details`.
    #[error("auth error {code:?} (status {status})")]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The stable `auth.*` code.
        code: AuthErrorCode,
        /// The advisory, client-facing message.
        message: String,
        /// Optional structured details (e.g. validation errors or a retry window).
        details: Option<serde_json::Value>,
    },
    /// A non-2xx response whose body was not a recognizable `auth.*` envelope.
    #[error("unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
        /// The raw response body (lossy UTF-8), for diagnostics.
        body: String,
    },
    /// The HTTP request failed before a response was received (connect/timeout/transport).
    #[error("transport error: {0}")]
    Transport(String),
    /// A 2xx body did not deserialize into the expected shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// A session-bound call (`me`/`logout`/`refresh`) was made with no stored session.
    #[error("no active session")]
    NoSession,
}

/// The in-memory access + refresh pair held after a successful authentication.
#[derive(Clone)]
struct SessionTokens {
    /// The signed HS256 access JWT (sent as the `Authorization: Bearer` credential).
    access: String,
    /// The opaque refresh token (sent on refresh).
    refresh: String,
}

/// The outcome of a login/register: a full authentication, or an MFA challenge that must be
/// completed via [`AuthClient::mfa_challenge`]. Mirrors the untagged `LoginResult` union.
#[derive(Clone, Debug)]
pub enum AuthOutcome {
    /// Authentication succeeded; the token pair is stored on the client.
    Authenticated(Box<AuthResult>),
    /// A second factor is required; submit the challenge with the temp token.
    MfaRequired(MfaChallengeResult),
}

/// Inputs for [`AuthClient::register`].
#[derive(Debug, Clone)]
pub struct RegisterRequest {
    /// The email to register.
    pub email: String,
    /// The plaintext password.
    pub password: String,
    /// The display name.
    pub name: String,
    /// The tenant scope.
    pub tenant_id: String,
}

/// Inputs for [`AuthClient::login`].
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// The login email.
    pub email: String,
    /// The plaintext password.
    pub password: String,
    /// The tenant scope.
    pub tenant_id: String,
}

/// The reset proof for [`AuthClient::reset_password`]: exactly one of the emailed token, a
/// numeric OTP, or a `verify-otp`-issued verified token. The type makes the server's
/// "exactly one of" cross-validation a compile-time choice.
#[derive(Debug, Clone)]
pub enum ResetPasswordProof {
    /// `method = "token"`: the emailed reset token.
    Token(String),
    /// `method = "otp"`: the numeric OTP.
    Otp(String),
    /// The 2-step flow: the verified token issued by `verify-otp`.
    VerifiedToken(String),
}

/// Inputs for [`AuthClient::reset_password`].
#[derive(Debug, Clone)]
pub struct ResetPasswordRequest {
    /// The account email.
    pub email: String,
    /// The new plaintext password.
    pub new_password: String,
    /// The reset proof (token / OTP / verified token).
    pub proof: ResetPasswordProof,
    /// The tenant scope.
    pub tenant_id: String,
}

/// The `{ user }`-wrapped body returned by `GET /auth/me`.
#[derive(serde::Deserialize)]
struct MeBody {
    /// The credential-free user.
    user: SafeAuthUser,
}

/// A typed, `reqwest`-backed client for a `bymax-auth-axum` backend.
pub struct AuthClient {
    /// The shared HTTP client (a cheap-to-clone connection pool).
    http: reqwest::Client,
    /// The backend origin, e.g. `https://api.example.com` (no trailing slash).
    base_url: String,
    /// The stored session token pair, set on a successful authentication.
    tokens: Mutex<Option<SessionTokens>>,
    /// Serializes refresh so concurrent `401`s share one rotation (single-flight).
    refresh_lock: tokio::sync::Mutex<()>,
}

impl AuthClient {
    /// Build a client targeting `base_url` (the backend origin; a trailing slash is
    /// trimmed) with a default `reqwest::Client`.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_http_client(base_url, reqwest::Client::new())
    }

    /// Build a client over a caller-supplied `reqwest::Client`, so a deployment can set its
    /// own timeout, proxy, connection pool, or (for HTTPS) TLS provider.
    #[must_use]
    pub fn with_http_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        Self {
            http,
            base_url,
            tokens: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether the client currently holds a session (set by a successful authentication).
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.snapshot().is_some()
    }

    /// `POST /auth/register`. On success the token pair is stored; an MFA-gated tenant
    /// returns an [`AuthOutcome::MfaRequired`] challenge instead.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError`] on a backend error, a transport failure, or a body that
    /// does not deserialize.
    pub async fn register(&self, input: &RegisterRequest) -> Result<AuthOutcome, AuthClientError> {
        let body = serde_json::json!({
            "email": input.email,
            "password": input.password,
            "name": input.name,
            "tenantId": input.tenant_id,
        });
        let request = self.post("/auth/register").body(body.to_string());
        self.complete_login(request).await
    }

    /// `POST /auth/login`. Returns a full authentication or an MFA challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError`] on a backend error, a transport failure, or a body that
    /// does not deserialize.
    pub async fn login(&self, input: &LoginRequest) -> Result<AuthOutcome, AuthClientError> {
        let body = serde_json::json!({
            "email": input.email,
            "password": input.password,
            "tenantId": input.tenant_id,
        });
        let request = self.post("/auth/login").body(body.to_string());
        self.complete_login(request).await
    }

    /// `POST /auth/mfa/challenge`. Completes a pending MFA challenge with the temp token plus
    /// a TOTP or recovery code; on success the token pair is stored.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError`] on a backend error, a transport failure, or a body that
    /// does not deserialize.
    pub async fn mfa_challenge(
        &self,
        mfa_temp_token: &str,
        code: &str,
    ) -> Result<AuthResult, AuthClientError> {
        let body = serde_json::json!({ "mfaTempToken": mfa_temp_token, "code": code });
        let request = self.post("/auth/mfa/challenge").body(body.to_string());
        let result: AuthResult = self.send_json(request).await?;
        self.store_tokens(&result.access_token, &result.refresh_token);
        Ok(result)
    }

    /// `GET /auth/me`. Uses the stored access token; on a `401` it performs one serialized
    /// refresh and retries.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError::NoSession`] when no session is stored, or another
    /// [`AuthClientError`] on a backend/transport/decode failure (including a refresh that
    /// itself fails).
    pub async fn me(&self) -> Result<SafeAuthUser, AuthClientError> {
        let access = self.access_token().ok_or(AuthClientError::NoSession)?;
        match self.fetch_me(&access).await {
            Err(AuthClientError::Api { status, .. }) if status == UNAUTHORIZED => {
                // Single-flight refresh: serialize so concurrent 401s share one rotation,
                // passing the access token that just failed so a waiter that finds the
                // session already rotated skips a redundant refresh.
                self.refresh_single_flight(&access).await?;
                let access = self.access_token().ok_or(AuthClientError::NoSession)?;
                self.fetch_me(&access).await
            }
            other => other,
        }
    }

    /// `POST /auth/refresh`. Rotates the stored refresh token into a fresh pair and stores it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError::NoSession`] when no session is stored, or another
    /// [`AuthClientError`] on a backend/transport/decode failure.
    pub async fn refresh(&self) -> Result<RotatedTokens, AuthClientError> {
        let refresh = self.refresh_token().ok_or(AuthClientError::NoSession)?;
        let body = serde_json::json!({ "refreshToken": refresh });
        let request = self.post("/auth/refresh").body(body.to_string());
        let tokens: RotatedTokens = self.send_json(request).await?;
        self.store_tokens(&tokens.access_token, &tokens.refresh_token);
        Ok(tokens)
    }

    /// `POST /auth/logout`. Revokes the current session and clears the stored tokens.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError::NoSession`] when no session is stored, or another
    /// [`AuthClientError`] on a backend/transport failure.
    pub async fn logout(&self) -> Result<(), AuthClientError> {
        let access = self.access_token().ok_or(AuthClientError::NoSession)?;
        let request = self
            .post("/auth/logout")
            .header(AUTHORIZATION, format!("Bearer {access}"));
        self.send_no_content(request).await?;
        self.clear_tokens();
        Ok(())
    }

    /// `POST /auth/password/forgot-password`. Anti-enumeration: the same outcome regardless
    /// of whether the account exists.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError`] on a backend or transport failure.
    pub async fn forgot_password(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> Result<(), AuthClientError> {
        let body = serde_json::json!({ "email": email, "tenantId": tenant_id });
        let request = self
            .post("/auth/password/forgot-password")
            .body(body.to_string());
        self.send_no_content(request).await
    }

    /// `POST /auth/password/reset-password`. Completes a reset with exactly one proof
    /// (token / OTP / verified token), lifted into the [`ResetPasswordProof`] type.
    ///
    /// # Errors
    ///
    /// Returns [`AuthClientError`] on a backend or transport failure.
    pub async fn reset_password(
        &self,
        input: &ResetPasswordRequest,
    ) -> Result<(), AuthClientError> {
        let mut body = serde_json::json!({
            "email": input.email,
            "newPassword": input.new_password,
            "tenantId": input.tenant_id,
        });
        let (key, value) = match &input.proof {
            ResetPasswordProof::Token(token) => ("token", token),
            ResetPasswordProof::Otp(otp) => ("otp", otp),
            ResetPasswordProof::VerifiedToken(token) => ("verifiedToken", token),
        };
        body[key] = serde_json::Value::String(value.clone());
        let request = self
            .post("/auth/password/reset-password")
            .body(body.to_string());
        self.send_no_content(request).await
    }

    // ---- internal helpers --------------------------------------------------------------

    /// Build a JSON `POST` request to `path` under the base URL.
    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{path}", self.base_url))
            .header(CONTENT_TYPE, "application/json")
    }

    /// Send a login/register request, parse the untagged `LoginResult`, and store tokens on
    /// a full authentication.
    async fn complete_login(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<AuthOutcome, AuthClientError> {
        let result: LoginResult = self.send_json(request).await?;
        match result {
            LoginResult::Success(auth) => {
                self.store_tokens(&auth.access_token, &auth.refresh_token);
                Ok(AuthOutcome::Authenticated(auth))
            }
            LoginResult::MfaChallenge(challenge) => Ok(AuthOutcome::MfaRequired(challenge)),
        }
    }

    /// `GET /auth/me` with the given bearer access token, parsing the `{ user }` wrapper.
    async fn fetch_me(&self, access: &str) -> Result<SafeAuthUser, AuthClientError> {
        let request = self
            .http
            .get(format!("{}/auth/me", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {access}"));
        let body: MeBody = self.send_json(request).await?;
        Ok(body.user)
    }

    /// Refresh under the single-flight lock so concurrent callers share one rotation. The
    /// `stale_access` is the access token the caller saw fail; after acquiring the lock, if an
    /// earlier waiter has already rotated the session, the stored access token differs from
    /// `stale_access`, so this skips the redundant refresh and reuses the fresh token. With N
    /// concurrent `401`s on the same token this performs exactly one refresh.
    async fn refresh_single_flight(&self, stale_access: &str) -> Result<(), AuthClientError> {
        let _guard = self.refresh_lock.lock().await;
        match self.access_token() {
            Some(current) if current != stale_access => Ok(()),
            _ => self.refresh().await.map(|_| ()),
        }
    }

    /// Send a request expecting a JSON 2xx body of type `T`; map a non-2xx to the typed
    /// error and a malformed 2xx body to [`AuthClientError::Decode`].
    async fn send_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, AuthClientError> {
        let (status, bytes) = self.send(request).await?;
        if is_success(status) {
            serde_json::from_slice(&bytes).map_err(decode_error)
        } else {
            Err(parse_api_error(status, &bytes))
        }
    }

    /// Send a request expecting only a 2xx (no body needed); map a non-2xx to the typed error.
    async fn send_no_content(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<(), AuthClientError> {
        let (status, bytes) = self.send(request).await?;
        if is_success(status) {
            Ok(())
        } else {
            Err(parse_api_error(status, &bytes))
        }
    }

    /// Execute a request, returning the status and the raw body bytes, or a transport error.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<(u16, Vec<u8>), AuthClientError> {
        let response = request.send().await.map_err(transport_error)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(transport_error)?;
        Ok((status, bytes.to_vec()))
    }

    /// Lock the token state, recovering the guard if a prior holder panicked. The critical
    /// sections here only clone/assign small `String`s and never panic, so poison is
    /// unreachable in practice; recovering keeps the lock infallible without a dead arm.
    fn locked(&self) -> std::sync::MutexGuard<'_, Option<SessionTokens>> {
        self.tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A clone of the stored tokens, if any.
    fn snapshot(&self) -> Option<SessionTokens> {
        self.locked().clone()
    }

    /// The stored access token, if a session is held.
    fn access_token(&self) -> Option<String> {
        self.snapshot().map(|tokens| tokens.access)
    }

    /// The stored refresh token, if a session is held.
    fn refresh_token(&self) -> Option<String> {
        self.snapshot().map(|tokens| tokens.refresh)
    }

    /// Replace the stored token pair (after login/register/refresh/MFA success).
    fn store_tokens(&self, access: &str, refresh: &str) {
        *self.locked() = Some(SessionTokens {
            access: access.to_owned(),
            refresh: refresh.to_owned(),
        });
    }

    /// Drop the stored token pair (on logout).
    fn clear_tokens(&self) {
        *self.locked() = None;
    }
}

/// Whether a status code is a 2xx success.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Map a JSON deserialization failure on a 2xx body to [`AuthClientError::Decode`]. A free
/// function (not a per-`T` closure) so the decode path is a single covered function across
/// every response type `send_json` is instantiated for.
fn decode_error(error: serde_json::Error) -> AuthClientError {
    AuthClientError::Decode(error.to_string())
}

/// Map a `reqwest` transport failure (connect/timeout/body-read) to
/// [`AuthClientError::Transport`]. A free function shared by both transport call sites, so
/// the mapping is a single covered function rather than two closures.
fn transport_error(error: reqwest::Error) -> AuthClientError {
    AuthClientError::Transport(error.to_string())
}

/// Map a non-2xx response into a typed error: the `auth.*` envelope when the body parses,
/// otherwise an [`AuthClientError::UnexpectedStatus`] carrying the raw body.
fn parse_api_error(status: u16, bytes: &[u8]) -> AuthClientError {
    match serde_json::from_slice::<AuthErrorEnvelope>(bytes) {
        Ok(envelope) => AuthClientError::Api {
            status,
            code: envelope.error.code,
            message: envelope.error.message,
            details: envelope.error.details,
        },
        Err(_) => AuthClientError::UnexpectedStatus {
            status,
            body: String::from_utf8_lossy(bytes).into_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Build a raw HTTP/1.1 response with `Connection: close` so each request opens a fresh
    /// connection (the mock server serves one queued response per connection).
    fn response(status: u16, reason: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// Bind a loopback listener and serve `responses` in order — one per accepted connection
    /// — then return the base URL and the server task handle. A `None` queue entry drops the
    /// connection without responding, simulating a transport failure.
    async fn serve(responses: Vec<Option<Vec<u8>>>) -> Option<(String, JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        let handle = tokio::spawn(async move {
            for reply in responses {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                if let Some(bytes) = reply {
                    let _ = socket.write_all(&bytes).await;
                    let _ = socket.flush().await;
                }
            }
        });
        Some((format!("http://{addr}"), handle))
    }

    /// Wire a client to a mock server serving `responses`, run `body` against it, then await
    /// the server task. The one bind-skip lives here on a single line (covered), so the
    /// individual tests never carry their own multi-line skip guard.
    async fn with_server<F, Fut>(responses: Vec<Option<Vec<u8>>>, body: F)
    where
        F: FnOnce(AuthClient) -> Fut,
        Fut: Future<Output = ()>,
    {
        let Some((url, handle)) = serve(responses).await else { return };
        body(AuthClient::new(url)).await;
        let _ = handle.await;
    }

    /// Route a request for the single-flight concurrency test by inspecting the request line
    /// and bearer token: login seeds the session, the refresh `POST` bumps the shared counter
    /// and rotates `acc` → `acc2`, a `me` call carrying the fresh token succeeds, and a `me`
    /// call still carrying the stale token gets a `401`.
    fn route(request: &str, refresh_count: &AtomicUsize) -> Vec<u8> {
        if request.contains("POST /auth/login") {
            return response(200, "OK", &auth_body("acc", "ref"));
        }
        if request.contains("POST /auth/refresh") {
            refresh_count.fetch_add(1, Ordering::SeqCst);
            return response(200, "OK", r#"{"accessToken":"acc2","refreshToken":"ref2"}"#);
        }
        if request.contains("Bearer acc2") {
            return response(200, "OK", &me_body());
        }
        response(
            401,
            "Unauthorized",
            &error_body("auth.token_expired", "stale"),
        )
    }

    /// Bind a loopback listener that answers each request via [`route`] (counting refreshes)
    /// until `shutdown` fires. Unlike [`serve`], it is content-aware, so concurrent requests
    /// need no fixed response ordering. The graceful shutdown lets the task loop end normally.
    async fn serve_concurrent(
        refresh_count: Arc<AtomicUsize>,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Option<(String, JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown => break,
                    accepted = listener.accept() => {
                        let Ok((mut socket, _)) = accepted else { continue };
                        let mut buf = [0u8; 8192];
                        let Ok(n) = socket.read(&mut buf).await else { continue };
                        let reply = route(&String::from_utf8_lossy(&buf[..n]), &refresh_count);
                        let _ = socket.write_all(&reply).await;
                        let _ = socket.flush().await;
                    }
                }
            }
        });
        Some((format!("http://{addr}"), handle))
    }

    /// Wire a client to a content-aware mock server (sharing `refresh_count`), run `body`, then
    /// signal the server to stop and await its clean exit.
    async fn with_server_concurrent<F, Fut>(refresh_count: Arc<AtomicUsize>, body: F)
    where
        F: FnOnce(AuthClient) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let Some((url, handle)) = serve_concurrent(refresh_count, rx).await else { return };
        body(AuthClient::new(url)).await;
        let _ = tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn concurrent_401s_trigger_exactly_one_refresh() {
        // Three me() calls race on the same stale token: all 401, all queue behind the
        // single-flight lock, and exactly one rotation happens (the rest reuse the new token).
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&refresh_count);
        with_server_concurrent(refresh_count, |client| async move {
            let _ = client.login(&login_input()).await;
            let (a, b, c) = tokio::join!(client.me(), client.me(), client.me());
            assert!(a.is_ok());
            assert!(b.is_ok());
            assert!(c.is_ok());
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        })
        .await;
    }

    /// A success auth body (bearer mode): user + token pair.
    fn auth_body(access: &str, refresh: &str) -> String {
        format!(
            r#"{{"user":{{"id":"u1","email":"u@e.com","name":"U","role":"USER","status":"ACTIVE","tenantId":"t1","emailVerified":true,"mfaEnabled":false,"lastLoginAt":null,"createdAt":"2020-01-01T00:00:00Z"}},"accessToken":"{access}","refreshToken":"{refresh}"}}"#
        )
    }

    /// The `{ user }` body returned by `me`.
    fn me_body() -> String {
        r#"{"user":{"id":"u1","email":"u@e.com","name":"U","role":"USER","status":"ACTIVE","tenantId":"t1","emailVerified":true,"mfaEnabled":false,"lastLoginAt":null,"createdAt":"2020-01-01T00:00:00Z"}}"#.to_owned()
    }

    /// An `auth.*` error envelope body.
    fn error_body(code: &str, message: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#)
    }

    fn register_input() -> RegisterRequest {
        RegisterRequest {
            email: "u@e.com".to_owned(),
            password: "password123".to_owned(),
            name: "U".to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    fn login_input() -> LoginRequest {
        LoginRequest {
            email: "u@e.com".to_owned(),
            password: "password123".to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    #[tokio::test]
    async fn register_stores_the_token_pair_on_success() {
        // A 201 auth body authenticates and the client retains the session.
        let plan = vec![Some(response(201, "Created", &auth_body("acc", "ref")))];
        with_server(plan, |client| async move {
            let outcome = client.register(&register_input()).await;
            assert!(matches!(outcome, Ok(AuthOutcome::Authenticated(_))));
            assert!(client.has_session());
            assert_eq!(client.access_token().as_deref(), Some("acc"));
        })
        .await;
    }

    #[tokio::test]
    async fn login_returns_an_mfa_challenge() {
        // A challenge body maps to MfaRequired and stores no session.
        let challenge = r#"{"mfaRequired":true,"mfaTempToken":"temp.jwt"}"#;
        let plan = vec![Some(response(200, "OK", challenge))];
        with_server(plan, |client| async move {
            let outcome = client.login(&login_input()).await;
            assert!(
                matches!(outcome, Ok(AuthOutcome::MfaRequired(c)) if c.mfa_temp_token == "temp.jwt")
            );
            assert!(!client.has_session());
        })
        .await;
    }

    #[tokio::test]
    async fn login_maps_a_backend_error_envelope() {
        // A 401 with an auth.* envelope becomes a typed Api error carrying the code.
        let body = error_body("auth.invalid_credentials", "bad creds");
        let plan = vec![Some(response(401, "Unauthorized", &body))];
        with_server(plan, |client| async move {
            let error = client.login(&login_input()).await;
            assert!(matches!(
                error,
                Err(AuthClientError::Api {
                    status: 401,
                    code: AuthErrorCode::InvalidCredentials,
                    ..
                })
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn a_non_envelope_error_body_is_unexpected_status() {
        // A 500 whose body is not an auth.* envelope becomes UnexpectedStatus.
        let plan = vec![Some(response(500, "Server Error", "oops"))];
        with_server(plan, |client| async move {
            let error = client.login(&login_input()).await;
            assert!(matches!(
                error,
                Err(AuthClientError::UnexpectedStatus { status: 500, .. })
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn a_malformed_success_body_is_a_decode_error() {
        // A 200 whose body is not a LoginResult fails as Decode.
        let plan = vec![Some(response(200, "OK", "not json"))];
        with_server(plan, |client| async move {
            assert!(matches!(
                client.login(&login_input()).await,
                Err(AuthClientError::Decode(_))
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn a_dropped_connection_is_a_transport_error() {
        // The server drops without responding → transport error.
        with_server(vec![None], |client| async move {
            assert!(matches!(
                client.login(&login_input()).await,
                Err(AuthClientError::Transport(_))
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn me_uses_the_stored_token_and_succeeds() {
        // After login, me() returns the user via the stored access token.
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(200, "OK", &me_body())),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            let user = client.me().await;
            assert!(matches!(user, Ok(u) if u.email == "u@e.com"));
        })
        .await;
    }

    #[tokio::test]
    async fn me_without_a_session_is_no_session() {
        // No login: the session-bound calls report NoSession without a request.
        let client = AuthClient::new("http://127.0.0.1:1");
        assert!(matches!(client.me().await, Err(AuthClientError::NoSession)));
        assert!(matches!(
            client.logout().await,
            Err(AuthClientError::NoSession)
        ));
        assert!(matches!(
            client.refresh().await,
            Err(AuthClientError::NoSession)
        ));
    }

    #[tokio::test]
    async fn me_refreshes_once_on_401_then_retries() {
        // me() → 401, refresh → 200 (new pair), me() retry → 200. The single-flight path.
        let rotated = r#"{"accessToken":"acc2","refreshToken":"ref2"}"#;
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(
                401,
                "Unauthorized",
                &error_body("auth.token_expired", "stale"),
            )),
            Some(response(200, "OK", rotated)),
            Some(response(200, "OK", &me_body())),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            let user = client.me().await;
            assert!(matches!(user, Ok(u) if u.email == "u@e.com"));
            // The rotation updated the stored access token.
            assert_eq!(client.access_token().as_deref(), Some("acc2"));
        })
        .await;
    }

    #[tokio::test]
    async fn me_propagates_a_failed_refresh() {
        // me() → 401, then refresh itself 401s → the error propagates (no second me()).
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(
                401,
                "Unauthorized",
                &error_body("auth.token_expired", "stale"),
            )),
            Some(response(
                401,
                "Unauthorized",
                &error_body("auth.refresh_token_invalid", "gone"),
            )),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            assert!(matches!(
                client.me().await,
                Err(AuthClientError::Api {
                    code: AuthErrorCode::RefreshTokenInvalid,
                    ..
                })
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn me_propagates_a_non_401_error() {
        // A 403 from me() is returned as-is (no refresh attempt).
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(
                403,
                "Forbidden",
                &error_body("auth.forbidden", "no"),
            )),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            assert!(matches!(
                client.me().await,
                Err(AuthClientError::Api {
                    code: AuthErrorCode::Forbidden,
                    ..
                })
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn refresh_rotates_and_stores_the_new_pair() {
        // refresh() returns the rotated pair and updates the stored tokens.
        let rotated = r#"{"accessToken":"acc2","refreshToken":"ref2"}"#;
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(200, "OK", rotated)),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            let tokens = client.refresh().await;
            assert!(matches!(tokens, Ok(t) if t.access_token == "acc2"));
            assert_eq!(client.refresh_token().as_deref(), Some("ref2"));
        })
        .await;
    }

    #[tokio::test]
    async fn logout_clears_the_session() {
        // logout() succeeds on a 204 and drops the stored tokens.
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(204, "No Content", "")),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            assert!(client.logout().await.is_ok());
            assert!(!client.has_session());
        })
        .await;
    }

    #[tokio::test]
    async fn logout_maps_a_backend_error() {
        // A non-2xx on a no-content endpoint (logout) is mapped to the typed Api error.
        let body = error_body("auth.token_invalid", "nope");
        let plan = vec![
            Some(response(200, "OK", &auth_body("acc", "ref"))),
            Some(response(401, "Unauthorized", &body)),
        ];
        with_server(plan, |client| async move {
            let _ = client.login(&login_input()).await;
            assert!(matches!(
                client.logout().await,
                Err(AuthClientError::Api {
                    code: AuthErrorCode::TokenInvalid,
                    ..
                })
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn mfa_challenge_authenticates_and_stores_tokens() {
        // The challenge exchange returns an AuthResult and stores the session.
        let plan = vec![Some(response(200, "OK", &auth_body("macc", "mref")))];
        with_server(plan, |client| async move {
            let result = client.mfa_challenge("temp.jwt", "123456").await;
            assert!(matches!(result, Ok(r) if r.access_token == "macc"));
            assert!(client.has_session());
        })
        .await;
    }

    #[tokio::test]
    async fn forgot_password_succeeds_on_2xx() {
        // forgot-password returns 200 `{}`.
        let plan = vec![Some(response(200, "OK", "{}"))];
        with_server(plan, |client| async move {
            assert!(client.forgot_password("u@e.com", "t1").await.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn reset_password_sends_each_proof_variant() {
        // Each proof variant (token / otp / verified) completes on a 204.
        let proofs = [
            ResetPasswordProof::Token("tok".to_owned()),
            ResetPasswordProof::Otp("123456".to_owned()),
            ResetPasswordProof::VerifiedToken("vt".to_owned()),
        ];
        for proof in proofs {
            let plan = vec![Some(response(204, "No Content", ""))];
            with_server(plan, |client| async move {
                let input = ResetPasswordRequest {
                    email: "u@e.com".to_owned(),
                    new_password: "newpassword123".to_owned(),
                    proof,
                    tenant_id: "t1".to_owned(),
                };
                assert!(client.reset_password(&input).await.is_ok());
            })
            .await;
        }
    }

    #[test]
    fn with_http_client_trims_the_trailing_slash() {
        // A trailing slash on the base URL is normalized away.
        let client = AuthClient::with_http_client("http://x/", reqwest::Client::new());
        assert_eq!(client.base_url, "http://x");
        assert!(!client.has_session());
    }

    #[test]
    fn error_display_covers_each_variant() {
        // The Display strings are stable diagnostics, never the client-facing message.
        assert!(
            AuthClientError::Api {
                status: 401,
                code: AuthErrorCode::TokenInvalid,
                message: "m".to_owned(),
                details: None,
            }
            .to_string()
            .contains("401")
        );
        assert!(
            AuthClientError::UnexpectedStatus {
                status: 500,
                body: "b".to_owned()
            }
            .to_string()
            .contains("500")
        );
        assert!(
            AuthClientError::Transport("x".to_owned())
                .to_string()
                .contains("transport")
        );
        assert!(
            AuthClientError::Decode("x".to_owned())
                .to_string()
                .contains("decode")
        );
        assert_eq!(AuthClientError::NoSession.to_string(), "no active session");
    }
}
