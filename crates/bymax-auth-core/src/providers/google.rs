//! The built-in Google OAuth provider (§11.2), implemented over an injected
//! [`HttpClient`](crate::traits::HttpClient) — no `passport`, no third-party OAuth crate, and
//! no direct HTTP dependency. Endpoints, scopes, and the verified-email gate reproduce the
//! nest-auth Google plugin exactly. The `access_token`, `client_secret`, and any
//! token-endpoint payload are never logged.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::config::GoogleOAuthConfig;
use crate::services::oauth::percent_encode;
use crate::traits::{
    HttpClient, HttpError, HttpMethod, HttpRequest, OAuthProfile, OAuthProvider,
    OAuthProviderError, OAuthTokens,
};

/// Google's authorization endpoint (the user-facing consent screen).
const AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Google's token endpoint (authorization-code exchange).
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Google's userinfo endpoint (profile fetch).
const USERINFO_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

/// The default OpenID Connect scopes when the config supplies none.
const DEFAULT_SCOPES: [&str; 3] = ["openid", "email", "profile"];

/// The built-in Google [`OAuthProvider`]. Holds an `Arc<dyn HttpClient>` and issues its
/// token-exchange `POST` and userinfo `GET` through it; it never constructs a concrete client.
pub struct GoogleOAuthProvider {
    client_id: String,
    /// Never logged; redacted in `Debug` and zeroized on drop by [`SecretString`].
    client_secret: SecretString,
    callback_url: String,
    scope: Vec<String>,
    http: Arc<dyn HttpClient>,
}

impl GoogleOAuthProvider {
    /// Build the provider from its credentials and the injected transport. An empty configured
    /// scope falls back to the canonical OpenID Connect scopes (`openid email profile`).
    #[must_use]
    pub fn new(config: GoogleOAuthConfig, http: Arc<dyn HttpClient>) -> Self {
        let scope = if config.scope.is_empty() {
            DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect()
        } else {
            config.scope
        };
        Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            callback_url: config.callback_url,
            scope,
            http,
        }
    }

    /// Send a request through the injected transport, mapping a transport failure to the
    /// provider's [`OAuthProviderError::Transport`] (the engine then collapses it to the
    /// opaque `oauth_failed`).
    async fn send(
        &self,
        request: HttpRequest,
    ) -> Result<crate::traits::HttpResponse, OAuthProviderError> {
        self.http.send(request).await.map_err(map_http_error)
    }
}

#[async_trait::async_trait]
impl OAuthProvider for GoogleOAuthProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorize_url(&self, state: &str, code_challenge: Option<&str>) -> String {
        let scope = self.scope.join(" ");
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.callback_url.as_str()),
            ("scope", scope.as_str()),
            ("state", state),
        ];
        // PKCE: expose only the S256 challenge, never the verifier.
        if let Some(challenge) = code_challenge {
            pairs.push(("code_challenge", challenge));
            pairs.push(("code_challenge_method", "S256"));
        }
        format!("{AUTHORIZE_ENDPOINT}?{}", form_urlencode(&pairs))
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuthTokens, OAuthProviderError> {
        let secret = self.client_secret.expose_secret();
        let mut pairs = vec![
            ("code", code),
            ("client_id", self.client_id.as_str()),
            ("client_secret", secret),
            ("redirect_uri", self.callback_url.as_str()),
            ("grant_type", "authorization_code"),
        ];
        // Forward the PKCE verifier when the flow was initiated with PKCE.
        if let Some(verifier) = code_verifier {
            pairs.push(("code_verifier", verifier));
        }
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: TOKEN_ENDPOINT.to_owned(),
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
            body: Some(form_urlencode(&pairs).into_bytes()),
        };
        let response = self.send(request).await?;
        if !is_success(response.status) {
            return Err(OAuthProviderError::Http(response.status));
        }
        // Use a static decode label so the token payload never reaches a log line.
        let parsed: GoogleTokenResponse = serde_json::from_slice(&response.body)
            .map_err(|_| OAuthProviderError::Decode("token response".to_owned()))?;
        // The access token is only used as a Bearer credential once the type is confirmed.
        if !parsed.token_type.eq_ignore_ascii_case("bearer") {
            return Err(OAuthProviderError::UnexpectedTokenType(parsed.token_type));
        }
        Ok(OAuthTokens {
            access_token: parsed.access_token,
            token_type: parsed.token_type,
            expires_in: parsed.expires_in,
            scope: parsed.scope,
            id_token: parsed.id_token,
            refresh_token: parsed.refresh_token,
        })
    }

    async fn fetch_profile(&self, access_token: &str) -> Result<OAuthProfile, OAuthProviderError> {
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: USERINFO_ENDPOINT.to_owned(),
            headers: vec![
                ("authorization".to_owned(), format!("Bearer {access_token}")),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
            body: None,
        };
        let response = self.send(request).await?;
        if !is_success(response.status) {
            return Err(OAuthProviderError::Http(response.status));
        }
        let parsed: GoogleUserInfo = serde_json::from_slice(&response.body)
            .map_err(|_| OAuthProviderError::Decode("userinfo response".to_owned()))?;
        // Reject unless Google positively confirms the email is verified, so a non-standard or
        // changed response can never promote an unverified account to a trusted subject.
        if parsed.verified_email != Some(true) {
            return Err(OAuthProviderError::EmailNotVerified);
        }
        Ok(OAuthProfile {
            provider: "google".to_owned(),
            provider_id: parsed.id,
            email: parsed.email,
            name: parsed.name,
            avatar: parsed.picture,
        })
    }
}

/// Whether an HTTP status is a 2xx success.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Map a transport failure to the provider error. The [`HttpError`] `Display` carries no
/// secret or request body, so it is safe to retain for monitoring.
fn map_http_error(error: HttpError) -> OAuthProviderError {
    OAuthProviderError::Transport(error.to_string())
}

/// Encode `pairs` as `application/x-www-form-urlencoded` using strict RFC 3986 percent-encoding
/// (space → `%20`), suitable for both the authorize query string and the token POST body.
fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&percent_encode(key));
        out.push('=');
        out.push_str(&percent_encode(value));
    }
    out
}

/// The token-endpoint response. Only `access_token` and `token_type` are required; the rest
/// are retained for observability and never logged.
#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// The userinfo response (the subset the engine normalizes).
#[derive(Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    #[serde(default)]
    verified_email: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::HttpResponse;
    use std::sync::Mutex;
    use std::sync::PoisonError;

    /// Acquire a guard, recovering from poisoning.
    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A transport that captures the request and returns a canned `(status, body)` or a
    /// transport failure.
    struct CapturingClient {
        status: u16,
        body: Vec<u8>,
        fail: bool,
        captured: Mutex<Vec<HttpRequest>>,
    }

    impl CapturingClient {
        fn ok(status: u16, body: Vec<u8>) -> Self {
            Self {
                status,
                body,
                fail: false,
                captured: Mutex::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                status: 0,
                body: Vec::new(),
                fail: true,
                captured: Mutex::new(Vec::new()),
            }
        }

        fn last_body(&self) -> Option<String> {
            lock(&self.captured).last().and_then(|req| {
                req.body
                    .as_ref()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            })
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for CapturingClient {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
            lock(&self.captured).push(req);
            if self.fail {
                return Err(HttpError::Transport("boom".to_owned()));
            }
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn config() -> GoogleOAuthConfig {
        GoogleOAuthConfig {
            client_id: "cid".to_owned(),
            client_secret: SecretString::from("csecret".to_owned()),
            callback_url: "https://app.example.com/cb".to_owned(),
            scope: vec!["openid".to_owned(), "email".to_owned()],
        }
    }

    fn provider(client: Arc<dyn HttpClient>) -> GoogleOAuthProvider {
        GoogleOAuthProvider::new(config(), client)
    }

    #[test]
    fn new_defaults_the_scope_when_empty() {
        // An empty configured scope falls back to the canonical OpenID Connect scopes.
        let mut cfg = config();
        cfg.scope = Vec::new();
        let p = GoogleOAuthProvider::new(cfg, Arc::new(CapturingClient::ok(200, Vec::new())));
        let url = p.authorize_url("st", None);
        assert!(url.contains("scope=openid%20email%20profile"));
    }

    #[test]
    fn authorize_url_includes_state_pkce_and_encoded_redirect() {
        // The URL carries the fixed params, the percent-encoded redirect, and the S256
        // challenge when one is supplied.
        let p = provider(Arc::new(CapturingClient::ok(200, Vec::new())));
        let with = p.authorize_url("abc", Some("chal"));
        assert!(with.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(with.contains("response_type=code"));
        assert!(with.contains("client_id=cid"));
        assert!(with.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"));
        assert!(with.contains("state=abc"));
        assert!(with.contains("code_challenge=chal"));
        assert!(with.contains("code_challenge_method=S256"));
        // Without a challenge the PKCE params are absent.
        let without = p.authorize_url("abc", None);
        assert!(!without.contains("code_challenge"));
        assert_eq!(p.name(), "google");
    }

    #[tokio::test]
    async fn exchange_code_forwards_pkce_and_returns_tokens() {
        // A 2xx bearer response yields tokens; the POST body carries the verifier and grant.
        let body = b"{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":10,\
            \"scope\":\"openid\",\"id_token\":\"id\",\"refresh_token\":\"rt\"}"
            .to_vec();
        let client = Arc::new(CapturingClient::ok(200, body));
        let p = provider(client.clone());
        let tokens = p.exchange_code("the-code", Some("the-verifier")).await;
        assert!(matches!(&tokens, Ok(t) if t.access_token == "at" && t.expires_in == Some(10)));
        let Some(sent) = client.last_body() else { return };
        assert!(sent.contains("code=the-code"));
        assert!(sent.contains("client_secret=csecret"));
        assert!(sent.contains("grant_type=authorization_code"));
        assert!(sent.contains("code_verifier=the-verifier"));
    }

    #[tokio::test]
    async fn exchange_code_omits_verifier_when_absent() {
        // Without PKCE the body has no code_verifier field.
        let body = b"{\"access_token\":\"at\",\"token_type\":\"bearer\"}".to_vec();
        let client = Arc::new(CapturingClient::ok(200, body));
        let p = provider(client.clone());
        assert!(p.exchange_code("c", None).await.is_ok());
        let Some(sent) = client.last_body() else { return };
        assert!(!sent.contains("code_verifier"));
    }

    #[tokio::test]
    async fn exchange_code_maps_non_2xx_unexpected_type_decode_and_transport() {
        // Each failure mode maps to its provider error variant.
        let http = provider(Arc::new(CapturingClient::ok(400, b"{}".to_vec())))
            .exchange_code("c", None)
            .await;
        assert!(matches!(http, Err(OAuthProviderError::Http(400))));

        let mac = provider(Arc::new(CapturingClient::ok(
            200,
            b"{\"access_token\":\"at\",\"token_type\":\"mac\"}".to_vec(),
        )))
        .exchange_code("c", None)
        .await;
        assert!(matches!(mac, Err(OAuthProviderError::UnexpectedTokenType(t)) if t == "mac"));

        let decode = provider(Arc::new(CapturingClient::ok(200, b"not-json".to_vec())))
            .exchange_code("c", None)
            .await;
        assert!(matches!(decode, Err(OAuthProviderError::Decode(_))));

        let transport = provider(Arc::new(CapturingClient::failing()))
            .exchange_code("c", None)
            .await;
        assert!(matches!(transport, Err(OAuthProviderError::Transport(_))));
    }

    #[tokio::test]
    async fn fetch_profile_maps_a_verified_profile() {
        // A verified userinfo response maps id/email/name/picture into the normalized profile.
        let body = b"{\"id\":\"gid\",\"email\":\"u@example.com\",\"verified_email\":true,\
            \"name\":\"U\",\"picture\":\"https://pic\"}"
            .to_vec();
        let client = Arc::new(CapturingClient::ok(200, body));
        let p = provider(client.clone());
        let profile = p.fetch_profile("tok").await;
        assert!(matches!(&profile, Ok(prof)
            if prof.provider == "google"
            && prof.provider_id == "gid"
            && prof.email == "u@example.com"
            && prof.name.as_deref() == Some("U")
            && prof.avatar.as_deref() == Some("https://pic")));
        // The Authorization header carried the bearer token.
        let Some(req) = lock(&client.captured).last().cloned() else { return };
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "authorization" && v == "Bearer tok")
        );
    }

    #[tokio::test]
    async fn fetch_profile_rejects_unverified_absent_non_2xx_decode_and_transport() {
        // verified_email false or absent → EmailNotVerified; the transport/HTTP/decode
        // failures map to their variants.
        let unverified = provider(Arc::new(CapturingClient::ok(
            200,
            b"{\"id\":\"g\",\"email\":\"u@e.com\",\"verified_email\":false}".to_vec(),
        )))
        .fetch_profile("t")
        .await;
        assert!(matches!(
            unverified,
            Err(OAuthProviderError::EmailNotVerified)
        ));

        let absent = provider(Arc::new(CapturingClient::ok(
            200,
            b"{\"id\":\"g\",\"email\":\"u@e.com\"}".to_vec(),
        )))
        .fetch_profile("t")
        .await;
        assert!(matches!(absent, Err(OAuthProviderError::EmailNotVerified)));

        let http = provider(Arc::new(CapturingClient::ok(500, Vec::new())))
            .fetch_profile("t")
            .await;
        assert!(matches!(http, Err(OAuthProviderError::Http(500))));

        let decode = provider(Arc::new(CapturingClient::ok(200, b"nope".to_vec())))
            .fetch_profile("t")
            .await;
        assert!(matches!(decode, Err(OAuthProviderError::Decode(_))));

        let transport = provider(Arc::new(CapturingClient::failing()))
            .fetch_profile("t")
            .await;
        assert!(matches!(transport, Err(OAuthProviderError::Transport(_))));
    }
}
