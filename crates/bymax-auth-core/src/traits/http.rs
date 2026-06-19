//! The pluggable HTTP transport for OAuth providers. Providers never embed an HTTP
//! client; they perform every network call through the object-safe [`HttpClient`] trait,
//! whose request/response types are plain owned data carrying **no** external HTTP
//! dependency. The base `oauth` feature therefore adds the orchestration and provider
//! contracts without pulling `reqwest` (or any TLS stack) into the consumer's graph.
//!
//! A deployment either brings its own client (implementing [`HttpClient`] over whatever
//! it already has) or enables the `oauth-reqwest` feature for the bundled
//! [`ReqwestHttpClient`].

use async_trait::async_trait;

/// A minimal, object-safe HTTP transport. Connection, TLS, timeout, and proxy policy are
/// the implementation's concern; the engine only hands it owned request data.
///
/// # Errors
///
/// Returns [`HttpError`] for any transport-layer failure (DNS, connect, TLS, timeout,
/// body read). The OAuth engine maps every variant to the opaque client-facing
/// `OAuthFailed`, so provider internals never reach a caller.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform one request and return the full response.
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// The HTTP verbs the built-in OAuth flows need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET` — profile fetch.
    Get,
    /// `POST` — token exchange.
    Post,
}

/// A core-owned request value — no `http`/`reqwest` types, just owned data.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    /// The request method.
    pub method: HttpMethod,
    /// The absolute request URL.
    pub url: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

/// A core-owned response value.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// The HTTP status code (e.g. `200`, `400`) — no external `StatusCode` type.
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// The full response body.
    pub body: Vec<u8>,
}

/// A transport-layer failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The request exceeded the transport's timeout.
    #[error("http transport timeout")]
    Timeout,
    /// The transport could not establish a connection.
    #[error("http connect error: {0}")]
    Connect(String),
    /// Any other transport failure (TLS, body read, malformed response).
    #[error("http transport error: {0}")]
    Transport(String),
}

/// Default per-request timeout for the bundled [`ReqwestHttpClient`], in seconds.
#[cfg(feature = "oauth-reqwest")]
const REQWEST_DEFAULT_TIMEOUT_SECS: u64 = 10;

/// The bundled `reqwest`-backed transport, compiled only under the `oauth-reqwest`
/// feature, with a default per-request timeout. Enable the feature and pass an instance to
/// `AuthEngineBuilder::http_client`, or let the builder default to it.
///
/// No TLS backend is selected on `reqwest` here, because its default `rustls-tls` pulls
/// `ring`, which the workspace forbids (RustCrypto-only policy). The RustCrypto-backed
/// rustls provider is installed alongside the OAuth flow that performs the real HTTPS
/// exchange; until then an HTTPS request returns a transport error rather than silently
/// downgrading.
#[cfg(feature = "oauth-reqwest")]
#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

#[cfg(feature = "oauth-reqwest")]
impl ReqwestHttpClient {
    /// Construct a client with the default per-request timeout. Construction degrades to
    /// `reqwest`'s default client (logged via `tracing`) if the builder fails, so it is
    /// infallible.
    #[must_use]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(REQWEST_DEFAULT_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(error = %err, "reqwest client build failed; using the default client (no per-request timeout)");
                reqwest::Client::default()
            });
        Self { client }
    }
}

#[cfg(feature = "oauth-reqwest")]
impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "oauth-reqwest")]
#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        let response = builder.send().await.map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response.bytes().await.map_err(map_reqwest_error)?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Map a `reqwest` error to the transport-neutral [`HttpError`], preserving the failure
/// class (timeout vs. connect vs. other) without leaking `reqwest` types.
#[cfg(feature = "oauth-reqwest")]
fn map_reqwest_error(err: reqwest::Error) -> HttpError {
    if err.is_timeout() {
        HttpError::Timeout
    } else if err.is_connect() {
        HttpError::Connect(err.to_string())
    } else {
        HttpError::Transport(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A trivial transport that echoes a fixed response, proving [`HttpClient`] is
    /// object-safe and the value types round-trip.
    struct EchoClient;

    #[async_trait]
    impl HttpClient for EchoClient {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
            Ok(HttpResponse {
                status: 200,
                headers: req.headers,
                body: req.body.unwrap_or_default(),
            })
        }
    }

    #[tokio::test]
    async fn http_client_is_object_safe_and_round_trips() {
        // Behind `Arc<dyn HttpClient>` the trait must be object-safe; the echo proves the
        // owned request/response values cross the call unchanged.
        let client: Arc<dyn HttpClient> = Arc::new(EchoClient);
        let req = HttpRequest {
            method: HttpMethod::Post,
            url: "https://example.test/token".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(b"payload".to_vec()),
        };
        let res = client.send(req).await;
        assert!(matches!(&res, Ok(r) if r.status == 200));
        let Ok(res) = res else { return };
        assert_eq!(res.body, b"payload");
        assert_eq!(res.headers[0].0, "content-type");

        // A bodyless request echoes an empty body (the `None` default path).
        let empty = HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.test/userinfo".into(),
            headers: Vec::new(),
            body: None,
        };
        let res = client.send(empty).await;
        assert!(matches!(&res, Ok(r) if r.body.is_empty()));
    }

    #[test]
    fn http_error_messages_classify_the_failure() {
        // The Display strings feed `tracing`; pin them so a log scrape stays stable.
        assert_eq!(HttpError::Timeout.to_string(), "http transport timeout");
        assert_eq!(
            HttpError::Connect("dns".into()).to_string(),
            "http connect error: dns"
        );
        assert_eq!(
            HttpError::Transport("tls".into()).to_string(),
            "http transport error: tls"
        );
    }

    #[test]
    fn http_method_is_copy_and_comparable() {
        // The verbs are a closed set used for routing inside providers.
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }
}
