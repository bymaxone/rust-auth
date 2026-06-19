//! The pluggable HTTP transport for OAuth providers. Providers never embed an HTTP
//! client; they perform every network call through the object-safe [`HttpClient`] trait,
//! whose request/response types are plain owned data carrying **no** external HTTP
//! dependency. The base `oauth` feature therefore adds the orchestration and provider
//! contracts without pulling `reqwest` (or any TLS stack) into the consumer's graph.
//!
//! A deployment brings its own client by implementing [`HttpClient`] over whatever it
//! already has. The `oauth-reqwest` feature reserves the `reqwest` dependency for the
//! bundled transport, which is wired alongside the OAuth flow that performs the real HTTPS
//! exchange.

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
