//! The bundled `reqwest`-backed [`HttpClient`], compiled only under the `oauth-reqwest`
//! feature. It is a thin adapter: it maps the core-owned [`HttpRequest`] onto a `reqwest`
//! request, sends it, and maps the response (or a transport failure) back to the core-owned
//! [`HttpResponse`] / [`HttpError`]. No `http`/`reqwest` type appears on the `HttpClient`
//! contract, so a consumer that brings its own client pulls in nothing here.
//!
//! # TLS
//!
//! `reqwest` is pulled with `default-features = false` and **no** TLS backend, because every
//! `reqwest` TLS feature reintroduces a banned crate into the dependency graph:
//! `rustls-tls` pulls `ring`, `native-tls` pulls `openssl`/`openssl-sys`, and the
//! `rustls-tls-*-no-provider` variants leave `reqwest` without a runtime crypto provider (it
//! then panics on client build). The workspace ban-list (RustCrypto-only, zero native
//! binding, wasm-safe) forbids all of them. As shipped, this adapter therefore handles
//! plain-HTTP origins; for HTTPS endpoints (such as Google) a deployment supplies its own
//! [`HttpClient`] over an HTTP stack whose TLS provider it has chosen — the "bring your own
//! client" path (§11.1.1). See the crate README for the rationale and the escalation path.

use std::time::Duration;

use async_trait::async_trait;

use crate::traits::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};

/// The default per-request timeout (§11.1.1), bounding a slow origin.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`HttpClient`] backed by a shared `reqwest::Client`. Cloning the client is cheap (it
/// shares an internal connection pool), so one instance serves every provider request.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    /// Build the adapter with the default 10 s per-request timeout.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Transport`] if the underlying `reqwest::Client` cannot be built.
    pub fn new() -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(map_reqwest_error)?;
        Ok(Self { client })
    }

    /// Build the adapter over a caller-supplied `reqwest::Client`, so a deployment can set its
    /// own timeout, proxy, connection-pool, or TLS policy.
    #[must_use]
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
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
                    value.to_str().unwrap_or_default().to_owned(),
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

/// Classify a `reqwest::Error` into the core-owned [`HttpError`]. The error `Display` carries
/// the endpoint and kind but never a request body, so it is safe to retain for monitoring.
fn map_reqwest_error(error: reqwest::Error) -> HttpError {
    if error.is_timeout() {
        HttpError::Timeout
    } else if error.is_connect() {
        HttpError::Connect(error.to_string())
    } else {
        HttpError::Transport(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What a one-shot local server does once it accepts a connection.
    enum Behavior {
        /// Drain the request, then write the given raw HTTP/1.1 response bytes.
        Respond(Vec<u8>),
        /// Drain the request, then drop the connection without responding (a transport error).
        Drop,
        /// Accept and then hang, so a short client timeout fires.
        Hang,
    }

    /// Bind a plain-HTTP listener on `127.0.0.1:0`, serve `behavior` for exactly one connection
    /// on a background task, and return the bound address plus the task's join handle. Every
    /// test makes a single request to its own server, so one connection suffices; awaiting the
    /// handle lets a test wait for the server to run to completion deterministically. No TLS is
    /// involved, so the adapter's request-building, response-mapping, and error-mapping are
    /// exercised end to end.
    async fn spawn_server(
        behavior: Behavior,
    ) -> Option<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        let handle = tokio::spawn(serve_once(listener, behavior));
        Some((addr, handle))
    }

    /// Accept exactly one connection and apply `behavior`, then return. Extracted so the
    /// handler is a plain async fn whose normal return the get-request test awaits, exercising
    /// every arm to completion.
    async fn serve_once(listener: TcpListener, behavior: Behavior) {
        let Ok((mut socket, _)) = listener.accept().await else { return };
        let mut buf = [0u8; 1024];
        // Drain one read so the client finishes sending before we respond.
        let _ = socket.read(&mut buf).await;
        match behavior {
            Behavior::Respond(bytes) => {
                let _ = socket.write_all(&bytes).await;
                let _ = socket.flush().await;
            }
            Behavior::Drop => {}
            Behavior::Hang => {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    /// A raw `200 OK` response with the given body.
    fn ok_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn new_builds_a_client_with_the_default_timeout() {
        // The default constructor succeeds and yields a usable adapter.
        assert!(ReqwestHttpClient::new().is_ok());
    }

    #[tokio::test]
    async fn get_request_maps_status_headers_and_body() {
        // A GET over plain HTTP round-trips: status, a response header, and the body are mapped.
        let started = spawn_server(Behavior::Respond(ok_response("hello"))).await;
        let Some((addr, handle)) = started else { return };
        let Ok(client) = ReqwestHttpClient::new() else { return };
        let res = client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: format!("http://{addr}/userinfo"),
                headers: vec![("accept".to_owned(), "text/plain".to_owned())],
                body: None,
            })
            .await;
        assert!(matches!(&res, Ok(r) if r.status == 200 && r.body == b"hello"));
        let Ok(res) = res else { return };
        assert!(
            res.headers
                .iter()
                .any(|(k, v)| k == "content-length" && v == "5")
        );
        // Wait for the server task to run to completion so its handler body is fully exercised.
        let _ = handle.await;
    }

    #[tokio::test]
    async fn post_request_sends_headers_and_body() {
        // A POST with headers and a body is accepted; the response maps back to the core type.
        let started = spawn_server(Behavior::Respond(ok_response("{}"))).await;
        let Some((addr, _handle)) = started else { return };
        let Ok(client) = ReqwestHttpClient::new() else { return };
        let res = client
            .send(HttpRequest {
                method: HttpMethod::Post,
                url: format!("http://{addr}/token"),
                headers: vec![(
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                )],
                body: Some(b"grant_type=authorization_code".to_vec()),
            })
            .await;
        assert!(matches!(res, Ok(r) if r.status == 200 && r.body == b"{}"));
    }

    #[tokio::test]
    async fn connect_failure_maps_to_connect_error() {
        // Connecting to a port with no listener is a connect error.
        let started = spawn_server(Behavior::Respond(Vec::new())).await;
        let Some((addr, _handle)) = started else { return };
        // Bind then drop a fresh listener to obtain a definitely-closed port.
        let Ok(dead) = TcpListener::bind("127.0.0.1:0").await else { return };
        let Ok(dead_addr) = dead.local_addr() else { return };
        drop(dead);
        let _ = addr;
        let Ok(client) = ReqwestHttpClient::new() else { return };
        let res = client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: format!("http://{dead_addr}/"),
                headers: Vec::new(),
                body: None,
            })
            .await;
        assert!(matches!(res, Err(HttpError::Connect(_))));
    }

    #[tokio::test]
    async fn dropped_connection_maps_to_transport_error() {
        // A server that closes the connection without responding is a (non-connect, non-timeout)
        // transport error.
        let Some((addr, _handle)) = spawn_server(Behavior::Drop).await else { return };
        let Ok(client) = ReqwestHttpClient::new() else { return };
        let res = client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: format!("http://{addr}/"),
                headers: Vec::new(),
                body: None,
            })
            .await;
        assert!(matches!(res, Err(HttpError::Transport(_))));
    }

    #[tokio::test]
    async fn slow_origin_maps_to_timeout_error() {
        // A hanging origin trips the (short) per-request timeout, mapped to HttpError::Timeout.
        let Some((addr, _handle)) = spawn_server(Behavior::Hang).await else { return };
        let built = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build();
        let Ok(inner) = built else { return };
        let client = ReqwestHttpClient::with_client(inner);
        let res = client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: format!("http://{addr}/"),
                headers: Vec::new(),
                body: None,
            })
            .await;
        assert!(matches!(res, Err(HttpError::Timeout)));
    }
}
