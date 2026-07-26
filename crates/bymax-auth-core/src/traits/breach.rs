//! The seam for checking a password against a known-breach corpus.
//!
//! A password can satisfy every complexity rule and still be one an attacker tries first, so
//! the engine consults a corpus wherever a password is *set*. The check is a **seam, not a
//! dependency**: the default approves everything, so a deployment that upgrades the crate never
//! starts talking to a third party it did not ask for.

#[cfg(feature = "breach")]
use std::sync::Arc;

use async_trait::async_trait;

#[cfg(feature = "breach")]
use crate::traits::http::{HttpClient, HttpMethod, HttpRequest};

/// Decides whether a password appears in a known-breach corpus.
///
/// # Contract
///
/// Two rules an implementation must honor:
///
/// - **Never transmit the password.** The point of a range query is that the corpus is searched
///   with a prefix of a digest, not with the secret.
/// - **Fail open.** A corpus that is unreachable, slow, or rate-limiting must approve the
///   password. Returning "breached" on an error would let a third party's outage block password
///   changes — including the change someone is making *because* they were breached.
///
/// That is why the method returns `bool` rather than `Result`: there is no error an
/// implementation could return that the engine would be right to act on.
#[async_trait]
pub trait PasswordBreachChecker: Send + Sync {
    /// Whether the password is known to have been breached.
    async fn is_breached(&self, password: &str) -> bool;
}

/// The default checker: approves every password, and touches no network.
///
/// Registered when the builder is given none, so the credential path behaves exactly as it did
/// before the check existed.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllBreachChecker;

#[async_trait]
impl PasswordBreachChecker for AllowAllBreachChecker {
    async fn is_breached(&self, _password: &str) -> bool {
        false
    }
}

/// The range endpoint. The last five characters of the path are the digest prefix.
#[cfg(feature = "breach")]
const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Characters of the SHA-1 hex sent to the service. The rest never leaves the process.
#[cfg(feature = "breach")]
const PREFIX_LENGTH: usize = 5;

/// Checks a password against Have I Been Pwned without ever sending it.
///
/// The protocol is k-anonymity: the password is SHA-1'd locally, the **first five** hex
/// characters of the digest are sent, and the service answers with every suffix it holds under
/// that prefix — some hundreds of them. The comparison happens here, so the service learns a
/// prefix shared by thousands of distinct passwords and nothing else.
///
/// SHA-1 is not a security choice here and is not used as one: it is the corpus's index. The
/// password is still hashed for storage with the configured KDF.
///
/// The request runs over the crate's own [`HttpClient`] seam, so enabling the check pulls in no
/// HTTP stack of its own — the deployment supplies the transport it already has.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use bymax_auth_core::traits::{HibpBreachChecker, HttpClient};
/// # fn wire(http: Arc<dyn HttpClient>) {
/// let checker = Arc::new(HibpBreachChecker::new(http));
/// # let _ = checker;
/// # }
/// ```
#[cfg(feature = "breach")]
pub struct HibpBreachChecker {
    http: Arc<dyn HttpClient>,
}

#[cfg(feature = "breach")]
impl HibpBreachChecker {
    /// Build the checker over an HTTP transport.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>) -> Self {
        Self { http }
    }
}

#[cfg(feature = "breach")]
#[async_trait]
impl PasswordBreachChecker for HibpBreachChecker {
    async fn is_breached(&self, password: &str) -> bool {
        let digest = crate::services::to_hex(&bymax_auth_crypto::mac::sha1(password.as_bytes()))
            .to_uppercase();
        let (prefix, suffix) = digest.split_at(PREFIX_LENGTH);

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: format!("{HIBP_RANGE_URL}{prefix}"),
            // Padding hides the true response size from a network observer.
            headers: vec![("Add-Padding".to_owned(), "true".to_owned())],
            body: None,
        };

        // Every failure path approves the password. A transport error, a rate limit, a body
        // that is not UTF-8 — none of them are evidence about the password, and treating them
        // as evidence would make a hardening measure a dependency of the credential path.
        let Ok(response) = self.http.send(request).await else {
            tracing::warn!("breach check unreachable — password allowed");
            return false;
        };
        if !(200..300).contains(&response.status) {
            tracing::warn!(
                status = response.status,
                "breach check unavailable — password allowed"
            );
            return false;
        }
        let Ok(body) = String::from_utf8(response.body) else {
            tracing::warn!("breach check returned a non-UTF-8 body — password allowed");
            return false;
        };

        // Each line is `SUFFIX:COUNT`. A match at all is disqualifying; the count is not
        // consulted, because "breached once" is already too often.
        body.lines().any(|line| {
            line.split(':')
                .next()
                .is_some_and(|candidate| candidate.trim().eq_ignore_ascii_case(suffix))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default has to be inert: no network, and every password approved. A crate that
    /// starts contacting a third party because it was upgraded would be a surprise, and this
    /// is the property that prevents it.
    #[tokio::test]
    async fn the_default_checker_approves_everything() {
        assert!(!AllowAllBreachChecker.is_breached("hunter2").await);
        assert!(!AllowAllBreachChecker.is_breached("").await);
    }
}

#[cfg(all(test, feature = "breach"))]
mod hibp_tests {
    use super::*;
    use crate::testing::MockHttpClient;
    use crate::traits::http::{HttpError, HttpResponse};
    use std::sync::Mutex;

    const PASSWORD: &str = "correct horse battery staple";

    /// The SHA-1 of the password, upper-cased, as the range API indexes it.
    fn digest() -> String {
        crate::services::to_hex(&bymax_auth_crypto::mac::sha1(PASSWORD.as_bytes())).to_uppercase()
    }

    /// A client that records the URL it was asked for and answers with a fixed body.
    struct RecordingClient {
        body: String,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl HttpClient for RecordingClient {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(req.url.clone());
            }
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.body.clone().into_bytes(),
            })
        }
    }

    /// A client whose transport always fails.
    struct FailingClient;

    #[async_trait]
    impl HttpClient for FailingClient {
        async fn send(&self, _req: HttpRequest) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Transport("connection refused".to_owned()))
        }
    }

    #[tokio::test]
    async fn only_the_five_character_prefix_leaves_the_process() {
        // The k-anonymity property, asserted on the wire. Sending more than the prefix — the
        // whole digest, let alone the password — would defeat the entire point of a range
        // query, which is that the corpus is searched without revealing what is searched for.
        let digest = digest();
        let client = Arc::new(RecordingClient {
            body: String::new(),
            seen: Mutex::new(Vec::new()),
        });

        HibpBreachChecker::new(client.clone())
            .is_breached(PASSWORD)
            .await;

        let seen = client
            .seen
            .lock()
            .map(|urls| urls.clone())
            .unwrap_or_default();
        assert_eq!(seen.len(), 1);
        let url = &seen[0];
        assert!(url.ends_with(&digest[..5]));
        assert!(!url.contains(&digest[5..]));
        assert!(!url.contains(PASSWORD));
    }

    #[tokio::test]
    async fn a_suffix_in_the_range_is_a_breached_password() {
        // The match itself, compared locally against every line of the range. Case and the
        // CRLF line endings the service uses must not throw it off.
        let digest = digest();
        let body = format!(
            "0000000000000000000000000000000000A:3\r\n{}:42\r\n",
            &digest[5..]
        );
        let client = Arc::new(MockHttpClient::with_body(200, body.into_bytes()));

        assert!(HibpBreachChecker::new(client).is_breached(PASSWORD).await);

        let lowercase = format!("{}:1\r\n", digest[5..].to_lowercase());
        let client = Arc::new(MockHttpClient::with_body(200, lowercase.into_bytes()));
        assert!(HibpBreachChecker::new(client).is_breached(PASSWORD).await);
    }

    #[tokio::test]
    async fn a_range_without_the_suffix_is_a_clean_password() {
        let client = Arc::new(MockHttpClient::with_body(
            200,
            b"0000000000000000000000000000000000A:3\r\nFFFFF:1\r\n".to_vec(),
        ));

        assert!(!HibpBreachChecker::new(client).is_breached(PASSWORD).await);
    }

    #[tokio::test]
    async fn every_failure_approves_the_password() {
        // Fail-open is the rule that keeps this from becoming a dependency of the credential
        // path: a corpus that is down, rate-limiting, or answering garbage must not stop
        // someone changing their password — least of all during an incident, when changing it
        // is the urgent thing.
        let rate_limited = Arc::new(MockHttpClient::with_body(429, Vec::new()));
        assert!(
            !HibpBreachChecker::new(rate_limited)
                .is_breached(PASSWORD)
                .await
        );

        let transport_error = Arc::new(FailingClient);
        assert!(
            !HibpBreachChecker::new(transport_error)
                .is_breached(PASSWORD)
                .await
        );

        let not_utf8 = Arc::new(MockHttpClient::with_body(200, vec![0xff, 0xfe, 0xfd]));
        assert!(!HibpBreachChecker::new(not_utf8).is_breached(PASSWORD).await);
    }
}
