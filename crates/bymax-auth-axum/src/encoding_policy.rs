//! Which requests are refused for declaring a `Content-Encoding` the adapter does not decode
//! (transport layer).
//!
//! The scope is the shared contract's `requestEncoding` section: every route is checked except
//! the ones named below, so a route added later is checked until someone decides it should not
//! be. The check runs as a layer outside the route layers, ahead of authentication and rate
//! limiting: a refused request spends no rate-limit budget and reveals nothing about the
//! caller's authentication state.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::Method;

use crate::transport::Transport;

/// Methods whose requests are never checked: they carry no body the adapter reads.
const METHODS_NEVER_CHECKED: [Method; 4] =
    [Method::GET, Method::HEAD, Method::OPTIONS, Method::DELETE];

/// Routes (`METHOD path`, relative to the route prefix) that read their own body or none, and
/// are never refused for their encoding.
const UNCHECKED: [&str; 6] = [
    "POST logout",
    "POST refresh",
    "POST ws-ticket",
    "POST platform/logout",
    "POST platform/refresh",
    "POST sessions/revoke-all",
];

/// Routes that accept an empty body, so only a request that carries one is refused.
const WHEN_BODY: [&str; 2] = ["POST mfa/setup", "POST platform/mfa/setup"];

/// The route prefix the policy strips before it compares a path.
#[derive(Clone)]
pub(crate) struct EncodingPolicy {
    prefix: String,
}

impl EncodingPolicy {
    /// A policy for routes mounted under `prefix` (with its leading slash).
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.trim_end_matches('/').to_owned(),
        }
    }

    /// Whether `request` is refused: its encoding is not identity, and the route checks it.
    fn refuses(&self, request: &Request) -> bool {
        if METHODS_NEVER_CHECKED.contains(request.method()) {
            return false;
        }
        let path = request.uri().path();
        let relative = path
            .strip_prefix(self.prefix.as_str())
            .unwrap_or(path)
            .trim_start_matches('/');
        let route = format!("{} {relative}", request.method());
        if UNCHECKED.contains(&route.as_str()) {
            return false;
        }
        if WHEN_BODY.contains(&route.as_str()) && !carries_a_body(request.headers()) {
            return false;
        }
        !crate::validation::encoding_is_identity(request.headers())
    }
}

/// Whether the headers announce a body: a non-zero `Content-Length` or a `Transfer-Encoding`.
fn carries_a_body(headers: &http::HeaderMap) -> bool {
    let sized = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|length| length.trim() != "0");
    sized || headers.contains_key(http::header::TRANSFER_ENCODING)
}

/// The layer: answer the transport's `415` for a refused request, pass the rest on.
pub(crate) async fn refuse_undecoded_body(
    State(policy): State<EncodingPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if policy.refuses(&request) {
        return Transport::UnsupportedMedia.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// One list of the contract's `requestEncoding` section as a set of strings.
    fn contract_list(list: &str) -> BTreeSet<String> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root["requestEncoding"][list]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn owned(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    /// Routes the contract lists under `whenBody` that this crate does not serve yet, with the
    /// slice that serves each. The comparison below leaves them out of the contract's side, and
    /// [`the_pending_when_body_routes_are_still_unbuilt`] requires each to be missing from
    /// [`WHEN_BODY`] and present in the contract, so the slice that builds a route has to delete
    /// its entry, and a route the contract adds that is not listed fails the build.
    const PENDING_WHEN_BODY: [&str; 3] = [
        "POST workspaces/:workspaceId/leave",
        "POST workspaces/:workspaceId/restore",
        "POST workspaces/:workspaceId/switch",
    ];

    #[test]
    fn the_pending_when_body_routes_are_still_unbuilt() {
        let in_contract = contract_list("whenBody");
        for route in PENDING_WHEN_BODY {
            assert!(
                in_contract.contains(route),
                "{route} is pending but the contract does not list it"
            );
            assert!(
                !WHEN_BODY.contains(&route),
                "{route} is built; remove it from PENDING_WHEN_BODY"
            );
        }
    }

    #[test]
    fn the_exempt_lists_are_exactly_the_contracts() {
        assert_eq!(owned(&UNCHECKED), contract_list("unchecked"));
        let built: BTreeSet<String> = contract_list("whenBody")
            .into_iter()
            .filter(|route| !PENDING_WHEN_BODY.contains(&route.as_str()))
            .collect();
        assert_eq!(owned(&WHEN_BODY), built);
        let methods: BTreeSet<String> = METHODS_NEVER_CHECKED
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(methods, contract_list("methodsNeverChecked"));
    }

    #[test]
    fn a_body_is_announced_by_a_length_or_a_transfer_encoding() {
        let mut headers = http::HeaderMap::new();
        assert!(!carries_a_body(&headers));
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("0"),
        );
        assert!(!carries_a_body(&headers));
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("2"),
        );
        assert!(carries_a_body(&headers));
        let mut chunked = http::HeaderMap::new();
        chunked.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        assert!(carries_a_body(&chunked));
    }
}
