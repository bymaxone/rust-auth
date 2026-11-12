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

/// Routes that accept an empty body, so only a request that carries one is refused. A segment
/// written `:name` stands for any one non-empty path segment.
const WHEN_BODY: [&str; 5] = [
    "POST mfa/setup",
    "POST platform/mfa/setup",
    "POST workspaces/:workspaceId/leave",
    "POST workspaces/:workspaceId/restore",
    "POST workspaces/:workspaceId/switch",
];

/// Whether `route` (`METHOD path`) is one of `list`, where a `:name` segment of a listed route
/// matches any one non-empty segment of `route`.
fn listed(list: &[&str], route: &str) -> bool {
    list.iter().any(|template| {
        let mut wanted = template.split('/');
        let mut given = route.split('/');
        loop {
            match (wanted.next(), given.next()) {
                (None, None) => return true,
                (Some(want), Some(got)) if want == got => {}
                (Some(want), Some(got)) if want.starts_with(':') && !got.is_empty() => {}
                _ => return false,
            }
        }
    })
}

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
        if listed(&UNCHECKED, &route) {
            return false;
        }
        if listed(&WHEN_BODY, &route) && !carries_a_body(request.headers()) {
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

    #[test]
    fn the_exempt_lists_are_exactly_the_contracts() {
        assert_eq!(owned(&UNCHECKED), contract_list("unchecked"));
        assert_eq!(owned(&WHEN_BODY), contract_list("whenBody"));
        let methods: BTreeSet<String> = METHODS_NEVER_CHECKED
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(methods, contract_list("methodsNeverChecked"));
    }

    #[test]
    fn a_parameter_segment_matches_one_non_empty_segment() {
        let list = ["POST workspaces/:workspaceId/leave", "POST mfa/setup"];
        for matching in [
            "POST workspaces/:workspaceId/leave",
            "POST workspaces/0f8fad5b-d9cb-469f-a165-70867728950e/leave",
            "POST mfa/setup",
        ] {
            assert!(listed(&list, matching), "{matching}");
        }
        for other in [
            "POST workspaces//leave",
            "POST workspaces/w/leave/extra",
            "POST workspaces/w",
            "POST workspaces/w/restore",
            "PATCH workspaces/w/leave",
            "POST mfa/setup/extra",
            "POST mfa",
        ] {
            assert!(!listed(&list, other), "{other}");
        }
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
