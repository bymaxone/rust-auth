//! The route groups (§8.2): one module per controller, each exposing a `routes()` factory
//! that returns a `Router<AuthState>` with relative paths (the factory in `router.rs` nests
//! them under the configured prefix). Optional groups are feature-gated.
//!
//! Handlers are thin: they source request metadata, call an engine method, and hand the
//! outcome to the [`crate::delivery::TokenDelivery`] helper or render an `AuthError`. This
//! module holds the shared helpers every handler reuses.

pub(crate) mod auth;
pub(crate) mod password_reset;

#[cfg(feature = "invitations")]
pub(crate) mod invitations;
#[cfg(feature = "mfa")]
pub(crate) mod mfa;
#[cfg(feature = "oauth")]
pub(crate) mod oauth;
#[cfg(feature = "platform")]
pub(crate) mod platform;
#[cfg(all(feature = "platform", feature = "mfa"))]
pub(crate) mod platform_mfa;
#[cfg(feature = "sessions")]
pub(crate) mod sessions;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use bymax_auth_core::context::RequestContext;
use bymax_auth_types::{AuthError, FieldError};
use http::HeaderName;
use http::header;
use http::request::Parts;
use tower_cookies::Cookies;

use crate::dto::RefreshDto;
use crate::extractors::source_access_token;
use crate::state::AuthState;

/// The set of request headers that must never enter a `RequestContext`'s sanitized map (the
/// credential-bearing ones). Lowercased to match the normalized header keys. This is the
/// single source of truth for "sensitive" headers: both [`sanitize_headers`] (which drops
/// them from the engine context) and the tracing redaction layer
/// ([`sensitive_header_names`]) derive from it, so a header is never redacted in one path but
/// recorded in the other.
const SENSITIVE_HEADERS: [&str; 3] = ["authorization", "cookie", "x-csrf-token"];

/// The sensitive headers as typed [`HeaderName`]s, for the `SetSensitiveRequestHeadersLayer`
/// that masks them in `tracing` spans/events. Derived from [`SENSITIVE_HEADERS`] so the
/// redaction set always matches what [`sanitize_headers`] strips. Any entry that is not a
/// valid header name is skipped (the const holds only valid lowercase names).
pub(crate) fn sensitive_header_names() -> Vec<HeaderName> {
    SENSITIVE_HEADERS
        .iter()
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect()
}

/// Build a framework-neutral [`RequestContext`] from request parts: the client IP (peer
/// socket address, never a raw `X-Forwarded-For`), the `User-Agent`, and the sanitized
/// header map (sensitive entries removed, keys lowercased). The core never sees a real HTTP
/// request — this is the only place the adapter translates one.
pub(crate) fn request_context(parts: &Parts) -> RequestContext {
    let ip = peer_ip(parts);
    let user_agent = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let sanitized_headers = sanitize_headers(parts);
    RequestContext::new(ip, user_agent, sanitized_headers)
}

/// The peer socket IP from the `ConnectInfo` extension, or an empty string when absent (the
/// engine treats an empty IP as "unknown" for brute-force keying). Never reads
/// `X-Forwarded-For` — the trusted-proxy strategy applies only to the rate-limit key, not
/// the engine context.
pub(crate) fn peer_ip(parts: &Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_default()
}

/// The lowercased, sensitive-header-stripped view of the request headers, safe to log/persist.
fn sanitize_headers(parts: &Parts) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (name, value) in parts.headers.iter() {
        let key = name.as_str().to_ascii_lowercase();
        if SENSITIVE_HEADERS.contains(&key.as_str()) {
            continue;
        }
        if let Ok(text) = value.to_str() {
            map.insert(key, text.to_owned());
        }
    }
    map
}

/// Read the refresh token for a refresh/logout flow: the refresh cookie first, then the
/// body-supplied value (bearer/both mode). Never a query string. Returns an empty string
/// when neither channel carries it (the engine treats that as an invalid refresh).
pub(crate) fn source_refresh_token(
    cookies: &Cookies,
    refresh_cookie_name: &str,
    body_value: Option<&str>,
) -> String {
    cookies
        .get(refresh_cookie_name)
        .map(|cookie| cookie.value().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            body_value
                .map(str::to_owned)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default()
}

/// Parse an optional refresh body shared by the dashboard and platform refresh handlers: an
/// empty body yields a default [`RefreshDto`] (no body-supplied token, the cookie-mode case);
/// a present body must deserialize as a valid `RefreshDto` (unknown fields rejected). On a
/// malformed body it returns an `auth.validation` error whose `body` detail surfaces the
/// serde parse message — a body-shape diagnostic that leaks no secret. Both refresh paths use
/// this one helper so the parsing rule and the error envelope stay identical.
pub(crate) fn parse_optional_refresh_body(bytes: &[u8]) -> Result<RefreshDto, AuthError> {
    if bytes.is_empty() {
        return Ok(RefreshDto::default());
    }
    serde_json::from_slice::<RefreshDto>(bytes).map_err(|error| AuthError::Validation {
        details: vec![FieldError {
            field: "body".to_owned(),
            message: error.to_string(),
        }],
    })
}

/// A handler extractor that resolves an owned [`RequestContext`] from the request parts
/// (IP, `User-Agent`, sanitized headers) without consuming the body. Infallible — an absent
/// IP/UA degrades to empty strings.
pub(crate) struct RequestMeta(pub RequestContext);

impl<S> FromRequestParts<S> for RequestMeta
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(request_context(parts)))
    }
}

/// A handler extractor that resolves the raw access token from the configured channel
/// (cookie or `Authorization` header), or an empty string when absent — used by `logout` to
/// blacklist the presented token. Infallible (logout never blocks on a missing token).
pub(crate) struct PresentedAccessToken(pub String);

impl<S> FromRequestParts<S> for PresentedAccessToken
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let token = source_access_token(parts, auth_state.config()).unwrap_or_default();
        Ok(Self(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use tower_cookies::{Cookie, Cookies};

    fn parts_with(headers: &[(&'static str, &str)]) -> Parts {
        let mut builder = Request::builder().uri("/x");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (mut parts, ()) = builder.body(()).unwrap_or_default().into_parts();
        if let Ok(addr) = "203.0.113.9:4000".parse::<SocketAddr>() {
            parts.extensions.insert(ConnectInfo(addr));
        }
        parts
    }

    #[test]
    fn request_context_resolves_ip_ua_and_strips_sensitive_headers() {
        // The context carries the peer IP + UA; `authorization`/`cookie` never enter the
        // sanitized map, but a benign header (lowercased) does.
        let parts = parts_with(&[
            ("user-agent", "agent/9"),
            ("authorization", "Bearer secret"),
            ("cookie", "access_token=x"),
            ("X-Trace", "abc"),
        ]);
        let ctx = request_context(&parts);
        assert_eq!(ctx.ip, "203.0.113.9");
        assert_eq!(ctx.user_agent, "agent/9");
        assert!(!ctx.sanitized_headers.contains_key("authorization"));
        assert!(!ctx.sanitized_headers.contains_key("cookie"));
        assert_eq!(
            ctx.sanitized_headers.get("x-trace").map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn sensitive_header_names_cover_every_stripped_header() {
        // The tracing redaction set must include every header `sanitize_headers` strips —
        // notably `x-csrf-token`, which the global redaction layer would otherwise record.
        let names: Vec<String> = sensitive_header_names()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        for stripped in SENSITIVE_HEADERS {
            assert!(
                names.iter().any(|name| name == stripped),
                "redaction set missing {stripped}"
            );
        }
        assert!(names.iter().any(|name| name == "x-csrf-token"));
        assert_eq!(names.len(), SENSITIVE_HEADERS.len());
    }

    #[test]
    fn peer_ip_is_empty_without_connect_info() {
        // No `ConnectInfo` extension → an empty IP (the engine treats it as unknown).
        let (parts, ()) = Request::builder()
            .uri("/x")
            .body(())
            .unwrap_or_default()
            .into_parts();
        assert!(peer_ip(&parts).is_empty());
    }

    #[test]
    fn parse_optional_refresh_body_handles_empty_present_and_malformed() {
        // Empty body → default DTO (no body token); a valid JSON body deserializes the
        // token; a malformed body → `auth.validation` with the `body` field detail (the
        // serde message), the shared shape the dashboard and platform handlers both surface.
        assert!(matches!(
            parse_optional_refresh_body(b""),
            Ok(dto) if dto.refresh_token.is_none()
        ));
        assert!(matches!(
            parse_optional_refresh_body(br#"{"refreshToken":"r1"}"#),
            Ok(dto) if dto.refresh_token.as_deref() == Some("r1")
        ));
        assert!(matches!(
            parse_optional_refresh_body(b"{ not json"),
            Err(AuthError::Validation { details }) if details[0].field == "body"
        ));
    }

    #[test]
    fn source_refresh_token_prefers_cookie_then_body() {
        // The cookie wins when present; otherwise the body value is used; empty when neither.
        let jar = Cookies::default();
        jar.add(Cookie::new("refresh_token", "from-cookie"));
        assert_eq!(
            source_refresh_token(&jar, "refresh_token", Some("from-body")),
            "from-cookie"
        );

        let empty_jar = Cookies::default();
        assert_eq!(
            source_refresh_token(&empty_jar, "refresh_token", Some("from-body")),
            "from-body"
        );
        assert_eq!(source_refresh_token(&empty_jar, "refresh_token", None), "");
    }
}
