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

/// The set of request headers that must never enter a `RequestContext`'s sanitized map.
/// Lowercased to match the normalized header keys. This is the single source of truth for
/// "sensitive" headers: both [`sanitize_headers`] (which drops them from the engine context)
/// and the tracing redaction layer ([`sensitive_header_names`]) derive from it, so a header is
/// never redacted in one path but recorded in the other.
///
/// The list is nest-auth's `BLOCKED_HEADERS`, entry for entry, because the sanitized map is
/// handed to host-supplied hooks: a host that wires the same audit sink behind both backends
/// must not receive a header from one that the other withholds. Two categories are stripped:
///
/// - **Credential-bearing** (`authorization`, `cookie`, `proxy-authorization`,
///   `www-authenticate`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-session-id`) — these
///   are secrets, and a hook that logs its context would persist them verbatim.
/// - **Forwarded-identity** (`x-forwarded-for`, `x-forwarded-host`, `x-real-ip`,
///   `x-original-forwarded-for`, `cf-connecting-ip`, `true-client-ip`, `x-cluster-client-ip`)
///   — trivially spoofed by the client. A hook must take the address from
///   [`RequestContext::ip`], which the adapter resolves from the peer socket, never from a
///   header the caller chose.
const SENSITIVE_HEADERS: [&str; 15] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-id",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "x-original-forwarded-for",
    "cf-connecting-ip",
    "true-client-ip",
    "x-cluster-client-ip",
];

/// Suffixes that mark a custom `x-`-prefixed header as secret-bearing.
///
/// This is the second half of nest-auth's filter, whose regex is
/// `^x-.*-(token|secret|key|password|credential|auth|bearer|signature|hmac)$`. Expressed as
/// suffixes rather than a pattern so the crate keeps its dependency surface, matching the
/// regex exactly: the leading `x-` is stripped first and the REMAINDER must end with a
/// dash-prefixed suffix, so `x-request-token` is stripped while `x-token` — which the regex
/// also declines, since its `.*-` needs a dash of its own — is kept.
const SENSITIVE_HEADER_SUFFIXES: [&str; 9] = [
    "-token",
    "-secret",
    "-key",
    "-password",
    "-credential",
    "-auth",
    "-bearer",
    "-signature",
    "-hmac",
];

/// Whether a lowercased header name must be withheld from the sanitized map.
///
/// The blocklist is the floor; the suffix rule is what keeps a host's own convention
/// (`x-internal-service-key`, `x-webhook-signature`) from leaking through a filter that only
/// knew the names this library ships with.
fn is_sensitive_header(key: &str) -> bool {
    SENSITIVE_HEADERS.contains(&key)
        || key.strip_prefix("x-").is_some_and(|rest| {
            SENSITIVE_HEADER_SUFFIXES
                .iter()
                .any(|suffix| rest.ends_with(suffix))
        })
}

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
        if is_sensitive_header(&key) {
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

/// The platform twin of [`PresentedAccessToken`]: the raw platform access token from the
/// `Authorization: Bearer` header, or an empty string when absent. Platform sessions are always
/// bearer, so this never consults a cookie — the access cookie on a platform request can only
/// belong to the dashboard domain. Infallible (logout never blocks on a missing token).
#[cfg(feature = "platform")]
pub(crate) struct PresentedPlatformAccessToken(pub String);

#[cfg(feature = "platform")]
impl<S> FromRequestParts<S> for PresentedPlatformAccessToken
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            crate::extractors::source_platform_access_token(parts).unwrap_or_default(),
        ))
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
    fn the_blocklist_matches_nest_auths_entry_for_entry() {
        // The sanitized map goes to host-supplied hooks. A host wiring one audit sink behind
        // both backends must not receive from one what the other withholds, so the list is
        // pinned by name rather than by count alone.
        for blocked in [
            "authorization",
            "cookie",
            "proxy-authorization",
            "www-authenticate",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-session-id",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-real-ip",
            "x-original-forwarded-for",
            "cf-connecting-ip",
            "true-client-ip",
            "x-cluster-client-ip",
        ] {
            assert!(
                is_sensitive_header(blocked),
                "{blocked} is on nest-auth's blocklist but reaches the hook context here"
            );
        }
    }

    #[test]
    fn the_suffix_rule_reproduces_nest_auths_pattern() {
        // Every suffix the pattern names, on a custom header a host might define.
        for sensitive in [
            "x-refresh-token",
            "x-client-secret",
            "x-service-key",
            "x-api-password",
            "x-service-credential",
            "x-service-auth",
            "x-custom-bearer",
            "x-webhook-signature",
            "x-service-hmac",
        ] {
            assert!(is_sensitive_header(sensitive), "{sensitive} leaked");
        }

        // …and the boundaries, which are where a suffix rule and the regex it stands in for
        // could quietly disagree. The regex requires a dash of its own before the suffix, so a
        // bare `x-token` is NOT sensitive; a non-`x-` header is never matched by the pattern
        // however it ends; and an ordinary header is untouched.
        for benign in [
            "x-token",
            "x-key",
            "content-type",
            "x-request-id",
            "user-agent",
            "session-token",
            "accept",
        ] {
            assert!(
                !is_sensitive_header(benign),
                "{benign} was stripped, but nest-auth forwards it"
            );
        }
    }

    #[test]
    fn a_custom_secret_header_never_reaches_the_hook_context() {
        // End to end through the real context builder: the blocklist, the suffix rule, and a
        // benign header, so the filter is pinned where it is actually applied.
        let parts = parts_with(&[
            ("x-api-key", "k-1"),
            ("proxy-authorization", "Basic abc"),
            ("x-internal-service-key", "s-1"),
            ("x-request-id", "req-1"),
        ]);
        let ctx = request_context(&parts);
        assert!(!ctx.sanitized_headers.contains_key("x-api-key"));
        assert!(!ctx.sanitized_headers.contains_key("proxy-authorization"));
        assert!(!ctx.sanitized_headers.contains_key("x-internal-service-key"));
        assert_eq!(
            ctx.sanitized_headers
                .get("x-request-id")
                .map(String::as_str),
            Some("req-1")
        );
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
