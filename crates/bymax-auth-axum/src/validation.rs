//! The validation extractors `ValidatedJson<T>` (body) and `ValidatedQuery<T>` (query
//! string) (§8.4).
//!
//! Both deserialize with `serde` (the DTO's `#[serde(deny_unknown_fields)]` is the
//! `forbidNonWhitelisted` analogue — an unexpected field 400s), then run the DTO's `garde`
//! validation, mapping any failure to [`AuthError::Validation`] (400) with the per-field
//! messages under `error.details`. No message repeats the request: serde's own text names the
//! offending value, key and type, so a body that parses as JSON but does not fit answers a fixed
//! message, and a body the adapter cannot read answers the transport envelope
//! ([`crate::transport`]). `ValidatedJson<T>` reads the body, so it implements
//! `FromRequest` and must be the **last** handler argument; `ValidatedQuery<T>` reads only
//! the URI, so it implements `FromRequestParts` and may appear in any position.

use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRequest, FromRequestParts, Request};
use bymax_auth_types::{AuthError, FieldError};
use garde::Validate;
use http::StatusCode;
use http::request::Parts;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::response::AuthRejection;
use crate::structure::details_for;
use crate::transport::{BodyRejection, Transport};

/// What a body that is JSON but does not fit the route answers, in place of serde's text (which
/// repeats the value, the key or the type the client sent).
const BODY_SHAPE_MESSAGE: &str = "Request body does not match the expected shape.";

/// What a query string that does not fit the route answers, in place of serde's text.
const QUERY_SHAPE_MESSAGE: &str = "Query string does not match the expected shape.";

/// Body extractor: deserialize JSON into `T` (rejecting unknown fields), run `T`'s `garde`
/// validation, and yield `ValidatedJson(T)`. Any deserialization or validation failure
/// becomes [`AuthError::Validation`] (400) with per-field `details`. Consumes the body, so
/// it must be the **last** handler parameter.
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

/// Query-string twin of [`ValidatedJson`], for the OAuth endpoints. Reads only the URI, so
/// it implements `FromRequestParts` and may appear in any position.
#[derive(Debug)]
pub struct ValidatedQuery<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // The `Content-Type` has to say JSON, and that is a CSRF control rather than tidiness.
        // `Bytes::from_request` accepts any type, so `POST /auth/login` with
        // `Content-Type: text/plain` and a JSON body was accepted — and that combination is a
        // CORS *simple request*: no preflight, so a cross-origin page can send it and the
        // browser attaches cookies wherever `SameSite` permits. An HTML form with
        // `enctype="text/plain"` produces exactly that shape. Requiring the type re-arms the
        // preflight as a second barrier behind `enforce_trusted_origin`.
        //
        // It is also a wire divergence: nest-auth runs behind Nest's `express.json()`, which
        // parses only `application/json`, so the same request 400s there and succeeded here.
        require_readable_json(req.headers())?;

        // Buffer the body ourselves (rather than via axum's `Json`) so a malformed body and
        // an unknown field both render as the canonical `auth.validation` envelope instead
        // of axum's default plaintext 400/415.
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(map_bytes_rejection)?;
        let value = deserialize_json::<T>(&bytes)?;
        run_garde(&value)?;
        Ok(Self(value))
    }
}

/// Refuse a body whose `Content-Type` is not JSON.
///
/// Accepts `application/json` and the structured-suffix family (`application/…+json`), judging
/// only the media type (the parameters are [`require_readable_json`]'s), and compares
/// case-insensitively — RFC 9110 §8.3 makes the type and subtype case-insensitive. An ABSENT
/// header is refused too: it is not a shape any JSON client produces, and admitting it would
/// leave the preflight-free path open to anyone who simply omits the header.
fn require_json_content_type(headers: &http::HeaderMap) -> Result<(), AuthRejection> {
    let is_json = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|essence| essence == "application/json" || essence.ends_with("+json"));

    if is_json {
        Ok(())
    } else {
        Err(AuthRejection::from(AuthError::Validation {
            details: vec![FieldError {
                field: "content-type".to_owned(),
                message: "Content-Type must be application/json.".to_owned(),
            }],
        }))
    }
}

/// Refuse a body the adapter cannot read as JSON: the media type has to be JSON
/// ([`require_json_content_type`], a `400`), the charset has to be UTF-8 or unstated, and the
/// content encoding has to be identity or unstated (both a `415`: the adapter does not decode
/// anything else, so reading the bytes as UTF-8 JSON would be guessing).
fn require_readable_json(headers: &http::HeaderMap) -> Result<(), BodyRejection> {
    require_json_content_type(headers)?;
    if !charset_is_utf8(headers) || !encoding_is_identity(headers) {
        return Err(Transport::UnsupportedMedia.into());
    }
    Ok(())
}

/// Whether the `Content-Type` states no charset or states UTF-8 (compared case-insensitively,
/// with the value optionally quoted). Only `utf-8` is accepted: `utf8` and every other label are
/// charsets the adapter would have to decode.
fn charset_is_utf8(headers: &http::HeaderMap) -> bool {
    let Some(value) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    value.split(';').skip(1).all(|parameter| {
        let Some((name, charset)) = parameter.split_once('=') else {
            return true;
        };
        !name.trim().eq_ignore_ascii_case("charset")
            || charset
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case("utf-8")
    })
}

/// Whether every `Content-Encoding` the request names is `identity`.
pub(crate) fn encoding_is_identity(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .all(|value| {
            value.to_str().is_ok_and(|list| {
                list.split(',')
                    .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
            })
        })
}

/// Parse an OPTIONAL JSON body into `T`, running `T`'s `garde` rules when one is present.
///
/// The MFA-setup routes accept a body that may be absent — an OAuth-only account has no password
/// to send — so they cannot use [`ValidatedJson`], which requires one. They used to reach for
/// `serde_json::from_slice(&body).unwrap_or_default()` instead, which skipped `garde` entirely:
/// `MfaSetupDto`'s declared `max = 128` never ran, so a password up to the body cap reached the
/// KDF, and a `deny_unknown_fields` failure became `password: None` rather than the
/// `auth.validation` 400 nest-auth answers with. Same request, two different outcomes across the
/// two backends, on a bound the shared wire contract pins.
///
/// An empty body still means "nothing supplied"; anything else must be well-formed JSON of the
/// declared shape, and must say so in its `Content-Type` for the reason
/// [`require_json_content_type`] gives, in a charset and encoding [`require_readable_json`]
/// accepts.
// Only the MFA-setup routes take an optional body, and they compile only with the `mfa`
// feature — so without it this is dead code, and the workspace builds with `-D warnings`.
#[cfg(feature = "mfa")]
pub(crate) fn validate_optional_json<T>(
    headers: &http::HeaderMap,
    bytes: &[u8],
) -> Result<T, BodyRejection>
where
    T: Default + DeserializeOwned + Validate<Context = ()>,
{
    if bytes.is_empty() {
        return Ok(T::default());
    }
    require_readable_json(headers)?;
    let value = deserialize_json::<T>(bytes)?;
    run_garde(&value)?;
    Ok(value)
}

impl<T, S> FromRequestParts<S> for ValidatedQuery<T>
where
    T: DeserializeOwned + Validate<Context = ()>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or("");
        let value = deserialize_query::<T>(query)?;
        run_garde(&value)?;
        Ok(Self(value))
    }
}

/// Deserialize a JSON body into `T`.
///
/// A body that is not a JSON object or array at its root (a bare string, number or literal, or
/// no body at all), or that does not parse, answers the transport envelope's "Malformed
/// request": nest-auth's body parser accepts only an object or an array at the root and refuses
/// the rest the same way. A body that parses but does not fit `T` (an unknown key, a value of
/// the wrong type, a missing key) answers `auth.validation` with one entry for each failing
/// property, named by its wire name (see [`crate::structure`]); where no property can be named it
/// answers one fixed message under `body`. serde's own text is never used: it names the offending
/// value, key and type, which are the client's.
pub(crate) fn deserialize_json<T>(bytes: &[u8]) -> Result<T, BodyRejection>
where
    T: DeserializeOwned + Validate<Context = ()>,
{
    let first = bytes
        .iter()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'));
    if !matches!(first, Some(b'{' | b'[')) {
        return Err(Transport::Malformed(StatusCode::BAD_REQUEST).into());
    }
    serde_json::from_slice::<T>(bytes).map_err(|error| match error.classify() {
        serde_json::error::Category::Data => BodyRejection::from(AuthError::Validation {
            details: shape_details::<T>(bytes, "body", BODY_SHAPE_MESSAGE),
        }),
        _ => Transport::Malformed(StatusCode::BAD_REQUEST).into(),
    })
}

/// The details for a request that does not fit `T`: every failing property by its wire name, or
/// the one fixed entry naming `container` when no property can be named (a root that is not an
/// object, a type that is not one of this crate's DTOs).
fn shape_details<T>(bytes: &[u8], container: &str, message: &str) -> Vec<FieldError>
where
    T: DeserializeOwned + Validate<Context = ()>,
{
    let named = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|root| root.as_object().map(details_for::<T>))
        .unwrap_or_default();
    if named.is_empty() {
        vec![FieldError {
            field: container.to_owned(),
            message: message.to_owned(),
        }]
    } else {
        named
    }
}

/// Deserialize a query string into `T`, mapping any failure to `auth.validation`: every failing
/// property by its wire name, or a fixed message (serde's text names the offending key and value).
fn deserialize_query<T>(query: &str) -> Result<T, AuthRejection>
where
    T: DeserializeOwned + Validate<Context = ()>,
{
    serde_urlencoded::from_str::<T>(query).map_err(|_| {
        let pairs = serde_urlencoded::from_str::<Vec<(String, String)>>(query).unwrap_or_default();
        let body: Map<String, Value> = pairs
            .into_iter()
            .map(|(name, value)| (name, Value::String(value)))
            .collect();
        let named = details_for::<T>(&body);
        let details = if named.is_empty() {
            vec![FieldError {
                field: "query".to_owned(),
                message: QUERY_SHAPE_MESSAGE.to_owned(),
            }]
        } else {
            named
        };
        AuthRejection(AuthError::Validation { details })
    })
}

/// Fields whose wire name is the provider's own snake_case name, not the `camelCase` the rest of
/// the DTOs use: they are the OAuth callback's (RFC 6749 section 4.1.2.1), renamed explicitly on
/// the DTO. Their error names are already wire names and stay as they are.
const SNAKE_CASE_WIRE_FIELDS: [&str; 2] = ["error_description", "error_uri"];

/// `snake_case` as `camelCase`: an underscore is dropped and the letter after it is capitalised.
/// A leading underscore is dropped without capitalising, so the result never starts upper-case.
fn camel_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalise_next = false;
    for c in name.chars() {
        if c == '_' {
            capitalise_next = !out.is_empty();
        } else if capitalise_next {
            out.extend(c.to_uppercase());
            capitalise_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// One segment of a `garde` path (`name` or `name[3]`) as the wire names it.
fn wire_segment(segment: &str) -> String {
    let (name, index) = segment.split_at(segment.find('[').unwrap_or(segment.len()));
    if SNAKE_CASE_WIRE_FIELDS.contains(&name) {
        return segment.to_owned();
    }
    format!("{}{index}", camel_case(name))
}

/// A `garde` path, which names Rust fields, as the wire names it: the property a client sent
/// (`currentPassword`), which is what `nest-auth` reports and what a client keys its form
/// errors by. Every segment of a nested path is converted.
fn wire_path(path: &str) -> String {
    path.split('.')
        .map(wire_segment)
        .collect::<Vec<_>>()
        .join(".")
}

/// The details of a `garde` report: every `(path, message)`, with each path as the wire names it.
pub(crate) fn garde_details(report: &garde::Report) -> Vec<FieldError> {
    report
        .iter()
        .map(|(path, error)| FieldError {
            field: wire_path(&path.to_string()),
            message: error.to_string(),
        })
        .collect()
}

/// Run a DTO's `garde` validation, collecting every `(path, message)` into the typed
/// `Validation` details on failure, with each path as the wire names it.
fn run_garde<T: Validate<Context = ()>>(value: &T) -> Result<(), AuthRejection> {
    match value.validate() {
        Ok(()) => Ok(()),
        Err(report) => Err(AuthRejection(AuthError::Validation {
            details: garde_details(&report),
        })),
    }
}

/// Map axum's body-buffering rejection onto the transport envelope: a body over the limit is
/// the `413` kind, and any other failure to read the body keeps the `4xx` axum reports for it.
/// axum's own text is never used, so the library's envelope answers instead of a plain-text
/// default.
pub(crate) fn map_bytes_rejection(rejection: BytesRejection) -> BodyRejection {
    Transport::from_body_status(rejection.status()).into()
}

/// A path parameter, for the routes that read one. It differs from axum's own `Path` only in how
/// it fails: a parameter that cannot be decoded (invalid UTF-8 after percent-decoding) answers
/// the transport envelope's "Malformed request", not axum's plain-text "Invalid URL: ..." text.
#[cfg(any(feature = "sessions", feature = "oauth"))]
pub(crate) struct PathParam<T>(pub(crate) T);

#[cfg(any(feature = "sessions", feature = "oauth"))]
impl<T, S> FromRequestParts<S> for PathParam<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        axum::extract::Path::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(value)| Self(value))
            .map_err(|rejection| match rejection.status() {
                status if status.is_client_error() => Transport::Malformed(status).into(),
                // The route declares a parameter the router did not capture: the adapter's own
                // fault, not the client's, so it must not read as a malformed request.
                _ => BodyRejection::from(AuthError::Internal(Box::new(std::io::Error::other(
                    "a route's path parameter was not captured",
                )))),
            })
    }
}

/// The raw request body, for the routes that read an optional one themselves
/// (`parse_refresh_body`, [`validate_optional_json`]). It differs from axum's own
/// `Bytes` only in how it fails: a body over the limit or one that cannot be read answers the
/// transport envelope, not a plain-text default.
pub(crate) struct RequestBytes(pub(crate) axum::body::Bytes);

impl<S> FromRequest<S> for RequestBytes
where
    S: Send + Sync,
{
    type Rejection = BodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::body::Bytes::from_request(req, state)
            .await
            .map(Self)
            .map_err(map_bytes_rejection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{LoginDto, OAuthCallbackQuery, OAuthInitiateQuery};
    use axum::response::IntoResponse;

    #[test]
    fn deserialize_json_separates_unreadable_bodies_from_ones_of_the_wrong_shape() {
        // A body that is not JSON, or not an object at its root, is "Malformed request".
        for body in [
            &b"{ not json"[..],
            b"\"abc\"",
            b"42",
            b"true",
            b"null",
            b"",
            b"   ",
            b"{",
        ] {
            let err = deserialize_json::<LoginDto>(body).err();
            assert!(
                matches!(
                    err.map(|e| e.into_response().status()),
                    Some(StatusCode::BAD_REQUEST)
                ),
                "{body:?}"
            );
        }
        // Valid JSON of the wrong shape is `auth.validation` with a fixed `body` detail.
        let wrong = deserialize_json::<LoginDto>(br#"{"email":5}"#).err();
        let body = wrong.map(|e| e.into_response());
        assert!(body.is_some_and(|r| r.status() == StatusCode::BAD_REQUEST));
        // A well-formed body deserializes.
        let ok =
            deserialize_json::<LoginDto>(br#"{"email":"a@e.com","password":"p","tenantId":"t1"}"#);
        assert!(ok.is_ok());
    }

    fn header_map(pairs: &[(&'static str, &'static [u8])]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            if let Ok(value) = http::HeaderValue::from_bytes(value) {
                map.append(http::HeaderName::from_static(name), value);
            }
        }
        map
    }

    #[test]
    fn only_utf8_or_an_unstated_charset_is_readable() {
        for readable in [
            &b"application/json"[..],
            b"application/json; charset=utf-8",
            b"application/json; charset=UTF-8",
            b"application/json;charset=\"utf-8\"",
            b"application/json; boundary=x; charset=utf-8",
            // A parameter without a value names no charset.
            b"application/json; flag",
        ] {
            let label = String::from_utf8_lossy(readable);
            assert!(
                charset_is_utf8(&header_map(&[("content-type", readable)])),
                "{label}"
            );
        }
        for unreadable in [
            &b"application/json; charset=nope"[..],
            b"application/json; charset=utf8",
            b"application/json; charset = UTF-16",
            b"application/json; charset=\"latin1\"",
        ] {
            let label = String::from_utf8_lossy(unreadable);
            assert!(
                !charset_is_utf8(&header_map(&[("content-type", unreadable)])),
                "{label}"
            );
        }
        // No `Content-Type` at all states no charset.
        assert!(charset_is_utf8(&http::HeaderMap::new()));
    }

    #[test]
    fn only_the_identity_encoding_is_readable() {
        assert!(encoding_is_identity(&http::HeaderMap::new()));
        for readable in [&b"identity"[..], b"Identity", b"identity, identity"] {
            assert!(encoding_is_identity(&header_map(&[(
                "content-encoding",
                readable
            )])));
        }
        for unreadable in [&b"gzip"[..], b"identity, gzip", b"br", b"\xFF"] {
            assert!(!encoding_is_identity(&header_map(&[(
                "content-encoding",
                unreadable
            )])));
        }
        // Every `Content-Encoding` header counts, not only the first.
        assert!(!encoding_is_identity(&header_map(&[
            ("content-encoding", b"identity"),
            ("content-encoding", b"gzip"),
        ])));
    }

    #[cfg(any(feature = "sessions", feature = "oauth"))]
    #[tokio::test]
    async fn a_route_whose_path_parameter_was_not_captured_is_the_adapters_fault() {
        // A request that no route matched carries no captured parameters: asking for one is the
        // adapter's mistake and must not read as a bad request.
        let (mut parts, _body) = Request::new(axum::body::Body::empty()).into_parts();
        let rejection = PathParam::<String>::from_request_parts(&mut parts, &())
            .await
            .err();
        let response = rejection
            .map(IntoResponse::into_response)
            .unwrap_or_default();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // The status alone does not tell the adapter's fault from a malformed request that
        // carries the same status: the envelope's code does.
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        assert_eq!(envelope["error"]["code"], "auth.internal");
    }

    #[test]
    fn a_request_no_property_can_be_named_for_answers_one_fixed_entry_under_its_container() {
        // A root that is an array has no properties, so the body is the only thing to name.
        let array = deserialize_json::<LoginDto>(b"[]")
            .err()
            .map(|e| e.into_response().status());
        assert_eq!(array, Some(StatusCode::BAD_REQUEST));
        // A query serde refuses for no property of its own (a key given twice) names the query.
        let err = deserialize_query::<OAuthInitiateQuery>("tenantId=a&tenantId=b").err();
        assert!(matches!(
            err,
            Some(AuthRejection(AuthError::Validation { details }))
                if details.len() == 1 && details[0].field == "query"
        ));
        assert_eq!(
            shape_details::<LoginDto>(b"[]", "body", BODY_SHAPE_MESSAGE)
                .iter()
                .map(|d| (d.field.as_str(), d.message.as_str()))
                .collect::<Vec<_>>(),
            [("body", BODY_SHAPE_MESSAGE)]
        );
    }

    #[test]
    fn deserialize_query_maps_errors_and_parses_valid() {
        // An unknown field fails (`deny_unknown_fields`) and is named; a valid query parses.
        let err = deserialize_query::<OAuthInitiateQuery>("nope=1").err();
        assert!(matches!(
            err,
            Some(AuthRejection(AuthError::Validation { details })) if details[0].field == "nope"
        ));
        let ok = deserialize_query::<OAuthInitiateQuery>("tenantId=t1");
        assert!(matches!(ok, Ok(q) if q.tenant_id.as_deref() == Some("t1")));
        // An absent `tenantId` now parses: a deployment with a `TenantIdResolver` names the
        // tenant from the request, and the engine — not this layer — refuses the request when
        // neither a resolver nor a body value can scope it.
        assert!(matches!(
            deserialize_query::<OAuthInitiateQuery>(""),
            Ok(q) if q.tenant_id.is_none()
        ));
    }

    #[test]
    fn oauth_callback_query_accepts_unknown_provider_extras() {
        // A real provider appends parameters we do not enumerate (e.g. Google's `authuser`
        // beyond the named optionals). The callback DTO must ignore unknown query fields
        // while still extracting `code` and `state`, not reject the redirect.
        let ok = deserialize_query::<OAuthCallbackQuery>(
            "code=abc&state=xyz&authuser=0&delegatedClientId=foo&unexpected=1",
        );
        assert!(matches!(ok, Ok(q) if q.code.as_deref() == Some("abc") && q.state == "xyz"));
    }

    #[test]
    fn run_garde_collects_per_field_failures() {
        // An invalid DTO yields per-field validation details; a valid one passes.
        let Ok(bad) = deserialize_query::<OAuthInitiateQuery>("tenantId=") else { return };
        assert!(matches!(
            run_garde(&bad),
            Err(AuthRejection(AuthError::Validation { details })) if !details.is_empty()
        ));
        let Ok(good) = deserialize_query::<OAuthInitiateQuery>("tenantId=t1") else { return };
        assert!(run_garde(&good).is_ok());
    }

    #[test]
    fn a_rust_field_path_is_reported_as_the_wire_name() {
        // Single words are unchanged; snake_case becomes camelCase; a nested path converts every
        // segment and keeps an index; a leading underscore never capitalises the first letter.
        assert_eq!(wire_path("email"), "email");
        assert_eq!(wire_path("current_password"), "currentPassword");
        assert_eq!(wire_path("tenant_id"), "tenantId");
        assert_eq!(wire_path("order_items[3].item_id"), "orderItems[3].itemId");
        assert_eq!(wire_path("_internal_flag"), "internalFlag");
        assert_eq!(wire_path("a__b"), "aB");
    }

    #[test]
    fn the_providers_own_names_are_reported_as_they_are() {
        // `error_description` and `error_uri` ARE their wire names (the DTO renames them
        // explicitly), so converting them would name a field nothing sends.
        assert_eq!(wire_path("error_description"), "error_description");
        assert_eq!(wire_path("error_uri"), "error_uri");
        assert_eq!(wire_path("error"), "error");
    }
}
