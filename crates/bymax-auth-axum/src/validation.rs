//! The validation extractors `ValidatedJson<T>` (body) and `ValidatedQuery<T>` (query
//! string) (§8.4).
//!
//! Both deserialize with `serde` (the DTO's `#[serde(deny_unknown_fields)]` is the
//! `forbidNonWhitelisted` analogue — an unexpected field 400s), then run the DTO's `garde`
//! validation, mapping any failure to [`AuthError::Validation`] (400) with the per-field
//! messages under `error.details`. `ValidatedJson<T>` reads the body, so it implements
//! `FromRequest` and must be the **last** handler argument; `ValidatedQuery<T>` reads only
//! the URI, so it implements `FromRequestParts` and may appear in any position.

use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRequest, FromRequestParts, Request};
use bymax_auth_types::{AuthError, FieldError};
use garde::Validate;
use http::request::Parts;
use serde::de::DeserializeOwned;

use crate::response::AuthRejection;

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
    type Rejection = AuthRejection;

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
        require_json_content_type(req.headers())?;

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
/// Accepts `application/json` and the structured-suffix family (`application/…+json`), with any
/// parameters (`; charset=utf-8`) ignored, and compares case-insensitively — RFC 9110 §8.3 makes
/// the type and subtype case-insensitive. An ABSENT header is refused too: it is not a shape any
/// JSON client produces, and admitting it would leave the preflight-free path open to anyone who
/// simply omits the header.
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
/// [`require_json_content_type`] gives.
pub(crate) fn validate_optional_json<T>(
    headers: &http::HeaderMap,
    bytes: &[u8],
) -> Result<T, AuthRejection>
where
    T: Default + DeserializeOwned + Validate<Context = ()>,
{
    if bytes.is_empty() {
        return Ok(T::default());
    }
    require_json_content_type(headers)?;
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

/// Deserialize a JSON body into `T`, mapping any serde error (syntax, type, missing or
/// unknown field) to the single canonical `auth.validation` envelope. The serde message is
/// surfaced under the synthetic `body` field, never the wire bytes.
fn deserialize_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AuthRejection> {
    serde_json::from_slice::<T>(bytes).map_err(|error| {
        AuthRejection(AuthError::Validation {
            details: vec![FieldError {
                field: "body".to_owned(),
                message: error.to_string(),
            }],
        })
    })
}

/// Deserialize a query string into `T`, mapping any failure to `auth.validation`.
fn deserialize_query<T: DeserializeOwned>(query: &str) -> Result<T, AuthRejection> {
    serde_urlencoded::from_str::<T>(query).map_err(|error| {
        AuthRejection(AuthError::Validation {
            details: vec![FieldError {
                field: "query".to_owned(),
                message: error.to_string(),
            }],
        })
    })
}

/// Run a DTO's `garde` validation, collecting every `(path, message)` into the typed
/// `Validation` details on failure.
fn run_garde<T: Validate<Context = ()>>(value: &T) -> Result<(), AuthRejection> {
    match value.validate() {
        Ok(()) => Ok(()),
        Err(report) => {
            let details = report
                .iter()
                .map(|(path, error)| FieldError {
                    field: path.to_string(),
                    message: error.to_string(),
                })
                .collect();
            Err(AuthRejection(AuthError::Validation { details }))
        }
    }
}

/// Map axum's body-buffering rejection (e.g. the request-body limit was exceeded) onto the
/// canonical validation envelope, so even an oversized body fails as `auth.validation`
/// rather than axum's default response.
fn map_bytes_rejection(rejection: BytesRejection) -> AuthRejection {
    AuthRejection(AuthError::Validation {
        details: vec![FieldError {
            field: "body".to_owned(),
            message: rejection.body_text(),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{LoginDto, OAuthCallbackQuery, OAuthInitiateQuery};

    #[test]
    fn deserialize_json_maps_serde_errors_to_validation() {
        // A malformed body is `auth.validation` with the `body` field detail.
        let err = deserialize_json::<LoginDto>(b"{ not json").err();
        assert!(matches!(
            err,
            Some(AuthRejection(AuthError::Validation { details })) if details[0].field == "body"
        ));
        // A well-formed body deserializes.
        let ok =
            deserialize_json::<LoginDto>(br#"{"email":"a@e.com","password":"p","tenantId":"t1"}"#);
        assert!(ok.is_ok());
    }

    #[test]
    fn deserialize_query_maps_errors_and_parses_valid() {
        // A missing required field fails; a valid query parses.
        let err = deserialize_query::<OAuthInitiateQuery>("").err();
        assert!(matches!(
            err,
            Some(AuthRejection(AuthError::Validation { details })) if details[0].field == "query"
        ));
        let ok = deserialize_query::<OAuthInitiateQuery>("tenantId=t1");
        assert!(matches!(ok, Ok(q) if q.tenant_id == "t1"));
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
}
