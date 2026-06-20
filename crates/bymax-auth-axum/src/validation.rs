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
    use crate::dto::{LoginDto, OAuthInitiateQuery};

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
