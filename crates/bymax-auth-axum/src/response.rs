//! Rendering [`AuthError`] into the canonical HTTP response.
//!
//! The error type lives in `bymax-auth-types`, so the orphan rule forbids an
//! `impl IntoResponse for AuthError` here. Instead [`AuthRejection`] is a thin newtype the
//! adapter returns from every extractor rejection and handler `Result`, and
//! [`error_response`] builds the response: the `{ "error": { code, message, details } }`
//! envelope (already remapped past any internal-only sentinel by
//! [`bymax_auth_types::AuthError::to_envelope`]), the status from the §8.6 map, and a
//! `Retry-After` header for the lockout / OTP-cap / rate-limit codes. The underlying cause
//! of an [`AuthError::Internal`] is logged but **never** serialized into the body (§15.1).

use axum::Json;
use axum::response::{IntoResponse, Response};
use bymax_auth_types::AuthError;
use http::{HeaderValue, StatusCode, header};

/// A newtype wrapping an engine/adapter [`AuthError`] so the adapter can implement
/// `IntoResponse` for it (the error type itself lives in another crate). Returned from
/// every extractor `Rejection` and handler error path.
#[derive(Debug)]
pub struct AuthRejection(pub AuthError);

impl From<AuthError> for AuthRejection {
    fn from(error: AuthError) -> Self {
        Self(error)
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        error_response(&self.0)
    }
}

/// Build the canonical HTTP response for an [`AuthError`]: the JSON envelope, the mapped
/// status, and — for the lockout / OTP-cap / rate-limit codes — a `Retry-After` header
/// computed from the error's `retry_after_seconds`. An [`AuthError::Internal`] logs its
/// cause via `tracing` and renders only the generic 500 envelope, never the cause.
#[must_use]
pub fn error_response(error: &AuthError) -> Response {
    if let AuthError::Internal(cause) = error {
        // The cause is for operators only — log it, but never serialize it into the body.
        tracing::error!(%cause, "internal auth error");
    }

    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let envelope = error.to_envelope();
    let mut response = (status, Json(envelope)).into_response();

    if let Some(seconds) = retry_after_seconds(error)
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

/// The `Retry-After` value (seconds) for the codes that carry one — the per-account
/// lockout, the OTP attempt cap, and the edge rate-limit rejection — or `None` for every
/// other code. `AccountLocked`/`TooManyRequests` carry an explicit value; `OtpMaxAttempts`
/// has no engine-supplied window here, so it emits no header (the body still 429s).
fn retry_after_seconds(error: &AuthError) -> Option<u64> {
    match error {
        AuthError::AccountLocked {
            retry_after_seconds,
        }
        | AuthError::TooManyRequests {
            retry_after_seconds,
        } => *retry_after_seconds,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn internal_error_renders_a_generic_500_without_leaking_the_cause() {
        // The Internal variant logs its cause but serializes only the generic envelope.
        let cause = std::io::Error::other("secret detail");
        let error = AuthError::Internal(Box::new(cause));
        let response = error_response(&error);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn lockout_and_rate_limit_attach_retry_after() {
        // AccountLocked and TooManyRequests carry a Retry-After header from their seconds.
        let locked = AuthError::AccountLocked {
            retry_after_seconds: Some(120),
        };
        let response = error_response(&locked);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("120")
        );

        // A None retry value attaches no header (still 429).
        let none = AuthError::TooManyRequests {
            retry_after_seconds: None,
        };
        let resp = error_response(&none);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn auth_rejection_into_response_renders_the_envelope() {
        // The newtype `IntoResponse` forwards to `error_response`.
        let rejection = AuthRejection(AuthError::TokenInvalid);
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // `From<AuthError>` constructs the newtype.
        let from: AuthRejection = AuthError::Forbidden.into();
        assert_eq!(from.into_response().status(), StatusCode::FORBIDDEN);
    }
}
