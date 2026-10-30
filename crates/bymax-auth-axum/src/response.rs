//! Rendering [`AuthError`] into the canonical HTTP response.
//!
//! The error type lives in `bymax-auth-types`, so the orphan rule forbids an
//! `impl IntoResponse for AuthError` here. Instead [`AuthRejection`] is a thin newtype the
//! adapter returns from every extractor rejection and handler `Result`, and
//! [`error_response`] builds the response: the `{ "error": { code, message, details } }`
//! envelope (already remapped past any internal-only sentinel by
//! [`bymax_auth_types::AuthError::to_envelope`]), the status `errorCatalog.statuses` pins in
//! `conformance/wire-contract.json` for that remapped code, and a `Retry-After` header for
//! the per-account lockout and the edge rate-limit rejection. The OTP attempt cap is
//! deliberately not among them — it reaches the client as `auth.otp_invalid`, so the header
//! would restore what the collapse removes. The underlying cause of an
//! [`AuthError::Internal`] is logged but **never** serialized into the body (§15.1).

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

/// Build the canonical HTTP response for an [`AuthError`]: the JSON envelope, the status
/// the shared contract pins for the wire code, and — for the lockout and rate-limit codes —
/// a `Retry-After` header computed from the error's `retry_after_seconds`. An
/// [`AuthError::Internal`] logs its cause via `tracing` and renders only the generic 500
/// envelope, never the cause.
///
/// The OTP cap is deliberately absent from that list: it reaches the client as
/// `auth.otp_invalid`, so a `Retry-After` would hand back through a header exactly what the
/// code collapse withholds — only a record that exists can reach an attempt ceiling.
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

/// Render an anti-enumerating flow's outcome: the uniform response for everything the
/// account's state could explain, and the real error for a request-shape failure.
///
/// The three public mail-triggering routes (`forgot-password`, `resend-otp`,
/// `resend-verification`) answer identically whether or not the account exists — that is the
/// whole anti-enumeration contract, and it is why they discard the engine's `Err`.
///
/// [`AuthError::Validation`] is the one error that must not be discarded, because it cannot be
/// explained by any account. It is reached only on the two tenant-scoping refusals — no
/// `TenantIdResolver` is configured and the body named no tenant, or one IS configured and the
/// body named one anyway — both decided before any lookup runs, so surfacing either reveals
/// only what the caller already knows about their own request. What it does disclose is which
/// of the two shapes this deployment takes, and that is the point: a client cannot be told to
/// stop sending a field it is never allowed to hear about. Collapsing it instead answers `200`
/// to a request that sent no mail and never could — the failure that looks like success from
/// every side: the caller waits for a message that was never going to arrive, and the
/// deployment's misconfiguration stays invisible.
///
/// Everything else still collapses. An account that does not exist, one that is blocked, and a
/// store that is briefly unreachable are all indistinguishable here by design.
#[must_use]
pub fn anti_enumerating_outcome(outcome: &Result<(), AuthError>, uniform: Response) -> Response {
    match outcome {
        Err(error @ AuthError::Validation { .. }) => error_response(error),
        _ => uniform,
    }
}

/// The `Retry-After` value (seconds) for the two codes that carry one — the per-account
/// lockout and the edge rate-limit rejection — or `None` for every other code.
///
/// `OtpMaxAttempts` is deliberately **not** among them, and this doc comment used to say the
/// opposite twice over: it listed the cap as carrying a header, then explained the absence by
/// claiming "the body still 429s". The body does not. The cap is internal-only and reaches a
/// caller as `auth.otp_invalid` with that code's 401, so a `Retry-After` would hand back
/// through a header exactly what the collapse withholds — only a record that exists can reach
/// an attempt ceiling. The 429 the variant carries pre-remap is for logs and never ships.
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
    fn an_unscopable_request_is_surfaced_while_every_account_outcome_still_collapses() {
        // The anti-enumeration contract is about the ACCOUNT: existence, blocked status and a
        // briefly unreachable store must be indistinguishable. A request that names no tenant
        // with no resolver configured is none of those — it is decided before any lookup runs,
        // so it can be answered honestly, and it must be: collapsing it answers 200 to a caller
        // whose mail was never going to be sent, and hides the misconfiguration that caused it.
        let uniform = || StatusCode::NO_CONTENT.into_response();

        let unscopable: Result<(), AuthError> = Err(AuthError::Validation {
            details: vec![bymax_auth_types::FieldError {
                field: "tenantId".to_owned(),
                message: "required".to_owned(),
            }],
        });
        let surfaced = anti_enumerating_outcome(&unscopable, uniform());
        assert_eq!(surfaced.status(), StatusCode::BAD_REQUEST);

        // Success, an account-dependent refusal, and an infrastructure failure are one response.
        for outcome in [
            Ok(()),
            Err(AuthError::OtpInvalid),
            Err(AuthError::Internal(Box::new(std::io::Error::other("down")))),
        ] {
            assert_eq!(
                anti_enumerating_outcome(&outcome, uniform()).status(),
                StatusCode::NO_CONTENT,
                "an account-dependent outcome escaped the uniform response: {outcome:?}"
            );
        }
    }

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
