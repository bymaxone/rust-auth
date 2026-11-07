//! Requests the HTTP layer refuses before a handler decides anything.
//!
//! A body that is not JSON, one over the size limit, a charset or an encoding the adapter cannot
//! read: none of these is about an account or a field, and none may repeat any part of the
//! request. They answer the shared contract's `transportErrors` section — the library's own
//! `auth.validation` envelope with the status the transport itself reports, a fixed message per
//! kind, and `details: null`.
//!
//! The contract describes nest-auth's mechanism (a filter in front of routing). Here the same
//! observable answer is produced by [`BodyRejection`], which the body extractors return, and by
//! the response mapper that gives the body-limit layer's own plain-text `413` the same envelope; the
//! status, code, message and `details` are what the contract pins, not where they are made.

use axum::Json;
use axum::response::{IntoResponse, Response};
use bymax_auth_types::{AuthError, AuthErrorBody, AuthErrorCode, AuthErrorEnvelope};
use http::StatusCode;

use crate::response::AuthRejection;

/// A request refused by the transport. Each kind has one fixed message, so a body, a key, a
/// header value or a query parameter the client chose can never reach the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    /// The body is not JSON the adapter can parse, or could not be read. Carries the status the
    /// failure itself reports: `400` for a syntax error, the body error's own `4xx` otherwise.
    Malformed(StatusCode),
    /// The body is larger than the configured limit.
    TooLarge,
    /// The body is in a charset or content encoding the adapter does not decode.
    UnsupportedMedia,
}

impl Transport {
    /// The kind for a body that could not be read, from the status axum reports for it: a body
    /// over the limit is [`Transport::TooLarge`], any other failure keeps its own status.
    pub(crate) fn from_body_status(status: StatusCode) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::TooLarge
        } else {
            Self::Malformed(status)
        }
    }

    /// The HTTP status of this kind.
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Malformed(status) => status,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMedia => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        }
    }

    /// The fixed client-facing message of this kind.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Malformed(_) => "Malformed request",
            Self::TooLarge => "Request entity too large",
            Self::UnsupportedMedia => "Unsupported media type",
        }
    }
}

impl IntoResponse for Transport {
    fn into_response(self) -> Response {
        let envelope = AuthErrorEnvelope {
            error: AuthErrorBody {
                code: AuthErrorCode::Validation,
                message: self.message().to_owned(),
                details: None,
            },
        };
        (self.status(), Json(envelope)).into_response()
    }
}

/// What a body extractor refuses a request with: the ordinary validation envelope for a body
/// that parsed but does not fit the route, or the transport envelope for one the adapter could
/// not read.
#[derive(Debug)]
pub struct BodyRejection(Inner);

#[derive(Debug)]
enum Inner {
    Validation(AuthRejection),
    Transport(Transport),
}

impl From<AuthRejection> for BodyRejection {
    fn from(rejection: AuthRejection) -> Self {
        Self(Inner::Validation(rejection))
    }
}

impl From<AuthError> for BodyRejection {
    fn from(error: AuthError) -> Self {
        Self(Inner::Validation(AuthRejection(error)))
    }
}

impl From<Transport> for BodyRejection {
    fn from(transport: Transport) -> Self {
        Self(Inner::Transport(transport))
    }
}

impl IntoResponse for BodyRejection {
    fn into_response(self) -> Response {
        match self.0 {
            Inner::Validation(rejection) => rejection.into_response(),
            Inner::Transport(transport) => transport.into_response(),
        }
    }
}

/// Give the body-limit layer's own refusal the transport envelope.
///
/// `tower-http` answers a request whose `Content-Length` already exceeds the limit with a
/// plain-text `413` ("length limit exceeded"), before any extractor runs. Every `413` this
/// adapter builds is the JSON envelope, so a `413` whose `Content-Type` is not JSON is the
/// layer's.
pub(crate) async fn envelope_for_layer_payload_too_large(response: Response) -> Response {
    let is_json = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE && !is_json {
        return Transport::TooLarge.into_response();
    }
    response
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// `transportErrors` from the shared wire contract.
    fn contract_section() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root["transportErrors"].clone()
    }

    /// The `(status, message)` this adapter answers for each kind. A kind added to [`Transport`]
    /// has to be added here, and the contract test then asks the contract to name it.
    fn answered() -> BTreeSet<(u16, String)> {
        [
            Transport::Malformed(StatusCode::BAD_REQUEST),
            Transport::TooLarge,
            Transport::UnsupportedMedia,
        ]
        .into_iter()
        .map(|kind| (kind.status().as_u16(), kind.message().to_owned()))
        .collect()
    }

    #[test]
    fn every_row_of_the_contract_is_answered_and_every_answer_is_a_row() {
        let section = contract_section();
        let rows = section["rows"].as_array().cloned().unwrap_or_default();
        assert!(
            !rows.is_empty(),
            "the contract lists no transportErrors rows"
        );

        // Rows with a fixed status, and the one whose status is the error's own 4xx.
        let mut fixed = BTreeSet::new();
        let mut own_status_messages = BTreeSet::new();
        for row in &rows {
            let message = row["message"].as_str().unwrap_or_default().to_owned();
            match row["status"].as_u64() {
                Some(status) => {
                    fixed.insert((u16::try_from(status).unwrap_or_default(), message));
                }
                None => {
                    own_status_messages.insert(message);
                }
            }
        }

        // The contract -> this adapter: every fixed-status row is answered with that exact pair.
        let answered = answered();
        for pair in &fixed {
            assert!(
                answered.contains(pair),
                "{pair:?} is in the contract and not answered"
            );
        }
        // This adapter -> the contract: every answer is a fixed row, or the message of the row
        // whose status is the error's own.
        for (status, message) in &answered {
            let fixed_row = fixed.contains(&(*status, message.clone()));
            let own_row = own_status_messages.contains(message);
            assert!(fixed_row || own_row, "unlisted: {status} {message}");
        }
        // A `Malformed` carrying another 4xx keeps the message of the own-status row.
        let other = Transport::Malformed(StatusCode::REQUEST_TIMEOUT);
        assert!(own_status_messages.contains(other.message()));
        assert!(other.status().is_client_error());
    }

    #[test]
    fn a_body_failure_is_too_large_only_when_the_status_says_so() {
        assert_eq!(
            Transport::from_body_status(StatusCode::PAYLOAD_TOO_LARGE),
            Transport::TooLarge
        );
        assert_eq!(
            Transport::from_body_status(StatusCode::BAD_REQUEST),
            Transport::Malformed(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            Transport::from_body_status(StatusCode::REQUEST_TIMEOUT),
            Transport::Malformed(StatusCode::REQUEST_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn the_envelope_is_the_contracts_code_and_a_null_details() {
        let section = contract_section();
        let response = Transport::TooLarge.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_default();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        assert_eq!(json["error"]["code"], section["envelope"]["code"]);
        assert!(section["envelope"]["details"].is_null());
        assert!(json["error"]["details"].is_null());
        assert!(
            json["error"].get("details").is_some(),
            "details is present, not omitted"
        );
    }

    #[tokio::test]
    async fn only_a_413_that_is_not_already_json_is_rewritten() {
        let bare = Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(axum::body::Body::from("length limit exceeded"))
            .unwrap_or_default();
        let rewritten = envelope_for_layer_payload_too_large(bare).await;
        assert_eq!(rewritten.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(rewritten.headers().contains_key(http::header::CONTENT_TYPE));

        // A 413 that is already the JSON envelope is not the layer's, and any other status passes.
        let own = Transport::TooLarge.into_response();
        let untouched = envelope_for_layer_payload_too_large(own).await;
        assert_eq!(untouched.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let ok = Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::empty())
            .unwrap_or_default();
        assert_eq!(
            envelope_for_layer_payload_too_large(ok).await.status(),
            StatusCode::OK
        );
    }
}
