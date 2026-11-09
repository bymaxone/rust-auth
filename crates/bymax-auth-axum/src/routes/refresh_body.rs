//! The optional JSON body that carries a refresh token (adapter routes layer).
//!
//! Refresh, logout, revoke-all and the platform pair read the caller's refresh token from the
//! cookie or from this body, depending on the delivery mode. A body the mode reads is held to one
//! rule everywhere: a missing field or JSON `null` means no token, a string of 1 to 2048
//! characters is the token, and anything else is refused before the route does anything. A
//! refused request repeats no part of the body.

use bymax_auth_core::config::TokenDelivery;
use bymax_auth_types::{AuthError, FieldError};
use http::StatusCode;
use serde_json::Value;

use crate::transport::{BodyRejection, Transport};

/// The most characters a body refresh token may have; the value is hashed before it is looked
/// up, so a longer one buys nothing but the bytes it costs to carry.
const MAX_TOKEN_CHARS: usize = 2048;

/// Shown when the body's `refreshToken` is present and not a string of 1 to 2048 characters.
const TOKEN_MESSAGE: &str = "refreshToken must be a string of 1 to 2048 characters.";

/// Whether the delivery mode takes the refresh token from the body: bearer and both do, cookie
/// reads the cookie only.
pub(crate) fn reads_body(delivery: TokenDelivery) -> bool {
    delivery != TokenDelivery::Cookie
}

/// The body-supplied refresh token, or `None` when the body carries none.
///
/// An empty body is no token. A non-empty body must be JSON the adapter can parse whichever mode
/// the deployment runs, since the same body is refused by the transport everywhere else. Only
/// when `reads_body` is true (the delivery mode takes the token from the body) is its content
/// held to the token rule: the root has to be an object, and `refreshToken` has to be absent,
/// `null`, or a string of 1 to 2048 characters. Where the mode reads the cookie, a value in the
/// body is ignored.
///
/// # Errors
///
/// "Malformed request" for a body that is not JSON, whose root is a bare value, or (when the body
/// is read) is not an object; `auth.validation` naming `refreshToken` for a token of the wrong
/// type or outside the length bounds.
pub(crate) fn parse_refresh_body(
    bytes: &[u8],
    reads_body: bool,
) -> Result<Option<String>, BodyRejection> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let malformed = || BodyRejection::from(Transport::Malformed(StatusCode::BAD_REQUEST));
    let root = serde_json::from_slice::<Value>(bytes).map_err(|_| malformed())?;
    let object = match root {
        Value::Object(object) => object,
        Value::Array(_) if !reads_body => return Ok(None),
        _ => return Err(malformed()),
    };
    if !reads_body {
        return Ok(None);
    }
    match object.get("refreshToken") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(token)) if within_bounds(token) => Ok(Some(token.clone())),
        Some(_) => Err(out_of_bounds()),
    }
}

/// Whether `token` is a string of 1 to 2048 characters, the bound every channel holds a refresh
/// token to.
pub(crate) fn within_bounds(token: &str) -> bool {
    (1..=MAX_TOKEN_CHARS).contains(&token.chars().count())
}

/// The refusal for a refresh token outside the bounds: `auth.validation` naming `refreshToken`,
/// repeating no part of the value.
pub(crate) fn out_of_bounds() -> BodyRejection {
    BodyRejection::from(AuthError::Validation {
        details: vec![FieldError {
            field: "refreshToken".to_owned(),
            message: TOKEN_MESSAGE.to_owned(),
        }],
    })
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    fn parse(body: &[u8], reads_body: bool) -> Result<Option<String>, StatusCode> {
        parse_refresh_body(body, reads_body).map_err(|rejection| rejection.into_response().status())
    }

    #[test]
    fn a_missing_field_and_null_and_an_empty_body_are_no_token() {
        for body in [
            &b""[..],
            b"{}",
            br#"{"refreshToken":null}"#,
            br#"{"other":1}"#,
        ] {
            assert_eq!(parse(body, true), Ok(None), "{body:?}");
        }
    }

    #[test]
    fn a_string_of_one_to_the_limit_is_the_token() {
        assert_eq!(
            parse(br#"{"refreshToken":"r"}"#, true),
            Ok(Some("r".to_owned()))
        );
        let longest = format!(r#"{{"refreshToken":"{}"}}"#, "x".repeat(MAX_TOKEN_CHARS));
        assert_eq!(
            parse(longest.as_bytes(), true),
            Ok(Some("x".repeat(MAX_TOKEN_CHARS)))
        );
    }

    #[test]
    fn a_token_outside_the_bounds_or_of_the_wrong_type_is_refused() {
        let too_long = format!(
            r#"{{"refreshToken":"{}"}}"#,
            "x".repeat(MAX_TOKEN_CHARS + 1)
        );
        let refused = [
            br#"{"refreshToken":""}"#.to_vec(),
            too_long.into_bytes(),
            br#"{"refreshToken":5}"#.to_vec(),
            br#"{"refreshToken":true}"#.to_vec(),
            br#"{"refreshToken":{"a":1}}"#.to_vec(),
            br#"{"refreshToken":["a"]}"#.to_vec(),
        ];
        for body in &refused {
            assert_eq!(parse(body, true), Err(StatusCode::BAD_REQUEST));
        }
    }

    #[test]
    fn the_length_is_counted_in_characters() {
        let token = "é".repeat(MAX_TOKEN_CHARS);
        let body = format!(r#"{{"refreshToken":"{token}"}}"#);
        assert_eq!(parse(body.as_bytes(), true), Ok(Some(token)));
    }

    #[test]
    fn a_body_that_is_not_an_object_is_refused_where_it_is_read() {
        for body in [
            &b"[]"[..],
            br#"["a"]"#,
            b"\"abc\"",
            b"42",
            b"true",
            b"null",
            b"{ not json",
        ] {
            assert_eq!(parse(body, true), Err(StatusCode::BAD_REQUEST), "{body:?}");
        }
    }

    #[test]
    fn where_the_body_is_not_read_only_its_syntax_is_checked() {
        // The cookie carries the token, so a value in the body is ignored, as are an array root and
        // bad bounds; a body no parser accepts is still refused.
        for body in [
            &br#"{"refreshToken":5}"#[..],
            br#"{"refreshToken":""}"#,
            b"[]",
            b"{}",
        ] {
            assert_eq!(parse(body, false), Ok(None), "{body:?}");
        }
        for body in [&b"{ not json"[..], b"\"abc\"", b"42"] {
            assert_eq!(parse(body, false), Err(StatusCode::BAD_REQUEST), "{body:?}");
        }
    }
}
