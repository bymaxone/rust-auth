//! Parity and wire-shape tests for the error model, exercised through the crate's
//! public API: the [`AuthErrorCode`] catalog (exact `auth.*` strings + HTTP statuses),
//! the internal-only remap, the `{ error: { code, message, details } }` envelope, and
//! the reduced client response shape. Kept as an integration test so the production
//! `error.rs` stays focused on the catalog itself.

use bymax_auth_types::{AuthError, AuthErrorCode, AuthErrorResponse, FieldError};

/// Every catalog code paired with its exact wire string and HTTP status. The table is
/// the executable mirror of the technical-specification error catalog (§15.3) — a code
/// whose serialization or status drifts from nest-auth breaks parity and fails here.
fn catalog() -> Vec<(AuthErrorCode, &'static str, u16)> {
    use AuthErrorCode::*;
    vec![
        (InvalidCredentials, "auth.invalid_credentials", 401),
        (AccountLocked, "auth.account_locked", 429),
        (AccountInactive, "auth.account_inactive", 403),
        (AccountSuspended, "auth.account_suspended", 403),
        (AccountBanned, "auth.account_banned", 403),
        (PendingApproval, "auth.pending_approval", 403),
        (TokenExpired, "auth.token_expired", 401),
        (TokenRevoked, "auth.token_revoked", 401),
        (TokenInvalid, "auth.token_invalid", 401),
        (RefreshTokenInvalid, "auth.refresh_token_invalid", 401),
        (SessionExpired, "auth.session_expired", 401),
        (SessionLimitReached, "auth.session_limit_reached", 409),
        (SessionNotFound, "auth.session_not_found", 404),
        (TokenMissing, "auth.token_missing", 401),
        (EmailAlreadyExists, "auth.email_already_exists", 409),
        (EmailNotVerified, "auth.email_not_verified", 403),
        (MfaRequired, "auth.mfa_required", 403),
        (MfaInvalidCode, "auth.mfa_invalid_code", 401),
        (MfaAlreadyEnabled, "auth.mfa_already_enabled", 409),
        (MfaNotEnabled, "auth.mfa_not_enabled", 400),
        (MfaSetupRequired, "auth.mfa_setup_required", 400),
        (MfaTempTokenInvalid, "auth.mfa_temp_token_invalid", 401),
        (RecoveryCodeInvalid, "auth.recovery_code_invalid", 401),
        (PasswordTooWeak, "auth.password_too_weak", 400),
        (
            PasswordResetTokenInvalid,
            "auth.password_reset_token_invalid",
            400,
        ),
        (
            PasswordResetTokenExpired,
            "auth.password_reset_token_expired",
            400,
        ),
        (OtpInvalid, "auth.otp_invalid", 401),
        (OtpExpired, "auth.otp_expired", 401),
        (OtpMaxAttempts, "auth.otp_max_attempts", 429),
        (InsufficientRole, "auth.insufficient_role", 403),
        (Forbidden, "auth.forbidden", 403),
        (InvalidInvitationToken, "auth.invalid_invitation_token", 400),
        (OauthFailed, "auth.oauth_failed", 401),
        (OauthEmailMismatch, "auth.oauth_email_mismatch", 409),
        (PlatformAuthRequired, "auth.platform_auth_required", 401),
        (Validation, "auth.validation", 400),
        (TooManyRequests, "auth.too_many_requests", 429),
        (Internal, "auth.internal", 500),
    ]
}

/// One instance of every [`AuthError`] variant, so the `code`/`http_status`/
/// `client_message`/`details` matches are exhaustively exercised.
fn all_errors() -> Vec<AuthError> {
    vec![
        AuthError::InvalidCredentials,
        AuthError::AccountLocked {
            retry_after_seconds: Some(300),
        },
        AuthError::AccountInactive,
        AuthError::AccountSuspended,
        AuthError::AccountBanned,
        AuthError::PendingApproval,
        AuthError::TokenExpired,
        AuthError::TokenRevoked,
        AuthError::TokenInvalid,
        AuthError::RefreshTokenInvalid,
        AuthError::SessionExpired,
        AuthError::SessionLimitReached,
        AuthError::SessionNotFound,
        AuthError::TokenMissing,
        AuthError::EmailAlreadyExists,
        AuthError::EmailNotVerified,
        AuthError::MfaRequired,
        AuthError::MfaInvalidCode,
        AuthError::MfaAlreadyEnabled,
        AuthError::MfaNotEnabled,
        AuthError::MfaSetupRequired,
        AuthError::MfaTempTokenInvalid,
        AuthError::RecoveryCodeInvalid,
        AuthError::PasswordTooWeak,
        AuthError::PasswordResetTokenInvalid,
        AuthError::PasswordResetTokenExpired,
        AuthError::OtpInvalid,
        AuthError::OtpExpired,
        AuthError::OtpMaxAttempts,
        AuthError::InsufficientRole,
        AuthError::Forbidden,
        AuthError::InvalidInvitationToken,
        AuthError::OauthFailed,
        AuthError::OauthEmailMismatch,
        AuthError::PlatformAuthRequired,
        AuthError::Validation {
            details: vec![FieldError {
                field: "email".to_owned(),
                message: "must be an email".to_owned(),
            }],
        },
        AuthError::TooManyRequests {
            retry_after_seconds: None,
        },
        AuthError::Internal(Box::<dyn std::error::Error + Send + Sync>::from("boom")),
    ]
}

#[test]
fn every_code_serializes_to_its_string_and_maps_to_its_status() {
    // Table-driven parity check: each code's `auth.*` string and HTTP status must match
    // the catalog exactly. The catalog covers all 38 codes.
    assert_eq!(catalog().len(), 38);
    for (code, wire, status) in catalog() {
        let json = serde_json::to_string(&code).unwrap_or_default();
        assert_eq!(json, format!("\"{wire}\""), "wrong string for {code:?}");
        assert_eq!(code.http_status(), status, "wrong status for {code:?}");
        // Each code also round-trips back from its string form.
        let parsed = serde_json::from_str::<AuthErrorCode>(&json).ok();
        assert_eq!(parsed, Some(code));
        // Every code carries a non-empty client message.
        assert!(!code.client_message().is_empty());
    }
}

#[test]
fn internal_only_codes_remap_to_token_invalid_on_the_wire() {
    // The three token sentinels must never reach a client; they collapse to
    // `token_invalid`, denying an attacker an expired-vs-revoked-vs-missing oracle.
    for code in [
        AuthErrorCode::TokenExpired,
        AuthErrorCode::TokenRevoked,
        AuthErrorCode::TokenMissing,
    ] {
        assert!(code.is_internal_only());
        assert_eq!(code.to_wire(), AuthErrorCode::TokenInvalid);
    }
    // A public code is its own wire form and is not internal-only.
    assert!(!AuthErrorCode::TokenInvalid.is_internal_only());
    assert_eq!(AuthErrorCode::Forbidden.to_wire(), AuthErrorCode::Forbidden);
}

#[test]
fn auth_error_exposes_code_status_and_message_for_every_variant() {
    // Walk one instance of every variant so the `code`/`http_status`/
    // `client_message`/`is_internal_only` arms are all exercised.
    for err in all_errors() {
        assert_eq!(err.http_status(), err.code().http_status());
        assert!(!err.client_message().is_empty());
        // Internal-only errors report the public (token_invalid) message.
        if err.is_internal_only() {
            assert_eq!(err.client_message(), "Invalid token");
        }
    }
}

#[test]
fn account_locked_details_carry_retry_after_in_camel_case() {
    // The lockout/throttle details must surface `retryAfterSeconds` (camelCase) so a
    // client can read the cooldown alongside the `Retry-After` header.
    let locked = AuthError::AccountLocked {
        retry_after_seconds: Some(42),
    };
    let details = locked.details().unwrap_or(serde_json::Value::Null);
    assert_eq!(details, serde_json::json!({ "retryAfterSeconds": 42 }));
    // A `None` cooldown yields no details object.
    let no_retry = AuthError::TooManyRequests {
        retry_after_seconds: None,
    };
    assert!(no_retry.details().is_none());
    // A code without structured data has no details.
    assert!(AuthError::Forbidden.details().is_none());
}

#[test]
fn validation_details_serialize_the_field_errors() {
    // Validation details must carry the per-field messages so the client can map each
    // failure back to its form field.
    let err = AuthError::Validation {
        details: vec![FieldError {
            field: "password".to_owned(),
            message: "too short".to_owned(),
        }],
    };
    let details = err.details().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        details,
        serde_json::json!([{ "field": "password", "message": "too short" }])
    );
}

#[test]
fn envelope_has_the_canonical_shape_and_uses_the_wire_code() {
    // The wire body must be exactly `{ error: { code, message, details } }`, and an
    // internal-only error must surface the remapped public code, never the sentinel.
    let env = AuthError::TokenExpired.to_envelope();
    let json = serde_json::to_value(&env).unwrap_or_default();
    assert_eq!(
        json,
        serde_json::json!({
            "error": { "code": "auth.token_invalid", "message": "Invalid token" }
        })
    );
    // A details-bearing error includes the structured payload under `error.details`.
    let locked = AuthError::AccountLocked {
        retry_after_seconds: Some(5),
    }
    .to_envelope();
    let locked_json = serde_json::to_value(&locked).unwrap_or_default();
    assert_eq!(
        locked_json,
        serde_json::json!({
            "error": {
                "code": "auth.account_locked",
                "message": "Account temporarily locked. Please try again in a few minutes.",
                "details": { "retryAfterSeconds": 5 }
            }
        })
    );
}

#[test]
fn reduced_response_uses_the_wire_code_and_round_trips() {
    // The client-facing `AuthErrorResponse` carries the remapped code + message and
    // (de)serializes losslessly.
    let resp = AuthError::TokenRevoked.to_response();
    assert_eq!(resp.code, AuthErrorCode::TokenInvalid);
    assert_eq!(resp.message, "Invalid token");
    let json = serde_json::to_string(&resp).unwrap_or_default();
    assert!(json.contains("\"auth.token_invalid\""));
    let back = serde_json::from_str::<AuthErrorResponse>(&json).ok();
    assert_eq!(back, Some(resp));
}

#[test]
fn display_is_a_log_string_distinct_from_the_client_message() {
    // The thiserror `Display` is a diagnostic for logs, never the client message — the
    // two are deliberately different surfaces.
    let err = AuthError::InvalidCredentials;
    assert_eq!(format!("{err}"), "invalid credentials");
    assert_eq!(err.client_message(), "Invalid email or password");
    // The internal variant's source is preserved for `tracing` but never serialized.
    let internal = AuthError::Internal(Box::<dyn std::error::Error + Send + Sync>::from("db"));
    assert_eq!(format!("{internal}"), "internal error");
    assert_eq!(internal.code(), AuthErrorCode::Internal);
}

#[test]
fn field_error_round_trips_with_camel_case() {
    // FieldError must (de)serialize cleanly for the validation details payload.
    let fe = FieldError {
        field: "email".to_owned(),
        message: "required".to_owned(),
    };
    let json = serde_json::to_string(&fe).unwrap_or_default();
    let back = serde_json::from_str::<FieldError>(&json).ok();
    assert_eq!(back, Some(fe));
}
