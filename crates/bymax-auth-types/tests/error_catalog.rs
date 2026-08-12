//! Parity and wire-shape tests for the error model, exercised through the crate's
//! public API: the [`AuthErrorCode`] catalog (exact `auth.*` strings), the HTTP status
//! each code answers, the internal-only remap, the `{ error: { code, message, details } }`
//! envelope, and the reduced client response shape. Kept as an integration test so the
//! production `error.rs` stays focused on the catalog itself.
//!
//! The code strings and the statuses are both checked against
//! `conformance/wire-contract.json` — the artifact nest-auth holds byte-identical — rather
//! than against a table written down here. See [`catalog`] for why that distinction is the
//! point of this file and not an implementation detail of it.

use bymax_auth_types::{AuthError, AuthErrorCode, AuthErrorResponse, FieldError};
use std::collections::BTreeMap;

/// Every catalog code paired with its exact wire string.
///
/// The HTTP status is deliberately **not** a column here. It is read from the shared contract
/// instead (see [`contract_statuses`]), because a status written down in this file is only ever
/// compared against itself. This table used to carry a status column, under a doc comment
/// claiming that "a code whose serialization or status drifts from nest-auth breaks parity and
/// fails here" — it did not. Thirteen codes answered a different status on each implementation
/// while both suites stayed green, because each side was self-consistent and neither read the
/// other. A parity test that reads only its own side is not a parity test.
fn catalog() -> Vec<(AuthErrorCode, &'static str)> {
    use AuthErrorCode::*;
    vec![
        (InvalidCredentials, "auth.invalid_credentials"),
        (AccountLocked, "auth.account_locked"),
        (AccountInactive, "auth.account_inactive"),
        (AccountSuspended, "auth.account_suspended"),
        (AccountBanned, "auth.account_banned"),
        (PendingApproval, "auth.pending_approval"),
        (TokenExpired, "auth.token_expired"),
        (TokenRevoked, "auth.token_revoked"),
        (TokenInvalid, "auth.token_invalid"),
        (RefreshTokenInvalid, "auth.refresh_token_invalid"),
        (SessionNotFound, "auth.session_not_found"),
        (TokenMissing, "auth.token_missing"),
        (EmailAlreadyExists, "auth.email_already_exists"),
        (EmailNotVerified, "auth.email_not_verified"),
        (EmailChangeTokenInvalid, "auth.email_change_token_invalid"),
        (MfaRequired, "auth.mfa_required"),
        (MfaInvalidCode, "auth.mfa_invalid_code"),
        (MfaAlreadyEnabled, "auth.mfa_already_enabled"),
        (MfaNotEnabled, "auth.mfa_not_enabled"),
        (MfaSetupRequired, "auth.mfa_setup_required"),
        (MfaTempTokenInvalid, "auth.mfa_temp_token_invalid"),
        (MfaStateConflict, "auth.mfa_state_conflict"),
        (PasswordCompromised, "auth.password_compromised"),
        (
            PasswordResetTokenInvalid,
            "auth.password_reset_token_invalid",
        ),
        (OtpInvalid, "auth.otp_invalid"),
        (OtpExpired, "auth.otp_expired"),
        (OtpMaxAttempts, "auth.otp_max_attempts"),
        (InsufficientRole, "auth.insufficient_role"),
        (Forbidden, "auth.forbidden"),
        (UntrustedOrigin, "auth.untrusted_origin"),
        (ReauthenticationRequired, "auth.reauthentication_required"),
        (InvalidInvitationToken, "auth.invalid_invitation_token"),
        (OauthFailed, "auth.oauth_failed"),
        (OauthEmailMismatch, "auth.oauth_email_mismatch"),
        (PlatformAuthRequired, "auth.platform_auth_required"),
        (Validation, "auth.validation"),
        (TooManyRequests, "auth.too_many_requests"),
        (Internal, "auth.internal"),
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
        AuthError::MfaStateConflict,
        AuthError::PasswordCompromised,
        AuthError::PasswordResetTokenInvalid,
        AuthError::OtpInvalid,
        AuthError::OtpExpired,
        AuthError::OtpMaxAttempts,
        AuthError::InsufficientRole,
        AuthError::Forbidden,
        AuthError::UntrustedOrigin,
        AuthError::ReauthenticationRequired,
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
fn every_code_serializes_to_its_string_and_round_trips() {
    // Table-driven wire-string check: each code's `auth.*` string must match the catalog
    // exactly. The catalog covers all 38 codes; the status each one answers is asserted
    // against the shared contract in `every_code_answers_the_wire_status_the_contract_pins`.
    assert_eq!(catalog().len(), 38);
    for (code, wire) in catalog() {
        let json = serde_json::to_string(&code).unwrap_or_default();
        assert_eq!(json, format!("\"{wire}\""), "wrong string for {code:?}");
        // Each code also round-trips back from its string form.
        let parsed = serde_json::from_str::<AuthErrorCode>(&json).ok();
        assert_eq!(parsed, Some(code));
        // Every code carries a non-empty client message.
        assert!(!code.client_message().is_empty());
    }
}

#[test]
fn the_table_lists_every_variant_of_the_enum() {
    // Compile-time anchor. The match below is exhaustive over `AuthErrorCode`, so adding a
    // variant to the enum stops the build here until someone comes back and adds it to
    // `catalog()` as well. Without it the table is complete only by habit — and a code
    // rust-auth can emit that nest-auth has never heard of is the same drift in a different
    // column from the one that caused this file to be rewritten.
    use AuthErrorCode::*;
    for (code, _) in catalog() {
        match code {
            InvalidCredentials
            | AccountLocked
            | AccountInactive
            | AccountSuspended
            | AccountBanned
            | PendingApproval
            | TokenExpired
            | TokenRevoked
            | TokenInvalid
            | RefreshTokenInvalid
            | SessionNotFound
            | TokenMissing
            | EmailAlreadyExists
            | EmailNotVerified
            | EmailChangeTokenInvalid
            | MfaRequired
            | MfaInvalidCode
            | MfaAlreadyEnabled
            | MfaNotEnabled
            | MfaSetupRequired
            | MfaTempTokenInvalid
            | MfaStateConflict
            | PasswordCompromised
            | PasswordResetTokenInvalid
            | OtpInvalid
            | OtpExpired
            | OtpMaxAttempts
            | InsufficientRole
            | Forbidden
            | UntrustedOrigin
            | ReauthenticationRequired
            | InvalidInvitationToken
            | OauthFailed
            | OauthEmailMismatch
            | PlatformAuthRequired
            | Validation
            | TooManyRequests
            | Internal => {}
        }
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
    // The OTP sentinels collapse the same way, onto `otp_invalid`. `forgot_password` answers
    // uniformly whether or not an address exists, but only writes an OTP record when it does —
    // so an absent record answering differently from a wrong code turned that uniform answer
    // definitive after one extra request.
    for code in [AuthErrorCode::OtpExpired, AuthErrorCode::OtpMaxAttempts] {
        assert!(code.is_internal_only());
        assert_eq!(code.to_wire(), AuthErrorCode::OtpInvalid);
        // …including the status, or the oracle survives as 429-vs-401.
        assert_eq!(code.to_wire().http_status(), 401);
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
        // The wire code decides both, because both are part of the answer a client sees.
        assert_eq!(err.http_status(), err.code().to_wire().http_status());
        assert!(!err.client_message().is_empty());
        // Whether the error is internal-only is ASSERTED here, and the branch below is keyed off
        // `to_wire` instead. It used to be keyed off `is_internal_only()` itself — so a version
        // of that method answering `false` for everything did not fail this test, it *skipped*
        // the two assertions inside, and the suite stayed green. A check whose condition is the
        // function under test cannot fail when that function is wrong; it only stops running.
        let collapses = err.code() != err.code().to_wire();
        assert_eq!(err.is_internal_only(), collapses);
        if collapses {
            // An internal-only error reports the message of the code it collapses onto, never its
            // own — the message would give back exactly what the collapse took away.
            assert_eq!(err.client_message(), err.code().to_wire().client_message());
            assert_ne!(err.client_message(), err.code().client_message());
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
    //
    // `details` is `null` here, not absent: the shared contract declares the key present with
    // an `object|null` value, and one client library decodes both backends. This assertion used
    // to omit it while the comment above already said "exactly" — the two disagreed, and the
    // comment was right.
    let env = AuthError::TokenExpired.to_envelope();
    let json = serde_json::to_value(&env).unwrap_or_default();
    assert_eq!(
        json,
        serde_json::json!({
            "error": {
                "code": "auth.token_invalid",
                "message": "Invalid token",
                "details": null
            }
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

/// Parse the shared cross-implementation contract.
///
/// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which can
/// back the same deployment. Reading it here rather than repeating its values means a code — or
/// a status — that moves on one side turns that side red, instead of surfacing as a client that
/// decodes one backend and not the other.
///
/// A missing or unparseable file yields `null`, which empties every accessor below and fails the
/// set comparisons loudly rather than vacuously passing them.
fn contract_root() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)
}

/// Read a string array from `errorCatalog.{key}` in the shared contract.
///
/// Panics on an empty list, following the precedent `bymax-auth-core`'s store tests set for the
/// same hazard: a contract that failed to load reads as "nothing to check", and an assertion that
/// runs over nothing reports the same green as one that ran and passed.
fn contract_codes(key: &str) -> Vec<String> {
    let codes: Vec<String> = contract_root()
        .get("errorCatalog")
        .and_then(|s| s.get(key))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !codes.is_empty(),
        "the wire contract named no codes under `errorCatalog.{key}` — it did not load"
    );
    codes
}

/// Read the `errorCatalog.statuses` map — `auth.*` code to HTTP status — from the shared
/// contract.
///
/// These are **wire** statuses: the status a caller actually receives. An internal-only code
/// therefore carries the status of the public code it collapses onto, not one of its own, which
/// is why every assertion against this map goes through [`AuthErrorCode::to_wire`] first.
/// Panics on an empty map, for the reason given on [`contract_codes`].
fn contract_statuses() -> BTreeMap<String, u16> {
    let statuses: BTreeMap<String, u16> = contract_root()
        .get("errorCatalog")
        .and_then(|s| s.get("statuses"))
        .and_then(serde_json::Value::as_object)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(code, status)| {
                    let status = status.as_u64().and_then(|s| u16::try_from(s).ok())?;
                    Some((code.clone(), status))
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !statuses.is_empty(),
        "the wire contract pinned no statuses under `errorCatalog.statuses` — it did not load"
    );
    statuses
}

#[test]
fn the_catalog_names_exactly_the_codes_the_shared_contract_does() {
    // One vocabulary across both implementations: a code present on one side only is a client
    // branch that never fires against the other, and a code neither side emits is a branch that
    // never fires at all — which is what five of them were before this check existed.
    let mut expected = contract_codes("codes");
    let mut actual: Vec<String> = catalog()
        .iter()
        .filter_map(|(code, _)| serde_json::to_value(code).ok())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    expected.sort();
    actual.sort();
    assert_eq!(
        actual, expected,
        "the catalog drifted from the shared contract"
    );
}

#[test]
fn the_internal_only_codes_are_exactly_the_ones_the_contract_names() {
    // Each collapses onto a public code so a caller cannot tell "valid until revoked" from
    // "never valid", or "no record was ever written here" from "wrong code". The set has to
    // match on both sides, or one backend hands back a distinction the other withholds.
    let expected = contract_codes("internalOnly");
    let mut actual: Vec<String> = catalog()
        .iter()
        .filter(|(code, _)| code.is_internal_only())
        .filter_map(|(code, _)| serde_json::to_value(code).ok())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    actual.sort();
    let mut expected = expected;
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn every_code_answers_the_wire_status_the_contract_pins() {
    // The status is as much of the contract as the code string — a client switching on
    // `error.code` reaches the status line first, retrying a 4xx, backing off on a 429,
    // resolving a 409 — so it is checked against the same shared bytes nest-auth is checked
    // against. That is the whole repair: the previous version of this assertion read a column
    // in this file, so thirteen codes could and did answer differently on each side.
    //
    // `to_wire()` comes first deliberately. The contract pins what a caller receives, and an
    // internal-only code never reaches one under its own name.
    // `contract_statuses` refuses to return an empty map, so a contract that failed to load fails
    // here rather than letting the loop below pass over nothing.
    let statuses = contract_statuses();
    for (code, wire) in catalog() {
        assert_eq!(
            Some(code.to_wire().http_status()),
            statuses.get(wire).copied(),
            "wrong wire status for {wire}"
        );
    }
}

#[test]
fn the_contract_pins_a_status_for_exactly_the_codes_it_names() {
    // A code with no status and a status with no code are both drift — the first is a value no
    // gate covers, which is exactly how the thirteen diverged; the second is a row describing a
    // code that no longer exists. Compared against the contract's own code list and against the
    // enum's, so no one of the three can move without the other two.
    let pinned: Vec<String> = contract_statuses().into_keys().collect();
    let mut codes = contract_codes("codes");
    codes.sort();
    assert_eq!(
        pinned, codes,
        "errorCatalog.statuses and errorCatalog.codes name different codes"
    );
    let mut variants: Vec<String> = catalog()
        .iter()
        .map(|(_, wire)| (*wire).to_owned())
        .collect();
    variants.sort();
    assert_eq!(
        pinned, variants,
        "errorCatalog.statuses and AuthErrorCode name different codes"
    );
}

#[test]
fn the_otp_ceiling_sentinel_keeps_a_pre_wire_status_of_its_own() {
    // `auth.otp_max_attempts` is the one code whose own status differs from the one the contract
    // pins: 429 here, 401 there. Both are deliberate, and the contract is right to pin the 401 —
    // only a record that exists can reach an attempt ceiling, so answering 429 would hand back
    // through the status line exactly what `to_wire` removes from the body.
    assert_eq!(AuthErrorCode::OtpMaxAttempts.http_status(), 429);
    assert_eq!(AuthErrorCode::OtpMaxAttempts.to_wire().http_status(), 401);
    // No client can observe the 429: `AuthError::http_status` remaps before it reads the status,
    // so the sentinel value is reachable only from the code, for logs and internal control flow.
    assert_eq!(AuthError::OtpMaxAttempts.http_status(), 401);
    // The other four sentinels have nothing to hide by comparison — their own status is already
    // the one their public form answers, which is why the contract's table reads unremarkably
    // for them and why this one code needed the explanation above.
    for code in [
        AuthErrorCode::TokenExpired,
        AuthErrorCode::TokenRevoked,
        AuthErrorCode::TokenMissing,
        AuthErrorCode::OtpExpired,
    ] {
        assert_eq!(code.http_status(), code.to_wire().http_status());
    }
}
