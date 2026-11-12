//! Unit tests of the error model: the wire envelope against the shared contract, and the
//! exhaustive anchor over `AuthErrorCode`, which has to live in the defining crate because the
//! enum is `#[non_exhaustive]` everywhere else.

use super::*;

#[test]
fn every_code_is_named_in_an_exhaustive_match() {
    // Compile-time anchor. `AuthErrorCode` is `#[non_exhaustive]`, which only binds other
    // crates, so this match inside the defining crate stays exhaustive: adding a variant
    // stops the build here until it is also added to `catalog()` in
    // `tests/error_catalog.rs`, which the shared contract is compared against. The match must
    // stay exhaustive: a closed enum of ~50 codes is one decision whose length is the enum's, so a
    // wildcard arm would trade the compile-time guarantee for a line count.
    use AuthErrorCode::*;
    let named = |code: AuthErrorCode| match code {
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
        | ApiKeyInvalid
        | ApiKeyScopeInsufficient
        | ApiKeyNotFound
        | Validation
        | TooManyRequests
        | WorkspaceRequired
        | WorkspaceNotFound
        | InsufficientWorkspaceRole
        | LastOwner
        | AlreadyMember
        | InvitationEmailMismatch
        | RegistrationClosed
        | WorkspaceLimitReached
        | WorkspacePendingDeletion
        | Internal => true,
    };
    assert!(named(AuthErrorCode::Internal));
}

#[test]
fn the_error_envelope_matches_the_shared_wire_contract() {
    // `conformance/wire-contract.json` is held byte-identical by nest-auth, and one client
    // library decodes both backends. The section is asserted against a REAL serialized
    // error, not against the struct definition: the shape a reader sees is the JSON, and
    // `skip_serializing_if` on a field is invisible in the type.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    let shape = root
        .get("errorEnvelope")
        .and_then(|e| e.get("shape"))
        .and_then(|s| s.get("error"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert!(
        shape.is_object(),
        "the wire contract declared no `errorEnvelope.shape.error` — it did not load"
    );
    assert_eq!(
        shape.get("code").and_then(serde_json::Value::as_str),
        Some("string")
    );
    assert_eq!(
        shape.get("message").and_then(serde_json::Value::as_str),
        Some("string")
    );
    // `object|null`, not `object?`: the key is always there.
    assert_eq!(
        shape.get("details").and_then(serde_json::Value::as_str),
        Some("object|null")
    );

    // An error carrying no details still emits the key, as null. Omitting it is the
    // divergence this test exists for: `undefined` and `null` are different values to the
    // shared client, and a key that is sometimes absent makes every reader handle two
    // shapes for one meaning.
    let envelope = AuthError::InvalidCredentials.to_envelope();
    let json: serde_json::Value =
        serde_json::to_value(&envelope).unwrap_or(serde_json::Value::Null);
    let body = json
        .get("error")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert!(body.is_object(), "the envelope has no `error` object");
    for field in ["code", "message", "details"] {
        assert!(
            body.get(field).is_some(),
            "`error.{field}` is named in the wire contract but absent from the JSON"
        );
    }
    assert_eq!(body.get("details"), Some(&serde_json::Value::Null));
    assert!(body.get("code").is_some_and(serde_json::Value::is_string));
    assert!(
        body.get("message")
            .is_some_and(serde_json::Value::is_string)
    );

    // …and an error that DOES carry details puts an object there, so the `object|null`
    // union is pinned in both directions.
    let envelope = AuthError::AccountLocked {
        retry_after_seconds: Some(300),
    }
    .to_envelope();
    let json: serde_json::Value =
        serde_json::to_value(&envelope).unwrap_or(serde_json::Value::Null);
    let details = json
        .get("error")
        .and_then(|error| error.get("details"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert!(details.is_object(), "structured details are not an object");
}
