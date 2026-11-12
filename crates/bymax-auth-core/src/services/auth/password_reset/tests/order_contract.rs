//! The order of the checks on a password reset against `passwordResetOrder` of the shared contract
//! (layer: core services, test support).
//!
//! Each step the contract lists is driven through `reset_password`, and the wire codes its
//! requests answer are compared with the codes the step names, as sets in both directions: a code
//! the step names that no request here answers fails, and so does an answer the step does not
//! name. Steps are compared by position, so a step the contract adds, drops or reorders fails too.

use std::collections::BTreeSet;

use super::*;

const EMAIL: &str = "order@example.com";

/// Under the deployment floor, and refused by the default screen as well: a request carrying it
/// shows which of the two judges first.
const SHORT: &str = "password123";
/// Past the floor and refused by the default screen.
const KNOWN: &str = "password1234567";
/// Past the floor and accepted by the screen.
const GOOD: &str = "glidingwalnut42";

/// One request's proofs, as `(token, otp, verified_token)`.
type Proofs<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>);

fn section() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["passwordResetOrder"].clone()
}

/// The `auth.*` codes a sentence of the contract names.
fn codes_named(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .filter(|word| word.starts_with("auth."))
        .map(|word| word.trim_end_matches('.').to_owned())
        .collect()
}

/// The code a caller is answered for `outcome`, or `ok`.
fn wire(outcome: &Result<(), AuthError>) -> String {
    let code = outcome.as_ref().err().map(|error| error.code().to_wire());
    code.and_then(|code| serde_json::to_value(code).ok())
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "ok".to_owned())
}

fn input(new_password: &str, (token, otp, verified): Proofs<'_>) -> ResetPasswordInput {
    ResetPasswordInput {
        email: EMAIL.to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: new_password.to_owned(),
        token: token.map(str::to_owned),
        otp: otp.map(str::to_owned),
        verified_token: verified.map(str::to_owned),
    }
}

async fn reset(h: &Harness, new_password: &str, proofs: Proofs<'_>) -> Result<(), AuthError> {
    h.engine
        .reset_password(input(new_password, proofs), &ctx())
        .await
}

/// Step 1: more than one proof, none, or one the configured method does not take, whatever the
/// new password is.
async fn classify_answers() -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let (Some(otp), Some(token)) = (otp_harness(), token_harness()) else {
        return seen;
    };
    let verified = "v".repeat(64);
    let shapes: [(&Harness, Proofs<'_>); 5] = [
        (&otp, (None, None, None)),
        (&otp, (None, Some("123456"), Some(&verified))),
        (&otp, (Some("t"), None, None)),
        (&token, (None, Some("123456"), None)),
        (&token, (None, None, Some(&verified))),
    ];
    for password in [SHORT, KNOWN, GOOD] {
        for (h, proofs) in shapes {
            seen.insert(wire(&reset(h, password, proofs).await));
        }
    }
    seen
}

/// Step 2: a usable proof and a refused password, the floor before the screen. A refused password
/// consumes neither a token nor an OTP: each still completes the reset afterwards.
async fn judge_answers() -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let (Some(th), Some(oh)) = (token_harness(), otp_harness()) else {
        return seen;
    };
    let screened = th.engine.passwords().assert_not_compromised(SHORT).await;
    assert!(matches!(screened, Err(AuthError::PasswordCompromised)));
    let id = th.seed(SeedUser::active(EMAIL, "old-pw")).await;
    let token = "c".repeat(64);
    let context = ResetContext {
        user_id: id,
        email: EMAIL.to_owned(),
        tenant_id: "t1".to_owned(),
        password_fingerprint: String::new(),
    };
    assert!(th.stores.put_token(&token, &context, 600).await.is_ok());
    let _ = oh.seed(SeedUser::active(EMAIL, "old-pw")).await;
    let identifier = oh.engine.hashed_identifier("t1", EMAIL);
    let otp = oh.engine.otp();
    let stored = otp.store(OtpPurpose::PasswordReset, &identifier, "123456", 600);
    assert!(stored.await.is_ok());
    for password in [SHORT, KNOWN] {
        seen.insert(wire(
            &reset(&th, password, (Some(&token), None, None)).await,
        ));
        seen.insert(wire(
            &reset(&oh, password, (None, Some("123456"), None)).await,
        ));
    }
    let by_token = reset(&th, GOOD, (Some(&token), None, None)).await;
    assert!(by_token.is_ok(), "a refused password consumed the token");
    let by_otp = reset(&oh, GOOD, (None, Some("123456"), None)).await;
    assert!(by_otp.is_ok(), "a refused password consumed the OTP");
    seen
}

/// Step 3: a token proof that is not valid, and every OTP failure — an absent record (which is
/// what an expired one is once its TTL has run), a wrong code, and the attempt ceiling.
async fn spend_answers() -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let (Some(th), Some(oh)) = (token_harness(), otp_harness()) else {
        return seen;
    };
    let unknown = "0".repeat(64);
    seen.insert(wire(&reset(&th, GOOD, (Some(&unknown), None, None)).await));
    seen.insert(wire(&reset(&oh, GOOD, (None, None, Some(&unknown))).await));
    let identifier = oh.engine.hashed_identifier("t1", EMAIL);
    let otp = oh.engine.otp();
    let stored = otp.store(OtpPurpose::PasswordReset, &identifier, "123456", 600);
    assert!(stored.await.is_ok());
    // Wrong codes until well past the ceiling: the record answers a wrong code, then the ceiling,
    // then is gone. Each is told apart internally and never on the wire.
    let mut internal = Vec::new();
    for _ in 0..10 {
        let outcome = reset(&oh, GOOD, (None, Some("654321"), None)).await;
        internal.extend(outcome.as_ref().err().map(AuthError::code));
        seen.insert(wire(&outcome));
    }
    let expected = [
        bymax_auth_types::AuthErrorCode::OtpInvalid,
        bymax_auth_types::AuthErrorCode::OtpMaxAttempts,
        bymax_auth_types::AuthErrorCode::OtpExpired,
    ];
    assert!(
        expected.iter().all(|code| internal.contains(code)),
        "{internal:?}"
    );
    seen
}

#[tokio::test]
async fn each_step_answers_exactly_the_codes_the_contract_names_for_it() {
    let steps: Vec<String> = section()["steps"]
        .as_array()
        .map(|steps| {
            steps
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let observed = [
        classify_answers().await,
        judge_answers().await,
        spend_answers().await,
    ];
    assert_eq!(steps.len(), observed.len(), "{steps:?}");
    for (index, (step, seen)) in steps.iter().zip(&observed).enumerate() {
        assert!(step.starts_with(&format!("{}. ", index + 1)), "{step}");
        assert_eq!(&codes_named(step), seen, "step {}: {step}", index + 1);
    }
}

#[test]
fn the_section_states_the_steps_and_their_reason_and_nothing_else() {
    // The reason's two claims are what the steps above drive: a request with no usable proof is
    // answered before the password is judged, and a refused password spends no proof.
    let section = section();
    let keys: BTreeSet<&str> = section
        .as_object()
        .map(|map| {
            map.keys()
                .map(String::as_str)
                .filter(|key| !key.starts_with('$'))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(keys, BTreeSet::from(["reason", "steps"]));
    let reason = section["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("never reaches the password policy"),
        "{reason}"
    );
    assert!(
        reason.contains("never consumes a single-use proof"),
        "{reason}"
    );
}
