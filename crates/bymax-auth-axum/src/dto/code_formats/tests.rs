//! Which second-factor code shapes each request body accepts. The cases run through the real
//! DTOs, so a validator that is not attached to its field is caught here.

use garde::Validate;

use crate::dto::{MfaChallengeDto, MfaDisableDto, MfaRegenerateRecoveryCodesDto, MfaVerifyDto};

/// Six-character strings that are not six ASCII digits, and digit runs of the wrong length.
const NOT_A_TOTP: &[&str] = &[
    "12345a",
    "abcdef",
    "12 456",
    " 12345",
    "12345 ",
    "+12345",
    "１２３４５６",
    // A trailing line break: `^\d{6}$` in JavaScript refuses it, so this side must too.
    "123456\n",
    "12345",
    "1234567",
    "",
];

#[test]
fn the_totp_only_endpoints_take_six_ascii_digits_and_nothing_else() {
    let verify = |code: &str| {
        MfaVerifyDto {
            code: code.to_owned(),
        }
        .validate()
        .is_ok()
    };
    let disable = |code: &str| {
        MfaDisableDto {
            code: code.to_owned(),
        }
        .validate()
        .is_ok()
    };
    let regenerate = |code: &str| {
        MfaRegenerateRecoveryCodesDto {
            code: code.to_owned(),
        }
        .validate()
        .is_ok()
    };
    for code in ["123456", "000000", "999999"] {
        assert!(verify(code) && disable(code) && regenerate(code), "{code}");
    }
    for code in NOT_A_TOTP {
        assert!(!verify(code), "verify-enable accepted {code:?}");
        assert!(!disable(code), "disable accepted {code:?}");
        assert!(!regenerate(code), "recovery-codes accepted {code:?}");
    }
}

#[test]
fn the_challenge_takes_a_totp_or_a_recovery_code() {
    let accepted = |code: &str| {
        MfaChallengeDto {
            mfa_temp_token: None,
            code: code.to_owned(),
        }
        .validate()
        .is_ok()
    };
    for code in [
        "123456",
        "A1B2-C3D4-E5F6-0789-ABCD-EF01",
        "a1b2-c3d4-e5f6-0789-abcd-ef01",
        "0000-0000-0000-0000-0000-0000",
    ] {
        assert!(accepted(code), "{code}");
    }
}

#[test]
fn the_challenge_refuses_everything_that_is_neither() {
    let accepted = |code: &str| {
        MfaChallengeDto {
            mfa_temp_token: None,
            code: code.to_owned(),
        }
        .validate()
        .is_ok()
    };
    for code in [
        // Six characters that are hex but not digits are not a TOTP code.
        "abcdef",
        "12345a",
        // The right characters in the wrong shape.
        "A1B2C3D4E5F60789ABCDEF01",
        "A1B2-C3D4-E5F6-0789-ABCD",
        "A1B2-C3D4-E5F6-0789-ABCD-EF01-2345",
        "A1B2-C3D4-E5F6-0789-ABCD-EF0",
        "A1B2_C3D4_E5F6_0789_ABCD_EF01",
        "G1B2-C3D4-E5F6-0789-ABCD-EF01",
        " A1B2-C3D4-E5F6-0789-ABCD-EF01",
        "A1B2-C3D4-E5F6-0789-ABCD-EF01\n",
        // Over the 29-character ceiling, and empty.
        "A1B2-C3D4-E5F6-0789-ABCD-EF01X",
        "",
    ] {
        assert!(!accepted(code), "the challenge accepted {code:?}");
    }
}
