//! The text rules, against values JavaScript was run on, and through every request body that
//! carries an email so a field that is not wired to the rule is caught.

use garde::Validate;
use serde_json::json;

use super::{normalize, not_blank};
use crate::dto::{
    ChangeEmailDto, CreateInvitationDto, ForgotPasswordDto, LoginDto, PlatformLoginDto,
    RegisterDto, ResendOtpDto, ResendVerificationDto, ResetPasswordDto, RevokeInvitationDto,
    VerifyEmailDto, VerifyOtpDto,
};

#[test]
fn trim_and_lowercase_match_what_javascript_returned() {
    // Each pair was produced by `value.trim().toLowerCase()` in Node.
    for (raw, expected) in [
        ("  a@e.com ", "a@e.com"),
        ("\u{FEFF}a@e.com", "a@e.com"),
        ("a@e.com\u{0085}", "a@e.com\u{0085}"),
        ("\u{0085}a@e.com", "\u{0085}a@e.com"),
        ("\u{00A0}a@e.com\u{3000}", "a@e.com"),
        ("\u{2028}a@e.com\u{2029}", "a@e.com"),
        ("A@E.COM", "a@e.com"),
        ("İ@E.COM", "i\u{307}@e.com"),
        ("a@e.com\u{200B}", "a@e.com\u{200B}"),
        ("\u{180E}a@e.com", "\u{180E}a@e.com"),
    ] {
        assert_eq!(normalize(raw), expected, "{raw:?}");
    }
}

#[test]
fn lowercasing_matches_what_javascript_returned_on_the_hard_cases() {
    // Each pair was produced by `value.toLowerCase()` in Node. The cases are the ones where a
    // lowercase mapping is not a simple one-to-one table lookup.
    for (raw, expected) in [
        // U+0130 lowercases to `i` plus a combining dot above.
        ("\u{0130}@e.com", "i\u{0307}@e.com"),
        // Final sigma is contextual: word-final gives `ς`, anywhere else `σ`, and a case-ignorable
        // character such as `.` does not end the word.
        ("A\u{03A3}@e.com", "a\u{03C2}@e.com"),
        ("A\u{03A3}B@e.com", "a\u{03C3}b@e.com"),
        ("\u{03A3}@e.com", "\u{03C3}@e.com"),
        ("\u{03A3}A@e.com", "\u{03C3}a@e.com"),
        ("A\u{03A3}.B@e.com", "a\u{03C3}.b@e.com"),
        ("A\u{03A3} @e.com", "a\u{03C2} @e.com"),
        // Capital sharp s, the Kelvin sign, the ohm and angstrom signs.
        ("\u{1E9E}@e.com", "\u{00DF}@e.com"),
        ("\u{212A}@e.com", "k@e.com"),
        ("\u{2126}@e.com", "\u{03C9}@e.com"),
        ("\u{212B}@e.com", "\u{00E5}@e.com"),
        // Full-width Latin capitals map to full-width small letters, not to ASCII.
        (
            "\u{FF21}\u{FF22}\u{FF23}@e.com",
            "\u{FF41}\u{FF42}\u{FF43}@e.com",
        ),
        ("\u{1E9E}\u{03A3}@e.com", "\u{00DF}\u{03C2}@e.com"),
        // Already lower case, and a character with no lower-case form.
        ("\u{00DF}@e.com", "\u{00DF}@e.com"),
    ] {
        assert_eq!(normalize(raw), expected, "{raw:?}");
    }
}

#[test]
fn blankness_matches_what_javascript_returned() {
    // `!/\S/.test(value)` in Node: true means blank.
    for (value, blank) in [
        ("   ", true),
        ("\t\n", true),
        ("\u{FEFF}", true),
        ("\u{00A0}", true),
        ("\u{0085}", false),
        ("\u{200B}", false),
        ("a", false),
        (" a ", false),
    ] {
        assert_eq!(not_blank(value, &()).is_err(), blank, "{value:?}");
    }
}

/// Deserialize `body` into `T`, validate it, and return the email it holds through `email`.
fn email_after<T>(body: serde_json::Value, email: fn(&T) -> &str) -> Option<String>
where
    T: serde::de::DeserializeOwned + Validate<Context = ()>,
{
    let dto: T = serde_json::from_value(body).ok()?;
    dto.validate().ok()?;
    Some(email(&dto).to_owned())
}

#[test]
fn every_email_field_is_trimmed_and_lowercased_before_it_is_validated() {
    let padded = "  User@Example.COM  ";
    let want = Some("user@example.com".to_owned());
    let pw = "glidingwalnut42";
    assert_eq!(
        email_after::<RegisterDto>(
            json!({ "email": padded, "password": pw, "name": "Nm", "tenantId": "t1" }),
            |d| &d.email
        ),
        want
    );
    assert_eq!(
        email_after::<LoginDto>(
            json!({ "email": padded, "password": pw, "tenantId": "t1" }),
            |d| &d.email
        ),
        want
    );
    assert_eq!(
        email_after::<ForgotPasswordDto>(json!({ "email": padded, "tenantId": "t1" }), |d| &d
            .email),
        want
    );
    assert_eq!(
        email_after::<ResendOtpDto>(json!({ "email": padded, "tenantId": "t1" }), |d| &d.email),
        want
    );
    assert_eq!(
        email_after::<ResendVerificationDto>(json!({ "email": padded, "tenantId": "t1" }), |d| &d
            .email),
        want
    );
    assert_eq!(
        email_after::<PlatformLoginDto>(json!({ "email": padded, "password": pw }), |d| &d.email),
        want
    );
    assert_eq!(
        email_after::<ChangeEmailDto>(json!({ "newEmail": padded, "currentPassword": pw }), |d| &d
            .new_email),
        want
    );
    assert_eq!(
        email_after::<ResetPasswordDto>(
            json!({ "email": padded, "newPassword": pw, "otp": "123456", "tenantId": "t1" }),
            |d| &d.email
        ),
        want
    );
    assert_eq!(
        email_after::<VerifyOtpDto>(
            json!({ "email": padded, "otp": "123456", "tenantId": "t1" }),
            |d| &d.email
        ),
        want
    );
    assert_eq!(
        email_after::<VerifyEmailDto>(
            json!({ "email": padded, "otp": "123456", "tenantId": "t1" }),
            |d| &d.email
        ),
        want
    );
    assert_eq!(
        email_after::<CreateInvitationDto>(json!({ "email": padded, "role": "USER" }), |d| &d
            .email),
        want
    );
    assert_eq!(
        email_after::<RevokeInvitationDto>(json!({ "email": padded }), |d| &d.email),
        want
    );
}

#[test]
fn a_platform_password_of_only_whitespace_is_refused_and_any_other_is_not() {
    let accepted = |password: &str| {
        email_after::<PlatformLoginDto>(
            json!({ "email": "admin@example.com", "password": password }),
            |d| &d.email,
        )
        .is_some()
    };
    for blank in ["   ", "\t\n", "\u{FEFF}", "\u{00A0}\u{3000}"] {
        assert!(!accepted(blank), "a blank password was accepted: {blank:?}");
    }
    // Whitespace is allowed inside a password, and so are characters JavaScript does not call
    // whitespace: only an all-whitespace value is refused.
    for fine in ["a", " a ", "pass word", "\u{200B}", "\u{0085}"] {
        assert!(
            accepted(fine),
            "a legitimate password was refused: {fine:?}"
        );
    }
}
