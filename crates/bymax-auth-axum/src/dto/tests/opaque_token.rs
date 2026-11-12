//! The `opaqueToken` bound of the shared contract against every DTO field that carries a token
//! either library minted: the refresh token and the reset link token (layer: HTTP adapter, test
//! support).
//!
//! The bound is read from `requestFieldBounds.opaqueToken`, never restated here, and each field is
//! driven through its real `garde` validation. The contract's minimum is 1, so the empty value is
//! the case below it; [`super::assert_bounded`] checks the minimum only when it is above 1, and the
//! empty case is asserted on its own.

use super::*;

/// What one field's DTO answers for a token value.
type Build = fn(String) -> Result<(), garde::Report>;

fn change_password(token: String) -> Result<(), garde::Report> {
    ChangePasswordDto {
        current_password: "hunter2".to_owned(),
        new_password: "hunter2hunter2".to_owned(),
        refresh_token: Some(token),
    }
    .validate()
}

fn reset_password(token: String) -> Result<(), garde::Report> {
    ResetPasswordDto {
        email: "a@e.com".to_owned(),
        new_password: "hunter2hunter2".to_owned(),
        token: Some(token),
        otp: None,
        verified_token: None,
        tenant_id: Some("t1".to_owned()),
    }
    .validate()
}

fn refresh(token: String) -> Result<(), garde::Report> {
    RefreshDto {
        refresh_token: Some(token),
    }
    .validate()
}

/// Every field the bound applies to, by the DTO and wire property that carry it.
const TOKEN_FIELDS: [(&str, Build); 3] = [
    ("ChangePasswordDto.refreshToken", change_password),
    ("ResetPasswordDto.token", reset_password),
    ("RefreshDto.refreshToken", refresh),
];

#[test]
fn every_opaque_token_field_enforces_the_contract_bound_in_characters() {
    // The bound counts code points, so it is probed with a one-byte and a four-byte character:
    // a field that counted bytes would refuse the astral value well inside the bound.
    for (_, build) in TOKEN_FIELDS {
        assert_bounded("opaqueToken", 'a', &build);
        assert_bounded("opaqueToken", '\u{1F600}', &build);
    }
}

#[test]
fn an_opaque_token_below_the_contract_minimum_is_refused() {
    let (min, _) = contract_bound("opaqueToken");
    let min = min.unwrap_or(0);
    assert!(min >= 1, "the contract names no minimum for opaqueToken");
    for (field, build) in TOKEN_FIELDS {
        assert!(accepts(&build, 'a', min), "{field} refused its own minimum");
        assert!(
            !accepts(&build, 'a', min - 1),
            "{field} accepted a value below the contract minimum"
        );
    }
}
