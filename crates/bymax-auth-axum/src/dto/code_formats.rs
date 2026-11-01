//! The shapes of the second-factor codes a request may carry (layer: HTTP adapter).
//!
//! A TOTP code is exactly six ASCII digits and a recovery code is six hyphen-separated groups of
//! four hexadecimal digits, the two shapes the engine mints. Refusing anything else at the edge
//! keeps a malformed value from reaching the engine, where a wrong code counts as a failed
//! attempt against the account's lockout.

/// Whether `value` is exactly six ASCII digits, a TOTP code.
fn is_totp_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `value` is `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, each `X` a hexadecimal digit of either
/// case: the recovery-code shape.
fn is_recovery_code(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 6
        && groups
            .iter()
            .all(|group| group.len() == 4 && group.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// `garde` validator: exactly six ASCII digits. For the endpoints that take a TOTP code only.
pub(super) fn totp_code(value: &str, _: &()) -> garde::Result {
    if is_totp_code(value) {
        Ok(())
    } else {
        Err(garde::Error::new("must be exactly 6 digits"))
    }
}

/// `garde` validator: a TOTP code or a recovery code. For the challenge, which takes either.
pub(super) fn totp_or_recovery_code(value: &str, _: &()) -> garde::Result {
    if is_totp_code(value) || is_recovery_code(value) {
        Ok(())
    } else {
        Err(garde::Error::new(
            "must be a 6-digit code or a recovery code in XXXX-XXXX-XXXX-XXXX-XXXX-XXXX format",
        ))
    }
}

#[cfg(test)]
mod tests;
