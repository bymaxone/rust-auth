//! The request bounds of the workspace routes (layer: domain).
//!
//! The numbers are the `requestFieldBounds` entries `memberUserId`, `workspaceName`, `pageLimit`
//! and `pathParameters` of the shared contract, which the tests read from the file. A value
//! outside them is refused as `auth.validation` naming the field, and is never clamped or
//! repaired.
//!
//! Lengths count Unicode scalar values, the unit `@bymax-one/nest-auth` counts in. "Blank" means
//! only the whitespace JavaScript's `\s` and `trim` know, which is not the set `char::is_whitespace`
//! knows: U+FEFF is blank here and U+0085 is not.

/// The longest workspace name, as submitted, in characters.
pub const WORKSPACE_NAME_MAX_CHARS: usize = 120;

/// The longest member user id and workspace id in a path segment or body field, in characters.
pub const IDENTIFIER_MAX_CHARS: usize = 128;

/// The page size of a list when the request names none.
pub const PAGE_LIMIT_DEFAULT: u8 = 50;

/// The largest page size.
pub const PAGE_LIMIT_MAX: u8 = 100;

/// The longest pagination cursor, in characters.
pub const CURSOR_MAX_CHARS: usize = 512;

/// A request value outside its bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{field} is out of bounds")]
pub struct OutOfBounds {
    /// The wire name of the refused field, as the answer names it.
    pub field: &'static str,
}

/// Whether `c` is whitespace in JavaScript's `\s` and `String.prototype.trim`.
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// Whether `value` is empty or only whitespace.
#[must_use]
pub fn is_blank(value: &str) -> bool {
    value.chars().all(is_js_whitespace)
}

/// Whether `c` is a C0 control, DEL or a C1 control.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// A workspace name as the create and rename routes accept it, stored form.
///
/// The length bound (1 to 120) and the control-character rule apply to the value **as submitted**,
/// before trimming: a name that is too long as submitted, or carries a control character anywhere
/// (a tab or a newline at an edge included), is refused even though trimming would have removed it.
/// The accepted name is then trimmed, and one that is blank after trimming is refused the same way.
///
/// # Errors
///
/// [`OutOfBounds`] naming `name`.
pub fn normalize_workspace_name(submitted: &str) -> Result<String, OutOfBounds> {
    let refused = OutOfBounds { field: "name" };
    if submitted.chars().count() > WORKSPACE_NAME_MAX_CHARS || submitted.chars().any(is_control) {
        return Err(refused);
    }
    let trimmed = submitted.trim_matches(is_js_whitespace);
    if trimmed.is_empty() {
        return Err(refused);
    }
    Ok(trimmed.to_owned())
}

/// A path parameter or a member user id: 1 to 128 characters, not blank, no control character.
///
/// # Errors
///
/// [`OutOfBounds`] naming `field`.
pub fn check_identifier(field: &'static str, value: &str) -> Result<(), OutOfBounds> {
    let count = value.chars().count();
    if count == 0
        || count > IDENTIFIER_MAX_CHARS
        || is_blank(value)
        || value.chars().any(is_control)
    {
        return Err(OutOfBounds { field });
    }
    Ok(())
}

/// The `limit` query parameter of a paginated list.
///
/// It arrives as text and must be a whole number written in decimal digits without a leading zero,
/// from 1 to 100: `5` is accepted and `05`, `+5`, ` 5`, `5.0`, `0`, `101` and an empty `limit=` are
/// refused. An absent parameter is [`PAGE_LIMIT_DEFAULT`]. Nothing is clamped.
///
/// # Errors
///
/// [`OutOfBounds`] naming `limit`.
pub fn parse_page_limit(raw: Option<&str>) -> Result<u8, OutOfBounds> {
    let Some(text) = raw else {
        return Ok(PAGE_LIMIT_DEFAULT);
    };
    let digits = text.bytes().all(|byte| byte.is_ascii_digit());
    match text.parse::<u8>() {
        Ok(value) if digits && !text.starts_with('0') && value <= PAGE_LIMIT_MAX => Ok(value),
        _ => Err(OutOfBounds { field: "limit" }),
    }
}

/// The opaque `cursor` query parameter: 1 to 512 characters, no control character.
///
/// # Errors
///
/// [`OutOfBounds`] naming `cursor`.
pub fn check_cursor(value: &str) -> Result<(), OutOfBounds> {
    let count = value.chars().count();
    if count == 0 || count > CURSOR_MAX_CHARS || value.chars().any(is_control) {
        return Err(OutOfBounds { field: "cursor" });
    }
    Ok(())
}
