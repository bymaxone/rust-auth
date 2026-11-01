//! Text rules applied to request fields before they are validated (layer: HTTP adapter).
//!
//! An email is trimmed and lowercased **before** the format and length checks, so `" A@E.com "`
//! is the address `a@e.com` and not a validation error, and a password that is only whitespace
//! is refused. Both follow nest-auth's DTOs, which use JavaScript's `trim()` and `/\S/`; the
//! whitespace set below is JavaScript's, because Rust's `char::is_whitespace` differs from it at
//! U+0085 (a line terminator Rust trims and JavaScript does not) and U+FEFF (the byte order mark
//! JavaScript trims and Rust does not).

use serde::{Deserialize, Deserializer};

/// Whether JavaScript treats `ch` as whitespace: its `WhiteSpace` and `LineTerminator` classes,
/// which are what `String.prototype.trim` strips and `\s` matches.
fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | ' ' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// `raw` trimmed of JavaScript whitespace and lowercased: nest-auth's `@Transform` on every email
/// field.
fn normalize(raw: &str) -> String {
    raw.trim_matches(is_js_whitespace).to_lowercase()
}

/// `serde` adapter for an email field: deserialize the string, then trim and lowercase it, so the
/// `garde` checks that run afterwards see the canonical address.
pub(super) fn normalized_email<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(normalize(&raw))
}

/// `garde` validator: the value holds at least one character JavaScript does not call whitespace
/// (`/\S/`), so a password of spaces cannot buy a key derivation.
pub(super) fn not_blank(value: &str, _: &()) -> garde::Result {
    if value.chars().all(is_js_whitespace) {
        Err(garde::Error::new("must not be blank"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
