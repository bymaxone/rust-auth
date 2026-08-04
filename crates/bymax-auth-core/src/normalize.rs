//! Canonicalization of caller-supplied identity input.
//!
//! Every value that becomes a lookup key, a Redis key segment, or a stored identity passes
//! through here first, so the rule lives in exactly one place on this side of the port.

/// Canonicalize an email address: trim surrounding whitespace, then lowercase.
///
/// This MUST run at the engine boundary, before the address is used to derive the
/// brute-force identifier, to look a user up, or to key an OTP/reset record. Skipping it
/// reopens the case-rotation bypass: `User@x.com` and `user@x.com` hash to different
/// lockout buckets while resolving the same account, so an attacker rotates the casing to
/// get a fresh failure budget and the lockout never trips. The same split would let one
/// account own several OTP and reset records at once.
///
/// Full Unicode lowercasing (`to_lowercase`), not `to_ascii_lowercase`: nest-auth uses
/// JavaScript's `toLowerCase()`, which is Unicode-aware, and the two implementations share
/// one Redis. An ASCII-only fold here would make a non-ASCII address canonicalize
/// differently on each backend and split its keyspace.
///
/// # Examples
///
/// ```
/// # use bymax_auth_core::normalize_email;
/// assert_eq!(normalize_email("  USER@Example.COM  "), "user@example.com");
/// ```
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Mask an email address for safe inclusion in a log line.
///
/// Keeps the first character of the local part and the whole domain, so an operator reading a
/// lockout or failed-login warning can tell which account it is about without the log becoming a
/// store of personal data. A value with no local part — no `@`, or one in the first position —
/// masks entirely rather than leaking the fragment it does have.
///
/// Byte-for-byte the same rule as nest-auth's `maskEmail`, so one log pipeline fed by both
/// backends shows one spelling for one account.
///
/// # Examples
///
/// ```
/// # use bymax_auth_core::mask_email;
/// assert_eq!(mask_email("john.doe@example.com"), "j***@example.com");
/// assert_eq!(mask_email("@example.com"), "***");
/// ```
#[must_use]
pub fn mask_email(email: &str) -> String {
    match email.find('@') {
        Some(at) if at > 0 => {
            let first = email.chars().next().unwrap_or_default();
            format!("{first}***{}", &email[at..])
        }
        _ => "***".to_owned(),
    }
}

/// Sanitize a request-derived value before it is interpolated into a log line.
///
/// A log line is a record, and a value carrying a newline writes a second one. `tracing`'s
/// `fmt` subscriber — the default a consumer reaches for — writes plain text, so an
/// unauthenticated caller who controls any field that reaches a log event can forge records in
/// it. `tenant_id` is the widest such field: it arrives in the body of `/login`, `/register`,
/// `/verify-email`, `/password/forgot-password` and `/oauth/{provider}`, all public, and is
/// attacker-chosen whenever no `TenantIdResolver` is configured — the default. A value like
/// `acme\nINFO login: success user_id=<victim>` puts a fabricated successful sign-in into the
/// operator's SIEM, or truncates the genuine records around it. ASVS v5 §16.4.1 requires log
/// data to be sanitized against exactly this.
///
/// The value is replaced wholesale rather than escaped: an operator reading `<malformed>`
/// learns the useful thing, which is that the field carried something no legitimate caller
/// sends. Anything printable passes through untouched, so a tenant naming scheme this library
/// cannot anticipate still reads normally.
///
/// Byte-for-byte the same rule as nest-auth's `logSafe`, so one log pipeline fed by both
/// backends renders one value one way. The DTOs reject control characters at the boundary as
/// well; this is the second lock, because a `TenantIdResolver` is the host's code and returns
/// whatever it returns.
///
/// # Examples
///
/// ```
/// # use bymax_auth_core::log_safe;
/// assert_eq!(log_safe("acme-corp"), "acme-corp");
/// assert_eq!(log_safe("acme\nINFO forged"), "<malformed>");
/// ```
#[must_use]
pub fn log_safe(value: &str) -> String {
    // C0, DEL and C1 — every character that can forge a record boundary in a line-oriented
    // pipeline. `is_control` covers C0 and C1 but not DEL, which is named explicitly.
    if value.chars().any(|c| c.is_control() || c == '\u{7f}') {
        return "<malformed>".to_owned();
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::{mask_email, normalize_email};

    #[test]
    fn trims_and_lowercases() {
        // The documented canonical case: surrounding whitespace goes, casing folds down, so
        // every spelling of one address collapses to a single key.
        assert_eq!(normalize_email("  USER@Example.COM  "), "user@example.com");
    }

    #[test]
    fn is_idempotent() {
        // Normalizing an already-canonical address must not change it; otherwise a value
        // normalized twice (boundary plus a nested call) would diverge from one normalized once.
        let once = normalize_email("user@example.com");
        assert_eq!(normalize_email(&once), once);
    }

    #[test]
    fn folds_every_casing_to_one_bucket() {
        // The security property itself: the case-rotation variants an attacker would cycle
        // through to reset a lockout must all produce the same canonical value.
        let canonical = normalize_email("user@example.com");
        for variant in ["USER@EXAMPLE.COM", "User@Example.Com", "uSeR@eXaMpLe.cOm"] {
            assert_eq!(normalize_email(variant), canonical);
        }
    }

    #[test]
    fn folds_non_ascii_case_like_javascript() {
        // Unicode-aware folding, matching nest-auth's `toLowerCase()`. An ASCII-only fold
        // would leave these uppercase and split the shared Redis keyspace per backend.
        assert_eq!(normalize_email("ÉLÈVE@example.com"), "élève@example.com");
        assert_eq!(normalize_email("ÄÖÜ@example.com"), "äöü@example.com");
    }

    #[test]
    fn strips_only_surrounding_whitespace() {
        // Interior characters are untouched: trimming is about transport padding, and an
        // address is never silently rewritten beyond case and edges.
        assert_eq!(
            normalize_email("\t user@example.com \n"),
            "user@example.com"
        );
        assert_eq!(
            normalize_email("a.b+tag@example.com"),
            "a.b+tag@example.com"
        );
    }

    #[test]
    fn masking_keeps_the_first_character_and_the_domain() {
        // What an operator needs from a lockout warning is which account and which domain —
        // never the full address, which would turn the log into a store of personal data.
        assert_eq!(mask_email("john.doe@example.com"), "j***@example.com");
        assert_eq!(mask_email("a@b.co"), "a***@b.co");
    }

    #[test]
    fn masking_hides_a_value_with_no_local_part() {
        // No `@` at all, or one in the first position, means there is no local part to keep a
        // character of — so nothing is echoed rather than the fragment that does exist.
        assert_eq!(mask_email("@example.com"), "***");
        assert_eq!(mask_email("not-an-email"), "***");
        assert_eq!(mask_email(""), "***");
    }

    #[test]
    fn masking_survives_a_multibyte_local_part() {
        // The domain is sliced at the byte index of `@`, and the kept character is taken as a
        // char: a non-ASCII first character must not panic on a byte boundary.
        assert_eq!(
            mask_email("\u{e9}lise@example.com"),
            "\u{e9}***@example.com"
        );
    }
}
