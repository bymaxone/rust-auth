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

#[cfg(test)]
mod tests {
    use super::normalize_email;

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
}
