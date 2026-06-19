//! Constant-time byte comparison — the only sanctioned way to compare secrets,
//! tokens, digests, OTPs, and authentication tags.
//!
//! A plain `==` on secret-derived bytes can leak information through its early-exit
//! timing; every such comparison in `bymax-auth` routes through this module instead.

use subtle::ConstantTimeEq;

/// Compare two byte slices for equality in constant time.
///
/// Backed by [`subtle::ConstantTimeEq`]. The comparison takes time proportional to
/// the slice length and does **not** short-circuit on the first differing byte, so it
/// leaks no information about *where* two values diverge. The single exception is a
/// length mismatch, which returns `false` immediately — at this crate's call sites the
/// compared values are fixed-length digests (e.g. SHA-256), so their length is not
/// secret and leaking it reveals nothing.
///
/// # Examples
///
/// ```
/// use bymax_auth_crypto::compare::constant_time_eq;
///
/// assert!(constant_time_eq(b"same-secret", b"same-secret"));
/// assert!(!constant_time_eq(b"secret-a", b"secret-b"));
/// assert!(!constant_time_eq(b"short", b"longer-value"));
/// ```
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn equal_slices_compare_equal() {
        // Identical byte sequences must compare equal — the baseline positive case
        // that the constant-time path still returns true for a real match.
        assert!(constant_time_eq(b"a-shared-secret", b"a-shared-secret"));
    }

    #[test]
    fn differing_same_length_slices_compare_unequal() {
        // Same length, one byte different: protects the core guarantee that a
        // single-byte difference is detected (and, under the hood, without an
        // early-exit timing leak).
        assert!(!constant_time_eq(b"secretA", b"secretB"));
    }

    #[test]
    fn length_mismatch_compares_unequal() {
        // A length mismatch must return false (and is the one permitted
        // short-circuit) — guards against accidentally treating a prefix as a match.
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn two_empty_slices_compare_equal() {
        // Two empty slices are equal — guards the zero-length boundary so callers
        // can compare possibly-empty values without a special case.
        assert!(constant_time_eq(b"", b""));
    }

    proptest! {
        #[test]
        fn agrees_with_plain_equality(a in proptest::collection::vec(any::<u8>(), 0..64),
                                      b in proptest::collection::vec(any::<u8>(), 0..64)) {
            // For arbitrary byte vectors the constant-time result must match plain
            // `==` exactly — the property that the timing-safe path is functionally
            // identical to ordinary equality, differing only in timing.
            prop_assert_eq!(constant_time_eq(&a, &b), a == b);
        }

        #[test]
        fn reflexive_for_any_input(a in proptest::collection::vec(any::<u8>(), 0..64)) {
            // Any value compared to a clone of itself is always equal — protects
            // reflexivity across the full input space, including the empty slice.
            prop_assert!(constant_time_eq(&a, &a.clone()));
        }
    }
}
