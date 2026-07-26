//! The account-status gate shared by every credential flow.
//!
//! Kept as one free function rather than a method per service so the dashboard, platform,
//! and MFA paths cannot drift into subtly different notions of "blocked".

use bymax_auth_types::AuthError;

/// Reject when `status` is one of the configured blocked account statuses.
///
/// Matching is case-insensitive on both sides: the status is application-defined (a host may
/// persist `"Suspended"`) while `blocked_statuses` is typically configured uppercase, and a
/// raw comparison would silently admit a blocked account.
///
/// The mapping is `banned → AccountBanned`, `inactive → AccountInactive`,
/// `suspended → AccountSuspended`, `pending`/`pending_approval → PendingApproval`; any other
/// blocked status falls back to `AccountInactive`, since a host may define its own.
///
/// Call this **before** the password KDF. A blocked account must never authenticate, and
/// gating ahead of the derivation also denies an attacker unbounded hashing work on an
/// account whose login could never succeed.
///
/// # Errors
///
/// Returns the status-specific [`AuthError`] when `status` is in the blocked set.
pub(crate) fn assert_not_blocked(
    status: &str,
    blocked_statuses: &[String],
) -> Result<(), AuthError> {
    if !blocked_statuses
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(status))
    {
        return Ok(());
    }

    Err(match status.to_ascii_lowercase().as_str() {
        "banned" => AuthError::AccountBanned,
        "inactive" => AuthError::AccountInactive,
        "suspended" => AuthError::AccountSuspended,
        "pending" | "pending_approval" => AuthError::PendingApproval,
        _ => AuthError::AccountInactive,
    })
}

#[cfg(test)]
mod tests {
    use super::assert_not_blocked;
    use bymax_auth_types::AuthError;

    fn blocked() -> Vec<String> {
        ["BANNED", "INACTIVE", "SUSPENDED"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn admits_a_status_that_is_not_blocked() {
        // The common case: an active account must pass, or every login fails closed.
        assert!(assert_not_blocked("active", &blocked()).is_ok());
    }

    #[test]
    fn admits_everything_when_no_status_is_configured_as_blocked() {
        // An empty blocked set disables the gate rather than blocking everything; a host may
        // legitimately configure no blocked statuses.
        assert!(assert_not_blocked("suspended", &[]).is_ok());
    }

    #[test]
    fn maps_each_known_status_to_its_own_error() {
        // The caller learns *why* the account was refused instead of one opaque rejection.
        // Asserted per variant rather than in a loop: `AuthError` is not `PartialEq`, and a
        // pattern match also pins the exact variant instead of an equality that a future
        // `PartialEq` impl could weaken.
        assert!(matches!(
            assert_not_blocked("banned", &["banned".to_owned()]),
            Err(AuthError::AccountBanned)
        ));
        assert!(matches!(
            assert_not_blocked("inactive", &["inactive".to_owned()]),
            Err(AuthError::AccountInactive)
        ));
        assert!(matches!(
            assert_not_blocked("suspended", &["suspended".to_owned()]),
            Err(AuthError::AccountSuspended)
        ));
        assert!(matches!(
            assert_not_blocked("pending", &["pending".to_owned()]),
            Err(AuthError::PendingApproval)
        ));
        assert!(matches!(
            assert_not_blocked("pending_approval", &["pending_approval".to_owned()]),
            Err(AuthError::PendingApproval)
        ));
    }

    #[test]
    fn falls_back_to_inactive_for_a_host_defined_status() {
        // A status configured as blocked but absent from the mapping must still reject rather
        // than leak through.
        let blocked = vec!["archived".to_owned()];
        assert!(matches!(
            assert_not_blocked("archived", &blocked),
            Err(AuthError::AccountInactive)
        ));
    }

    #[test]
    fn matches_case_insensitively_on_both_sides() {
        // The host's casing and the configured casing are independent. Folding only one side
        // would let a blocked account authenticate whenever the two disagree.
        assert!(assert_not_blocked("Suspended", &blocked()).is_err());
        assert!(assert_not_blocked("BANNED", &["banned".to_owned()]).is_err());
    }

    #[test]
    fn requires_an_exact_match_not_a_substring() {
        // A status that merely contains a blocked value must authenticate normally.
        assert!(assert_not_blocked("active_pending_review", &blocked()).is_ok());
    }
}
