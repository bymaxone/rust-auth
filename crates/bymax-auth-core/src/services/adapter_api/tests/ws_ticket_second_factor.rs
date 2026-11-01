//! A WebSocket ticket is minted only for a session that satisfies the second factor it is
//! enrolled in: the ticket opens a socket that is never re-checked, so it must not outlive a
//! challenge the session skipped.
//!
//! Layer: unit tests of the engine's ticket surface over the in-memory doubles, sharing the
//! fixtures of the parent test module.

use super::*;

#[tokio::test]
async fn only_an_enrolled_session_that_skipped_its_challenge_mints_nothing() {
    // The four combinations of the two claims: only "enrolled and not verified" is refused, and
    // it is refused as `MfaRequired`, not as an invalid token.
    let Some(h) = harness(base_config(), None) else { return };
    let seeded = seeded_claims(&h).await;
    for (enabled, verified, allowed) in [
        (false, false, true),
        (false, true, true),
        (true, true, true),
        (true, false, false),
    ] {
        let claims = DashboardClaims {
            mfa_enabled: enabled,
            mfa_verified: verified,
            ..seeded.clone()
        };
        let outcome = h.engine.issue_ws_ticket(&claims).await;
        if allowed {
            assert!(outcome.is_ok(), "enabled={enabled} verified={verified}");
        } else {
            assert!(matches!(outcome, Err(AuthError::MfaRequired)));
        }
    }
}

#[tokio::test]
async fn the_second_factor_is_judged_before_the_account_is_read() {
    // The claims name an account that does not exist. A read first would answer `TokenInvalid`;
    // the answer is `MfaRequired`, so nothing was looked up before the gate.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = DashboardClaims {
        sub: "no-such-account".to_owned(),
        mfa_enabled: true,
        mfa_verified: false,
        ..sample_claims()
    };
    let outcome = h.engine.issue_ws_ticket(&claims).await;
    assert!(matches!(outcome, Err(AuthError::MfaRequired)));
}
