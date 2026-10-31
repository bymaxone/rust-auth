//! The verified gate: refusal only for an unverified account under a deployment that requires verification.

use super::*;

/// The verified gate refuses an unverified account only when the deployment requires
/// verification, and admits every verified account either way. The unverified/required
/// case is the only refusal; the other three cells must admit.
#[tokio::test]
async fn the_verified_gate_depends_on_the_deployment_requirement_and_the_account() {
    use crate::services::auth::test_support::SeedUser;

    for required in [true, false] {
        let mut cfg = base_config();
        cfg.email_verification.required = required;
        let Some(h) = harness(cfg, None) else { return };
        let unverified = h
            .seed(SeedUser {
                email_verified: false,
                ..SeedUser::active("unverified@e.com", "correct horse battery staple")
            })
            .await;
        let verified = h
            .seed(SeedUser::active(
                "verified@e.com",
                "correct horse battery staple",
            ))
            .await;

        let unverified_outcome = h
            .engine
            .assert_user_active_and_verified(&unverified, "t1")
            .await;
        if required {
            assert!(matches!(
                unverified_outcome,
                Err(AuthError::EmailNotVerified)
            ));
        } else {
            assert!(unverified_outcome.is_ok());
        }
        assert!(
            h.engine
                .assert_user_active_and_verified(&verified, "t1")
                .await
                .is_ok()
        );
        // The status gate still applies underneath the verification gate.
        assert!(matches!(
            h.engine
                .assert_user_active_and_verified("no-such-user", "t1")
                .await,
            Err(AuthError::TokenInvalid)
        ));
    }
}
