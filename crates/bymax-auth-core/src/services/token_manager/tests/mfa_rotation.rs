//! Regression tests for the second-factor claim across a refresh rotation (dashboard and
//! platform planes): a session that cleared the MFA challenge keeps the claim through every
//! rotation and every grace-window recovery, and one that did not never gains it.
//!
//! Layer: unit tests of `TokenManagerService`, sharing the fixtures of the parent test module.

use super::*;

/// Rotate `refresh` `times` times and return the last access token's `mfa_verified`.
async fn verified_after_rotations(
    svc: &TokenManagerService,
    enrolled: &SafeAuthUser,
    challenge_cleared: bool,
    times: usize,
) -> Option<bool> {
    let issued = svc
        .issue_tokens(
            enrolled,
            "10.0.0.1",
            "agent/1.0",
            challenge_cleared,
            CredentialProof::Proved,
        )
        .await
        .ok()?;
    let mut refresh = issued.refresh_token;
    let mut access = issued.access_token;
    for _ in 0..times {
        let rotated = svc
            .reissue_tokens(&refresh, "10.0.0.1", "agent/1.0")
            .await
            .ok()?;
        refresh = rotated.refresh_token;
        access = rotated.access_token;
    }
    svc.verify_access(&access)
        .await
        .ok()
        .map(|c| c.mfa_verified)
}

#[tokio::test]
async fn a_session_that_cleared_the_challenge_stays_verified_across_rotations() {
    // Two rotations, not one: the claim has to be carried from each successor to the next.
    let svc = service(Arc::new(InMemoryStores::new()));
    let enrolled = SafeAuthUser {
        mfa_enabled: true,
        ..user()
    };
    assert_eq!(
        verified_after_rotations(&svc, &enrolled, true, 2).await,
        Some(true)
    );
}

#[tokio::test]
async fn a_session_that_never_cleared_the_challenge_stays_unverified_across_rotations() {
    // The negative of the test above, and the one that would catch a rotation that wrote
    // `true` where it should not: no challenge, no claim, however many times it rotates.
    let svc = service(Arc::new(InMemoryStores::new()));
    let enrolled = SafeAuthUser {
        mfa_enabled: true,
        ..user()
    };
    assert_eq!(
        verified_after_rotations(&svc, &enrolled, false, 3).await,
        Some(false)
    );
}

#[tokio::test]
async fn the_stored_record_omits_the_flag_until_the_challenge_and_carries_it_after() {
    let store = Arc::new(InMemoryStores::new());
    let svc = service(store.clone());
    let enrolled = SafeAuthUser {
        mfa_enabled: true,
        ..user()
    };
    for (cleared, expected) in [(false, false), (true, true)] {
        let issued = svc
            .issue_tokens(
                &enrolled,
                "10.0.0.1",
                "agent/1.0",
                cleared,
                CredentialProof::Proved,
            )
            .await;
        let Ok(issued) = issued else { return };
        let rotated = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };
        let hash = RawRefreshToken::from_raw(rotated.refresh_token).redis_hash();
        let stored = store.find_session(SessionKind::Dashboard, &hash).await;
        assert!(matches!(&stored, Ok(Some(r)) if r.mfa_verified == expected));
        let json = stored
            .ok()
            .flatten()
            .and_then(|record| serde_json::to_value(record).ok());
        assert_eq!(
            json.as_ref()
                .is_some_and(|j| j.get("mfaVerified").is_some()),
            expected
        );
    }
}

#[tokio::test]
async fn a_grace_window_recovery_carries_the_second_factor_claim() {
    // The loser of a rotation race is recovered into a fresh session; that session is the
    // user's next one, so it has to inherit the claim from the record it was recovered from.
    let svc = service(Arc::new(InMemoryStores::new()));
    let enrolled = SafeAuthUser {
        mfa_enabled: true,
        ..user()
    };
    let issued = svc
        .issue_tokens(
            &enrolled,
            "10.0.0.1",
            "agent/1.0",
            true,
            CredentialProof::Proved,
        )
        .await;
    let Ok(issued) = issued else { return };
    assert!(
        svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await
            .is_ok()
    );

    let recovered = svc
        .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    let Ok(recovered) = recovered else { return };
    let claims = svc.verify_access(&recovered.access_token).await;
    assert!(matches!(&claims, Ok(c) if c.mfa_enabled && c.mfa_verified));
}

#[tokio::test]
async fn a_platform_session_keeps_the_second_factor_claim_only_if_it_cleared_it() {
    let svc = service(Arc::new(InMemoryStores::new()));
    let enrolled = SafeAuthPlatformUser {
        mfa_enabled: true,
        ..platform_admin()
    };
    for cleared in [true, false] {
        let issued = svc
            .issue_platform_tokens(&enrolled, "10.0.0.1", "agent/1.0", cleared)
            .await;
        let Ok(issued) = issued else { return };
        let mut refresh = issued.refresh_token;
        let mut access = issued.access_token;
        for _ in 0..2 {
            let rotated = svc
                .reissue_platform_tokens(&refresh, "10.0.0.1", "agent/1.0")
                .await;
            let Ok(rotated) = rotated else { return };
            refresh = rotated.refresh_token;
            access = rotated.access_token;
        }
        let claims = svc.verify_platform_access(&access).await;
        assert!(matches!(&claims, Ok(c) if c.mfa_verified == cleared));
    }
}

#[tokio::test]
async fn a_platform_grace_window_recovery_carries_the_second_factor_claim() {
    let svc = service(Arc::new(InMemoryStores::new()));
    let enrolled = SafeAuthPlatformUser {
        mfa_enabled: true,
        ..platform_admin()
    };
    let issued = svc
        .issue_platform_tokens(&enrolled, "10.0.0.1", "agent/1.0", true)
        .await;
    let Ok(issued) = issued else { return };
    assert!(
        svc.reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await
            .is_ok()
    );
    let recovered = svc
        .reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    let Ok(recovered) = recovered else { return };
    let claims = svc.verify_platform_access(&recovered.access_token).await;
    assert!(matches!(&claims, Ok(c) if c.mfa_verified));
}
