//! The platform MFA challenge, the separation from dashboard paths, the repository error
//! mapping and the rehash on verify (layer: core services, test support).

use super::*;

#[tokio::test]
async fn mfa_enabled_admin_gets_a_platform_challenge() {
    // A correct password for an MFA-enabled admin returns the challenge, not tokens.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "mfa@admin.io", "pw");
    let _ = h
        .admins
        .update_mfa(
            &id,
            UpdatePlatformMfaData {
                mfa_enabled: true,
                mfa_secret: Some("enc".to_owned()),
                mfa_recovery_codes: None,
            },
        )
        .await;
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let result = svc.login("mfa@admin.io", "pw", "1.2.3.4", "agent").await;
    assert!(matches!(
        result,
        Ok(PlatformLoginResult::MfaChallenge(MfaChallengeResult {
            mfa_required: true,
            ..
        }))
    ));
}

#[tokio::test]
async fn no_dashboard_path_is_reachable_for_a_platform_admin() {
    // A platform admin is not a dashboard user: the dashboard login cannot find them (they
    // live in a separate repository), so the dashboard surface is unreachable for them.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _ = seed_admin(&h.admins, "iso@admin.io", "pw");
    let dashboard = h
        .engine
        .login(
            crate::services::auth::LoginInput {
                email: "iso@admin.io".to_owned(),
                password: "pw".to_owned(),
                tenant_id: Some("t1".to_owned()),
            },
            &RequestContext::new("1.2.3.4", "agent", std::collections::BTreeMap::new()),
        )
        .await;
    // The dashboard repository has no such user, so login is a generic credential failure —
    // never a success that would cross the domain boundary.
    assert!(matches!(dashboard, Err(AuthError::InvalidCredentials)));
    // And the dashboard login never returns a platform result type, by construction.
    assert!(!matches!(dashboard, Ok(LoginResult::Success(_))));
}

#[tokio::test]
async fn mfa_enabled_admin_fails_closed_without_the_mfa_surface() {
    // A platform domain enabled WITHOUT MFA config has no challenge surface, so an
    // MFA-enabled admin cannot complete a login: it fails closed as InvalidCredentials
    // rather than being handed a session that skips the second factor.
    let mut cfg = platform_config();
    cfg.mfa = None; // no MFA surface in this build
    let Some(h) = harness(cfg) else { unreachable!() };
    let id = seed_admin(&h.admins, "nomfa@admin.io", "pw");
    let _ = h
        .admins
        .update_mfa(
            &id,
            UpdatePlatformMfaData {
                mfa_enabled: true,
                mfa_secret: Some("enc".to_owned()),
                mfa_recovery_codes: None,
            },
        )
        .await;
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let result = svc.login("nomfa@admin.io", "pw", "1.2.3.4", "agent").await;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[test]
fn repository_error_maps_backend_and_conflict_to_internal() {
    // A backend failure and a (contract-impossible) conflict both collapse to the opaque
    // internal error, so a platform repository failure never surfaces its concrete cause.
    assert!(matches!(
        repository_error(crate::RepositoryError::Backend("db down".into())),
        AuthError::Internal(_)
    ));
    assert!(matches!(
        repository_error(crate::RepositoryError::Conflict("dup".to_owned())),
        AuthError::Internal(_)
    ));
}

#[test]
fn the_hash_is_upgraded_only_when_the_toggle_is_on_and_the_hash_is_stale() {
    assert!(upgrades_hash(true, true));
    assert!(!upgrades_hash(true, false), "a current hash is left alone");
    assert!(
        !upgrades_hash(false, true),
        "the toggle disables the upgrade"
    );
    assert!(!upgrades_hash(false, false));
}

#[tokio::test]
async fn a_current_hash_is_left_alone_on_login() {
    // The upgrade needs *both* the toggle and a genuinely stale hash. Either one alone
    // must not rewrite a current one: a rehash on every login is a write on the hot path
    // for no gain, and it would leave the toggle disabling nothing.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "fresh@admin.io", "s3cret-pass");
    let before = h.admins.find_by_id(&id).await;
    let Ok(Some(before)) = before else { unreachable!() };
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    assert!(matches!(
        svc.login("fresh@admin.io", "s3cret-pass", "1.2.3.4", "agent")
            .await,
        Ok(PlatformLoginResult::Success(_))
    ));
    // Long enough for a spawned rehash to have landed if one had been spawned.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = h.admins.find_by_id(&id).await;
    let Ok(Some(after)) = after else { unreachable!() };
    assert_eq!(before.password_hash, after.password_hash);
}

#[tokio::test]
async fn rehash_on_verify_upgrades_a_weaker_admin_hash() {
    // A hash stored under weaker scrypt params is upgraded on a successful login; the
    // detached task replaces the stored hash with a stronger one.
    #[cfg(feature = "scrypt")]
    {
        let Some(h) = harness(platform_config()) else { unreachable!() };
        let weak_params = bymax_auth_crypto::password::PasswordParams {
            active: bymax_auth_crypto::password::PasswordAlgorithm::Scrypt,
            scrypt: bymax_auth_crypto::password::ScryptParams {
                cost_factor: 1 << 14,
                block_size: 8,
                parallelization: 1,
            },
            #[cfg(feature = "argon2")]
            argon2: bymax_auth_crypto::password::Argon2Params::default(),
        };
        let weak_hash = bymax_auth_crypto::password::hash(b"pw", &weak_params).unwrap_or_default();
        let id = "admin-weak@admin.io".to_owned();
        h.admins.insert(AuthPlatformUser {
            id: id.clone(),
            email: "weak@admin.io".to_owned(),
            name: "Admin".to_owned(),
            password_hash: weak_hash.clone(),
            role: "SUPER_ADMIN".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            platform_id: None,
            last_login_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        });
        let Some(svc) = h.engine.platform_auth() else { unreachable!() };
        let result = svc.login("weak@admin.io", "pw", "1.2.3.4", "agent").await;
        assert!(matches!(result, Ok(PlatformLoginResult::Success(_))));
        // Poll rather than sleep a fixed span: the rehash is one derivation at the
        // configured cost, and a wait tuned on a laptop fails on a slower runner while
        // saying nothing about the code.
        let mut stored = None;
        for _ in 0..300 {
            if let Ok(Some(admin)) = h.admins.find_by_id(&id).await
                && admin.password_hash != weak_hash
            {
                stored = Some(admin);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Asserted before the destructure so a rehash that never landed fails loudly here;
        // the `let-else` below then cannot swallow it into a silent pass.
        assert!(stored.is_some(), "the stored hash was never upgraded");
        let Some(stored) = stored else { unreachable!() };
        assert_ne!(stored.password_hash, weak_hash);
        // The other fire-and-forget task on this path: the successful login is stamped.
        assert!(stored.last_login_at.is_some());
    }
}
