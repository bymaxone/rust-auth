//! Tests of the platform administrator sign-in, rotation and status gate, with the harness the
//! child modules share (layer: core services, test support).

use super::*;
mod enrolment_rotation_tests;
mod logout_failure_tests;
mod logout_pending_tests;
mod logout_tests;
mod mfa_and_rehash_tests;
use crate::config::{AuthConfig, Environment};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::testing::{InMemoryPlatformUserRepository, InMemoryStores};
use bymax_auth_types::{AuthPlatformUser, LoginResult, PlatformLoginResult, UpdatePlatformMfaData};
use secrecy::SecretString;
use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;

/// A config that enables the platform domain with a disjoint platform hierarchy, MFA wired,
/// and a known JWT secret, valid under either hasher matrix.
fn platform_config() -> AuthConfig {
    let mut cfg = AuthConfig::default();
    #[cfg(not(feature = "scrypt"))]
    {
        cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
    }
    cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    cfg.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    cfg.roles.platform_hierarchy = Some(HashMap::from([
        ("SUPER_ADMIN".to_owned(), vec!["SUPPORT".to_owned()]),
        ("SUPPORT".to_owned(), Vec::new()),
    ]));
    cfg.platform.enabled = true;
    cfg.blocked_statuses = vec![
        "BANNED".to_owned(),
        "INACTIVE".to_owned(),
        "SUSPENDED".to_owned(),
        "PENDING_APPROVAL".to_owned(),
    ];
    // Wire MFA so the platform login can issue a real challenge for an MFA-enabled admin.
    // The encryption key is a 32-byte base64 value; the issuer is required and non-empty.
    {
        use base64::Engine as _;
        cfg.mfa = Some(crate::config::MfaConfig {
            previous_encryption_keys: Vec::new(),
            encryption_key: SecretString::from(
                base64::engine::general_purpose::STANDARD.encode([5u8; 32]),
            ),
            issuer: "Bymax Platform".to_owned(),
            recovery_code_count: 8,
            totp_window: 1,
        });
    }
    cfg
}

/// An engine plus the concrete platform repository behind it, so a test can both drive the
/// platform flows and seed/inspect the backing admins.
struct PlatformHarness {
    engine: AuthEngine,
    admins: Arc<InMemoryPlatformUserRepository>,
    stores: Arc<InMemoryStores>,
}

/// Build a platform harness from `cfg`. Returns `None` if assembly somehow fails.
fn harness(cfg: AuthConfig) -> Option<PlatformHarness> {
    harness_with_hooks(cfg, None)
}

/// The same harness, with `hooks` registered when given.
fn harness_with_hooks(
    cfg: AuthConfig,
    hooks: Option<Arc<dyn AuthHooks>>,
) -> Option<PlatformHarness> {
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let mut builder = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
        .platform_user_repository(admins.clone())
        .redis_stores(stores.clone());
    if let Some(hooks) = hooks {
        builder = builder.hooks(hooks);
    }
    let engine = builder.build().ok()?;
    Some(PlatformHarness {
        engine,
        admins,
        stores,
    })
}

/// Hash a plaintext password with the compiled hasher, for seeding an admin's stored hash.
fn hash_password(plain: &str) -> String {
    #[cfg(not(feature = "scrypt"))]
    let params = bymax_auth_crypto::password::PasswordParams {
        active: bymax_auth_crypto::password::PasswordAlgorithm::Argon2id,
        ..bymax_auth_crypto::password::PasswordParams::default()
    };
    #[cfg(feature = "scrypt")]
    let params = bymax_auth_crypto::password::PasswordParams::default();
    bymax_auth_crypto::password::hash(plain.as_bytes(), &params).unwrap_or_default()
}

/// Seed a platform admin (active, no MFA) and return its id.
fn seed_admin(admins: &InMemoryPlatformUserRepository, email: &str, password: &str) -> String {
    let id = format!("admin-{email}");
    admins.insert(AuthPlatformUser {
        id: id.clone(),
        email: email.to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password(password),
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
    id
}

#[test]
fn the_platform_lockout_preimage_matches_the_shared_wire_contract() {
    // The `platform:` namespace is what keeps this counter disjoint from the dashboard's.
    // Without it a tenant whose id is literally `platform` produced a byte-identical
    // identifier, so five unauthenticated dashboard logins against an operator's address
    // locked that operator out of the console — and a successful one cleared the lockout
    // mid-attack. nest-auth writes the same counter into the same Redis, so the preimage is
    // read from the shared contract rather than repeated here.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let Some(service) = h.engine.platform_auth() else { unreachable!() };

    let template =
        crate::services::contract_preimage("platform").replace("{email}", "operator@example.com");
    assert_eq!(
        service.brute_force_identifier("operator@example.com"),
        to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            service.identifier_key.as_ref(),
            template.as_bytes(),
        )),
        "the platform lockout preimage drifted from the shared contract"
    );
    // And it is not the dashboard's, for any tenant id — including the one that collided.
    assert_ne!(
        service.brute_force_identifier("operator@example.com"),
        h.engine
            .lockout_identifier("platform", "operator@example.com"),
    );
}

#[test]
fn engine_exposes_no_platform_service_when_the_domain_is_disabled() {
    // With `platform.enabled = false` the engine constructs no platform service, even though
    // the feature is compiled in.
    let mut cfg = platform_config();
    cfg.platform.enabled = false;
    cfg.roles.platform_hierarchy = None;
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
        .platform_user_repository(admins)
        .redis_stores(stores)
        .build();
    assert!(matches!(&built, Ok(engine) if engine.platform_auth().is_none()));
}

#[test]
fn engine_exposes_the_platform_service_when_the_domain_is_enabled() {
    // The inverse: every platform test below recovers the service through the harness, so an
    // engine that stopped handing it back is named here rather than by each of them.
    let admins = Arc::new(InMemoryPlatformUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(platform_config())
        .environment(Environment::Test)
        .user_repository(Arc::new(crate::testing::InMemoryUserRepository::new()))
        .platform_user_repository(admins)
        .redis_stores(stores)
        .build();
    assert!(matches!(&built, Ok(engine) if engine.platform_auth().is_some()));
}

#[tokio::test]
async fn the_platform_rehash_refuses_to_overwrite_a_password_that_changed() {
    // The dashboard twin's reasoning, on the plane where it matters most. The task carries
    // the PLAINTEXT it is upgrading and a KDF derivation is slow by construction, so it
    // lands well after the login that scheduled it. The situation where an admin's password
    // changes in that window is not random: it is a rotation BECAUSE the old one was
    // compromised, where the attacker's own login is what scheduled this task. An
    // unconditional write re-installs the compromised credential over the new one.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "rotate@admin.io", "oldsecret77");
    // Read as one expression rather than a `let ... else`: the else arm of a binding that
    // cannot fail is a branch no test can take, and this crate's coverage gate is 100% of
    // lines.
    let original = h
        .admins
        .find_by_id(&id)
        .await
        .ok()
        .flatten()
        .map(|admin| admin.password_hash)
        .unwrap_or_default();

    // The rotation lands first, so the row no longer holds the hash that was verified.
    assert!(
        h.admins
            .update_password(&id, "$scrypt$rotated")
            .await
            .is_ok()
    );

    // The upgrade, still carrying the OLD plaintext, must decline rather than write.
    assert!(
        run_rehash_platform_password(
            h.engine.passwords().clone(),
            h.admins.clone(),
            "oldsecret77".to_owned(),
            id.clone(),
            original,
        )
        .await
        .is_ok()
    );

    let after = h
        .admins
        .find_by_id(&id)
        .await
        .ok()
        .flatten()
        .map(|admin| admin.password_hash)
        .unwrap_or_default();
    assert_eq!(
        after, "$scrypt$rotated",
        "the rotation must survive the upgrade that raced it"
    );
}

#[tokio::test]
async fn login_issues_a_platform_session_with_no_tenant() {
    // A correct password for an active admin returns a full platform session; me/refresh
    // then work against the platform keyspace.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _ = seed_admin(&h.admins, "ok@admin.io", "s3cret-pass");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let result = svc
        .login("ok@admin.io", "s3cret-pass", "1.2.3.4", "agent")
        .await;
    assert!(matches!(&result, Ok(PlatformLoginResult::Success(_))));
    let Ok(PlatformLoginResult::Success(auth)) = result else { unreachable!() };
    assert_eq!(auth.admin.email, "ok@admin.io");
    assert!(!auth.access_token.is_empty());

    // The platform access token verifies as a platform token and carries no tenant.
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&auth.access_token)
        .await;
    assert!(matches!(&claims, Ok(c) if c.role == "SUPER_ADMIN"));

    // me returns the admin; refresh rotates to a new pair.
    let me = svc.me(&format!("admin-{}", "ok@admin.io")).await;
    assert!(matches!(me, Ok(u) if u.email == "ok@admin.io"));
    let rotated = svc.refresh(&auth.refresh_token, "1.2.3.4", "agent").await;
    assert!(matches!(&rotated, Ok(r) if r.refresh_token != auth.refresh_token));
}

#[tokio::test]
async fn unknown_admin_and_wrong_password_are_indistinguishable() {
    // Both failure paths return InvalidCredentials and both honor the timing floor, so
    // neither status/body nor latency leaks whether the admin exists.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _ = seed_admin(&h.admins, "real@admin.io", "right-pass");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };

    let unknown_started = Instant::now();
    let unknown = svc.login("ghost@admin.io", "any", "1.2.3.4", "agent").await;
    let unknown_elapsed = unknown_started.elapsed();

    let wrong_started = Instant::now();
    let wrong = svc
        .login("real@admin.io", "wrong-pass", "1.2.3.4", "agent")
        .await;
    let wrong_elapsed = wrong_started.elapsed();

    assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
    assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
    assert!(unknown_elapsed >= Duration::from_millis(300));
    assert!(wrong_elapsed >= Duration::from_millis(300));
}

#[tokio::test]
async fn lockout_triggers_after_max_attempts() {
    // The default cap is five failures; the sixth attempt is AccountLocked with a retry
    // hint, before any credential check — keyed by the platform brute-force identifier.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let _ = seed_admin(&h.admins, "lock@admin.io", "right");
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    for _ in 0..5 {
        let attempt = svc
            .login("lock@admin.io", "wrong", "1.2.3.4", "agent")
            .await;
        assert!(matches!(attempt, Err(AuthError::InvalidCredentials)));
    }
    let locked = svc
        .login("lock@admin.io", "right", "1.2.3.4", "agent")
        .await;
    assert!(matches!(
        locked,
        Err(AuthError::AccountLocked {
            retry_after_seconds: Some(_)
        })
    ));

    // The counter is keyed per admin. One shared identifier would let any address lock
    // every administrator out of the platform by failing its own login five times.
    let _ = seed_admin(&h.admins, "other@admin.io", "right");
    assert!(matches!(
        svc.login("other@admin.io", "right", "1.2.3.4", "agent")
            .await,
        Ok(PlatformLoginResult::Success(_))
    ));
}

#[tokio::test]
async fn a_deleted_admin_cannot_rotate_and_leaves_nothing_behind() {
    // The session record outlived the account. Rotation used to work entirely from that
    // record, so a removed operator kept minting console access for the refresh token's
    // whole lifetime. The refusal is compensated, not merely returned: the rotation above
    // already minted a live pair, and leaving it would hand back exactly the access this
    // gate exists to end.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let id = seed_admin(&h.admins, "ghost@admin.io", "glidingwalnut42");
    let signed_in = h
        .engine
        .platform_auth()
        .map(|svc| svc.login("ghost@admin.io", "glidingwalnut42", "1.2.3.4", "a"));
    let Some(login) = signed_in else { unreachable!() };
    let Ok(PlatformLoginResult::Success(auth)) = login.await else { unreachable!() };

    assert!(h.admins.remove(&id));

    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let refused = svc.refresh(&auth.refresh_token, "1.2.3.4", "a").await;
    assert!(matches!(refused, Err(AuthError::RefreshTokenInvalid)));

    // Total compensation: the pair minted a moment ago went with every other one, so a
    // second attempt has nothing left to rotate.
    let again = svc.refresh(&auth.refresh_token, "1.2.3.4", "a").await;
    assert!(matches!(again, Err(AuthError::RefreshTokenInvalid)));
}

#[tokio::test]
async fn a_blocked_admin_cannot_rotate_and_loses_every_platform_session() {
    // Rotation works entirely from the stored `prt:` record, so without this backstop a
    // SUSPENDED or BANNED operator kept renewing access every fifteen minutes for the
    // refresh token's whole lifetime — on the highest-privilege identity in the system.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    h.admins.insert(AuthPlatformUser {
        id: "admin-live".to_owned(),
        email: "live@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password("pw"),
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
    let signed_in = svc.login("live@admin.io", "pw", "1.2.3.4", "a").await;
    let Ok(PlatformLoginResult::Success(auth)) = signed_in else { unreachable!() };

    // While active, the rotation works.
    let rotated = svc.refresh(&auth.refresh_token, "1.2.3.4", "a").await;
    assert!(rotated.is_ok(), "an active admin must rotate: {rotated:?}");
    let Ok(rotated) = rotated else { unreachable!() };

    // Suspended through the host's admin surface — the record in Redis is untouched.
    h.admins.insert(AuthPlatformUser {
        id: "admin-live".to_owned(),
        email: "live@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password("pw"),
        role: "SUPER_ADMIN".to_owned(),
        status: "SUSPENDED".to_owned(),
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    });

    assert!(matches!(
        svc.refresh(&rotated.refresh_token, "1.2.3.4", "a").await,
        Err(AuthError::AccountSuspended)
    ));
    // Compensated, not merely refused: the rotation that just ran minted a live pair, and
    // leaving it would hand back the access the suspension exists to end.
    assert!(matches!(
        svc.refresh(&rotated.refresh_token, "1.2.3.4", "a").await,
        Err(AuthError::RefreshTokenInvalid)
    ));
}

#[tokio::test]
async fn a_demoted_admin_stops_carrying_the_old_role_on_the_very_next_rotation() {
    // The dashboard plane closed this and the platform plane was left with the identical
    // hole — on the higher-privilege identity. Rotation builds its claims from the `prt:`
    // record written at login, so a demotion from SUPER_ADMIN to SUPPORT had no effect on
    // a live console session: it kept minting SUPER_ADMIN-roled tokens for the refresh
    // token's whole lifetime, and every role check reads that claim.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let make = |role: &str, mfa: bool| AuthPlatformUser {
        id: "admin-demoted".to_owned(),
        email: "demoted@admin.io".to_owned(),
        name: "Admin".to_owned(),
        password_hash: hash_password("pw"),
        role: role.to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: mfa,
        mfa_secret: None,
        mfa_recovery_codes: None,
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    };
    h.admins.insert(make("SUPER_ADMIN", false));
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    let signed_in = svc.login("demoted@admin.io", "pw", "1.2.3.4", "a").await;
    let Ok(PlatformLoginResult::Success(auth)) = signed_in else { unreachable!() };

    // One rotation to put SUPER_ADMIN into this lineage, then the demotion.
    let promoted = svc.refresh(&auth.refresh_token, "1.2.3.4", "a").await;
    assert!(
        promoted.is_ok(),
        "the first rotation must succeed: {promoted:?}"
    );
    let Ok(promoted) = promoted else { unreachable!() };
    let before = h
        .engine
        .tokens()
        .verify_platform_access(&promoted.access_token)
        .await;
    assert!(before.is_ok(), "the rotated token must verify: {before:?}");
    let Ok(before) = before else { unreachable!() };
    assert_eq!(before.role, "SUPER_ADMIN");

    h.admins.insert(make("SUPPORT", false));
    let rotated = svc.refresh(&promoted.refresh_token, "1.2.3.4", "a").await;
    assert!(
        rotated.is_ok(),
        "the demoting rotation must succeed: {rotated:?}"
    );
    let Ok(rotated) = rotated else { unreachable!() };
    let after = h
        .engine
        .tokens()
        .verify_platform_access(&rotated.access_token)
        .await;
    assert!(after.is_ok(), "the demoted token must verify: {after:?}");
    let Ok(after) = after else { unreachable!() };
    assert_eq!(
        after.role, "SUPPORT",
        "the demotion never reached the token"
    );

    // The same freeze on the claim that gates the second factor: `MfaSatisfied` refuses a
    // token only when `mfa_enabled && !mfa_verified`, so a console session created before
    // the admin enrolled stayed exempt for the refresh token's whole lifetime.
    h.admins.insert(make("SUPPORT", true));
    let with_mfa = svc.refresh(&rotated.refresh_token, "1.2.3.4", "a").await;
    assert!(
        with_mfa.is_ok(),
        "the MFA rotation must succeed: {with_mfa:?}"
    );
    let Ok(with_mfa) = with_mfa else { unreachable!() };
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&with_mfa.access_token)
        .await;
    assert!(
        claims.is_ok(),
        "the MFA-stamped token must verify: {claims:?}"
    );
    let Ok(claims) = claims else { unreachable!() };
    assert!(claims.mfa_enabled, "the MFA flag never reached the token");
}

#[tokio::test]
async fn each_blocked_status_maps_to_its_specific_error() {
    // Every blocked status maps to its own 403 — for the holder of the password. The gate
    // runs AFTER the KDF now: answering before it enumerated operator accounts and read
    // their moderation state, so each call here proves the password first.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    for (email, status) in [
        ("banned@admin.io", "BANNED"),
        ("inactive@admin.io", "INACTIVE"),
        ("suspended@admin.io", "SUSPENDED"),
    ] {
        let id = format!("admin-{email}");
        h.admins.insert(AuthPlatformUser {
            id,
            email: email.to_owned(),
            name: "Admin".to_owned(),
            password_hash: hash_password("pw"),
            role: "SUPER_ADMIN".to_owned(),
            status: status.to_owned(),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            platform_id: None,
            last_login_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        });
    }
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    assert!(matches!(
        svc.login("banned@admin.io", "pw", "1.2.3.4", "a").await,
        Err(AuthError::AccountBanned)
    ));
    assert!(matches!(
        svc.login("inactive@admin.io", "pw", "1.2.3.4", "a").await,
        Err(AuthError::AccountInactive)
    ));
    assert!(matches!(
        svc.login("suspended@admin.io", "pw", "1.2.3.4", "a").await,
        Err(AuthError::AccountSuspended)
    ));
    // The pending alias and an unknown blocked status both map through the gate helper.
    assert!(matches!(
        svc.assert_not_blocked("PENDING_APPROVAL"),
        Err(AuthError::PendingApproval)
    ));
    assert!(matches!(svc.assert_not_blocked("ACTIVE"), Ok(())));
}

#[tokio::test]
async fn pending_and_unknown_blocked_statuses_map_through_the_gate() {
    // The lowercase "pending" alias maps to PendingApproval, and a blocked status with no
    // specific arm falls back to AccountInactive.
    let mut cfg = platform_config();
    cfg.blocked_statuses = vec!["pending".to_owned(), "FROZEN".to_owned()];
    let Some(h) = harness(cfg) else { unreachable!() };
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    assert!(matches!(
        svc.assert_not_blocked("pending"),
        Err(AuthError::PendingApproval)
    ));
    assert!(matches!(
        svc.assert_not_blocked("FROZEN"),
        Err(AuthError::AccountInactive)
    ));
}

#[tokio::test]
async fn me_returns_token_invalid_for_an_unknown_admin() {
    // `me` projects the stored admin; an unknown subject is TokenInvalid.
    let Some(h) = harness(platform_config()) else { unreachable!() };
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    assert!(matches!(
        svc.me("missing").await,
        Err(AuthError::TokenInvalid)
    ));
}

/// A hook spy that records which logout hook fired, for whom, and on which plane.
#[derive(Default)]
struct LogoutSpy {
    platform: std::sync::Mutex<Vec<(String, crate::traits::HookPlane, Option<String>)>>,
    dashboard: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl AuthHooks for LogoutSpy {
    async fn after_logout(
        &self,
        user_id: &str,
        _ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        if let Ok(mut seen) = self.dashboard.lock() {
            seen.push(user_id.to_owned());
        }
        Ok(())
    }

    async fn after_platform_logout(
        &self,
        admin_id: &str,
        ctx: &HookContext,
    ) -> Result<(), crate::traits::HookError> {
        if let Ok(mut seen) = self.platform.lock() {
            seen.push((admin_id.to_owned(), ctx.plane, ctx.tenant_id.clone()));
        }
        Ok(())
    }
}
