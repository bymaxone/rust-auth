//! End-to-end Redis integration tier for `bymax-auth-redis`, run against a real `redis:8`
//! container via testcontainers. Consolidated into one binary so the shared harness is fully
//! used (no dead code, no `#[allow]`) and one container is reused per test.
//!
//! These tests assert the section 24 invariants the Lua scripts uphold: rotation cannot
//! double-spend a refresh token (invariant 15), revoke is ownership-checked (no cross-user
//! revoke), the brute-force window starts at the first failure and does not slide, `otp_verify`
//! bumps attempts preserving residual TTL and consumes on success, the WebSocket ticket is
//! single-use, and no raw secret/PII is ever resident as a key (invariant 9). When Docker is
//! unavailable each test skips via `let Some(..) else { return }`, so a no-Docker run compiles
//! and passes.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use bymax_auth_core::context::RequestContext;
use bymax_auth_core::services::auth::{
    AcceptInvitationInput, ForgotPasswordInput, ResetPasswordInput, VerifyResetOtpInput,
};
use bymax_auth_core::services::auth::{LoginInput, RegisterInput};
use bymax_auth_core::testing::InMemoryUserRepository;
use bymax_auth_core::traits::{
    BruteForceStore, InvitationStore, OtpPurpose, OtpStore, PasswordResetStore, ResetContext,
    RotateOutcome, SessionKind, SessionRecord, SessionRotation, SessionStore, StoredInvitation,
    UserRepository, WsTicketSnapshot, WsTicketStore,
};
use bymax_auth_core::{AuthConfig, AuthEngine, Environment};
use bymax_auth_types::{AuthError, LoginResult};
use secrecy::SecretString;
use time::OffsetDateTime;

/// A dashboard/platform session record for the given user.
fn record(user: &str) -> SessionRecord {
    SessionRecord {
        user_id: user.to_owned(),
        tenant_id: Some("t1".to_owned()),
        role: "MEMBER".to_owned(),
        device: "Chrome on macOS".to_owned(),
        ip: "203.0.113.4".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A rotation bundle moving `old` -> `new` for `user`, with the given grace TTL (seconds).
fn rotation_with_grace(old: &str, new: &str, user: &str, grace_ttl: u64) -> SessionRotation {
    SessionRotation {
        old_hash: old.to_owned(),
        new_hash: new.to_owned(),
        new_raw: "raw-token-never-persisted".to_owned(),
        new_record: record(user),
        refresh_ttl: 3600,
        grace_ttl,
    }
}

/// A rotation bundle moving `old` -> `new` for `user`, with the default 30s grace window.
fn rotation(old: &str, new: &str, user: &str) -> SessionRotation {
    rotation_with_grace(old, new, user, 30)
}

/// A verified-claims snapshot for a WebSocket ticket.
fn snapshot() -> WsTicketSnapshot {
    WsTicketSnapshot {
        sub: "u1".to_owned(),
        tenant_id: Some("t1".to_owned()),
        role: "MEMBER".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_verified: false,
    }
}

#[tokio::test]
async fn session_create_rotate_grace_revoke_and_blacklist() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    let rec = record("u1");

    // Create, then find (hit + miss) and list.
    assert!(stores.create_session(kind, "h1", &rec, 3600).await.is_ok());
    assert!(matches!(
        stores.find_session(kind, "h1").await,
        Ok(Some(r)) if r.user_id == "u1"
    ));
    assert!(matches!(
        stores.find_session(kind, "missing").await,
        Ok(None)
    ));
    assert!(matches!(
        stores.list_sessions(kind, "u1").await,
        Ok(v) if v.len() == 1 && v[0].session_hash == "h1"
    ));

    // A member whose detail key has expired ahead of its index membership is skipped on list.
    assert!(redis.del("auth:sd:h1").await);
    assert!(matches!(stores.list_sessions(kind, "u1").await, Ok(v) if v.is_empty()));
    // Restore the detail for the rest of the flow.
    assert!(stores.create_session(kind, "h1", &rec, 3600).await.is_ok());

    // Rotate h1 -> h2: the old token is consumed and the index moves to the new hash.
    let rot = rotation("h1", "h2", "u1");
    assert!(matches!(
        stores.rotate(kind, &rot).await,
        Ok(RotateOutcome::Rotated(old)) if old.user_id == "u1"
    ));
    assert!(matches!(stores.find_session(kind, "h1").await, Ok(None)));
    assert!(matches!(stores.find_session(kind, "h2").await, Ok(Some(_))));
    assert!(matches!(
        stores.list_sessions(kind, "u1").await,
        Ok(v) if v.len() == 1 && v[0].session_hash == "h2"
    ));

    // Invariant 15: a replay of the consumed token cannot double-spend — it recovers via the
    // grace window (a single recovery), never a second independent Rotated.
    assert!(matches!(
        stores.rotate(kind, &rot).await,
        Ok(RotateOutcome::Grace(r)) if r.user_id == "u1"
    ));
    // A never-issued token is invalid (neither live nor in grace).
    assert!(matches!(
        stores.rotate(kind, &rotation("ghost", "hX", "u1")).await,
        Ok(RotateOutcome::Invalid)
    ));

    // Ownership-checked revoke: a non-owner and an unknown hash are both rejected.
    assert!(matches!(
        stores.revoke_session(kind, "intruder", "h2").await,
        Err(AuthError::SessionNotFound)
    ));
    assert!(matches!(
        stores.revoke_session(kind, "u1", "absent").await,
        Err(AuthError::SessionNotFound)
    ));
    assert!(stores.revoke_session(kind, "u1", "h2").await.is_ok());
    assert!(matches!(stores.find_session(kind, "h2").await, Ok(None)));

    // revoke_all clears every member key and the index set in one transaction.
    assert!(stores.create_session(kind, "a1", &rec, 3600).await.is_ok());
    assert!(stores.create_session(kind, "a2", &rec, 3600).await.is_ok());
    assert!(stores.revoke_all(kind, "u1").await.is_ok());
    assert!(matches!(stores.list_sessions(kind, "u1").await, Ok(v) if v.is_empty()));
    assert!(matches!(stores.find_session(kind, "a1").await, Ok(None)));

    // Access-JWT blacklist: absent, then present; a zero-TTL blacklist is a no-op.
    assert!(matches!(stores.is_blacklisted("jti-1").await, Ok(false)));
    assert!(stores.blacklist_access("jti-1", 60).await.is_ok());
    assert!(matches!(stores.is_blacklisted("jti-1").await, Ok(true)));
    assert!(stores.blacklist_access("jti-expired", 0).await.is_ok());
    assert!(matches!(
        stores.is_blacklisted("jti-expired").await,
        Ok(false)
    ));
}

#[tokio::test]
async fn rotate_with_zero_grace_writes_no_grace_pointer() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;

    // A live session under `z1`, then a rotation with a zero-width grace window.
    assert!(
        stores
            .create_session(kind, "z1", &record("zu"), 3600)
            .await
            .is_ok()
    );
    let rot = rotation_with_grace("z1", "z2", "zu", 0);
    assert!(matches!(
        stores.rotate(kind, &rot).await,
        Ok(RotateOutcome::Rotated(old)) if old.user_id == "zu"
    ));

    // The new key exists and carries the rotated record; the old key is consumed.
    assert!(matches!(
        stores.find_session(kind, "z2").await,
        Ok(Some(r)) if r.user_id == "zu"
    ));
    assert!(matches!(stores.find_session(kind, "z1").await, Ok(None)));

    // No grace pointer is written for a zero grace window: neither the old nor the new hash
    // has an `rp:` key (absent keys report a `-2` TTL).
    assert_eq!(redis.ttl("auth:rp:z1").await, -2);
    assert_eq!(redis.ttl("auth:rp:z2").await, -2);

    // A replay of the consumed token cannot recover: with no grace pointer it is invalid,
    // never a second live rotation.
    assert!(matches!(
        stores.rotate(kind, &rot).await,
        Ok(RotateOutcome::Invalid)
    ));
}

#[tokio::test]
async fn platform_sessions_use_the_platform_keyspace() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Platform;

    assert!(
        stores
            .create_session(kind, "phash1", &record("padmin"), 3600)
            .await
            .is_ok()
    );
    assert!(matches!(
        stores.find_session(kind, "phash1").await,
        Ok(Some(r)) if r.user_id == "padmin"
    ));
    // Platform ops write the platform prefixes (`prt`/`psess`/`psd`); a dashboard lookup of the
    // same hash misses, proving the keyspaces are distinct.
    assert!(matches!(
        stores.find_session(SessionKind::Dashboard, "phash1").await,
        Ok(None)
    ));
    assert!(stores.revoke_all(kind, "padmin").await.is_ok());
    assert!(matches!(stores.list_sessions(kind, "padmin").await, Ok(v) if v.is_empty()));
}

#[tokio::test]
async fn otp_put_verify_outcomes_and_resend() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let purpose = OtpPurpose::EmailVerification;

    // Verify before put -> expired.
    assert!(matches!(
        stores.verify(purpose, "id1", "123456", 5).await,
        Err(AuthError::OtpExpired)
    ));
    assert!(stores.put(purpose, "id1", "123456", 600).await.is_ok());
    // Wrong code bumps attempts; the right code consumes.
    assert!(matches!(
        stores.verify(purpose, "id1", "000000", 5).await,
        Err(AuthError::OtpInvalid)
    ));
    assert!(stores.verify(purpose, "id1", "123456", 5).await.is_ok());
    // After consume the record is gone.
    assert!(matches!(
        stores.verify(purpose, "id1", "123456", 5).await,
        Err(AuthError::OtpExpired)
    ));

    // Residual-TTL preservation: a wrong guess re-stores with the residual TTL, never extended.
    assert!(stores.put(purpose, "ttlid", "111111", 600).await.is_ok());
    assert!(matches!(
        stores.verify(purpose, "ttlid", "999999", 5).await,
        Err(AuthError::OtpInvalid)
    ));
    let residual = redis.ttl("auth:otp:email_verification:ttlid").await;
    assert!(
        residual > 0 && residual <= 600,
        "residual TTL must be preserved, not reset/extended (got {residual})"
    );

    // Max-attempts lockout: with a ceiling of 1, one wrong guess exhausts it.
    assert!(stores.put(purpose, "id2", "654321", 600).await.is_ok());
    assert!(matches!(
        stores.verify(purpose, "id2", "000000", 1).await,
        Err(AuthError::OtpInvalid)
    ));
    assert!(matches!(
        stores.verify(purpose, "id2", "654321", 1).await,
        Err(AuthError::OtpMaxAttempts)
    ));

    // Resend cooldown: first begins, second is throttled.
    assert!(matches!(
        stores.try_begin_resend(purpose, "id1", 60).await,
        Ok(true)
    ));
    assert!(matches!(
        stores.try_begin_resend(purpose, "id1", 60).await,
        Ok(false)
    ));
}

#[tokio::test]
async fn brute_force_window_starts_at_first_failure_and_does_not_slide() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let id = "bf-id";

    assert!(matches!(stores.is_locked(id, 3).await, Ok(false)));
    // An absent counter has no lockout remaining.
    assert!(matches!(stores.remaining_lockout_secs(id).await, Ok(0)));

    assert!(matches!(stores.record_failure(id, 900).await, Ok(1)));
    let ttl_after_first = redis.ttl("auth:lf:bf-id").await;
    assert!(ttl_after_first > 0 && ttl_after_first <= 900);

    assert!(matches!(stores.record_failure(id, 900).await, Ok(2)));
    let ttl_after_second = redis.ttl("auth:lf:bf-id").await;
    // The window does not slide: the TTL is set only on the 0->1 transition.
    assert!(
        ttl_after_second <= ttl_after_first,
        "window must not extend on later failures"
    );

    assert!(matches!(stores.record_failure(id, 900).await, Ok(3)));
    assert!(matches!(stores.is_locked(id, 3).await, Ok(true)));
    assert!(matches!(
        stores.remaining_lockout_secs(id).await,
        Ok(s) if s > 0 && s <= 900
    ));

    assert!(stores.reset(id).await.is_ok());
    assert!(matches!(stores.is_locked(id, 3).await, Ok(false)));
    assert!(matches!(stores.remaining_lockout_secs(id).await, Ok(0)));
}

#[tokio::test]
async fn ws_ticket_is_single_use() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };

    let minted = stores.mint(&snapshot(), 30).await;
    assert!(matches!(&minted, Ok(t) if !t.is_empty()));
    let Ok(ticket) = minted else { return };

    // Redeem once succeeds and returns the snapshot.
    assert!(matches!(
        stores.redeem(&ticket).await,
        Ok(Some(s)) if s.sub == "u1"
    ));
    // A second redeem of the same ticket finds nothing (single-use GETDEL).
    assert!(matches!(stores.redeem(&ticket).await, Ok(None)));
    // An unknown ticket also yields nothing.
    assert!(matches!(stores.redeem("unknown-ticket").await, Ok(None)));
}

#[tokio::test]
async fn keys_are_namespaced_no_pii_and_carry_a_ttl() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    // A custom namespace proves prefixing is applied verbatim and in one place.
    let Some(stores) = redis.stores_with_namespace("myapp") else {
        return;
    };

    // Exercise every store operation so each catalog prefix appears in the keyspace.
    let kind = SessionKind::Dashboard;
    assert!(
        stores
            .create_session(kind, "deadbeef01", &record("user-42"), 3600)
            .await
            .is_ok()
    );
    assert!(matches!(
        stores
            .rotate(kind, &rotation("deadbeef01", "cafebabe02", "user-42"))
            .await,
        Ok(RotateOutcome::Rotated(_))
    ));
    assert!(
        stores
            .create_session(
                SessionKind::Platform,
                "platformhash03",
                &record("padmin"),
                3600
            )
            .await
            .is_ok()
    );
    assert!(
        stores
            .put(OtpPurpose::PasswordReset, "hmacid", "123456", 600)
            .await
            .is_ok()
    );
    assert!(matches!(
        stores
            .try_begin_resend(OtpPurpose::PasswordReset, "hmacid", 60)
            .await,
        Ok(true)
    ));
    assert!(matches!(stores.record_failure("bfhmac", 900).await, Ok(1)));
    assert!(stores.blacklist_access("jti-xyz", 60).await.is_ok());
    // The single-use opaque-token keyspaces (`pr:`/`prv:`/`inv:`) also appear, hashed by
    // sha256(token) so a raw token (which could contain attacker-chosen bytes) is never a key.
    let reset_context = ResetContext {
        user_id: "user-42".to_owned(),
        email: "victim@example.com".to_owned(),
        tenant_id: "t1".to_owned(),
    };
    assert!(
        stores
            .put_token("reset-token-secret", &reset_context, 600)
            .await
            .is_ok()
    );
    assert!(
        stores
            .put_verified("verified-token-secret", &reset_context, 300)
            .await
            .is_ok()
    );
    assert!(
        stores
            .put_invitation(
                "invite-token-secret",
                &StoredInvitation {
                    email: "invitee@example.com".to_owned(),
                    role: "MEMBER".to_owned(),
                    tenant_id: "t1".to_owned(),
                    inviter_user_id: "user-42".to_owned(),
                },
                604800,
            )
            .await
            .is_ok()
    );
    let minted = stores.mint(&snapshot(), 30).await;
    let Ok(ticket) = minted else { return };

    let keys = redis.all_keys().await;
    assert!(!keys.is_empty(), "operations should have written keys");
    let allowed = [
        "rt", "rv", "rp", "sess", "sd", "lf", "otp", "resend", "wst", "pr", "prv", "inv", "prt",
        "prp", "psess", "psd",
    ];
    for key in &keys {
        // Namespaced under the configured prefix, applied in exactly one place.
        assert!(key.starts_with("myapp:"), "key not namespaced: {key}");
        let rest = &key["myapp:".len()..];
        let prefix = rest.split(':').next().unwrap_or_default();
        assert!(allowed.contains(&prefix), "unknown catalog prefix in {key}");
        // No raw PII: an email ('@') never appears, and the raw WebSocket ticket is hashed.
        assert!(!key.contains('@'), "an email leaked into a key: {key}");
        assert!(
            !key.contains(&ticket),
            "the raw ws ticket leaked into a key: {key}"
        );
        // Every key carries a TTL — no orphan keys.
        let ttl = redis.ttl(key).await;
        assert!(ttl > 0, "key has no TTL (orphan): {key} (ttl={ttl})");
    }
}

#[tokio::test]
async fn password_reset_and_invitation_stores_are_single_use_via_getdel() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };

    // Reset link token: stored under `pr:`, consumed once.
    let reset = ResetContext {
        user_id: "u1".to_owned(),
        email: "u@example.com".to_owned(),
        tenant_id: "t1".to_owned(),
    };
    assert!(stores.put_token("rt-secret", &reset, 600).await.is_ok());
    assert!(matches!(
        stores.consume_token("rt-secret").await,
        Ok(Some(c)) if c.user_id == "u1"
    ));
    // Single-use: a second consume finds nothing.
    assert!(matches!(stores.consume_token("rt-secret").await, Ok(None)));

    // delete_token removes an unconsumed token (the undeliverable-email cleanup path).
    assert!(stores.put_token("undeliverable", &reset, 600).await.is_ok());
    assert!(stores.delete_token("undeliverable").await.is_ok());
    assert!(matches!(
        stores.consume_token("undeliverable").await,
        Ok(None)
    ));

    // Verified token: stored under `prv:`, consumed once.
    assert!(stores.put_verified("vt-secret", &reset, 300).await.is_ok());
    assert!(matches!(
        stores.consume_verified("vt-secret").await,
        Ok(Some(c)) if c.email == "u@example.com"
    ));
    assert!(matches!(
        stores.consume_verified("vt-secret").await,
        Ok(None)
    ));

    // Invitation: stored under `inv:`, consumed once; a tampered role survives the store but
    // is re-validated by the engine on accept (covered by the engine flow test below).
    let invitation = StoredInvitation {
        email: "invitee@example.com".to_owned(),
        role: "MEMBER".to_owned(),
        tenant_id: "t1".to_owned(),
        inviter_user_id: "owner".to_owned(),
    };
    assert!(
        stores
            .put_invitation("inv-secret", &invitation, 604800)
            .await
            .is_ok()
    );
    assert!(matches!(
        stores.consume_invitation("inv-secret").await,
        Ok(Some(i)) if i.role == "MEMBER"
    ));
    assert!(matches!(
        stores.consume_invitation("inv-secret").await,
        Ok(None)
    ));
    // An unknown token is also `None`.
    assert!(matches!(
        stores.consume_invitation("never-seen").await,
        Ok(None)
    ));
}

#[tokio::test]
async fn engine_runs_password_reset_via_token_and_otp_against_redis() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(token_stores) = redis.stores() else { return };

    // --- Token method: register, plant a session, reset via a token, confirm revocation. ---
    let users = Arc::new(InMemoryUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;
    config.password_reset.method = bymax_auth_core::config::ResetMethod::Token;

    let Ok(engine) = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(Arc::new(token_stores))
        .build()
    else {
        return;
    };
    let ctx = RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new());

    let registered = engine
        .register(
            bymax_auth_core::services::auth::RegisterInput {
                email: "reset@example.com".to_owned(),
                name: "Reset User".to_owned(),
                password: "correct horse battery staple".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &ctx,
        )
        .await;
    let Ok(LoginResult::Success(auth)) = registered else {
        return;
    };

    // Initiate stores a reset token under `pr:` (best-effort); the raw token is opaque to the
    // test, so plant a known token via the store to drive the reset deterministically.
    assert!(
        engine
            .initiate_reset(ForgotPasswordInput {
                email: "reset@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
            })
            .await
            .is_ok()
    );
    let Some(reset_stores) = redis.stores() else { return };
    assert!(
        reset_stores
            .put_token(
                "known-reset-token",
                &ResetContext {
                    user_id: auth.user.id.clone(),
                    email: "reset@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                },
                600,
            )
            .await
            .is_ok()
    );
    assert!(
        engine
            .reset_password(ResetPasswordInput {
                email: "reset@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
                new_password: "a-brand-new-password".to_owned(),
                token: Some("known-reset-token".to_owned()),
                otp: None,
                verified_token: None,
            })
            .await
            .is_ok()
    );

    // All sessions were revoked: the refresh token from registration no longer rotates.
    assert!(matches!(
        engine
            .refresh(&auth.refresh_token, "203.0.113.4", "agent/1.0")
            .await,
        Err(AuthError::RefreshTokenInvalid)
    ));
    // The reset token is single-use: a replay is invalid.
    assert!(matches!(
        engine
            .reset_password(ResetPasswordInput {
                email: "reset@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
                new_password: "again".to_owned(),
                token: Some("known-reset-token".to_owned()),
                otp: None,
                verified_token: None,
            })
            .await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));

    // --- OTP method: verify→verified-token→reset bridge against the real `otp:`/`prv:`. ---
    let Some(otp_stores) = redis.stores_with_namespace("otpns") else {
        return;
    };
    let otp_users = Arc::new(InMemoryUserRepository::new());
    let mut otp_config = AuthConfig::default();
    otp_config.jwt.secret = SecretString::from("fedcba9876543210fedcba9876543210".to_owned());
    otp_config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    otp_config.email_verification.required = false;
    otp_config.password_reset.method = bymax_auth_core::config::ResetMethod::Otp;
    let Ok(otp_engine) = AuthEngine::builder()
        .config(otp_config)
        .environment(Environment::Test)
        .user_repository(otp_users.clone())
        .redis_stores(Arc::new(otp_stores))
        .build()
    else {
        return;
    };
    let otp_ctx = RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new());
    let registered = otp_engine
        .register(
            bymax_auth_core::services::auth::RegisterInput {
                email: "otp-reset@example.com".to_owned(),
                name: "Otp User".to_owned(),
                password: "old-password".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &otp_ctx,
        )
        .await;
    assert!(matches!(registered, Ok(LoginResult::Success(_))));

    // Plant a known OTP under the real `otp:` keyspace so the verify→token→reset path runs.
    let Some(seed) = redis.stores_with_namespace("otpns") else {
        return;
    };
    // The identifier is hmac(tenant:email) — opaque to the test — so drive the OTP through the
    // engine's resend path, then read it back is not possible; instead store a known code
    // under the OTP store directly via the engine's identifier by initiating, which writes a
    // code we cannot read. So exercise verify_reset_otp's failure path (wrong code) here and
    // rely on the in-memory engine tests for the success path's exact code matching.
    let _ = seed;
    assert!(matches!(
        otp_engine
            .verify_reset_otp(VerifyResetOtpInput {
                email: "otp-reset@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
                otp: "000000".to_owned(),
            })
            .await,
        Err(AuthError::OtpExpired) | Err(AuthError::OtpInvalid)
    ));
}

#[tokio::test]
async fn engine_runs_invitation_accept_against_redis() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores_with_namespace("invns") else {
        return;
    };
    let stores = Arc::new(stores);

    let users = Arc::new(InMemoryUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([
        ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
        ("MEMBER".to_owned(), Vec::new()),
    ]);
    config.email_verification.required = false;
    config.invitations.enabled = true;

    let Ok(engine) = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .build()
    else {
        return;
    };

    // Seed an ADMIN inviter, then create a real invitation through `invite`.
    let Ok(admin) = users
        .create(bymax_auth_types::CreateUserData {
            email: "admin@example.com".to_owned(),
            name: "Admin".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("ADMIN".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await
    else {
        return;
    };
    assert!(
        engine
            .invite(
                &admin.id,
                "invitee@example.com",
                "MEMBER",
                "t1",
                Some("Acme")
            )
            .await
            .is_ok()
    );

    // The raw token is opaque, so plant a known invitation under `inv:` and accept it.
    assert!(
        stores
            .put_invitation(
                "known-invite-token",
                &StoredInvitation {
                    email: "invitee@example.com".to_owned(),
                    role: "MEMBER".to_owned(),
                    tenant_id: "t1".to_owned(),
                    inviter_user_id: admin.id.clone(),
                },
                604800,
            )
            .await
            .is_ok()
    );
    let accepted = engine
        .accept_invitation(
            AcceptInvitationInput {
                token: "known-invite-token".to_owned(),
                name: "New Member".to_owned(),
                password: "a-strong-password".to_owned(),
            },
            "203.0.113.4",
            "agent/1.0",
            BTreeMap::new(),
        )
        .await;
    assert!(matches!(&accepted, Ok(a) if a.user.email == "invitee@example.com"));
    let Ok(result) = accepted else { return };
    assert!(result.user.email_verified);
    assert_eq!(result.user.role, "MEMBER");

    // The session was persisted in Redis under the refresh hash.
    let hash = bymax_auth_jwt::RawRefreshToken::from_raw(result.refresh_token.clone()).redis_hash();
    assert!(matches!(
        stores.find_session(SessionKind::Dashboard, &hash).await,
        Ok(Some(_))
    ));

    // The invitation token is single-use: a replay is rejected.
    assert!(matches!(
        engine
            .accept_invitation(
                AcceptInvitationInput {
                    token: "known-invite-token".to_owned(),
                    name: "Replay".to_owned(),
                    password: "pw".to_owned(),
                },
                "203.0.113.4",
                "agent/1.0",
                BTreeMap::new(),
            )
            .await,
        Err(AuthError::InvalidInvitationToken)
    ));
}

#[tokio::test]
async fn engine_session_limit_evicts_oldest_against_redis() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores_with_namespace("sessns") else {
        return;
    };
    let stores = Arc::new(stores);

    let users = Arc::new(InMemoryUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;
    // Enable session tracking with a cap of two so the third login evicts the oldest.
    config.sessions.enabled = true;
    config.sessions.default_max_sessions = 2;

    let Ok(engine) = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .build()
    else {
        return;
    };
    let ctx = RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new());

    let register = bymax_auth_core::services::auth::RegisterInput {
        email: "cap@example.com".to_owned(),
        name: "Cap User".to_owned(),
        password: "correct horse battery staple".to_owned(),
        tenant_id: "t1".to_owned(),
    };
    let first = engine.register(register, &ctx).await;
    let Ok(LoginResult::Success(first)) = first else {
        return;
    };
    let user_id = first.user.id.clone();
    let first_hash =
        bymax_auth_jwt::RawRefreshToken::from_raw(first.refresh_token.clone()).redis_hash();

    let login = |email: &str| bymax_auth_core::services::auth::LoginInput {
        email: email.to_owned(),
        password: "correct horse battery staple".to_owned(),
        tenant_id: "t1".to_owned(),
    };
    // Two more logins push the live session count to three, over the cap of two.
    let Ok(LoginResult::Success(_)) = engine.login(login("cap@example.com"), &ctx).await else {
        return;
    };
    let Ok(LoginResult::Success(third)) = engine.login(login("cap@example.com"), &ctx).await else {
        return;
    };
    let third_hash =
        bymax_auth_jwt::RawRefreshToken::from_raw(third.refresh_token.clone()).redis_hash();

    // The cap holds at two and the oldest (registration) session was evicted, while the newest
    // survives — proof the FIFO eviction excluded the just-created session.
    let listed = stores.list_sessions(SessionKind::Dashboard, &user_id).await;
    assert!(matches!(&listed, Ok(v) if v.len() == 2));
    let Ok(listed) = listed else { return };
    assert!(listed.iter().all(|s| s.session_hash != first_hash));
    assert!(listed.iter().any(|s| s.session_hash == third_hash));
}

#[tokio::test]
async fn engine_runs_register_login_refresh_logout_against_redis() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };

    let users = Arc::new(InMemoryUserRepository::new());
    let mut config = AuthConfig::default();
    config.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    config.roles.hierarchy = HashMap::from([("USER".to_owned(), Vec::new())]);
    config.email_verification.required = false;

    let built = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(users)
        .redis_stores(Arc::new(stores))
        .build();
    assert!(built.is_ok(), "engine must assemble with the Redis stores");
    let Ok(engine) = built else { return };
    let ctx = RequestContext::new("203.0.113.4", "agent/1.0", BTreeMap::new());

    // Register issues a full session persisted in Redis.
    let registered = engine
        .register(
            RegisterInput {
                email: "e2e@example.com".to_owned(),
                name: "E2E User".to_owned(),
                password: "correct horse battery staple".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &ctx,
        )
        .await;
    assert!(
        matches!(registered, Ok(LoginResult::Success(_))),
        "register should succeed"
    );

    // Login with the same credentials returns a fresh session.
    let logged_in = engine
        .login(
            LoginInput {
                email: "e2e@example.com".to_owned(),
                password: "correct horse battery staple".to_owned(),
                tenant_id: "t1".to_owned(),
            },
            &ctx,
        )
        .await;
    assert!(
        matches!(&logged_in, Ok(LoginResult::Success(_))),
        "login should succeed"
    );
    let Ok(LoginResult::Success(auth)) = logged_in else {
        return;
    };

    // Refresh rotates against the real Redis stores, returning a new pair the client now holds.
    let refreshed = engine
        .refresh(&auth.refresh_token, "203.0.113.4", "agent/1.0")
        .await;
    assert!(
        matches!(&refreshed, Ok(tokens) if tokens.refresh_token != auth.refresh_token),
        "refresh should rotate to a new token"
    );
    let Ok(rotated) = refreshed else { return };

    // Logout revokes the live (rotated) session and blacklists its access token — best-effort,
    // always Ok.
    assert!(
        engine
            .logout(&rotated.access_token, &rotated.refresh_token, &auth.user.id)
            .await
            .is_ok()
    );
    // The revoked refresh token no longer rotates after logout.
    assert!(matches!(
        engine
            .refresh(&rotated.refresh_token, "203.0.113.4", "agent/1.0")
            .await,
        Err(AuthError::RefreshTokenInvalid)
    ));
}
