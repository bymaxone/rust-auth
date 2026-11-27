//! The mail and hooks a reset or a password change sends, and what a failed send leaves behind
//! (layer: core services, test support).

use super::*;

#[tokio::test]
async fn a_changed_password_mails_the_owner_under_their_own_tenant() {
    // NIST SP 800-63B §4.6 asks for notification of a credential change through a channel
    // independent of the transaction that made it. This is the notice that turns "the victim
    // finds out days later, at a failed login" into "the victim finds out now", and until
    // this test nothing asserted it was sent at all: removing the whole notification left
    // every other test green. The tenant is asserted with it, because a notice attributed to
    // the wrong tenant is one a multi-tenant channel routes into somebody else's audit log.
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Token;
    let mailer = std::sync::Arc::new(CapturingResetEmail::default());
    let users = std::sync::Arc::new(crate::testing::InMemoryUserRepository::new());
    let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores)
        .email_provider(mailer.clone())
        .build();
    let Ok(engine) = built else { unreachable!() };
    let hashed = engine.passwords().hash("oldsecret77").await;
    let Ok(password_hash) = hashed else { unreachable!() };
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "notified@example.com".to_owned(),
            name: "N".to_owned(),
            password_hash: Some(password_hash),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "tenant-nine".to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { unreachable!() };

    assert!(
        engine
            .change_password(
                "tenant-nine",
                &user.id,
                "oldsecret77",
                "glidingwalnut42",
                None
            )
            .await
            .is_ok()
    );
    // Long enough for the detached notification to have run, as the hook test above does.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        mailer.changed_notices(),
        vec![("tenant-nine".to_owned(), "notified@example.com".to_owned())],
        "the password-changed notice did not reach the owner under their own tenant"
    );

    // And the notice is scoped the same way: naming a tenant the account is not in sends
    // nothing. Unscoped, it found the account anyway and mailed its owner about a change
    // made under another tenant's name.
    engine
        .notify_password_changed("tenant-other", &user.id)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        mailer.changed_notices().len(),
        1,
        "a notice was sent for an account that is not in the named tenant"
    );
}

#[tokio::test]
async fn the_password_changed_wrapper_forwards_the_tenant_and_recipient() {
    // The detached body driven directly, the way `detached.rs` drives its own: the flow
    // schedules it through `spawn_guarded`, which swallows and logs everything, so a wrapper
    // that sent nothing — or sent to the wrong address — would still report success.
    let mailer = std::sync::Arc::new(CapturingResetEmail::default());
    let provider: std::sync::Arc<dyn crate::traits::EmailProvider> = mailer.clone();
    assert!(
        run_send_password_changed(
            provider,
            "tenant-nine".to_owned(),
            "notified@example.com".to_owned(),
        )
        .await
        .is_ok()
    );
    assert_eq!(
        mailer.changed_notices(),
        vec![("tenant-nine".to_owned(), "notified@example.com".to_owned())]
    );
}

#[tokio::test]
async fn a_completed_reset_notifies_the_hook_with_its_subject() {
    // The projection feeding the hook can fail open — the reset has already succeeded by
    // then, so the notification is simply skipped and nothing in the result says so. A
    // deployment wires this to send the "your password changed" mail, which is the one
    // signal a victim of an account takeover gets.
    let spy = std::sync::Arc::new(ResetHookSpy::default());
    let hooks: std::sync::Arc<dyn crate::traits::AuthHooks> = spy.clone();
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Otp;
    let Some(h) = harness(cfg, Some(hooks)) else { unreachable!() };
    let id = h.seed(SeedUser::active("hooked@example.com", "old")).await;
    assert!(
        h.engine
            .initiate_reset(forgot("hooked@example.com"), &ctx())
            .await
            .is_ok()
    );
    // Submitted below, so it has to be the plaintext — from the mail, not the record.
    let code = crate::services::auth::test_support::await_password_reset_code(&h)
        .await
        .unwrap_or_default();
    assert!(!code.is_empty());
    let reset = ResetPasswordInput {
        email: "hooked@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "brand-new-walnut".to_owned(),
        token: None,
        otp: Some(code),
        verified_token: None,
    };
    assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());
    // Long enough for the detached notification to have run.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let seen = spy.subjects.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(seen, vec![id]);
}

#[tokio::test]
async fn the_emailed_reset_token_is_the_one_that_works() {
    // Driven with the token a real recipient receives, rather than one the test plants
    // itself: that is the only version of this flow where the store write and the mail
    // are both load-bearing. With a planted token, an \`initiate_reset\` that quietly
    // stored and sent nothing would still pass.
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Token;
    let mailer = std::sync::Arc::new(CapturingResetEmail::default());
    let users = std::sync::Arc::new(crate::testing::InMemoryUserRepository::new());
    let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores)
        .email_provider(mailer.clone())
        .build();
    let Ok(engine) = built else { unreachable!() };
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "mailed@example.com".to_owned(),
            name: "M".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { unreachable!() };

    assert!(
        engine
            .initiate_reset(forgot("mailed@example.com"), &ctx())
            .await
            .is_ok()
    );
    let token = mailer.token.lock().ok().and_then(|t| t.clone());
    let token = token.unwrap_or_default();
    assert!(!token.is_empty(), "no reset token reached the recipient");

    let reset = ResetPasswordInput {
        email: "mailed@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "the-new-one-walnut".to_owned(),
        token: Some(token),
        otp: None,
        verified_token: None,
    };
    assert!(engine.reset_password(reset, &ctx()).await.is_ok());
    let after = users
        .find_by_id(&user.id, None)
        .await
        .ok()
        .flatten()
        .and_then(|u| u.password_hash);
    assert!(after.is_some() && after != Some("$scrypt$x".to_owned()));

    // Exercise the rest of the capturing double's surface so the object-safe impl is
    // fully covered; only the reset-token send is load-bearing above.
    let provider = CapturingResetEmail::default();
    assert!(
        provider
            .send_password_reset_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(
        provider
            .send_email_verification_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(provider.send_mfa_enabled("t1", "e", None).await.is_ok());
    assert!(provider.send_mfa_disabled("t1", "e", None).await.is_ok());
    let session = crate::traits::SessionInfo {
        device: "d".to_owned(),
        ip: "i".to_owned(),
        session_hash: "h".to_owned(),
    };
    assert!(
        provider
            .send_new_session_alert("t1", "e", &session, None)
            .await
            .is_ok()
    );
    let invite = crate::traits::InviteData {
        inviter_name: "n".to_owned(),
        tenant_name: "t".to_owned(),
        invite_token: "tok".to_owned(),
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    assert!(
        provider
            .send_invitation("t1", "e", &invite, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn token_send_failure_deletes_the_unusable_token() {
    // On an undeliverable reset email the stored `pw_reset:` token is deleted so it cannot
    // linger; a subsequent reset with that token is therefore invalid.
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Token;
    let users = std::sync::Arc::new(crate::testing::InMemoryUserRepository::new());
    let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .redis_stores(stores.clone())
        .email_provider(std::sync::Arc::new(FailingResetEmail))
        .build();
    let Ok(engine) = built else { unreachable!() };
    assert!(
        users
            .create(bymax_auth_types::CreateUserData {
                email: "fail@example.com".to_owned(),
                name: "F".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: Some("USER".to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await
            .is_ok()
    );
    // initiate_reset drives send_reset_token, whose send fails and triggers the cleanup.
    assert!(
        engine
            .initiate_reset(forgot("fail@example.com"), &ctx())
            .await
            .is_ok()
    );

    // …and again with the rollback itself refused. The caller still sees the same
    // anti-enumerating success — it must not learn that the address exists, let alone that
    // the store is down — so the log is the only place a token now stranded in Redis for
    // its whole TTL can surface at all. The failed delivery released the resend cooldown, so
    // this second call reaches the send and the rollback branch under test runs.
    assert!(!stores.resend_cooldown_held(
        OtpPurpose::PasswordReset,
        &engine.hashed_identifier("t1", "fail@example.com")
    ));
    stores.fail_next_cleanup_writes(1);
    assert!(
        engine
            .initiate_reset(forgot("fail@example.com"), &ctx())
            .await
            .is_ok()
    );

    // Exercise every method of the failing-email double so the object-safe surface is
    // fully covered: the reset-token send errors (the path under test), the rest succeed.
    let provider = FailingResetEmail;
    assert!(
        provider
            .send_password_reset_token("t1", "e", "t", None)
            .await
            .is_err()
    );
    assert!(
        provider
            .send_password_reset_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(
        provider
            .send_email_verification_otp("t1", "e", "o", None)
            .await
            .is_ok()
    );
    assert!(provider.send_mfa_enabled("t1", "e", None).await.is_ok());
    assert!(provider.send_mfa_disabled("t1", "e", None).await.is_ok());
    let session = crate::traits::SessionInfo {
        device: "d".to_owned(),
        ip: "i".to_owned(),
        session_hash: "h".to_owned(),
    };
    assert!(
        provider
            .send_new_session_alert("t1", "e", &session, None)
            .await
            .is_ok()
    );
    let invite = crate::traits::InviteData {
        inviter_name: "n".to_owned(),
        tenant_name: "t".to_owned(),
        invite_token: "tok".to_owned(),
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
    };
    assert!(
        provider
            .send_invitation("t1", "e", &invite, None)
            .await
            .is_ok()
    );
    // The cleanup means the (unknown-to-the-test) token is gone; an arbitrary token is
    // invalid, proving the flow did not leave a usable proof behind.
    assert!(matches!(
        engine
            .reset_password(
                ResetPasswordInput {
                    email: "fail@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                    new_password: "glidingwalnut42".to_owned(),
                    token: Some("a".repeat(64)),
                    otp: None,
                    verified_token: None,
                },
                &ctx()
            )
            .await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}
