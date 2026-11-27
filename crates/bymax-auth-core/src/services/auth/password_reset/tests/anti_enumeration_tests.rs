//! What the reset flow answers and logs without naming an account, its timing floor, input
//! redaction and the doubles' own coverage (layer: core services, test support).

use super::*;

#[tokio::test]
async fn a_reset_code_that_could_not_be_stored_is_logged_without_naming_the_account() {
    // The caller still gets the uniform success, so the failure is invisible to it; the log
    // line is the only place an operator can learn that no code is being stored. It carries
    // the cause and nothing that identifies the account, so it reads the same whichever
    // account it belonged to.
    let Some(h) = otp_harness() else { unreachable!() };
    let _ = h.seed(SeedUser::active("logged@example.com", "pw")).await;
    h.stores.fail_next_otp_puts(1);

    let (events, guard) = crate::log_capture::capture_events();
    let outcome = h
        .engine
        .initiate_reset(forgot("logged@example.com"), &ctx())
        .await;
    drop(guard);

    assert!(outcome.is_ok(), "the response stays uniform: {outcome:?}");
    let reported: Vec<_> = events
        .iter()
        .into_iter()
        .filter(|event| event.rendered.contains("the proof could not be issued"))
        .collect();
    assert_eq!(reported.len(), 1, "{reported:?}");
    let line = &reported[0].rendered;
    assert!(line.contains("cause=internal"), "{line}");
    assert!(
        !line.contains("otp store unavailable"),
        "the store's text was logged: {line}"
    );
    assert!(
        !events.contains("logged@example.com"),
        "the address was logged: {line}"
    );
}

#[tokio::test]
async fn initiate_and_resend_are_anti_enumerating() {
    // Initiate and resend both return Ok and honor the ≥300ms floor for an existing, a
    // blocked, and an absent account; a second resend within the window is a silent Ok.
    let Some(h) = otp_harness() else { unreachable!() };
    let _ = h.seed(SeedUser::active("present@example.com", "pw")).await;
    let _ = h
        .seed(SeedUser {
            email: "blocked@example.com".to_owned(),
            password: "pw".to_owned(),
            tenant_id: "t1".to_owned(),
            status: "BANNED".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        })
        .await;

    for email in [
        "present@example.com",
        "blocked@example.com",
        "absent@example.com",
    ] {
        let started = Instant::now();
        assert!(h.engine.initiate_reset(forgot(email), &ctx()).await.is_ok());
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    let started = Instant::now();
    assert!(
        h.engine
            .resend_reset_otp(
                ResendResetOtpInput {
                    email: "present@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                },
                &ctx()
            )
            .await
            .is_ok()
    );
    assert!(started.elapsed() >= Duration::from_millis(300));
    // A second resend within the cooldown is the silent-success branch.
    assert!(
        h.engine
            .resend_reset_otp(
                ResendResetOtpInput {
                    email: "present@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                },
                &ctx()
            )
            .await
            .is_ok()
    );
    // An absent account is indistinguishable on resend.
    assert!(
        h.engine
            .resend_reset_otp(
                ResendResetOtpInput {
                    email: "ghost@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                },
                &ctx()
            )
            .await
            .is_ok()
    );

    // Resend canonicalizes its address like the other two entry points: a code requested
    // under one spelling is filed where the confirm step will look for it. Every branch
    // here answers `Ok(())`, so only the OTP record shows which one ran — and it has to be
    // an account with no code on file yet, or an earlier `initiate` would have left one
    // under that identifier and the assertion would hold either way.
    let _ = h.seed(SeedUser::active("shout@example.com", "pw")).await;
    let identifier = h.engine.hashed_identifier("t1", "shout@example.com");
    assert!(
        h.stores
            .peek_otp(OtpPurpose::PasswordReset, &identifier)
            .is_none()
    );
    assert!(
        h.engine
            .resend_reset_otp(
                ResendResetOtpInput {
                    email: "SHOUT@Example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                },
                &ctx()
            )
            .await
            .is_ok()
    );
    assert!(
        h.stores
            .peek_otp(OtpPurpose::PasswordReset, &identifier)
            .is_some(),
        "the resent code must be filed under the canonical spelling"
    );
}

#[tokio::test]
async fn verify_reset_otp_rejects_a_vanished_account_and_a_wrong_code() {
    // A wrong OTP surfaces the OTP error; a valid OTP for an email with no backing user
    // does not mint a verified token.
    let Some(h) = otp_harness() else { unreachable!() };
    let _ = h.seed(SeedUser::active("vrf@example.com", "pw")).await;
    assert!(
        h.engine
            .initiate_reset(forgot("vrf@example.com"), &ctx())
            .await
            .is_ok()
    );
    assert!(matches!(
        h.engine
            .verify_reset_otp(
                VerifyResetOtpInput {
                    email: "vrf@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                    otp: "000000".to_owned(),
                },
                &ctx()
            )
            .await,
        Err(AuthError::OtpInvalid)
    ));
    // A valid OTP stored for an email with no backing user collapses to the
    // invalid-token error (no verified token is issued for a vanished account).
    let ghost_id = h.engine.hashed_identifier("t1", "ghost@example.com");
    // Planted through the OTP service, not straight into the store: the service fingerprints
    // the code before it writes, so a record written at the store level would hold a
    // plaintext the verify step no longer looks for — the test would then pass for the wrong
    // reason, reporting "no user" where the code simply did not match.
    assert!(
        h.engine
            .otp()
            .store(OtpPurpose::PasswordReset, &ghost_id, "111111", 600)
            .await
            .is_ok()
    );
    assert!(matches!(
        h.engine
            .verify_reset_otp(
                VerifyResetOtpInput {
                    email: "ghost@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                    otp: "111111".to_owned(),
                },
                &ctx()
            )
            .await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}

#[test]
fn reset_password_input_debug_redacts_password_and_proofs() {
    // A stray `{:?}` must never expose the new password or a live single-use proof.
    let input = ResetPasswordInput {
        email: "e@x.io".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "super-secret".to_owned(),
        token: Some("live-token".to_owned()),
        otp: Some("123456".to_owned()),
        verified_token: Some("live-verified".to_owned()),
    };
    let dbg = format!("{input:?}");
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("super-secret"));
    assert!(!dbg.contains("live-token"));
    assert!(!dbg.contains("123456"));
    assert!(!dbg.contains("live-verified"));
    assert!(dbg.contains("e@x.io"));
}

#[test]
fn digest_eq_is_true_only_for_equal_inputs() {
    // The digest-binding compare matches equal strings and rejects unequal ones.
    assert!(digest_eq("user@example.com", "user@example.com"));
    assert!(!digest_eq("user@example.com", "other@example.com"));
    assert!(!digest_eq("t1", "t2"));
}

/// An email provider whose reset-token send always fails, to drive the delete-on-failure
/// cleanup of an undeliverable reset token.
#[tokio::test]
async fn the_failing_lookup_repo_still_answers_the_mutators() {
    // The double exists to fail ONE read. Its mutators are what make it a valid
    // `UserRepository`, and `update_email` is the one the trait grew last — a method
    // nothing calls is a method nothing proves, including that it does not accidentally
    // fail a flow that shares the double.
    use crate::traits::UserRepository as _;

    assert!(
        FailingLookupRepo
            .update_email("u1", "t1", "new@example.com")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_reset_doubles_answer_every_send_the_trait_declares() {
    // These doubles exist to fail (or capture) ONE send. Their remaining methods are what
    // make them valid `EmailProvider`s at all, and a method nothing calls is a method
    // nothing proves — including that it does not accidentally fail the flows that share
    // the double. The address-change send is the one the trait grew last.
    use crate::traits::EmailProvider as _;

    assert!(
        FailingResetEmail
            .send_email_change_verification("t1", "new@example.com", "t", None)
            .await
            .is_ok()
    );
    let capturing = CapturingResetEmail::default();
    assert!(
        capturing
            .send_email_change_verification("t1", "new@example.com", "t", None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn initiate_with_no_reset_store_is_a_silent_success() {
    // An engine wired without a password-reset store still returns the uniform Ok on
    // initiate (the store-not-configured path inside send_reset_token is swallowed).
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Token;
    let users = std::sync::Arc::new(crate::testing::InMemoryUserRepository::new());
    let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        // Wire only the three required stores; no password-reset store.
        .session_store(stores.clone())
        .otp_store(stores.clone())
        .brute_force_store(stores.clone())
        .build();
    let Ok(engine) = built else { unreachable!() };
    assert!(
        users
            .create(bymax_auth_types::CreateUserData {
                email: "nostore@example.com".to_owned(),
                name: "N".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: Some("USER".to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await
            .is_ok()
    );
    assert!(
        engine
            .initiate_reset(forgot("nostore@example.com"), &ctx())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn anti_enum_timing_floor_holds_even_on_an_infrastructure_error() {
    // A backend failure on the account lookup must still honor the ≥300ms floor before the
    // error is surfaced, so a backend error cannot be told apart from a normal response by
    // latency on either initiate or resend.
    let mut cfg = base_config();
    cfg.password_reset.method = ResetMethod::Otp;
    let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(std::sync::Arc::new(FailingLookupRepo))
        .redis_stores(stores)
        .build();
    let Ok(engine) = built else { unreachable!() };

    let started = Instant::now();
    let initiate = engine
        .initiate_reset(forgot("err@example.com"), &ctx())
        .await;
    assert!(matches!(initiate, Err(AuthError::Internal(_))));
    assert!(started.elapsed() >= Duration::from_millis(300));

    // The resend path begins a fresh cooldown (so it reaches the failing lookup), then the
    // backend error surfaces only after the timing floor.
    let started = Instant::now();
    let resend = engine
        .resend_reset_otp(
            ResendResetOtpInput {
                email: "err2@example.com".to_owned(),
                tenant_id: Some("t1".to_owned()),
            },
            &ctx(),
        )
        .await;
    assert!(matches!(resend, Err(AuthError::Internal(_))));
    assert!(started.elapsed() >= Duration::from_millis(300));

    // Exercise the rest of the failing repository's object-safe surface so it is fully
    // covered: the lookups/creates error, the no-op updates succeed.
    let repo = FailingLookupRepo;
    assert!(matches!(repo.find_by_id("x", None).await, Ok(None)));
    assert!(repo.find_by_email("e", "t").await.is_err());
    assert!(repo.create(create_data()).await.is_err());
    assert!(repo.update_password("x", "t", "h").await.is_ok());
    assert!(
        repo.update_mfa(
            "x",
            "t1",
            bymax_auth_types::UpdateMfaData {
                mfa_enabled: false,
                mfa_secret: None,
                mfa_recovery_codes: None,
            },
        )
        .await
        .is_ok()
    );
    assert!(repo.update_last_login("x", "t").await.is_ok());
    assert!(repo.update_status("x", "t", "ACTIVE").await.is_ok());
    assert!(repo.update_email_verified("x", "t", true).await.is_ok());
    assert!(matches!(
        repo.find_by_oauth_id("g", "1", "t").await,
        Ok(None)
    ));
    assert!(repo.link_oauth("x", "t1", "g", "1").await.is_ok());
    assert!(repo.create_with_oauth(oauth_data()).await.is_err());
}
