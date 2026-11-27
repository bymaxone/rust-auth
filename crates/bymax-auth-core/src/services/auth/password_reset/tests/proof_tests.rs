//! Resetting by token, by OTP and by verified token, and what each proof refuses
//! (layer: core services, test support).

use super::*;

#[tokio::test]
async fn token_method_resets_and_revokes_all_sessions() {
    // The token method stores a reset token, the reset consumes it, the password changes,
    // and every session is revoked.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("reset@example.com", "old-pw"))
        .await;
    let before = stored_hash(&h, &id).await;

    // Plant a live session so the post-reset revoke is observable.
    let hash = "a".repeat(64);
    let record = crate::traits::SessionRecord {
        user_id: id.clone(),
        tenant_id: Some("t1".to_owned()),
        role: "USER".to_owned(),
        device: "Chrome".to_owned(),
        ip: "1.2.3.4".to_owned(),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        mfa_enabled: false,
        mfa_verified: false,
        family_id: "fam-test".to_owned(),
        family_created_at: Some(time::OffsetDateTime::UNIX_EPOCH),
    };
    assert!(
        h.stores
            .create_session(
                SessionKind::Dashboard,
                &h.engine.session_subject(
                    SessionKind::Dashboard,
                    record.tenant_id.as_deref(),
                    &record.user_id
                ),
                &hash,
                &record,
                3600,
            )
            .await
            .is_ok()
    );

    // Initiate stores a token; capture it from the in-memory store via consume? Instead,
    // drive send_reset_token directly to learn the raw token is single-use end to end.
    assert!(
        h.engine
            .initiate_reset(forgot("reset@example.com"), &ctx())
            .await
            .is_ok()
    );
    // The stored token is opaque to the test; reset via a freshly minted, known token.
    let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { unreachable!() };
    let known = "f".repeat(64);
    assert!(
        h.stores
            .put_token(
                &known,
                &ResetContext {
                    user_id: user.id.clone(),
                    email: "reset@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600
            )
            .await
            .is_ok()
    );
    let reset = ResetPasswordInput {
        email: "reset@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "brandnewwalnut42".to_owned(),
        token: Some(known.clone()),
        otp: None,
        verified_token: None,
    };
    assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());

    // The password changed and the session was revoked.
    let after = stored_hash(&h, &id).await;
    assert_ne!(before, after);
    assert!(matches!(
        h.stores.find_session(SessionKind::Dashboard, &hash).await,
        Ok(None)
    ));
    // The token is single-use: a replay is now invalid.
    let replay = ResetPasswordInput {
        email: "reset@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "anotherwalnut42".to_owned(),
        token: Some(known),
        otp: None,
        verified_token: None,
    };
    assert!(matches!(
        h.engine.reset_password(replay, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}

#[tokio::test]
async fn reset_bumps_the_token_epoch_so_pre_reset_access_tokens_are_invalidated() {
    // A reset revokes the refresh sessions AND advances the user's token epoch, so every
    // already-issued (stateless) access token is rejected on its next verification rather
    // than lingering for its remaining lifetime.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h.seed(SeedUser::active("epoch@example.com", "pw")).await;
    // Before the reset the user carries the inert epoch 0.
    assert!(matches!(
        h.stores
            .current_epoch(
                SessionKind::Dashboard,
                &h.engine
                    .session_subject(SessionKind::Dashboard, Some("t1"), &id),
            )
            .await,
        Ok(0)
    ));
    let known = "e".repeat(64);
    assert!(
        h.stores
            .put_token(
                &known,
                &ResetContext {
                    user_id: id.clone(),
                    email: "epoch@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600,
            )
            .await
            .is_ok()
    );
    let reset = ResetPasswordInput {
        email: "epoch@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "brandnewwalnut42".to_owned(),
        token: Some(known),
        otp: None,
        verified_token: None,
    };
    assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());
    // The reset advanced the epoch: any token stamped at 0 is now below the current value.
    assert!(matches!(
        h.stores
            .current_epoch(
                SessionKind::Dashboard,
                &h.engine
                    .session_subject(SessionKind::Dashboard, Some("t1"), &id),
            )
            .await,
        Ok(1)
    ));
}

#[tokio::test]
async fn a_rejected_new_password_leaves_the_reset_token_unspent() {
    // The proof is single-use and consumed atomically, so a screen rejection that arrived
    // after the consumption told the caller their password was unacceptable and, in the
    // same breath, that the only credential they had to fix it was gone — the whole mail
    // round trip repeated for a mistake the request itself carried.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h.seed(SeedUser::active("spend@example.com", "pw")).await;
    let known = "c".repeat(64);
    assert!(
        h.stores
            .put_token(
                &known,
                &ResetContext {
                    user_id: id,
                    email: "spend@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600
            )
            .await
            .is_ok()
    );

    // `password1234567` reduces to `password`, which is exactly what the default screen refuses —
    // and it clears the length floor, so the refusal it asserts is the screen and not the floor.
    let refused = ResetPasswordInput {
        email: "spend@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "password1234567".to_owned(),
        token: Some(known.clone()),
        otp: None,
        verified_token: None,
    };
    assert!(matches!(
        h.engine.reset_password(refused, &ctx()).await,
        Err(AuthError::PasswordCompromised)
    ));

    // The same token still works, which is the whole point.
    let retried = ResetPasswordInput {
        email: "spend@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "glidingwalnut42".to_owned(),
        token: Some(known),
        otp: None,
        verified_token: None,
    };
    assert!(h.engine.reset_password(retried, &ctx()).await.is_ok());
}

#[tokio::test]
async fn token_binding_rejects_a_mismatched_email() {
    // A token whose stored context was bound to a different email is rejected on reset.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h.seed(SeedUser::active("bind@example.com", "pw")).await;
    let known = "b".repeat(64);
    assert!(
        h.stores
            .put_token(
                &known,
                &ResetContext {
                    user_id: id,
                    email: "bind@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600
            )
            .await
            .is_ok()
    );
    // Submit the token while claiming a different email — the digest binding fails.
    let reset = ResetPasswordInput {
        email: "attacker@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "glidingwalnut42".to_owned(),
        token: Some(known),
        otp: None,
        verified_token: None,
    };
    assert!(matches!(
        h.engine.reset_password(reset, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}

#[tokio::test]
async fn otp_method_resets_directly_and_via_verified_token() {
    // The OTP method resets with a direct OTP, and the verify→verified-token→reset bridge
    // also completes a reset.
    let Some(h) = otp_harness() else { unreachable!() };
    let id = h.seed(SeedUser::active("otp@example.com", "old")).await;
    let identifier = h.engine.hashed_identifier("t1", "otp@example.com");

    // Direct OTP path: send, read the code from the in-memory store, reset.
    assert!(
        h.engine
            .initiate_reset(forgot("otp@example.com"), &ctx())
            .await
            .is_ok()
    );
    // From the mail; the stored record is a keyed fingerprint, not the code. Awaited and
    // asserted like the second issuance below: the send is detached, so an immediate read
    // races it, and `else { return }` would turn a lost race into a test that exercises
    // neither reset path and still reports success.
    let mailed = crate::services::auth::test_support::await_password_reset_code(&h).await;
    assert!(mailed.is_some(), "the reset mail never carried a code");
    let Some(code) = mailed else { unreachable!() };
    let reset = ResetPasswordInput {
        email: "otp@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "walnutviaotp4242".to_owned(),
        token: None,
        otp: Some(code.clone()),
        verified_token: None,
    };
    assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());

    // Verified-token bridge: re-send an OTP, verify it for a token, reset with the token.
    // The earlier initiate claimed the resend cooldown — that gate is what stops a caller
    // re-minting an OTP (and a fresh `attempts: 0`) at will — so release it explicitly
    // rather than silently getting no second code and skipping the rest of this test.
    assert!(
        h.stores
            .expire_resend_cooldown(OtpPurpose::PasswordReset, &identifier)
    );
    assert!(
        h.engine
            .initiate_reset(forgot("otp@example.com"), &ctx())
            .await
            .is_ok()
    );
    // Submitted below, so it has to be the plaintext — from the mail, not the record.
    // Awaited and asserted: the send is detached, and a lost race must fail rather than skip.
    let mailed = crate::services::auth::test_support::await_password_reset_code(&h).await;
    assert!(mailed.is_some(), "the reset mail never carried a code");
    let Some(code2) = mailed else { unreachable!() };
    let verified = h
        .engine
        .verify_reset_otp(
            VerifyResetOtpInput {
                email: "otp@example.com".to_owned(),
                tenant_id: Some("t1".to_owned()),
                otp: code2,
            },
            &ctx(),
        )
        .await;
    assert!(verified.is_ok());
    let Ok(verified_token) = verified else { unreachable!() };
    let reset2 = ResetPasswordInput {
        email: "otp@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "walnutviaverified42".to_owned(),
        token: None,
        otp: None,
        verified_token: Some(verified_token.clone()),
    };
    assert!(h.engine.reset_password(reset2, &ctx()).await.is_ok());
    let _ = id;
    // The verified token is single-use.
    let replay = ResetPasswordInput {
        email: "otp@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "glidingwalnut42".to_owned(),
        token: None,
        otp: None,
        verified_token: Some(verified_token),
    };
    assert!(matches!(
        h.engine.reset_password(replay, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}

#[tokio::test]
async fn initiate_shares_the_resend_cooldown_so_the_otp_attempt_ceiling_cannot_be_reset() {
    // `resend_reset_otp` was throttled and `initiate_reset` was not, which made the
    // throttle decorative: the caller just used the other door. It also made the OTP's
    // 5-attempt ceiling per-issuance rather than per-account, because every issuance
    // rewrites the record with `attempts: 0` — so an attacker who knows an address could
    // loop "initiate, guess five times" at a six-digit code forever, and mail the victim
    // once per lap while doing it.
    let Some(h) = otp_harness() else { unreachable!() };
    let _ = h
        .seed(SeedUser::active("throttled@example.com", "old"))
        .await;
    let identifier = h.engine.hashed_identifier("t1", "throttled@example.com");

    assert!(
        h.engine
            .initiate_reset(forgot("throttled@example.com"), &ctx())
            .await
            .is_ok()
    );
    let first = h
        .stores
        .peek_otp(OtpPurpose::PasswordReset, &identifier)
        .unwrap_or_default();
    assert!(!first.is_empty(), "the first initiate mints an OTP");

    // Burn four of the five attempts, then try to buy five more with a second initiate.
    for _ in 0..4 {
        let _ = h
            .engine
            .verify_reset_otp(
                VerifyResetOtpInput {
                    email: "throttled@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                    otp: "000000".to_owned(),
                },
                &ctx(),
            )
            .await;
    }

    assert!(
        h.engine
            .initiate_reset(forgot("throttled@example.com"), &ctx())
            .await
            .is_ok(),
        "a throttled initiate is still a silent success — it must not answer whether the account exists"
    );
    // The stored code is untouched, which means its attempt counter is too: the second
    // call bought nothing.
    assert_eq!(
        h.stores.peek_otp(OtpPurpose::PasswordReset, &identifier),
        Some(first),
        "the cooldown must stop a second issuance from resetting the attempt counter"
    );
}

#[tokio::test]
async fn a_reset_started_in_one_casing_completes_in_another() {
    // Both entry points canonicalize the address before anything derives a key from it.
    // Without that, the OTP identifier written by `initiate_reset` and the one read by
    // `reset_password` disagree whenever the user types their address differently — and
    // every test above happens to use one spelling throughout, so nothing noticed.
    let Some(h) = otp_harness() else { unreachable!() };
    let id = h.seed(SeedUser::active("case@example.com", "old")).await;
    let before = stored_hash(&h, &id).await;
    // Started with the address shouted.
    assert!(
        h.engine
            .initiate_reset(forgot("CASE@Example.COM"), &ctx())
            .await
            .is_ok()
    );
    // The OTP is filed under the canonical spelling, whatever was typed.
    let identifier = h.engine.hashed_identifier("t1", "case@example.com");
    // Submitted below, so it has to be the plaintext — from the mail, not the record.
    let code = crate::services::auth::test_support::await_password_reset_code(&h)
        .await
        .unwrap_or_default();
    assert!(
        !code.is_empty(),
        "no reset OTP was minted under the canonical spelling"
    );
    // And completed with yet another spelling.
    let reset = ResetPasswordInput {
        email: "Case@Example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "walnutaftercasechange42".to_owned(),
        token: None,
        otp: Some(code),
        verified_token: None,
    };
    assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());
    // The password really changed: the stored hash is not the seeded one.
    let after = stored_hash(&h, &id).await;
    assert!(after.is_some() && after != before);

    // The verified-token bridge canonicalizes too, so the OTP minted under one spelling
    // verifies under another and the token it returns completes the reset. The first
    // initiate above claimed the resend cooldown — which is the point of that gate — so
    // release it explicitly rather than silently getting no second OTP.
    assert!(
        h.stores
            .expire_resend_cooldown(OtpPurpose::PasswordReset, &identifier)
    );
    assert!(
        h.engine
            .initiate_reset(forgot("case@example.com"), &ctx())
            .await
            .is_ok()
    );
    // Submitted below, so it has to be the plaintext — from the mail, not the record.
    let second = crate::services::auth::test_support::await_password_reset_code(&h)
        .await
        .unwrap_or_default();
    assert!(!second.is_empty());
    let verified = h
        .engine
        .verify_reset_otp(
            VerifyResetOtpInput {
                email: "cAsE@eXaMpLe.CoM".to_owned(),
                tenant_id: Some("t1".to_owned()),
                otp: second,
            },
            &ctx(),
        )
        .await;
    assert!(verified.is_ok(), "the OTP must verify under any spelling");
    let Ok(verified_token) = verified else { unreachable!() };
    let bridged = ResetPasswordInput {
        email: "CASE@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "walnutagain4242".to_owned(),
        token: None,
        otp: None,
        verified_token: Some(verified_token),
    };
    assert!(h.engine.reset_password(bridged, &ctx()).await.is_ok());
    assert!(stored_hash(&h, &id).await != after);
}

#[tokio::test]
async fn reset_password_rejects_zero_or_multiple_proofs_and_method_mismatch() {
    // No proof, two proofs, and a token presented to the OTP method are all rejected.
    let Some(h) = otp_harness() else { unreachable!() };
    let none = ResetPasswordInput {
        email: "x@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "p".to_owned(),
        token: None,
        otp: None,
        verified_token: None,
    };
    assert!(matches!(
        h.engine.reset_password(none, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
    let two = ResetPasswordInput {
        email: "x@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "p".to_owned(),
        token: None,
        otp: Some("123456".to_owned()),
        verified_token: Some("v".to_owned()),
    };
    assert!(matches!(
        h.engine.reset_password(two, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
    // A token to the OTP method is an explicit mismatch.
    let mismatch = ResetPasswordInput {
        email: "x@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "p".to_owned(),
        token: Some("t".to_owned()),
        otp: None,
        verified_token: None,
    };
    assert!(matches!(
        h.engine.reset_password(mismatch, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));

    // The token method rejects an OTP proof (no token present).
    let Some(ht) = token_harness() else { unreachable!() };
    let otp_to_token = ResetPasswordInput {
        email: "x@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: "p".to_owned(),
        token: None,
        otp: Some("123456".to_owned()),
        verified_token: None,
    };
    assert!(matches!(
        ht.engine.reset_password(otp_to_token, &ctx()).await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));
}
