//! The signed-in password change and the invalidation a completed reset performs
//! (layer: core services, test support).

use super::*;

/// An account with no local password fingerprints as the empty string, which the consume
/// path reads as "no binding". That is the right reading: there was no password to bind to,
/// and a proof minted then is invalidated the moment one is set — because the fingerprint
/// computed at consume time will no longer be empty.
#[test]
fn a_passwordless_account_fingerprints_as_empty() {
    let mut user = AuthUser {
        id: "u1".into(),
        email: "user@example.com".into(),
        name: "User".into(),
        password_hash: None,
        role: "MEMBER".into(),
        status: "ACTIVE".into(),
        tenant_id: "t1".into(),
        email_verified: true,
        mfa_enabled: false,
        mfa_secret: None,
        mfa_recovery_codes: None,
        oauth_provider: Some("google".into()),
        oauth_provider_id: Some("google-123".into()),
        last_login_at: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
    };
    assert_eq!(password_fingerprint(&user), "");

    user.password_hash = Some("$scrypt$abc".to_owned());
    assert_ne!(password_fingerprint(&user), "");
}

#[tokio::test]
async fn a_completed_reset_invalidates_the_tokens_issued_beside_it() {
    // Each `forgot-password` writes its own key, so several proofs can be alive at once, and
    // completing one used to leave the rest valid. That is the wrong end state exactly when
    // it matters: a victim who resets BECAUSE an attacker read a link from their mailbox had
    // not closed the link the attacker read, and the attacker could set the password again
    // for the rest of the TTL.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("siblings@example.com", "oldsecret77"))
        .await;
    let Some(store) = h.engine.password_reset_store() else { unreachable!() };

    // Two proofs, both bound to the password in force now.
    let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { unreachable!() };
    let context = ResetContext {
        user_id: id.clone(),
        email: "siblings@example.com".to_owned(),
        tenant_id: "t1".to_owned(),
        password_fingerprint: password_fingerprint(&user),
    };
    let first = "1".repeat(64);
    let second = "2".repeat(64);
    assert!(store.put_token(&first, &context, 600).await.is_ok());
    assert!(store.put_token(&second, &context, 600).await.is_ok());

    // The victim completes the reset with the second link.
    let input = |token: &str, password: &str| ResetPasswordInput {
        email: "siblings@example.com".to_owned(),
        tenant_id: Some("t1".to_owned()),
        new_password: password.to_owned(),
        token: Some(token.to_owned()),
        otp: None,
        verified_token: None,
    };
    assert!(
        h.engine
            .reset_password(input(&second, "victimchosen456"), &ctx())
            .await
            .is_ok()
    );

    // The first link — the one the attacker read — no longer works.
    assert!(matches!(
        h.engine
            .reset_password(input(&first, "attackerchosen789"), &ctx())
            .await,
        Err(AuthError::PasswordResetTokenInvalid)
    ));

    // …and the victim's password is the one that stands.
    assert!(
        login_ok(&h, "siblings@example.com", "victimchosen456")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn change_password_requires_the_current_one_and_rotates() {
    // ASVS v5 §6.2.2 and §6.2.3 at Level 1: users can change their password, and the change
    // takes both the current and the new one. The current password is what makes it safe —
    // a session alone is not proof of identity, so a token lifted by XSS or from a shared
    // machine must not be enough to rotate the credential and lock the owner out.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("changer@example.com", "oldsecret77"))
        .await;

    // A wrong current password writes nothing.
    let refused = h
        .engine
        .change_password("t1", &id, "not-the-password", "glidingwalnut42", None)
        .await;
    assert!(matches!(refused, Err(AuthError::InvalidCredentials)));

    // The right one rotates it, and the new password is what logs in afterwards.
    assert!(
        h.engine
            .change_password("t1", &id, "oldsecret77", "glidingwalnut42", None)
            .await
            .is_ok()
    );
    assert!(
        login_ok(&h, "changer@example.com", "glidingwalnut42")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn change_password_does_not_reach_an_account_in_another_tenant() {
    // `find_by_id(.., None)` is the cross-tenant admin lookup. Reading with it here meant a
    // caller in `t2` naming an id that lives in `t1` verified the current password against
    // `t1`'s account and rotated it, while the session revocation (keyed on the caller's
    // tenant) swept `t2`'s sessions: the wrong account changed and the right sessions went.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("tenant-one@example.com", "oldsecret77"))
        .await;

    let crossed = h
        .engine
        .change_password("t2", &id, "oldsecret77", "glidingwalnut42", None)
        .await;
    assert!(
        matches!(crossed, Err(AuthError::InvalidCredentials)),
        "a caller in another tenant must not be able to rotate this account: {crossed:?}"
    );

    // The account is untouched: the old password still logs in, the attempted one does not.
    assert!(
        login_ok(&h, "tenant-one@example.com", "oldsecret77")
            .await
            .is_some()
    );
    assert!(
        login_ok(&h, "tenant-one@example.com", "glidingwalnut42")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn a_reset_context_from_another_tenant_does_not_read_the_account() {
    // The reset proof carries its tenant, so the two follow-up reads (is the proof still
    // bound to the password, and the user handed to the hook) are scoped by it. Unscoped,
    // a context naming `t2` still found the `t1` account, compared its password fingerprint
    // and handed its profile to the hook.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("ctx-scope@example.com", "oldsecret77"))
        .await;
    let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { unreachable!() };
    let foreign = ResetContext {
        user_id: id.clone(),
        email: user.email.clone(),
        tenant_id: "t2".to_owned(),
        password_fingerprint: password_fingerprint(&user),
    };

    assert!(
        h.engine.assert_proof_still_bound(&foreign).await.is_err(),
        "a proof for another tenant must not read this account's password"
    );
    assert!(
        h.engine.project_user_for_hook(&foreign).await.is_none(),
        "a context for another tenant must not project this account to the hook"
    );
}

#[tokio::test]
async fn change_password_carries_the_password_lockout() {
    // `login` refuses an account after N wrong passwords. This door asks for the SAME secret
    // and used to refuse nothing, so a caller holding a stolen access token but not the
    // password could guess it here without limit — and winning replaces the credential,
    // which locks the owner out of their own account. The per-IP limiter is not that
    // control: in this crate it is in-process and per-instance, so a distributed caller
    // sidesteps it entirely, and it is not keyed to the account under attack.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("locked@example.com", "oldsecret77"))
        .await;

    // Spend the budget on wrong guesses.
    for _ in 0..5 {
        let _ = h
            .engine
            .change_password("t1", &id, "not-the-password", "glidingwalnut42", None)
            .await;
    }

    // Now even the RIGHT password is refused, and with the lockout code rather than the
    // credential one — the caller has to wait, not keep guessing.
    let refused = h
        .engine
        .change_password("t1", &id, "oldsecret77", "glidingwalnut42", None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::AccountLocked { .. })),
        "expected the re-proof lockout to engage, got {refused:?}"
    );

    // …and nothing was written: the credential the owner still knows is intact.
    assert!(
        login_ok(&h, "locked@example.com", "oldsecret77")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn change_password_spares_the_caller_session_when_it_is_identified() {
    // ASVS v5 §7.4.3: the other sessions end. The caller's own survives, so the device that
    // made the change is not signed out by making it — it silently re-mints its access
    // token on the next rotation instead.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("keeper@example.com", "oldsecret77"))
        .await;
    let mine = login_ok(&h, "keeper@example.com", "oldsecret77").await;
    let Some(mine) = mine else { unreachable!() };
    let other = login_ok(&h, "keeper@example.com", "oldsecret77").await;
    let Some(other) = other else { unreachable!() };

    assert!(
        h.engine
            .change_password(
                "t1",
                &id,
                "oldsecret77",
                "glidingwalnut42",
                Some(&mine.refresh_token)
            )
            .await
            .is_ok()
    );

    // The other device is gone…
    assert!(
        h.engine
            .refresh(&other.refresh_token, "1.2.3.4", "agent")
            .await
            .is_err()
    );
    // …and the caller's own still rotates.
    assert!(
        h.engine
            .refresh(&mine.refresh_token, "1.2.3.4", "agent")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn change_password_refuses_an_account_with_no_local_password() {
    // An account provisioned purely through OAuth has nothing to prove and nothing to
    // change — its credential belongs to the provider. Answering the same
    // `InvalidCredentials` as a wrong password keeps the two indistinguishable.
    let Some(h) = token_harness() else { unreachable!() };
    let created = h
        .users
        .create(CreateUserData {
            email: "oauth-only@example.com".to_owned(),
            name: "OAuth Only".to_owned(),
            password_hash: None,
            role: None,
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { unreachable!() };

    let refused = h
        .engine
        .change_password("t1", &user.id, "anything", "glidingwalnut42", None)
        .await;
    assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn change_password_refuses_a_new_password_the_screen_rejects() {
    // The screen runs on the change path as it does on register and reset — otherwise the
    // one flow a user reaches *because* they were told their password was weak is the one
    // that lets them pick another weak one.
    let Some(h) = token_harness() else { unreachable!() };
    let id = h
        .seed(SeedUser::active("weak@example.com", "oldsecret77"))
        .await;

    let refused = h
        .engine
        .change_password("t1", &id, "oldsecret77", "Password1234567", None)
        .await;
    assert!(matches!(refused, Err(AuthError::PasswordCompromised)));
}

#[tokio::test]
async fn apply_reset_skips_the_hook_for_a_vanished_subject() {
    // A reset whose bound context points at a user id that no longer resolves still
    // succeeds (password update + revoke run on the id), and the hook projection is
    // skipped — covering the `None` arm of the hook user lookup.
    let Some(h) = token_harness() else { unreachable!() };
    // Seed a real account so the email/tenant binding matches, then plant a token whose
    // stored user_id is a non-existent id.
    let _ = h.seed(SeedUser::active("vanish@example.com", "pw")).await;
    let token = "1".repeat(64);
    assert!(
        h.stores
            .put_token(
                &token,
                &ResetContext {
                    user_id: "ghost-user-id".to_owned(),
                    email: "vanish@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600
            )
            .await
            .is_ok()
    );
    assert!(
        h.engine
            .reset_password(
                ResetPasswordInput {
                    email: "vanish@example.com".to_owned(),
                    tenant_id: Some("t1".to_owned()),
                    new_password: "glidingwalnut42".to_owned(),
                    token: Some(token),
                    otp: None,
                    verified_token: None,
                },
                &ctx()
            )
            .await
            .is_ok()
    );
}
