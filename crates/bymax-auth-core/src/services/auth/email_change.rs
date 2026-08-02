//! Changing the address on an account (§7.11), in two steps.
//!
//! The address is the account's recovery credential: whoever controls it can drive a password
//! reset to a mailbox the owner does not read. That makes moving it a security operation, not
//! a profile edit, and it is why the flow costs three things rather than one.
//!
//! **The current password is re-proved.** A stolen access token alone cannot move the recovery
//! address — the thief has to already hold the credential that would let them take the account
//! anyway. It is also why no session is revoked here: anyone who can complete this flow could
//! already sign in, so ending the caller's other sessions would cost the user their devices
//! and buy nothing.
//!
//! **The new address is proved before it is adopted.** A token goes to it and nowhere else, so
//! a typo cannot lock the owner out of their own account and an attacker cannot point the
//! account at a mailbox they merely claim.
//!
//! **The old address is told.** NIST SP 800-63B §4.6 asks for notification of a credential
//! change, and this is the one that matters most: it is the last message the owner can receive
//! at an address they still control, and it is what turns a silent takeover into one they can
//! see happening.
//!
//! Held byte-compatible with nest-auth over the shared `ec:` keyspace, so a change requested
//! through one backend is confirmable through the other.

use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_types::{AuthError, AuthUser};

use crate::engine::AuthEngine;
use crate::normalize::normalize_email;
use crate::services::auth::map_repository_error;
use crate::traits::EmailChangeContext;

/// Bytes of entropy in an address-change token before hex encoding (256-bit, 64 hex chars).
const EMAIL_CHANGE_TOKEN_BYTES: usize = 32;

impl AuthEngine {
    /// Start an address change: re-prove the password, then mail a single-use token to the new
    /// address. Nothing about the account changes until that token comes back.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidCredentials`] when the account has no local password or the
    /// submitted one is wrong — the same error a failed login returns, so a thief holding an
    /// access token learns nothing they did not already know.
    /// Returns [`AuthError::EmailAlreadyExists`] when the address is the account's own or
    /// belongs to another account in the tenant, or a store/repository [`AuthError`].
    pub async fn request_email_change(
        &self,
        user_id: &str,
        new_email: &str,
        current_password: &str,
    ) -> Result<(), AuthError> {
        let new_email = normalize_email(new_email);
        let store = self.password_reset_store().ok_or_else(|| {
            crate::services::internal_error("password reset store not configured")
        })?;

        let user = self
            .user_repository()
            .find_by_id(user_id, None)
            .await
            .map_err(map_repository_error)?
            // A verified token whose subject no longer exists, and an account with no local
            // password, answer identically: the caller cannot prove a credential this account
            // does not have.
            .ok_or(AuthError::InvalidCredentials)?;
        let Some(phc) = user.password_hash.clone() else {
            return Err(AuthError::InvalidCredentials);
        };

        // A suspended or banned account may not move its own recovery credential. The address
        // is where every reset link and verification code goes, so changing it is at least as
        // privileged as minting an invitation — which this library already refuses a blocked
        // caller. nest-auth gates the matching route with `UserStatusGuard`; this plane had no
        // equivalent, so the operator's kill switch bought nothing here against an attacker
        // still holding an unexpired access token and the password.
        self.assert_user_not_blocked(&user.status)?;

        // Counted like a login: this door asks for the account password, so it carries the
        // password's lockout. Winning the guess here moves the address the account recovers
        // through, which is persistence rather than a single theft. Checked BEFORE the KDF, so
        // a locked account is not an amplifier either.
        let bf_id = self.reproof_identifier("email-change", user_id);
        if self.brute_force().is_locked(&bf_id).await? {
            let retry = self.brute_force().remaining_lockout_secs(&bf_id).await?;
            tracing::warn!(%user_id, "email change: account locked");
            return Err(AuthError::AccountLocked {
                retry_after_seconds: Some(retry),
            });
        }

        if !self
            .passwords()
            .verify(current_password, &phc)
            .await?
            .matched
        {
            self.brute_force().record_failure(&bf_id).await?;
            tracing::warn!(%user_id, "email change: current password rejected");
            return Err(AuthError::InvalidCredentials);
        }
        self.brute_force().reset(&bf_id).await?;

        self.assert_address_is_free(&user, &new_email).await?;

        let raw = generate_secure_token(EMAIL_CHANGE_TOKEN_BYTES);
        let context = EmailChangeContext {
            user_id: user_id.to_owned(),
            new_email: new_email.clone(),
            tenant_id: user.tenant_id.clone(),
            // Binds the token to the password in force right now, exactly as a reset proof is
            // bound. An attacker who plants a change request and waits loses it the moment the
            // victim changes their password — which is the first thing a victim does.
            password_fingerprint: super::password_reset::password_fingerprint(&user),
        };
        let ttl = self.config().config().email_change.token_ttl.as_secs();
        store.put_email_change(&raw, &context, ttl).await?;

        // Delivery failure is surfaced, not swallowed: a change whose verification could not be
        // sent has not started, and telling the caller it succeeded would leave them waiting on
        // a message that is never coming.
        self.email_provider()
            .send_email_change_verification(&new_email, &raw, None)
            .await
            .map_err(|error| {
                tracing::error!(%error, "email change: verification could not be delivered");
                crate::services::internal_error("email change verification delivery failed")
            })?;

        tracing::info!(%user_id, "email change: verification sent");
        Ok(())
    }

    /// Complete an address change against a token that came back from the new address.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::EmailChangeTokenInvalid`] when the token is unknown, expired,
    /// already used, or no longer bound to the account's password;
    /// [`AuthError::EmailAlreadyExists`] when the address was taken between the request and the
    /// confirmation; or a store/repository [`AuthError`].
    pub async fn confirm_email_change(&self, token: &str) -> Result<(), AuthError> {
        let store = self.password_reset_store().ok_or_else(|| {
            crate::services::internal_error("password reset store not configured")
        })?;

        // Atomic read-and-delete: a link works exactly once, whatever happens after.
        let context = store
            .consume_email_change(token)
            .await?
            .ok_or(AuthError::EmailChangeTokenInvalid)?;

        let user = self
            .user_repository()
            .find_by_id(&context.user_id, None)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::EmailChangeTokenInvalid)?;

        assert_still_bound(&context, &user)?;
        // The account's standing is re-read here too, and for the same reason the address is:
        // the request and the confirmation are separated by the whole TTL. A token minted
        // before a suspension would otherwise still move the recovery address of an account
        // that has since been suspended or banned — and the recovery address is what a
        // password reset is sent to, so it is the one field a blocked account must not be able
        // to change.
        self.assert_user_not_blocked(&user.status)?;
        // Re-checked here and not only at request time: the two are separated by the whole TTL,
        // and whoever registers the address in between would otherwise lose it to this change.
        self.assert_address_is_free(&user, &context.new_email)
            .await?;

        let old_email = user.email.clone();
        self.user_repository()
            .update_email(&context.user_id, &context.new_email)
            .await
            .map_err(map_repository_error)?;
        tracing::info!(user_id = %context.user_id, "email change: address changed");

        // Fire-and-forget, but logged: a change the user asked for and proved is not rolled
        // back because a mail server was down, and an operator needs to know when the notice —
        // the owner's last chance to see a takeover — did not go out.
        if let Err(error) = self
            .email_provider()
            .send_email_changed_notification(&old_email, &context.new_email, None)
            .await
        {
            tracing::error!(%error, "email change: notification to the previous address failed");
        }
        Ok(())
    }

    /// Refuse an address the account already has, or that another account in the tenant holds.
    ///
    /// Answering [`AuthError::EmailAlreadyExists`] does disclose that an address is registered
    /// — the same disclosure `register` and invitation acceptance already make, and the same
    /// one the caller could obtain there. Withholding it here would buy nothing while leaving a
    /// user who typos into a colleague's address waiting on a message that never comes, with no
    /// way to tell why.
    ///
    /// The account's own current address is refused through the same error: it is a change that
    /// changes nothing, and letting it through would send a verification for a move that is not
    /// happening.
    async fn assert_address_is_free(
        &self,
        user: &AuthUser,
        new_email: &str,
    ) -> Result<(), AuthError> {
        if normalize_email(&user.email) == new_email {
            return Err(AuthError::EmailAlreadyExists);
        }
        let taken = self
            .user_repository()
            .find_by_email(new_email, &user.tenant_id)
            .await
            .map_err(map_repository_error)?
            .is_some();
        if taken {
            return Err(AuthError::EmailAlreadyExists);
        }
        Ok(())
    }
}

/// Refuse a token whose binding no longer matches the account's password.
///
/// An empty stored fingerprint means the token predates the binding — a rolling deploy, or a
/// sibling implementation that has not taken this change — and is accepted, exactly as the
/// reset flow accepts one: refusing them would break every change in flight for a window this
/// narrow.
fn assert_still_bound(context: &EmailChangeContext, user: &AuthUser) -> Result<(), AuthError> {
    if context.password_fingerprint.is_empty() {
        return Ok(());
    }
    // Constant-time, per §24 invariant 13. Both operands are server-side, so this is the letter
    // of the invariant rather than a reachable oracle — see the twin in `password_reset.rs`.
    if super::password_reset::digest_eq(
        &context.password_fingerprint,
        &super::password_reset::password_fingerprint(user),
    ) {
        return Ok(());
    }
    tracing::warn!(
        user_id = %context.user_id,
        "email change: token no longer bound to the account password"
    );
    Err(AuthError::EmailChangeTokenInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, harness};
    use crate::testing::InMemoryUserRepository;
    use crate::traits::{PasswordResetStore, UserRepository};

    /// A harness with the address-change flow tunable, and email verification off so seeding
    /// stays about the address rather than about the onboarding gate.
    fn setup() -> Option<Harness> {
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        harness(cfg, None)
    }

    /// Read the address currently stored for an account.
    async fn stored_email(h: &Harness, id: &str) -> Option<String> {
        h.users
            .find_by_id(id, None)
            .await
            .ok()
            .flatten()
            .map(|user| user.email)
    }

    /// An email provider whose two address-change sends always fail, so the delivery arms —
    /// which the flow treats very differently — can be reached at all.
    struct FailingChangeEmail;

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for FailingChangeEmail {
        async fn send_email_change_verification(
            &self,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Err(crate::traits::EmailError::Delivery("smtp down".into()))
        }

        async fn send_email_changed_notification(
            &self,
            _old_email: &str,
            _new_email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Err(crate::traits::EmailError::Delivery("smtp down".into()))
        }

        async fn send_password_reset_token(
            &self,
            _email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_password_reset_otp(
            &self,
            _email: &str,
            _otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_email_verification_otp(
            &self,
            _email: &str,
            _otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_mfa_enabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_mfa_disabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_new_session_alert(
            &self,
            _email: &str,
            _session: &crate::traits::email::SessionInfo,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_invitation(
            &self,
            _email: &str,
            _invite: &crate::traits::email::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
    }

    /// A harness whose email provider fails both address-change sends.
    fn setup_with_failing_email() -> Option<Harness> {
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let users = std::sync::Arc::new(InMemoryUserRepository::new());
        let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
        crate::engine::AuthEngine::builder()
            .config(cfg)
            .environment(crate::config::Environment::Test)
            .user_repository(users.clone())
            .redis_stores(stores.clone())
            .email_provider(std::sync::Arc::new(FailingChangeEmail))
            .build()
            .ok()
            .map(|engine| Harness {
                engine,
                users,
                stores,
            })
    }

    /// An engine wired without a password-reset store, which is where the pending change lives.
    fn engine_without_the_store() -> Option<(
        crate::engine::AuthEngine,
        std::sync::Arc<InMemoryUserRepository>,
    )> {
        let mut cfg = base_config();
        cfg.email_verification.required = false;
        let users = std::sync::Arc::new(InMemoryUserRepository::new());
        let stores = std::sync::Arc::new(crate::testing::InMemoryStores::new());
        crate::engine::AuthEngine::builder()
            .config(cfg)
            .environment(crate::config::Environment::Test)
            .user_repository(users.clone())
            // The three required stores only — no password-reset store, so no `ec:` keyspace.
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores)
            .build()
            .ok()
            .map(|engine| (engine, users))
    }

    #[tokio::test]
    async fn an_engine_without_the_single_use_store_refuses_both_steps() {
        // The pending change lives in the password-reset keyspace. Without that store there is
        // nowhere to put the token and nowhere to read it back, so both ends refuse rather than
        // half-completing — a request that appeared to succeed would mail a link to a token
        // that was never written.
        let Some((engine, users)) = engine_without_the_store() else { return };
        let created = users
            .create(bymax_auth_types::CreateUserData {
                email: "nostore@example.com".to_owned(),
                name: "N".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: Some("USER".to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        let Ok(user) = created else { return };

        let requested = engine
            .request_email_change(&user.id, "new@example.com", "right")
            .await;
        assert!(matches!(requested, Err(AuthError::Internal(_))));

        let confirmed = engine.confirm_email_change(&"a".repeat(64)).await;
        assert!(matches!(confirmed, Err(AuthError::Internal(_))));
    }

    #[tokio::test]
    async fn an_account_with_no_local_password_cannot_move_its_address() {
        // An OAuth-only account has no credential this library can re-prove, and the address is
        // exactly what a re-prove protects. It answers as a wrong password does, so the caller
        // cannot tell the two apart — an account that exists but has no local password is not
        // something a stranger should learn.
        let Some(h) = setup() else { return };
        let created = h
            .users
            .create(bymax_auth_types::CreateUserData {
                email: "oauth@example.com".to_owned(),
                name: "N".to_owned(),
                password_hash: None,
                role: Some("USER".to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        let Ok(user) = created else { return };

        let refused = h
            .engine
            .request_email_change(&user.id, "new@example.com", "anything")
            .await;
        assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn a_blocked_account_cannot_move_its_address() {
        // The address is where every reset link and verification code goes, so moving it is at
        // least as privileged as minting an invitation — which this library already refuses a
        // blocked caller. This path had no status gate at all, so an operator who suspended a
        // compromised account bought nothing against an attacker still holding an unexpired
        // access token and the password: they could redirect the account's recovery credential
        // to an address of their own. nest-auth gates the matching route with `UserStatusGuard`.
        let Some(h) = setup() else { return };
        let id = h
            .seed(SeedUser::active("blocked@example.com", "right"))
            .await;
        assert!(h.users.update_status(&id, "SUSPENDED").await.is_ok());

        let refused = h
            .engine
            .request_email_change(&id, "attacker@example.com", "right")
            .await;

        assert!(
            matches!(refused, Err(AuthError::AccountSuspended)),
            "a suspended account must not move its address: {refused:?}"
        );
    }

    #[tokio::test]
    async fn an_undeliverable_verification_fails_the_request_rather_than_stranding_it() {
        // The opposite of the notification below, and deliberately so: the verification IS the
        // flow. Answering Ok would leave the user waiting on a message that is never coming,
        // with a token they cannot reach sitting in the store until it expires.
        let Some(h) = setup_with_failing_email() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        let refused = h
            .engine
            .request_email_change(&id, "new@example.com", "right")
            .await;
        assert!(matches!(refused, Err(AuthError::Internal(_))));
    }

    #[tokio::test]
    async fn an_undeliverable_notice_does_not_undo_a_change_the_user_proved() {
        // The notice to the PREVIOUS address is the owner's last chance to see a takeover, so
        // its failure is logged — but the change itself was asked for and proved, and rolling
        // it back because a mail server was down would punish the user for the operator's
        // outage. Fire-and-forget, and the address moves.
        let Some(h) = setup_with_failing_email() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;
        let token = "d".repeat(64);
        let Some(store) = h.engine.password_reset_store() else { return };
        let stored = store
            .put_email_change(
                &token,
                &EmailChangeContext {
                    user_id: id.clone(),
                    new_email: "new@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600,
            )
            .await;
        assert!(stored.is_ok());

        assert!(h.engine.confirm_email_change(&token).await.is_ok());
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("new@example.com")
        );
    }

    #[tokio::test]
    async fn a_token_still_bound_to_the_password_is_accepted() {
        // The other side of the binding. An absent fingerprint is accepted because it predates
        // the check; a PRESENT one has to match, and matching is the ordinary case — every
        // token the flow itself mints carries the fingerprint of the password in force when it
        // was minted, and the overwhelming majority are confirmed without a password change in
        // between.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("bound@example.com", "right")).await;
        let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { return };
        let token = "f".repeat(64);
        let Some(store) = h.engine.password_reset_store() else { return };
        let stored = store
            .put_email_change(
                &token,
                &EmailChangeContext {
                    user_id: id.clone(),
                    new_email: "bound-new@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: super::super::password_reset::password_fingerprint(&user),
                },
                600,
            )
            .await;
        assert!(stored.is_ok());

        assert!(h.engine.confirm_email_change(&token).await.is_ok());
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("bound-new@example.com")
        );
    }

    #[tokio::test]
    async fn the_failing_change_double_still_answers_every_other_send() {
        // The double exists to fail the TWO address-change sends. That everything else about it
        // succeeds is what makes it a valid `EmailProvider` — and what makes the tests above
        // about the address change rather than about a provider that is broken everywhere.
        use crate::traits::EmailProvider as _;

        let session = crate::traits::email::SessionInfo {
            device: "Chrome".to_owned(),
            ip: "1.2.3.4".to_owned(),
            session_hash: "abcd1234".to_owned(),
        };
        let invite = crate::traits::email::InviteData {
            inviter_name: "Inviter".to_owned(),
            tenant_name: "Tenant".to_owned(),
            invite_token: "t".to_owned(),
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };

        assert!(
            FailingChangeEmail
                .send_password_reset_token("e@x.io", "t", None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_password_reset_otp("e@x.io", "123456", None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_email_verification_otp("e@x.io", "123456", None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_mfa_enabled("e@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_mfa_disabled("e@x.io", None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_new_session_alert("e@x.io", &session, None)
                .await
                .is_ok()
        );
        assert!(
            FailingChangeEmail
                .send_invitation("e@x.io", &invite, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_token_carrying_no_binding_is_accepted() {
        // An absent fingerprint reads as "no binding", not as "binding failed". It is what a
        // sibling implementation that has not taken this change writes, and refusing it would
        // break every change in flight across a rolling deploy — a window this narrow is not
        // worth an outage. The binding still holds whenever the field is present.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;
        let token = "e".repeat(64);
        let Some(store) = h.engine.password_reset_store() else { return };
        let stored = store
            .put_email_change(
                &token,
                &EmailChangeContext {
                    user_id: id.clone(),
                    new_email: "unbound@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    password_fingerprint: String::new(),
                },
                600,
            )
            .await;
        assert!(stored.is_ok());

        assert!(h.engine.confirm_email_change(&token).await.is_ok());
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("unbound@example.com")
        );
    }

    #[tokio::test]
    async fn a_change_is_not_applied_until_the_new_address_proves_itself() {
        // The whole point of the two steps. A flow that wrote the address at request time and
        // verified afterwards would hand an attacker the account for the length of the TTL.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        assert!(
            h.engine
                .request_email_change(&id, "new@example.com", "right")
                .await
                .is_ok()
        );

        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("old@example.com")
        );
    }

    #[tokio::test]
    async fn the_wrong_current_password_mints_nothing() {
        // The re-prove is the gate that stops a stolen access token from moving the recovery
        // address. Without it, a thief with a token takes the account outright.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        assert!(matches!(
            h.engine
                .request_email_change(&id, "new@example.com", "wrong")
                .await,
            Err(AuthError::InvalidCredentials)
        ));
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("old@example.com")
        );
    }

    #[tokio::test]
    async fn an_account_that_cannot_prove_a_password_is_refused() {
        // A subject that no longer exists answers exactly as one with no local password: the
        // caller learns nothing either way.
        let Some(h) = setup() else { return };

        assert!(matches!(
            h.engine
                .request_email_change("ghost", "new@example.com", "right")
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn an_address_that_is_taken_or_unchanged_is_refused() {
        // Moving onto an address someone else holds would put two accounts on one recovery
        // credential; moving onto the account's own is a change that changes nothing and would
        // send a verification for a move that is not happening.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;
        let _ = h.seed(SeedUser::active("taken@example.com", "right")).await;

        assert!(matches!(
            h.engine
                .request_email_change(&id, "taken@example.com", "right")
                .await,
            Err(AuthError::EmailAlreadyExists)
        ));
        assert!(matches!(
            h.engine
                .request_email_change(&id, "OLD@Example.com", "right")
                .await,
            Err(AuthError::EmailAlreadyExists)
        ));
    }

    #[tokio::test]
    async fn a_confirmed_change_moves_the_address_exactly_once() {
        // The link is single-use: the read and the delete are one operation, so clicking twice
        // — or racing — applies once.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        // The raw token is opaque, so plant a known one — the pair `request` writes.
        let token = "d".repeat(64);
        let context = EmailChangeContext {
            user_id: id.clone(),
            new_email: "new@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            password_fingerprint: String::new(),
        };
        assert!(
            h.stores
                .put_email_change(&token, &context, 3600)
                .await
                .is_ok()
        );

        assert!(h.engine.confirm_email_change(&token).await.is_ok());
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("new@example.com")
        );

        // …and the same link a second time reaches nothing.
        assert!(matches!(
            h.engine.confirm_email_change(&token).await,
            Err(AuthError::EmailChangeTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn a_token_no_longer_bound_to_the_password_is_refused() {
        // An attacker who plants a change request and waits loses it the moment the victim
        // changes their password — which is the first thing a victim does.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        let token = "e".repeat(64);
        let context = EmailChangeContext {
            user_id: id.clone(),
            new_email: "new@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            // A fingerprint that matches no password this account has ever had.
            password_fingerprint: "f".repeat(64),
        };
        assert!(
            h.stores
                .put_email_change(&token, &context, 3600)
                .await
                .is_ok()
        );

        assert!(matches!(
            h.engine.confirm_email_change(&token).await,
            Err(AuthError::EmailChangeTokenInvalid)
        ));
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("old@example.com")
        );
    }

    #[tokio::test]
    async fn an_unknown_token_and_a_vanished_account_are_both_refused() {
        let Some(h) = setup() else { return };

        assert!(matches!(
            h.engine.confirm_email_change(&"0".repeat(64)).await,
            Err(AuthError::EmailChangeTokenInvalid)
        ));

        // A record naming an account that has since been deleted.
        let token = "1".repeat(64);
        let context = EmailChangeContext {
            user_id: "ghost".to_owned(),
            new_email: "new@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            password_fingerprint: String::new(),
        };
        assert!(
            h.stores
                .put_email_change(&token, &context, 3600)
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine.confirm_email_change(&token).await,
            Err(AuthError::EmailChangeTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn an_address_taken_between_the_request_and_the_confirmation_is_refused() {
        // The two are separated by the whole TTL, and whoever registered the address in
        // between would otherwise lose it to a change requested before they existed.
        let Some(h) = setup() else { return };
        let id = h.seed(SeedUser::active("old@example.com", "right")).await;

        let token = "2".repeat(64);
        let context = EmailChangeContext {
            user_id: id.clone(),
            new_email: "contested@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            password_fingerprint: String::new(),
        };
        assert!(
            h.stores
                .put_email_change(&token, &context, 3600)
                .await
                .is_ok()
        );
        // Someone registers it while the link sits in a mailbox.
        let _ = h
            .seed(SeedUser::active("contested@example.com", "right"))
            .await;

        assert!(matches!(
            h.engine.confirm_email_change(&token).await,
            Err(AuthError::EmailAlreadyExists)
        ));
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("old@example.com")
        );
    }
    /// A suspension landing between the request and the confirmation stops the change.
    ///
    /// The two are separated by the whole token TTL, so a link minted while the account was in
    /// good standing is still in a mailbox when the suspension happens. The address it moves is
    /// the one a password reset is sent to — the single field a blocked account most needs to
    /// be unable to change, since changing it is how a suspension gets undone from outside.
    #[tokio::test]
    async fn a_confirmation_is_refused_once_the_account_is_blocked() {
        let Some(h) = setup() else { return };
        let id = h
            .seed(SeedUser::active("blocked@example.com", "right"))
            .await;

        let token = "3".repeat(64);
        let context = EmailChangeContext {
            user_id: id.clone(),
            new_email: "attacker@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            password_fingerprint: String::new(),
        };
        assert!(
            h.stores
                .put_email_change(&token, &context, 3600)
                .await
                .is_ok()
        );

        // The account is suspended while the link sits in a mailbox.
        assert!(h.users.update_status(&id, "SUSPENDED").await.is_ok());

        let confirmed = h.engine.confirm_email_change(&token).await;
        assert!(
            matches!(confirmed, Err(AuthError::AccountSuspended)),
            "a blocked account must be refused with its status error: {confirmed:?}"
        );
        assert_eq!(
            stored_email(&h, &id).await.as_deref(),
            Some("blocked@example.com")
        );
    }
}
