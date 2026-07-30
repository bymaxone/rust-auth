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

        if !self
            .passwords()
            .verify(current_password, &phc)
            .await?
            .matched
        {
            tracing::warn!(%user_id, "email change: current password rejected");
            return Err(AuthError::InvalidCredentials);
        }

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
    if context.password_fingerprint == super::password_reset::password_fingerprint(user) {
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
}
