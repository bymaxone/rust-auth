//! Re-proving the account at the keyboard before a change a session alone must not authorise:
//! enrolling a second factor, scheduling a workspace's deletion, handing its ownership over
//! (layer: service).
//!
//! An account with a password proves it again, counted by the `reauthFailureCounter` of
//! `userSubjectDerivedKeys` (`lf:{hmac_sha256(hmacKey, 'reauth:{userSubject}')}`), so a stolen
//! access token cannot guess the password here without limit. An account with no password (one
//! provisioned through OAuth) proves a recent real sign-in instead, by the `recentAuthMarker` the
//! token manager plants on issuance and never on rotation. Every door that asks for a re-proof
//! goes through here, so there is one derivation of each key to be right.

use bymax_auth_crypto::mac::hmac_sha256;
use bymax_auth_types::{AuthError, MfaContext};

use crate::services::brute_force::BruteForceService;
use crate::services::password::PasswordService;
use crate::services::{to_hex, user_subject, user_subject_hash};
use crate::traits::SessionStore;

/// The collaborators a re-proof reads and counts with.
pub(crate) struct Reproof<'a> {
    /// The lockout counter a wrong password is counted by.
    pub(crate) brute_force: &'a BruteForceService,
    /// The password verifier.
    pub(crate) passwords: &'a PasswordService,
    /// The store holding the recent-authentication marker.
    pub(crate) session_store: &'a dyn SessionStore,
    /// The identifier key every account-derived key is an HMAC under.
    pub(crate) identifier_key: &'a [u8; 64],
}

/// The account being re-proved: its plane, its tenant (`None` on the platform plane), its id and
/// its stored password hash, `None` for an account with no local password.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProvingAccount<'a> {
    /// The plane the account belongs to.
    pub(crate) plane: MfaContext,
    /// The account's tenant, `None` on the platform plane.
    pub(crate) tenant_id: Option<&'a str>,
    /// The account.
    pub(crate) user_id: &'a str,
    /// The stored password hash, `None` for an account with no local password.
    pub(crate) password_hash: Option<&'a str>,
}

impl Reproof<'_> {
    /// The counter identifier of the password re-proof: `hmac_sha256('reauth:{userSubject}')`,
    /// hex. Namespaced by flow so an authenticated caller cannot spend the owner's sign-in budget,
    /// and by plane and tenant through the subject.
    pub(crate) fn failure_identifier(
        &self,
        plane: MfaContext,
        tenant_id: Option<&str>,
        user_id: &str,
    ) -> String {
        let subject = user_subject(plane, tenant_id, user_id);
        to_hex(&hmac_sha256(
            self.identifier_key,
            format!("reauth:{subject}").as_bytes(),
        ))
    }

    /// Requires `account` to prove itself again: by `password` when it has one, by a recent real
    /// sign-in when it has none.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccountLocked`] at the lockout ceiling, checked before the key derivation so a
    /// locked account is not an amplifier; [`AuthError::InvalidCredentials`] for a missing or wrong
    /// password, the answer a failed sign-in gives; [`AuthError::ReauthenticationRequired`] for an
    /// account with no password and no recent sign-in; a store failure as it comes.
    pub(crate) async fn assert(
        &self,
        account: ProvingAccount<'_>,
        password: Option<&str>,
    ) -> Result<(), AuthError> {
        let ProvingAccount {
            plane,
            tenant_id,
            user_id,
            password_hash,
        } = account;
        let Some(hash) = password_hash else {
            let marker = user_subject_hash(self.identifier_key, plane, tenant_id, user_id);
            if !self.session_store.has_recent_auth(&marker).await? {
                tracing::warn!(%user_id, "reauthenticate: no recent authentication");
                return Err(AuthError::ReauthenticationRequired);
            }
            return Ok(());
        };
        let counter = self.failure_identifier(plane, tenant_id, user_id);
        if self.brute_force.is_locked(&counter).await? {
            let retry = self.brute_force.remaining_lockout_secs(&counter).await?;
            tracing::warn!(%user_id, "reauthenticate: account locked");
            return Err(AuthError::AccountLocked {
                retry_after_seconds: Some(retry),
            });
        }
        // A missing password still pays the derivation, so "no password sent" and "wrong
        // password" take the same time.
        let outcome = self.passwords.verify(password.unwrap_or(""), hash).await?;
        if outcome.matched {
            self.brute_force.reset(&counter).await?;
            Ok(())
        } else {
            self.brute_force.record_failure(&counter).await?;
            Err(AuthError::InvalidCredentials)
        }
    }
}
