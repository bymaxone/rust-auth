//! The password-reset flows (§7.8): `initiate_reset` (anti-enumeration), `reset_password`
//! (token | otp | verified_token), `verify_otp` (returning a short-lived verified token),
//! `resend_otp` (atomic 60 s cooldown), and the private `apply_password_reset`.
//!
//! Initiation and resend are uniformly anti-enumerating: identical `Ok(())` and a ≥ 300 ms
//! timing floor whether or not the account exists, is blocked, or the email send fails.
//! Token and OTP proofs are consumed single-use (atomic `getdel` on the opaque-token
//! keyspaces, the attempt-bounded `otp_verify` for OTPs). `apply_password_reset` updates the
//! password **before** invalidating sessions so a crash between the two can never leave the
//! old password able to mint sessions.

use std::collections::BTreeMap;
use std::time::Instant;

use bymax_auth_crypto::mac::{sha256, verify_digest};
use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, AuthUser, SafeAuthUser};

use crate::config::ResetMethod;
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::normalize::normalize_email;
use crate::services::auth::detached::run_after_password_reset;
use crate::services::auth::{map_repository_error, normalize_anti_enum, spawn_guarded};
use crate::services::{is_refresh_token_shape, to_hex};
use crate::traits::{HookContext, HookPlane, OtpPurpose, ResetContext, SessionKind};

/// The lifetime, in seconds, of the short-lived verified token that bridges a successful
/// OTP verification to the reset form (§7.8 `VERIFIED_TOKEN_TTL_SECONDS`).
const VERIFIED_TOKEN_TTL_SECONDS: u64 = 300;

/// Seconds one account must wait between reset sends (§7.8.4), shared by `initiate_reset` and
/// `resend_reset_otp`.
///
/// It is not only about mail volume. Every issuance rewrites the OTP record with `attempts: 0`,
/// so an entry point that can be called freely converts the 5-attempt ceiling into 5 attempts
/// *per call*, and a six-digit code stops being a secret. Both doors therefore draw on one
/// budget under one key.
pub(super) const RESEND_COOLDOWN_SECS: u64 = 60;

/// The bytes of entropy in a reset link / verified token before hex-encoding (256-bit).
pub(super) const RESET_TOKEN_BYTES: usize = 32;

/// Input to initiate a reset: the account email and its tenant scope.
#[derive(Clone, Debug)]
pub struct ForgotPasswordInput {
    /// The account email.
    pub email: String,
    /// The tenant scope the caller named, or `None` when it named none. A configured
    /// `TenantIdResolver` overrules it; with no resolver, its absence is refused rather than
    /// defaulted: the refusal is a `validation` error naming this field.
    pub tenant_id: Option<String>,
}

/// The proof carried into [`AuthEngine::reset_password`]: exactly one of `token`, `otp`, or
/// `verified_token` must be present (the method config decides which is accepted). The
/// `Debug` impl redacts `new_password`.
#[derive(Clone)]
pub struct ResetPasswordInput {
    /// The account email (re-bound against the stored proof context).
    pub email: String,
    /// The tenant scope the caller named, or `None` when it named none. The RESOLVED tenant is
    /// what the stored proof context is re-bound against, not this value.
    pub tenant_id: Option<String>,
    /// The new plaintext password (redacted in `Debug`).
    pub new_password: String,
    /// The reset link token (token method).
    pub token: Option<String>,
    /// The numeric OTP (OTP method, direct).
    pub otp: Option<String>,
    /// The short-lived verified token (OTP method, two-step).
    pub verified_token: Option<String>,
}

impl std::fmt::Debug for ResetPasswordInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the new password and the live single-use proofs so a stray `{:?}` cannot leak
        // a credential or a reusable token.
        f.debug_struct("ResetPasswordInput")
            .field("email", &self.email)
            .field("tenant_id", &self.tenant_id)
            .field("new_password", &"[REDACTED]")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("otp", &self.otp.as_ref().map(|_| "[REDACTED]"))
            .field(
                "verified_token",
                &self.verified_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Input to exchange a verified OTP for a short-lived verified token (OTP method, two-step).
#[derive(Clone, Debug)]
pub struct VerifyResetOtpInput {
    /// The account email.
    pub email: String,
    /// The tenant scope the caller named, or `None` when it named none. A configured
    /// `TenantIdResolver` overrules it; with no resolver, its absence is refused rather than
    /// defaulted: the refusal is a `validation` error naming this field.
    pub tenant_id: Option<String>,
    /// The numeric OTP to verify (consumed on success).
    pub otp: String,
}

/// Input to resend a reset OTP, throttled by the atomic cooldown.
#[derive(Clone, Debug)]
pub struct ResendResetOtpInput {
    /// The account email.
    pub email: String,
    /// The tenant scope the caller named, or `None` when it named none. A configured
    /// `TenantIdResolver` overrules it; with no resolver, its absence is refused rather than
    /// defaulted: the refusal is a `validation` error naming this field.
    pub tenant_id: Option<String>,
}

impl AuthEngine {
    /// Initiate a password reset. The **account-state outcome is always `Ok(())`** — the body
    /// is identical whether or not the account exists, is blocked, or the email send fails —
    /// and the ≥ 300 ms anti-enumeration timing floor is honored on **every** path, so neither
    /// the response nor the latency reveals account existence. A failure **before** the account
    /// is known (the resend-cooldown store, the account lookup) is surfaced as an [`AuthError`];
    /// one **after** it (storing or sending the proof) is logged and the `Ok(())` stands. When the
    /// cooldown is released is recorded in the specification (7.8.4).
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only when the resend-cooldown store or the account lookup
    /// fails; account state never changes the otherwise-`Ok(())` outcome. The timing floor is
    /// applied before the error is returned, so an infra error stays latency-indistinguishable
    /// from a normal response.
    pub async fn initiate_reset(
        &self,
        input: ForgotPasswordInput,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        // Canonicalize first: every key below (the OTP/cooldown identifier, the lookup,
        // and the reset context written for the confirm step) must derive from one
        // spelling, or a reset started under one casing cannot be completed under another.
        //
        // The tenant goes through the resolver for the same reason `login` and `register` do:
        // when one is configured it is authoritative and a body that names a tenant is refused,
        // which is the whole anti-spoofing promise. Without it a caller on one tenant could drive
        // reset mail at accounts in another — and a reset started under the resolved tenant
        // could never be completed, because the stored context and the confirm step would
        // disagree about which tenant it belonged to.
        let tenant_id = self.resolve_tenant(input.tenant_id.as_deref(), ctx).await?;
        let email = normalize_email(&input.email);
        let started = Instant::now();
        // Run the fallible body, then normalize the elapsed time on EVERY exit — including an
        // infrastructure error — before returning, so a backend failure cannot be told apart
        // from a normal response by latency.
        let method = self.config().config().password_reset.method;
        let outcome = self.begin_reset_request(&tenant_id, &email, method).await;
        normalize_anti_enum(started).await;
        outcome
    }

    /// Reset the password using exactly one proof. The method config decides which proof is
    /// accepted: the token method consumes a reset link token; the OTP method accepts either a
    /// direct OTP or a verified token (a `token` is an explicit method mismatch).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PasswordResetTokenInvalid`] when no proof, more than one proof, the
    /// wrong proof for the method, or an invalid/consumed proof is presented; an OTP error
    /// ([`AuthError::OtpInvalid`]/[`AuthError::OtpExpired`]/[`AuthError::OtpMaxAttempts`]) for a
    /// failed OTP; or a hashing/store [`AuthError`].
    pub async fn reset_password(
        &self,
        input: ResetPasswordInput,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        // Canonicalize first: every key below (the OTP/cooldown identifier, the lookup,
        // and the reset context written for the confirm step) must derive from one
        // spelling, or a reset started under one casing cannot be completed under another.
        // The tenant goes through the resolver, exactly as `login` and `register` do: when one
        // is configured it is authoritative and a body that names a tenant is refused. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(input.tenant_id.as_deref(), ctx).await?;
        // Bound as plain values rather than rebuilt into a rebound `input`, and the helpers below
        // take them as arguments. The rebind used to carry BOTH tenants — the caller's in the
        // struct and the resolved one beside it — and reading the wrong one is a one-character
        // mistake no test would notice; it is exactly the mistake nest-auth had to fix on this
        // flow, where the resolved tenant was bound and `dto.tenantId` read anyway. Not carrying
        // it is what makes that unwritable, where clearing the field only made it unlikely.
        let email = normalize_email(&input.email);
        // Classify the proofs: exactly one of token / otp / verified_token must be present.
        let proof = match (
            input.token.as_deref(),
            input.otp.as_deref(),
            input.verified_token.as_deref(),
        ) {
            (Some(token), None, None) => Proof::Token(token),
            (None, Some(otp), None) => Proof::Otp(otp),
            (None, None, Some(verified)) => Proof::Verified(verified),
            // Zero proofs, or more than one, is an invalid request.
            _ => return Err(AuthError::PasswordResetTokenInvalid),
        };

        // Pair the proof with the configured method first: a request that names the wrong kind
        // of proof for this deployment is malformed, and nothing below should run for it.
        enum Dispatch<'a> {
            Stored(&'a str, ProofKind),
            Otp(&'a str),
        }
        let dispatch = match (self.config().config().password_reset.method, proof) {
            // The token method accepts only a reset link token.
            (ResetMethod::Token, Proof::Token(token)) => Dispatch::Stored(token, ProofKind::Token),
            // The OTP method accepts a direct OTP or the verified-token bridge.
            (ResetMethod::Otp, Proof::Otp(otp)) => Dispatch::Otp(otp),
            (ResetMethod::Otp, Proof::Verified(verified)) => {
                Dispatch::Stored(verified, ProofKind::Verified)
            }
            // Any other method/proof pairing is an explicit mismatch (e.g. a token submitted to
            // the OTP method, or an OTP/verified token submitted to the token method).
            _ => return Err(AuthError::PasswordResetTokenInvalid),
        };

        // The new password is judged BEFORE any proof is spent.
        //
        // Every proof below is single-use and consumed atomically — `getdel` for the two token
        // shapes, the verify script for the OTP — so a screen rejection that arrived after the
        // consumption burned the proof: the caller was told their password was unacceptable
        // and, in the same breath, that the only credential they had to fix it was gone. The
        // whole mail round trip had to be repeated for a mistake the request itself carried.
        //
        // Judging first means a caller holding no valid proof can drive the screen, which for
        // the bundled HIBP checker is an outbound range query. That is the same exposure
        // `register` already carries on the same screen, and this route is rate-limited — the
        // burned proof was the larger of the two costs by a wide margin.
        self.passwords()
            .assert_acceptable(&input.new_password, "newPassword")
            .await?;

        match dispatch {
            Dispatch::Stored(token, kind) => {
                self.reset_with_stored_proof(token, &tenant_id, &email, &input.new_password, kind)
                    .await
            }
            Dispatch::Otp(otp) => {
                self.reset_with_otp(otp, &tenant_id, &email, &input.new_password)
                    .await
            }
        }
    }

    /// Reset using a stored opaque proof (the reset link token or the OTP verified token):
    /// atomically consume it, re-bind it to the presented email/tenant (a digest compare that
    /// removes the variable-length oracle of a raw compare), then apply the reset.
    ///
    /// Takes the RESOLVED tenant and the normalized email as plain arguments rather than the
    /// caller's input struct: the struct's `tenant_id` is only what the caller asked for, a
    /// configured resolver may have overruled it, and binding the stored proof against the wrong
    /// one of the two is what turns this check into theatre. Not carrying the unresolved value
    /// is what makes that unwritable.
    async fn reset_with_stored_proof(
        &self,
        token: &str,
        tenant_id: &str,
        email: &str,
        new_password: &str,
        kind: ProofKind,
    ) -> Result<(), AuthError> {
        let store = self
            .password_reset_store()
            .ok_or(AuthError::PasswordResetTokenInvalid)?;
        let consumed = match kind {
            ProofKind::Token => store.consume_token(token).await?,
            ProofKind::Verified => store.consume_verified(token).await?,
        };
        let context = consumed.ok_or(AuthError::PasswordResetTokenInvalid)?;

        // Defense-in-depth: bind the stored proof to the submitted email + tenant. Hashing
        // first compares fixed-length digests, so the compare leaks no length information.
        if !digest_eq(&context.email, email) || !digest_eq(&context.tenant_id, tenant_id) {
            return Err(AuthError::PasswordResetTokenInvalid);
        }
        self.assert_proof_still_bound(&context).await?;
        self.apply_password_reset(&context, new_password).await
    }

    /// Reset using a direct OTP: verify (single-use, attempt-bounded), then look up the
    /// account and apply the reset. A vanished account collapses to the invalid-token error
    /// rather than a distinct "not found".
    ///
    /// Takes the resolved tenant and normalized email directly, for the reason
    /// [`AuthEngine::reset_with_stored_proof`] does.
    async fn reset_with_otp(
        &self,
        otp: &str,
        tenant_id: &str,
        email: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(tenant_id, email);
        self.otp()
            .verify(OtpPurpose::PasswordReset, &identifier, otp)
            .await?;
        let user = crate::services::auth::tenant_scoped(
            self.user_repository()
                .find_by_email(email, tenant_id)
                .await
                .map_err(map_repository_error)?,
            tenant_id,
        )
        .ok_or(AuthError::PasswordResetTokenInvalid)?;
        let context = ResetContext {
            user_id: user.id.clone(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            password_fingerprint: password_fingerprint(&user),
        };
        self.apply_password_reset(&context, new_password).await
    }

    /// Verify a reset OTP and, on success, mint a short-lived verified token that bridges the
    /// verify step to the reset form (closing the verify/reset race). A vanished account does
    /// not receive a verified token.
    ///
    /// # Errors
    ///
    /// Returns the OTP error on a failed verify, [`AuthError::PasswordResetTokenInvalid`] for a
    /// vanished account, or a store [`AuthError`].
    pub async fn verify_reset_otp(
        &self,
        input: VerifyResetOtpInput,
        ctx: &RequestContext,
    ) -> Result<String, AuthError> {
        // Canonicalize first: every key below (the OTP/cooldown identifier, the lookup,
        // and the reset context written for the confirm step) must derive from one
        // spelling, or a reset started under one casing cannot be completed under another.
        // The tenant goes through the resolver, exactly as `login` and `register` do: when one
        // is configured it is authoritative and a body that names a tenant is refused. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(input.tenant_id.as_deref(), ctx).await?;
        // Bound as plain values, for the reason `reset_password` does: the caller's unresolved
        // tenant is not carried past this line, so nothing below can read it by mistake.
        let email = normalize_email(&input.email);
        let identifier = self.hashed_identifier(&tenant_id, &email);
        self.otp()
            .verify(OtpPurpose::PasswordReset, &identifier, &input.otp)
            .await?;
        let user = crate::services::auth::tenant_scoped(
            self.user_repository()
                .find_by_email(&email, &tenant_id)
                .await
                .map_err(map_repository_error)?,
            &tenant_id,
        )
        .ok_or(AuthError::PasswordResetTokenInvalid)?;

        let store = self
            .password_reset_store()
            .ok_or(AuthError::PasswordResetTokenInvalid)?;
        let raw = generate_secure_token(RESET_TOKEN_BYTES);
        let context = ResetContext {
            password_fingerprint: password_fingerprint(&user),
            user_id: user.id,
            email,
            tenant_id,
        };
        store
            .put_verified(&raw, &context, VERIFIED_TOKEN_TTL_SECONDS)
            .await?;
        Ok(raw)
    }

    /// Re-issue a reset OTP. The **account-state outcome is always `Ok(())`** — an identical
    /// response and ≥ 300 ms timing floor whether or not the account exists or is blocked —
    /// preserving the atomic 60 s cooldown (a second resend inside the window is a silent
    /// `Ok(())`). An **infrastructure failure** (the cooldown gate or the account lookup is
    /// unreachable) is still surfaced as an [`AuthError`]; only the account state never changes
    /// the outcome.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only on an infrastructure failure (the cooldown gate or the
    /// account lookup); account state never changes the otherwise-`Ok(())` outcome. The timing
    /// floor is applied before the error is returned, so an infra error stays
    /// latency-indistinguishable from a normal response.
    pub async fn resend_reset_otp(
        &self,
        input: ResendResetOtpInput,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        // Canonicalize first: every key below (the OTP/cooldown identifier, the lookup,
        // and the reset context written for the confirm step) must derive from one
        // spelling, or a reset started under one casing cannot be completed under another.
        // The tenant goes through the resolver, exactly as `login` and `register` do: when one
        // is configured it is authoritative and a body that names a tenant is refused. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(input.tenant_id.as_deref(), ctx).await?;
        let email = normalize_email(&input.email);
        let started = Instant::now();
        // Run the fallible body, then normalize the elapsed time on EVERY exit — the cooldown
        // short-circuit, the success path, and any infrastructure error — so a backend failure
        // cannot be distinguished from a normal response by latency.
        let outcome = self
            .begin_reset_request(&tenant_id, &email, ResetMethod::Otp)
            .await;
        normalize_anti_enum(started).await;
        outcome
    }

    /// Apply the verified reset: hash the new password, persist it, then revoke every session.
    ///
    /// Change the password of an already-authenticated account, proving identity with the
    /// current password rather than an emailed token.
    ///
    /// This is the flow ASVS v5 §6.2.2 and §6.2.3 require at Level 1 — "users can change their
    /// password", and "password change functionality requires the user's current and new
    /// password" — and it was the one credential operation this library did not own. Without
    /// it a host either sends users through the *unauthenticated* recovery flow to rotate a
    /// password they already know, or hand-rolls hashing against `bymax-auth-crypto` with
    /// duplicated parameters and no guarantee that the sessions are revoked afterwards.
    ///
    /// The current password is what makes it safe. A session alone is not proof of identity: a
    /// token lifted by XSS or from a shared machine would otherwise be enough to rotate the
    /// credential, lock the real owner out of an account they still know the password to, and
    /// keep the attacker in.
    ///
    /// Every other session ends on success (ASVS v5 §7.4.3) and the token epoch is bumped, so
    /// already-issued access tokens die with them. The caller's own refresh session survives
    /// when `current_refresh` identifies it, so the device that made the change stays signed in
    /// and silently re-mints its access token on the next rotation. When it cannot be
    /// identified, every session goes, this one included: a change that leaves an unknown
    /// session alive is the failure the control exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidCredentials`] when the current password does not match, the
    /// account is gone, or it has no local password (an OAuth-only account has nothing to
    /// change — its credential belongs to the provider); [`AuthError::PasswordCompromised`]
    /// when the screen refuses the new password; or a repository/store [`AuthError`].
    pub async fn change_password(
        &self,
        tenant_id: &str,
        user_id: &str,
        current_password: &str,
        new_password: &str,
        current_refresh: Option<&str>,
    ) -> Result<(), AuthError> {
        // Scoped to the caller's tenant: `None` is the cross-tenant admin lookup, and the session
        // revocation below is keyed on this same tenant, so reading across tenants here would
        // verify and change one tenant's account while revoking another tenant's sessions.
        let user = self
            .user_repository()
            .find_by_id(user_id, Some(tenant_id))
            .await
            .map_err(map_repository_error)?;
        // A verified token whose subject is gone, and an account with no local password, answer
        // identically: the caller cannot prove a credential this account does not have.
        let Some(phc) = user.and_then(|user| user.password_hash) else {
            return Err(AuthError::InvalidCredentials);
        };

        // Counted like a login: this door asks for the account password, so it carries the
        // password's lockout. Checked BEFORE the KDF, so a locked account is not an amplifier.
        let bf_id = self.reproof_identifier("change-password", tenant_id, user_id);
        if self.brute_force().is_locked(&bf_id).await? {
            let retry = self.brute_force().remaining_lockout_secs(&bf_id).await?;
            tracing::warn!(
                event = "RUST_AUTH_PASSWORD_CHANGE_ACCOUNT_LOCKED",
                "password change: account locked"
            );
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
            tracing::warn!(
                event = "RUST_AUTH_PASSWORD_CHANGE_PASSWORD_REJECTED",
                "password change: current password rejected"
            );
            return Err(AuthError::InvalidCredentials);
        }
        self.brute_force().reset(&bf_id).await?;

        // The session to keep is settled before the password changes: a presented token that
        // names no live session of this account would otherwise write the new credential and
        // then keep nothing. A token that rotated away stands for its successor.
        let kept = match current_refresh {
            Some(raw) => Some(
                self.resolve_current_session(tenant_id, user_id, raw)
                    .await?,
            ),
            None => None,
        };

        self.passwords()
            .assert_acceptable(new_password, "newPassword")
            .await?;
        let new_hash = self.passwords().hash(new_password).await?;
        self.user_repository()
            .update_password(user_id, tenant_id, &new_hash)
            .await
            .map_err(map_repository_error)?;

        // Sessions go only after the password is durably written, for the same reason the reset
        // flow orders it that way: a crash between the two leaves stale refresh tokens alive
        // until their TTL, but the old password is already dead.
        self.end_other_sessions(tenant_id, user_id, kept.as_deref())
            .await?;

        tracing::info!(
            event = "RUST_AUTH_PASSWORD_CHANGED",
            "password change: completed, other sessions revoked"
        );
        self.notify_password_changed(tenant_id, user_id).await;
        Ok(())
    }

    /// The hash of the live session a presented refresh token stands for, settled before the
    /// password is written. A malformed token, or one that names no live session of the
    /// account, is [`AuthError::SessionNotFound`].
    async fn resolve_current_session(
        &self,
        tenant_id: &str,
        user_id: &str,
        raw: &str,
    ) -> Result<String, AuthError> {
        if !is_refresh_token_shape(raw) {
            return Err(AuthError::SessionNotFound);
        }
        let presented = RawRefreshToken::from_raw(raw.to_owned()).redis_hash();
        self.sessions()
            .resolve_live_session(tenant_id, user_id, &presented)
            .await
    }

    /// Ends every session but `kept`, once the new password is already written.
    ///
    /// With no session to keep every session ends. A kept session can rotate away while the new
    /// password is being hashed; the sweep follows it to its successor, and when it cannot be
    /// followed there is no current session left to spare, so every session ends and the epoch
    /// advances: the cleanup that makes the change safe is never aborted by the session it was
    /// told to spare. Any other failure of the sweep propagates.
    async fn end_other_sessions(
        &self,
        tenant_id: &str,
        user_id: &str,
        kept: Option<&str>,
    ) -> Result<(), AuthError> {
        if let Some(kept) = kept {
            match self
                .sessions()
                .revoke_all_except_current(tenant_id, user_id, kept)
                .await
            {
                Err(AuthError::SessionNotFound) => {}
                other => return other,
            }
        }
        let subject = self.session_subject(SessionKind::Dashboard, Some(tenant_id), user_id);
        self.session_store()
            .revoke_all(SessionKind::Dashboard, &subject)
            .await?;
        self.session_store()
            .bump_epoch(SessionKind::Dashboard, &subject)
            .await?;
        Ok(())
    }

    /// Send the "your password changed" notice, detached and best-effort.
    ///
    /// NIST SP 800-63B §4.6 asks for a notification through a channel independent of the
    /// transaction that bound the new credential. Never awaited and never allowed to fail the
    /// operation: a delivery problem must not undo a password that is already written, nor
    /// answer differently to the caller.
    async fn notify_password_changed(&self, tenant_id: &str, user_id: &str) {
        let Ok(Some(user)) = self
            .user_repository()
            .find_by_id(user_id, Some(tenant_id))
            .await
        else {
            return;
        };
        spawn_guarded(run_send_password_changed(
            self.email_provider().clone(),
            user.tenant_id,
            user.email,
        ));
    }

    /// Refuse a reset proof whose binding no longer matches the account's current password.
    ///
    /// Several proofs can be alive at once, and completing one used to leave the rest valid —
    /// the wrong end state precisely when it matters, since a victim resetting *because* an
    /// attacker read a link from their mailbox had not closed the link the attacker read. The
    /// binding makes the first completed rotation, reset or authenticated change, invalidate
    /// all of them.
    ///
    /// An empty stored fingerprint means the proof predates the binding (a rolling deploy, or a
    /// sibling implementation that has not taken this change) and is accepted: refusing those
    /// would break every reset in flight for a window this narrow.
    async fn assert_proof_still_bound(&self, context: &ResetContext) -> Result<(), AuthError> {
        if context.password_fingerprint.is_empty() {
            return Ok(());
        }
        let current = self
            .user_repository()
            .find_by_id(&context.user_id, Some(&context.tenant_id))
            .await
            .map_err(map_repository_error)?
            .map(|user| password_fingerprint(&user))
            .unwrap_or_default();

        // Constant-time, per §24 invariant 13 ("no `==` on secret bytes anywhere"). Both operands
        // are server-side here — a stored digest against one derived from the repository row — so
        // there is no attacker-controlled operand and no oracle to read the timing through. It
        // goes through `digest_eq` regardless: the invariant is worth more as a rule with no
        // exceptions than as one whose exceptions each need re-deriving, and the next edit to
        // this function does not have to re-establish why this one was safe.
        if digest_eq(&current, &context.password_fingerprint) {
            return Ok(());
        }
        tracing::warn!(
            event = "RUST_AUTH_PASSWORD_RESET_PROOF_STALE",
            "password reset: refusing a proof issued against a password that has since changed"
        );
        Err(AuthError::PasswordResetTokenInvalid)
    }

    /// **Operation order is security-critical:** the password is updated **before** sessions
    /// are invalidated. A crash between the two leaves stale refresh tokens alive only until
    /// their TTL — but the old password is already dead, so a stolen password cannot mint new
    /// sessions. The reverse order would leave the old password valid if `update_password`
    /// failed after invalidation. Cross-store (DB↔Redis) atomicity is unavailable; this
    /// ordering minimizes the partial-failure blast radius.
    async fn apply_password_reset(
        &self,
        context: &ResetContext,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // The breach screen ran in `reset_password`, before the proof was spent — see the note
        // there.
        let new_hash = self.passwords().hash(new_password).await?;
        self.user_repository()
            .update_password(&context.user_id, &context.tenant_id, &new_hash)
            .await
            .map_err(map_repository_error)?;
        // Sessions are invalidated only after the password is durably updated. This is the
        // dashboard reset flow, so only dashboard sessions are revoked; platform-admin sessions
        // are a separate identity surface with their own credential-reset path and are not
        // touched here. Revoking the refresh sessions stops rotation; bumping the token epoch
        // additionally invalidates every already-issued (stateless) access token at once, so a
        // reset takes effect immediately rather than lingering for the access-token lifetime.
        // The proof carries the tenant it was issued for, and that is the tenant the reset acts
        // in: resolving one from the id would be the cross-tenant lookup these keys moved to
        // avoid.
        let subject = self.session_subject(
            crate::traits::SessionKind::Dashboard,
            Some(&context.tenant_id),
            &context.user_id,
        );
        self.session_store()
            .revoke_all(crate::traits::SessionKind::Dashboard, &subject)
            .await?;
        self.session_store()
            .bump_epoch(crate::traits::SessionKind::Dashboard, &subject)
            .await?;
        // A completed reset is the event an operator correlates an account takeover against:
        // it revokes every session the account had and invalidates its outstanding access
        // tokens, so it belongs in the audit trail even when nothing failed.
        tracing::info!(
            event = "RUST_AUTH_PASSWORD_RESET_COMPLETED",
            "password reset: completed, all sessions revoked"
        );

        // A reset needs the notice at least as much as a change does: the classic takeover
        // completes one from a compromised mailbox and deletes the mail.
        self.notify_password_changed(&context.tenant_id, &context.user_id)
            .await;

        let hook_ctx = reset_context_hooks(context);
        let safe = self.project_user_for_hook(context).await;
        if let Some(safe) = safe {
            spawn_guarded(run_after_password_reset(
                self.hooks().clone(),
                safe,
                hook_ctx,
            ));
        }
        Ok(())
    }

    /// Project the reset's subject to a [`SafeAuthUser`] for the `after_password_reset` hook,
    /// or `None` if the account can no longer be loaded (the reset already succeeded — the
    /// hook is merely skipped).
    async fn project_user_for_hook(&self, context: &ResetContext) -> Option<SafeAuthUser> {
        match self
            .user_repository()
            .find_by_id(&context.user_id, Some(&context.tenant_id))
            .await
        {
            Ok(Some(user)) => Some(SafeAuthUser::from(user)),
            _ => None,
        }
    }
}

/// The single reset proof carried by a request, classified from the mutually-exclusive
/// `token` / `otp` / `verified_token` fields.
enum Proof<'a> {
    /// A reset link token (`pw_reset:`).
    Token(&'a str),
    /// A direct OTP.
    Otp(&'a str),
    /// An OTP-flow verified token (`pw_vtok:`).
    Verified(&'a str),
}

/// Which opaque-token keyspace a stored reset proof lives in.
#[derive(Clone, Copy)]
enum ProofKind {
    /// The reset link token (`pw_reset:`).
    Token,
    /// The OTP-flow verified token (`pw_vtok:`).
    Verified,
}

/// Constant-time equality of two strings by their SHA-256 digests. Hashing first compares
/// fixed-length values, so the compare reveals nothing about the inputs' lengths.
pub(crate) fn digest_eq(a: &str, b: &str) -> bool {
    verify_digest(&sha256(a.as_bytes()), &sha256(b.as_bytes()))
}

/// A [`HookContext`] carrying only the reset subject's identity (the reset flow has no
/// originating request context).
fn reset_context_hooks(context: &ResetContext) -> HookContext {
    HookContext {
        plane: HookPlane::Dashboard,
        user_id: Some(context.user_id.clone()),
        email: Some(context.email.clone()),
        tenant_id: Some(context.tenant_id.clone()),
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: BTreeMap::new(),
    }
}

/// A digest of the account's current password hash, binding a reset proof to that password.
///
/// The hash itself never leaves the repository — only this digest goes into the store, so a
/// leaked snapshot of the reset keyspace reveals nothing about the credential. An account with
/// no local password yields the empty string, which is a value like any other: a proof minted
/// then is invalidated as soon as one is set.
pub(super) fn password_fingerprint(user: &AuthUser) -> String {
    match user.password_hash.as_deref() {
        Some(phc) => to_hex(&sha256(phc.as_bytes())),
        None => String::new(),
    }
}

/// Send the "password changed" email (a named future so the detached spawn owns its data).
async fn run_send_password_changed(
    email: std::sync::Arc<dyn crate::traits::EmailProvider>,
    tenant_id: String,
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email
        .send_password_changed(&tenant_id, &recipient, None)
        .await
}

#[cfg(test)]
mod tests;
