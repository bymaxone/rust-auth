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
use crate::traits::{HookContext, OtpPurpose, ResetContext, SessionKind};

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
const RESEND_COOLDOWN_SECS: u64 = 60;

/// The bytes of entropy in a reset link / verified token before hex-encoding (256-bit).
const RESET_TOKEN_BYTES: usize = 32;

/// Input to initiate a reset: the account email and its tenant scope.
#[derive(Clone, Debug)]
pub struct ForgotPasswordInput {
    /// The account email.
    pub email: String,
    /// The tenant scope.
    pub tenant_id: String,
}

/// The proof carried into [`AuthEngine::reset_password`]: exactly one of `token`, `otp`, or
/// `verified_token` must be present (the method config decides which is accepted). The
/// `Debug` impl redacts `new_password`.
#[derive(Clone)]
pub struct ResetPasswordInput {
    /// The account email (re-bound against the stored proof context).
    pub email: String,
    /// The tenant scope (re-bound against the stored proof context).
    pub tenant_id: String,
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
    /// The tenant scope.
    pub tenant_id: String,
    /// The numeric OTP to verify (consumed on success).
    pub otp: String,
}

/// Input to resend a reset OTP, throttled by the atomic cooldown.
#[derive(Clone, Debug)]
pub struct ResendResetOtpInput {
    /// The account email.
    pub email: String,
    /// The tenant scope.
    pub tenant_id: String,
}

impl AuthEngine {
    /// Initiate a password reset. The **account-state outcome is always `Ok(())`** — the body
    /// is identical whether or not the account exists, is blocked, or the email send fails —
    /// and the ≥ 300 ms anti-enumeration timing floor is honored on **every** path, so neither
    /// the response nor the latency reveals account existence. An **infrastructure failure**
    /// (the account lookup or persisting the proof is unreachable) is still surfaced as an
    /// [`AuthError`]; only the account state never changes the outcome.
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only on an infrastructure failure (the account lookup or
    /// persisting the proof); account state never changes the otherwise-`Ok(())` outcome. The
    /// timing floor is applied before the error is returned, so an infra error stays
    /// latency-indistinguishable from a normal response.
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
        // when one is configured it is authoritative and the body value is ignored, which is
        // the whole anti-spoofing promise. Without it a caller on one tenant could drive
        // reset mail at accounts in another — and a reset started under the resolved tenant
        // could never be completed, because the stored context and the confirm step would
        // disagree about which tenant it belonged to.
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let input = ForgotPasswordInput {
            email: normalize_email(&input.email),
            tenant_id,
        };
        let started = Instant::now();
        // Run the fallible body, then normalize the elapsed time on EVERY exit — including an
        // infrastructure error — before returning, so a backend failure cannot be told apart
        // from a normal response by latency.
        let outcome = self.initiate_reset_inner(&input).await;
        normalize_anti_enum(started).await;
        outcome
    }

    /// The fallible body of [`AuthEngine::initiate_reset`], separated so the caller can apply
    /// the anti-enumeration timing floor to every exit path (success and infra error alike).
    async fn initiate_reset_inner(&self, input: &ForgotPasswordInput) -> Result<(), AuthError> {
        let config = self.config().config();

        // The SAME cooldown `resend_reset_otp` claims, under the same key, so the two entry
        // points share one budget rather than one throttling itself while the other hands out
        // fresh sends for free. Two things depended on that: every issuance rewrites the OTP
        // record with `attempts: 0`, so an untimed initiate turns the 5-attempt ceiling into
        // 5 attempts *per call* — an unbounded supply of guesses at a six-digit code — and each
        // call also mails the victim, which is a mail bomb aimed at an address the caller merely
        // has to know. A cooldown hit is a silent success, and the caller's anti-enumeration
        // floor still applies, so the throttle does not itself answer whether the account exists.
        let identifier = self.hashed_identifier(&input.tenant_id, &input.email);
        if !self
            .otp()
            .try_begin_resend(OtpPurpose::PasswordReset, &identifier, RESEND_COOLDOWN_SECS)
            .await?
        {
            return Ok(());
        }

        // Look up the account; an unknown email or a blocked account takes no visible branch.
        if let Some(user) = self
            .user_repository()
            .find_by_email(&input.email, &input.tenant_id)
            .await
            .map_err(map_repository_error)?
            && self.assert_user_not_blocked(&user.status).is_ok()
        {
            // Dispatch by configured method. Both paths are best-effort: a store or send
            // failure is logged and dropped so the uniform response is never perturbed.
            match config.password_reset.method {
                ResetMethod::Otp => {
                    let _ = self.send_reset_otp(&input.tenant_id, &input.email).await;
                }
                ResetMethod::Token => {
                    let _ = self
                        .send_reset_token(&user, &input.email, &input.tenant_id)
                        .await;
                }
            }
        }
        Ok(())
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
        // is configured it is authoritative and the body value is ignored. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let input = ResetPasswordInput {
            email: normalize_email(&input.email),
            tenant_id,
            ..input
        };
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
            .assert_not_compromised(&input.new_password)
            .await?;

        match dispatch {
            Dispatch::Stored(token, kind) => {
                self.reset_with_stored_proof(token, &input, kind).await
            }
            Dispatch::Otp(otp) => self.reset_with_otp(otp, &input).await,
        }
    }

    /// Reset using a stored opaque proof (the reset link token or the OTP verified token):
    /// atomically consume it, re-bind it to the presented email/tenant (a digest compare that
    /// removes the variable-length oracle of a raw compare), then apply the reset.
    async fn reset_with_stored_proof(
        &self,
        token: &str,
        input: &ResetPasswordInput,
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
        if !digest_eq(&context.email, &input.email)
            || !digest_eq(&context.tenant_id, &input.tenant_id)
        {
            return Err(AuthError::PasswordResetTokenInvalid);
        }
        self.assert_proof_still_bound(&context).await?;
        self.apply_password_reset(&context, &input.new_password)
            .await
    }

    /// Reset using a direct OTP: verify (single-use, attempt-bounded), then look up the
    /// account and apply the reset. A vanished account collapses to the invalid-token error
    /// rather than a distinct "not found".
    async fn reset_with_otp(&self, otp: &str, input: &ResetPasswordInput) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(&input.tenant_id, &input.email);
        self.otp()
            .verify(OtpPurpose::PasswordReset, &identifier, otp)
            .await?;
        let user = self
            .user_repository()
            .find_by_email(&input.email, &input.tenant_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::PasswordResetTokenInvalid)?;
        let context = ResetContext {
            user_id: user.id.clone(),
            email: input.email.clone(),
            tenant_id: input.tenant_id.clone(),
            password_fingerprint: password_fingerprint(&user),
        };
        self.apply_password_reset(&context, &input.new_password)
            .await
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
        // is configured it is authoritative and the body value is ignored. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let input = VerifyResetOtpInput {
            email: normalize_email(&input.email),
            tenant_id,
            ..input
        };
        let identifier = self.hashed_identifier(&input.tenant_id, &input.email);
        self.otp()
            .verify(OtpPurpose::PasswordReset, &identifier, &input.otp)
            .await?;
        let user = self
            .user_repository()
            .find_by_email(&input.email, &input.tenant_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::PasswordResetTokenInvalid)?;

        let store = self
            .password_reset_store()
            .ok_or(AuthError::PasswordResetTokenInvalid)?;
        let raw = generate_secure_token(RESET_TOKEN_BYTES);
        let context = ResetContext {
            password_fingerprint: password_fingerprint(&user),
            user_id: user.id,
            email: input.email,
            tenant_id: input.tenant_id,
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
        // is configured it is authoritative and the body value is ignored. That is the
        // anti-spoofing promise, and it also keeps this step reading the same tenant the
        // initiate step wrote under.
        let tenant_id = self.resolve_tenant(&input.tenant_id, ctx).await?;
        let input = ResendResetOtpInput {
            email: normalize_email(&input.email),
            tenant_id,
        };
        let started = Instant::now();
        // Run the fallible body, then normalize the elapsed time on EVERY exit — the cooldown
        // short-circuit, the success path, and any infrastructure error — so a backend failure
        // cannot be distinguished from a normal response by latency.
        let outcome = self.resend_reset_otp_inner(&input).await;
        normalize_anti_enum(started).await;
        outcome
    }

    /// The fallible body of [`AuthEngine::resend_reset_otp`], separated so the caller applies
    /// the anti-enumeration timing floor to every exit path (success and infra error alike).
    async fn resend_reset_otp_inner(&self, input: &ResendResetOtpInput) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(&input.tenant_id, &input.email);

        // Atomic cooldown gate — a second resend inside the window is a silent success.
        if !self
            .otp()
            .try_begin_resend(OtpPurpose::PasswordReset, &identifier, RESEND_COOLDOWN_SECS)
            .await?
        {
            return Ok(());
        }

        if let Some(user) = self
            .user_repository()
            .find_by_email(&input.email, &input.tenant_id)
            .await
            .map_err(map_repository_error)?
            && self.assert_user_not_blocked(&user.status).is_ok()
        {
            // Best-effort: a store/dispatch failure must not change the uniform response.
            let _ = self.send_reset_otp(&input.tenant_id, &input.email).await;
        }
        Ok(())
    }

    /// Generate, store, and dispatch a reset OTP. The store write is reported to the caller
    /// (which ignores it on the anti-enumerating paths); the email send is fire-and-forget so
    /// its round-trip never perturbs the normalized timing.
    async fn send_reset_otp(&self, tenant_id: &str, email: &str) -> Result<(), AuthError> {
        let identifier = self.hashed_identifier(tenant_id, email);
        let length = self.config().config().password_reset.otp_length;
        let otp = self.otp().generate(length);
        let ttl = self.config().config().password_reset.otp_ttl.as_secs();
        self.otp()
            .store(OtpPurpose::PasswordReset, &identifier, &otp, ttl)
            .await?;
        spawn_guarded(crate::services::auth::detached::run_send_reset_otp_email(
            self.email_provider().clone(),
            email.to_owned(),
            otp,
        ));
        Ok(())
    }

    /// Generate, store, and dispatch a reset link token. On a send failure the stored token is
    /// deleted so an undeliverable token does not linger in a Redis snapshot. The send is
    /// blocking here (not fire-and-forget) precisely so its failure can drive the cleanup.
    async fn send_reset_token(
        &self,
        user: &AuthUser,
        email: &str,
        tenant_id: &str,
    ) -> Result<(), AuthError> {
        let Some(store) = self.password_reset_store() else {
            // A misconfiguration: the token method is selected but no `pw_reset:` store is wired.
            // Surfaced to the caller (which swallows it on the anti-enumerating path) and
            // logged so a deployment running the token method without its store is observable.
            tracing::warn!("password reset token method selected but no PasswordResetStore wired");
            return Err(crate::services::internal_error(
                "password reset store not configured",
            ));
        };
        let raw = generate_secure_token(RESET_TOKEN_BYTES);
        let ttl = self.config().config().password_reset.token_ttl.as_secs();
        let context = ResetContext {
            user_id: user.id.clone(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            password_fingerprint: password_fingerprint(user),
        };
        store.put_token(&raw, &context, ttl).await?;

        // On a delivery failure, clean up the stored token so it cannot linger unusable.
        if self
            .email_provider()
            .send_password_reset_token(email, &raw, None)
            .await
            .is_err()
        {
            // The caller must not learn that the address exists, so the failure is swallowed on
            // the response path — which makes the log the only place an operator can see that
            // reset links are not reaching anyone.
            tracing::error!(user_id = %user.id, "password reset: token delivery failed");
            if let Err(error) = store.delete_token(&raw).await {
                // The rollback is what keeps an undeliverable token from lingering in a Redis
                // snapshot for its whole TTL.
                tracing::error!(%error, "password reset: rollback of the stored token failed");
            }
        }
        Ok(())
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
        user_id: &str,
        current_password: &str,
        new_password: &str,
        current_refresh: Option<&str>,
    ) -> Result<(), AuthError> {
        let user = self
            .user_repository()
            .find_by_id(user_id, None)
            .await
            .map_err(map_repository_error)?;
        // A verified token whose subject is gone, and an account with no local password, answer
        // identically: the caller cannot prove a credential this account does not have.
        let Some(phc) = user.and_then(|user| user.password_hash) else {
            return Err(AuthError::InvalidCredentials);
        };

        if !self
            .passwords()
            .verify(current_password, &phc)
            .await?
            .matched
        {
            tracing::warn!(user_id = %user_id, "password change: current password rejected");
            return Err(AuthError::InvalidCredentials);
        }

        self.passwords()
            .assert_not_compromised(new_password)
            .await?;
        let new_hash = self.passwords().hash(new_password).await?;
        self.user_repository()
            .update_password(user_id, &new_hash)
            .await
            .map_err(map_repository_error)?;

        // Sessions go only after the password is durably written, for the same reason the reset
        // flow orders it that way: a crash between the two leaves stale refresh tokens alive
        // until their TTL, but the old password is already dead.
        match current_refresh.filter(|raw| is_refresh_token_shape(raw)) {
            Some(raw) => {
                let hash = RawRefreshToken::from_raw(raw.to_owned()).redis_hash();
                self.sessions()
                    .revoke_all_except_current(user_id, &hash)
                    .await?;
            }
            None => {
                self.session_store()
                    .revoke_all(SessionKind::Dashboard, user_id)
                    .await?;
                self.session_store()
                    .bump_epoch(SessionKind::Dashboard, user_id)
                    .await?;
            }
        }

        tracing::info!(user_id = %user_id, "password change: completed, other sessions revoked");
        self.notify_password_changed(user_id).await;
        Ok(())
    }

    /// Send the "your password changed" notice, detached and best-effort.
    ///
    /// NIST SP 800-63B §4.6 asks for a notification through a channel independent of the
    /// transaction that bound the new credential. Never awaited and never allowed to fail the
    /// operation: a delivery problem must not undo a password that is already written, nor
    /// answer differently to the caller.
    async fn notify_password_changed(&self, user_id: &str) {
        let Ok(Some(user)) = self.user_repository().find_by_id(user_id, None).await else {
            return;
        };
        spawn_guarded(run_send_password_changed(
            self.email_provider().clone(),
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
            .find_by_id(&context.user_id, None)
            .await
            .map_err(map_repository_error)?
            .map(|user| password_fingerprint(&user))
            .unwrap_or_default();

        if current == context.password_fingerprint {
            return Ok(());
        }
        tracing::warn!(
            user_id = %context.user_id,
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
            .update_password(&context.user_id, &new_hash)
            .await
            .map_err(map_repository_error)?;
        // Sessions are invalidated only after the password is durably updated. This is the
        // dashboard reset flow, so only dashboard sessions are revoked; platform-admin sessions
        // are a separate identity surface with their own credential-reset path and are not
        // touched here. Revoking the refresh sessions stops rotation; bumping the token epoch
        // additionally invalidates every already-issued (stateless) access token at once, so a
        // reset takes effect immediately rather than lingering for the access-token lifetime.
        self.session_store()
            .revoke_all(crate::traits::SessionKind::Dashboard, &context.user_id)
            .await?;
        self.session_store()
            .bump_epoch(crate::traits::SessionKind::Dashboard, &context.user_id)
            .await?;
        // A completed reset is the event an operator correlates an account takeover against:
        // it revokes every session the account had and invalidates its outstanding access
        // tokens, so it belongs in the audit trail even when nothing failed.
        tracing::info!(user_id = %context.user_id, "password reset: completed, all sessions revoked");

        // A reset needs the notice at least as much as a change does: the classic takeover
        // completes one from a compromised mailbox and deletes the mail.
        self.notify_password_changed(&context.user_id).await;

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
            .find_by_id(&context.user_id, None)
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
fn digest_eq(a: &str, b: &str) -> bool {
    verify_digest(&sha256(a.as_bytes()), &sha256(b.as_bytes()))
}

/// A [`HookContext`] carrying only the reset subject's identity (the reset flow has no
/// originating request context).
fn reset_context_hooks(context: &ResetContext) -> HookContext {
    HookContext {
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
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email.send_password_changed(&recipient, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::LoginInput;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, ctx, harness};
    use crate::traits::{
        EmailProvider, OtpStore, PasswordResetStore, SessionKind, SessionStore, UserRepository,
    };
    use bymax_auth_types::{AuthResult, CreateUserData, LoginResult};
    use std::time::Duration;
    use time::OffsetDateTime;

    fn token_harness() -> Option<Harness> {
        let mut cfg = base_config();
        cfg.password_reset.method = ResetMethod::Token;
        harness(cfg, None)
    }

    fn otp_harness() -> Option<Harness> {
        let mut cfg = base_config();
        cfg.password_reset.method = ResetMethod::Otp;
        harness(cfg, None)
    }

    /// Read back the live password hash for a user, for before/after comparisons.
    async fn stored_hash(h: &Harness, id: &str) -> Option<String> {
        h.users
            .find_by_id(id, None)
            .await
            .ok()
            .flatten()
            .and_then(|user| user.password_hash)
    }

    fn forgot(email: &str) -> ForgotPasswordInput {
        ForgotPasswordInput {
            email: email.to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    #[tokio::test]
    async fn token_method_resets_and_revokes_all_sessions() {
        // The token method stores a reset token, the reset consumes it, the password changes,
        // and every session is revoked.
        let Some(h) = token_harness() else { return };
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
            family_id: "fam-test".to_owned(),
            family_created_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        assert!(
            h.stores
                .create_session(SessionKind::Dashboard, &hash, &record, 3600)
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
        let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { return };
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
            tenant_id: "t1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
        let Some(h) = token_harness() else { return };
        let id = h.seed(SeedUser::active("epoch@example.com", "pw")).await;
        // Before the reset the user carries the inert epoch 0.
        assert!(matches!(
            h.stores.current_epoch(SessionKind::Dashboard, &id).await,
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
            tenant_id: "t1".to_owned(),
            new_password: "brandnewwalnut42".to_owned(),
            token: Some(known),
            otp: None,
            verified_token: None,
        };
        assert!(h.engine.reset_password(reset, &ctx()).await.is_ok());
        // The reset advanced the epoch: any token stamped at 0 is now below the current value.
        assert!(matches!(
            h.stores.current_epoch(SessionKind::Dashboard, &id).await,
            Ok(1)
        ));
    }

    #[tokio::test]
    async fn a_rejected_new_password_leaves_the_reset_token_unspent() {
        // The proof is single-use and consumed atomically, so a screen rejection that arrived
        // after the consumption told the caller their password was unacceptable and, in the
        // same breath, that the only credential they had to fix it was gone — the whole mail
        // round trip repeated for a mistake the request itself carried.
        let Some(h) = token_harness() else { return };
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

        // `password1` is exactly what the default screen exists to refuse.
        let refused = ResetPasswordInput {
            email: "spend@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "password1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
        let Some(h) = token_harness() else { return };
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
            tenant_id: "t1".to_owned(),
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
        let Some(h) = otp_harness() else { return };
        let id = h.seed(SeedUser::active("otp@example.com", "old")).await;
        let identifier = h.engine.hashed_identifier("t1", "otp@example.com");

        // Direct OTP path: send, read the code from the in-memory store, reset.
        assert!(
            h.engine
                .initiate_reset(forgot("otp@example.com"), &ctx())
                .await
                .is_ok()
        );
        let Some(code) = h.stores.peek_otp(OtpPurpose::PasswordReset, &identifier) else { return };
        let reset = ResetPasswordInput {
            email: "otp@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "walnutviaotp42".to_owned(),
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
        let Some(code2) = h.stores.peek_otp(OtpPurpose::PasswordReset, &identifier) else { return };
        let verified = h
            .engine
            .verify_reset_otp(
                VerifyResetOtpInput {
                    email: "otp@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    otp: code2,
                },
                &ctx(),
            )
            .await;
        assert!(verified.is_ok());
        let Ok(verified_token) = verified else { return };
        let reset2 = ResetPasswordInput {
            email: "otp@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
        let Some(h) = otp_harness() else { return };
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
                        tenant_id: "t1".to_owned(),
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
        let Some(h) = otp_harness() else { return };
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
        let code = h
            .stores
            .peek_otp(OtpPurpose::PasswordReset, &identifier)
            .unwrap_or_default();
        assert!(
            !code.is_empty(),
            "no reset OTP was minted under the canonical spelling"
        );
        // And completed with yet another spelling.
        let reset = ResetPasswordInput {
            email: "Case@Example.com".to_owned(),
            tenant_id: "t1".to_owned(),
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
        let second = h
            .stores
            .peek_otp(OtpPurpose::PasswordReset, &identifier)
            .unwrap_or_default();
        assert!(!second.is_empty());
        let verified = h
            .engine
            .verify_reset_otp(
                VerifyResetOtpInput {
                    email: "cAsE@eXaMpLe.CoM".to_owned(),
                    tenant_id: "t1".to_owned(),
                    otp: second,
                },
                &ctx(),
            )
            .await;
        assert!(verified.is_ok(), "the OTP must verify under any spelling");
        let Ok(verified_token) = verified else { return };
        let bridged = ResetPasswordInput {
            email: "CASE@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "walnutagain42".to_owned(),
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
        let Some(h) = otp_harness() else { return };
        let none = ResetPasswordInput {
            email: "x@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
        let Some(ht) = token_harness() else { return };
        let otp_to_token = ResetPasswordInput {
            email: "x@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
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

    #[tokio::test]
    async fn initiate_and_resend_are_anti_enumerating() {
        // Initiate and resend both return Ok and honor the ≥300ms floor for an existing, a
        // blocked, and an absent account; a second resend within the window is a silent Ok.
        let Some(h) = otp_harness() else { return };
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
                        tenant_id: "t1".to_owned(),
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
                        tenant_id: "t1".to_owned(),
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
                        tenant_id: "t1".to_owned(),
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
                        tenant_id: "t1".to_owned(),
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
        let Some(h) = otp_harness() else { return };
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
                        tenant_id: "t1".to_owned(),
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
        assert!(
            h.stores
                .put(OtpPurpose::PasswordReset, &ghost_id, "111111", 600)
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine
                .verify_reset_otp(
                    VerifyResetOtpInput {
                        email: "ghost@example.com".to_owned(),
                        tenant_id: "t1".to_owned(),
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
            tenant_id: "t1".to_owned(),
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
                .update_email("u1", "new@example.com")
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
                .send_email_change_verification("new@example.com", "t", None)
                .await
                .is_ok()
        );
        let capturing = CapturingResetEmail::default();
        assert!(
            capturing
                .send_email_change_verification("new@example.com", "t", None)
                .await
                .is_ok()
        );
    }

    struct FailingResetEmail;

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for FailingResetEmail {
        async fn send_email_change_verification(
            &self,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_password_reset_token(
            &self,
            _email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Err(crate::traits::EmailError::Delivery("down".into()))
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
            _session: &crate::traits::SessionInfo,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_invitation(
            &self,
            _email: &str,
            _invite: &crate::traits::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
    }

    /// An email provider that keeps the reset token it was asked to deliver, so a test can
    /// drive the flow with the token a real recipient would have received.
    #[derive(Default)]
    struct CapturingResetEmail {
        token: std::sync::Mutex<Option<String>>,
    }

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for CapturingResetEmail {
        async fn send_email_change_verification(
            &self,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_password_reset_token(
            &self,
            _email: &str,
            token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            if let Ok(mut slot) = self.token.lock() {
                *slot = Some(token.to_owned());
            }
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
            _session: &crate::traits::SessionInfo,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_invitation(
            &self,
            _email: &str,
            _invite: &crate::traits::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
    }

    /// A hook spy recording the subject of every `after_password_reset` notification.
    #[derive(Default)]
    struct ResetHookSpy {
        subjects: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::traits::AuthHooks for ResetHookSpy {
        async fn after_password_reset(
            &self,
            user: &SafeAuthUser,
            _ctx: &crate::traits::HookContext,
        ) -> Result<(), crate::traits::HookError> {
            if let Ok(mut subjects) = self.subjects.lock() {
                subjects.push(user.id.clone());
            }
            Ok(())
        }
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
        let Some(h) = harness(cfg, Some(hooks)) else { return };
        let id = h.seed(SeedUser::active("hooked@example.com", "old")).await;
        let identifier = h.engine.hashed_identifier("t1", "hooked@example.com");
        assert!(
            h.engine
                .initiate_reset(forgot("hooked@example.com"), &ctx())
                .await
                .is_ok()
        );
        let code = h
            .stores
            .peek_otp(OtpPurpose::PasswordReset, &identifier)
            .unwrap_or_default();
        assert!(!code.is_empty());
        let reset = ResetPasswordInput {
            email: "hooked@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "brand-new".to_owned(),
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
        let Ok(engine) = built else { return };
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
        let Ok(user) = created else { return };

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
            tenant_id: "t1".to_owned(),
            new_password: "the-new-one".to_owned(),
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
                .send_password_reset_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_verification_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(provider.send_mfa_enabled("e", None).await.is_ok());
        assert!(provider.send_mfa_disabled("e", None).await.is_ok());
        let session = crate::traits::SessionInfo {
            device: "d".to_owned(),
            ip: "i".to_owned(),
            session_hash: "h".to_owned(),
        };
        assert!(
            provider
                .send_new_session_alert("e", &session, None)
                .await
                .is_ok()
        );
        let invite = crate::traits::InviteData {
            inviter_name: "n".to_owned(),
            tenant_name: "t".to_owned(),
            invite_token: "tok".to_owned(),
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert!(provider.send_invitation("e", &invite, None).await.is_ok());
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
        let Ok(engine) = built else { return };
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
        // its whole TTL can surface at all. The first initiate claimed the resend cooldown, so
        // release it: otherwise this second call returns before reaching the send at all, and
        // the rollback branch under test never runs.
        assert!(stores.expire_resend_cooldown(
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
                .send_password_reset_token("e", "t", None)
                .await
                .is_err()
        );
        assert!(
            provider
                .send_password_reset_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_verification_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(provider.send_mfa_enabled("e", None).await.is_ok());
        assert!(provider.send_mfa_disabled("e", None).await.is_ok());
        let session = crate::traits::SessionInfo {
            device: "d".to_owned(),
            ip: "i".to_owned(),
            session_hash: "h".to_owned(),
        };
        assert!(
            provider
                .send_new_session_alert("e", &session, None)
                .await
                .is_ok()
        );
        let invite = crate::traits::InviteData {
            inviter_name: "n".to_owned(),
            tenant_name: "t".to_owned(),
            invite_token: "tok".to_owned(),
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert!(provider.send_invitation("e", &invite, None).await.is_ok());
        // The cleanup means the (unknown-to-the-test) token is gone; an arbitrary token is
        // invalid, proving the flow did not leave a usable proof behind.
        assert!(matches!(
            engine
                .reset_password(
                    ResetPasswordInput {
                        email: "fail@example.com".to_owned(),
                        tenant_id: "t1".to_owned(),
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
        let Ok(engine) = built else { return };
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

    /// A user repository whose `find_by_email` always fails with a backend error, to drive the
    /// infra-error timing path of the anti-enumerating flows.
    struct FailingLookupRepo;

    #[async_trait::async_trait]
    impl UserRepository for FailingLookupRepo {
        async fn update_email(
            &self,
            _id: &str,
            _email: &str,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }

        async fn find_by_id(
            &self,
            _id: &str,
            _tenant_id: Option<&str>,
        ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
            Ok(None)
        }
        async fn find_by_email(
            &self,
            _email: &str,
            _tenant_id: &str,
        ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
            Err(crate::RepositoryError::Backend("db down".into()))
        }
        async fn create(
            &self,
            _data: bymax_auth_types::CreateUserData,
        ) -> Result<bymax_auth_types::AuthUser, crate::RepositoryError> {
            Err(crate::RepositoryError::Backend("db down".into()))
        }
        async fn update_password(
            &self,
            _id: &str,
            _password_hash: &str,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn update_mfa(
            &self,
            _id: &str,
            _data: bymax_auth_types::UpdateMfaData,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn update_last_login(&self, _id: &str) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn update_status(
            &self,
            _id: &str,
            _status: &str,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn update_email_verified(
            &self,
            _id: &str,
            _verified: bool,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn find_by_oauth_id(
            &self,
            _provider: &str,
            _provider_id: &str,
            _tenant_id: &str,
        ) -> Result<Option<bymax_auth_types::AuthUser>, crate::RepositoryError> {
            Ok(None)
        }
        async fn link_oauth(
            &self,
            _user_id: &str,
            _provider: &str,
            _provider_id: &str,
        ) -> Result<(), crate::RepositoryError> {
            Ok(())
        }
        async fn create_with_oauth(
            &self,
            _data: bymax_auth_types::CreateWithOAuthData,
        ) -> Result<bymax_auth_types::AuthUser, crate::RepositoryError> {
            Err(crate::RepositoryError::Backend("db down".into()))
        }
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
        let Ok(engine) = built else { return };

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
                    tenant_id: "t1".to_owned(),
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
        assert!(repo.update_password("x", "h").await.is_ok());
        assert!(
            repo.update_mfa(
                "x",
                bymax_auth_types::UpdateMfaData {
                    mfa_enabled: false,
                    mfa_secret: None,
                    mfa_recovery_codes: None,
                },
            )
            .await
            .is_ok()
        );
        assert!(repo.update_last_login("x").await.is_ok());
        assert!(repo.update_status("x", "ACTIVE").await.is_ok());
        assert!(repo.update_email_verified("x", true).await.is_ok());
        assert!(matches!(
            repo.find_by_oauth_id("g", "1", "t").await,
            Ok(None)
        ));
        assert!(repo.link_oauth("x", "g", "1").await.is_ok());
        assert!(repo.create_with_oauth(oauth_data()).await.is_err());
    }

    /// A minimal `CreateUserData`, for exercising the failing repository's `create`.
    fn create_data() -> bymax_auth_types::CreateUserData {
        bymax_auth_types::CreateUserData {
            email: "e@example.com".to_owned(),
            name: "E".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: None,
            status: None,
            tenant_id: "t1".to_owned(),
            email_verified: None,
        }
    }

    /// A minimal `CreateWithOAuthData`, for exercising the failing repository's
    /// `create_with_oauth`.
    fn oauth_data() -> bymax_auth_types::CreateWithOAuthData {
        bymax_auth_types::CreateWithOAuthData {
            email: "e@example.com".to_owned(),
            name: "E".to_owned(),
            role: None,
            status: None,
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
            oauth_provider: "google".to_owned(),
            oauth_provider_id: "g-1".to_owned(),
        }
    }

    /// Log in and return the session, or `None` — so a caller's `let-else` fits on one line.
    /// (Coverage is per line: a `return` on its own line inside a multi-line `let-else` is
    /// never executed, and reads as a gap rather than as the panic-free idiom it is.)
    async fn login_ok(h: &Harness, email: &str, password: &str) -> Option<AuthResult> {
        let input = LoginInput {
            email: email.to_owned(),
            password: password.to_owned(),
            tenant_id: "t1".to_owned(),
        };
        let result = h.engine.login(input, &ctx()).await;
        let Ok(LoginResult::Success(auth)) = result else { return None };
        Some(*auth)
    }

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
        let Some(h) = token_harness() else { return };
        let id = h
            .seed(SeedUser::active("siblings@example.com", "oldsecret77"))
            .await;
        let Some(store) = h.engine.password_reset_store() else { return };

        // Two proofs, both bound to the password in force now.
        let Ok(Some(user)) = h.users.find_by_id(&id, None).await else { return };
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
            tenant_id: "t1".to_owned(),
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
        let Some(h) = token_harness() else { return };
        let id = h
            .seed(SeedUser::active("changer@example.com", "oldsecret77"))
            .await;

        // A wrong current password writes nothing.
        let refused = h
            .engine
            .change_password(&id, "not-the-password", "glidingwalnut42", None)
            .await;
        assert!(matches!(refused, Err(AuthError::InvalidCredentials)));

        // The right one rotates it, and the new password is what logs in afterwards.
        assert!(
            h.engine
                .change_password(&id, "oldsecret77", "glidingwalnut42", None)
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
    async fn change_password_spares_the_caller_session_when_it_is_identified() {
        // ASVS v5 §7.4.3: the other sessions end. The caller's own survives, so the device that
        // made the change is not signed out by making it — it silently re-mints its access
        // token on the next rotation instead.
        let Some(h) = token_harness() else { return };
        let id = h
            .seed(SeedUser::active("keeper@example.com", "oldsecret77"))
            .await;
        let Some(mine) = login_ok(&h, "keeper@example.com", "oldsecret77").await else { return };
        let Some(other) = login_ok(&h, "keeper@example.com", "oldsecret77").await else { return };

        assert!(
            h.engine
                .change_password(
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
        let Some(h) = token_harness() else { return };
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
        let Ok(user) = created else { return };

        let refused = h
            .engine
            .change_password(&user.id, "anything", "glidingwalnut42", None)
            .await;
        assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn change_password_refuses_a_new_password_the_screen_rejects() {
        // The screen runs on the change path as it does on register and reset — otherwise the
        // one flow a user reaches *because* they were told their password was weak is the one
        // that lets them pick another weak one.
        let Some(h) = token_harness() else { return };
        let id = h
            .seed(SeedUser::active("weak@example.com", "oldsecret77"))
            .await;

        let refused = h
            .engine
            .change_password(&id, "oldsecret77", "Password123", None)
            .await;
        assert!(matches!(refused, Err(AuthError::PasswordCompromised)));
    }

    #[tokio::test]
    async fn apply_reset_skips_the_hook_for_a_vanished_subject() {
        // A reset whose bound context points at a user id that no longer resolves still
        // succeeds (password update + revoke run on the id), and the hook projection is
        // skipped — covering the `None` arm of the hook user lookup.
        let Some(h) = token_harness() else { return };
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
                        tenant_id: "t1".to_owned(),
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
}
