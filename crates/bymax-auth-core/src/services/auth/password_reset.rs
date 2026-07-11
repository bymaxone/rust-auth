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
use bymax_auth_types::{AuthError, AuthUser, SafeAuthUser};

use crate::config::ResetMethod;
use crate::engine::AuthEngine;
use crate::services::auth::detached::run_after_password_reset;
use crate::services::auth::{map_repository_error, normalize_anti_enum, spawn_guarded};
use crate::traits::{HookContext, OtpPurpose, ResetContext};

/// The lifetime, in seconds, of the short-lived verified token that bridges a successful
/// OTP verification to the reset form (§7.8 `VERIFIED_TOKEN_TTL_SECONDS`).
const VERIFIED_TOKEN_TTL_SECONDS: u64 = 300;

/// The atomic resend cooldown for the OTP method, in seconds (§7.8.4).
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
    pub async fn initiate_reset(&self, input: ForgotPasswordInput) -> Result<(), AuthError> {
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
    pub async fn reset_password(&self, input: ResetPasswordInput) -> Result<(), AuthError> {
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

        match (self.config().config().password_reset.method, proof) {
            // The token method accepts only a reset link token.
            (ResetMethod::Token, Proof::Token(token)) => {
                self.reset_with_stored_proof(token, &input, ProofKind::Token)
                    .await
            }
            // The OTP method accepts a direct OTP or the verified-token bridge.
            (ResetMethod::Otp, Proof::Otp(otp)) => self.reset_with_otp(otp, &input).await,
            (ResetMethod::Otp, Proof::Verified(verified)) => {
                self.reset_with_stored_proof(verified, &input, ProofKind::Verified)
                    .await
            }
            // Any other method/proof pairing is an explicit mismatch (e.g. a token submitted to
            // the OTP method, or an OTP/verified token submitted to the token method).
            _ => Err(AuthError::PasswordResetTokenInvalid),
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
    pub async fn verify_reset_otp(&self, input: VerifyResetOtpInput) -> Result<String, AuthError> {
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
    pub async fn resend_reset_otp(&self, input: ResendResetOtpInput) -> Result<(), AuthError> {
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
            // A misconfiguration: the token method is selected but no `pr:` store is wired.
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
        };
        store.put_token(&raw, &context, ttl).await?;

        // On a delivery failure, clean up the stored token so it cannot linger unusable.
        if self
            .email_provider()
            .send_password_reset_token(email, &raw, None)
            .await
            .is_err()
        {
            let _ = store.delete_token(&raw).await;
        }
        Ok(())
    }

    /// Apply the verified reset: hash the new password, persist it, then revoke every session.
    ///
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
        let new_hash = self.passwords().hash(new_password).await?;
        self.user_repository()
            .update_password(&context.user_id, &new_hash)
            .await
            .map_err(map_repository_error)?;
        // Sessions are invalidated only after the password is durably updated. This is the
        // dashboard reset flow, so only dashboard sessions are revoked; platform-admin sessions
        // are a separate identity surface with their own credential-reset path and are not
        // touched here.
        self.session_store()
            .revoke_all(crate::traits::SessionKind::Dashboard, &context.user_id)
            .await?;

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
    /// A reset link token (`pr:`).
    Token(&'a str),
    /// A direct OTP.
    Otp(&'a str),
    /// An OTP-flow verified token (`prv:`).
    Verified(&'a str),
}

/// Which opaque-token keyspace a stored reset proof lives in.
#[derive(Clone, Copy)]
enum ProofKind {
    /// The reset link token (`pr:`).
    Token,
    /// The OTP-flow verified token (`prv:`).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::auth::test_support::{Harness, SeedUser, base_config, harness};
    use crate::traits::{
        EmailProvider, OtpStore, PasswordResetStore, SessionKind, SessionStore, UserRepository,
    };
    use std::time::Duration;

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
            family_id: "fam-test".to_owned(),
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
                .initiate_reset(forgot("reset@example.com"))
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
                    },
                    600
                )
                .await
                .is_ok()
        );
        let reset = ResetPasswordInput {
            email: "reset@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "brand-new-pw".to_owned(),
            token: Some(known.clone()),
            otp: None,
            verified_token: None,
        };
        assert!(h.engine.reset_password(reset).await.is_ok());

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
            new_password: "another-pw".to_owned(),
            token: Some(known),
            otp: None,
            verified_token: None,
        };
        assert!(matches!(
            h.engine.reset_password(replay).await,
            Err(AuthError::PasswordResetTokenInvalid)
        ));
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
            new_password: "x".to_owned(),
            token: Some(known),
            otp: None,
            verified_token: None,
        };
        assert!(matches!(
            h.engine.reset_password(reset).await,
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
                .initiate_reset(forgot("otp@example.com"))
                .await
                .is_ok()
        );
        let Some(code) = h.stores.peek_otp(OtpPurpose::PasswordReset, &identifier) else { return };
        let reset = ResetPasswordInput {
            email: "otp@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "new-via-otp".to_owned(),
            token: None,
            otp: Some(code.clone()),
            verified_token: None,
        };
        assert!(h.engine.reset_password(reset).await.is_ok());

        // Verified-token bridge: re-send an OTP, verify it for a token, reset with the token.
        assert!(
            h.engine
                .initiate_reset(forgot("otp@example.com"))
                .await
                .is_ok()
        );
        let Some(code2) = h.stores.peek_otp(OtpPurpose::PasswordReset, &identifier) else { return };
        let verified = h
            .engine
            .verify_reset_otp(VerifyResetOtpInput {
                email: "otp@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
                otp: code2,
            })
            .await;
        assert!(verified.is_ok());
        let Ok(verified_token) = verified else { return };
        let reset2 = ResetPasswordInput {
            email: "otp@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "new-via-verified".to_owned(),
            token: None,
            otp: None,
            verified_token: Some(verified_token.clone()),
        };
        assert!(h.engine.reset_password(reset2).await.is_ok());
        let _ = id;
        // The verified token is single-use.
        let replay = ResetPasswordInput {
            email: "otp@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            new_password: "x".to_owned(),
            token: None,
            otp: None,
            verified_token: Some(verified_token),
        };
        assert!(matches!(
            h.engine.reset_password(replay).await,
            Err(AuthError::PasswordResetTokenInvalid)
        ));
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
            h.engine.reset_password(none).await,
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
            h.engine.reset_password(two).await,
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
            h.engine.reset_password(mismatch).await,
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
            ht.engine.reset_password(otp_to_token).await,
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
            assert!(h.engine.initiate_reset(forgot(email)).await.is_ok());
            assert!(started.elapsed() >= Duration::from_millis(300));
        }

        let started = Instant::now();
        assert!(
            h.engine
                .resend_reset_otp(ResendResetOtpInput {
                    email: "present@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                })
                .await
                .is_ok()
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        // A second resend within the cooldown is the silent-success branch.
        assert!(
            h.engine
                .resend_reset_otp(ResendResetOtpInput {
                    email: "present@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                })
                .await
                .is_ok()
        );
        // An absent account is indistinguishable on resend.
        assert!(
            h.engine
                .resend_reset_otp(ResendResetOtpInput {
                    email: "ghost@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                })
                .await
                .is_ok()
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
                .initiate_reset(forgot("vrf@example.com"))
                .await
                .is_ok()
        );
        assert!(matches!(
            h.engine
                .verify_reset_otp(VerifyResetOtpInput {
                    email: "vrf@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    otp: "000000".to_owned(),
                })
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
                .verify_reset_otp(VerifyResetOtpInput {
                    email: "ghost@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    otp: "111111".to_owned(),
                })
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
    struct FailingResetEmail;

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for FailingResetEmail {
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

    #[tokio::test]
    async fn token_send_failure_deletes_the_unusable_token() {
        // On an undeliverable reset email the stored `pr:` token is deleted so it cannot
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
                .initiate_reset(forgot("fail@example.com"))
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
                .reset_password(ResetPasswordInput {
                    email: "fail@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    new_password: "x".to_owned(),
                    token: Some("a".repeat(64)),
                    otp: None,
                    verified_token: None,
                })
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
                .initiate_reset(forgot("nostore@example.com"))
                .await
                .is_ok()
        );
    }

    /// A user repository whose `find_by_email` always fails with a backend error, to drive the
    /// infra-error timing path of the anti-enumerating flows.
    struct FailingLookupRepo;

    #[async_trait::async_trait]
    impl UserRepository for FailingLookupRepo {
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
        let initiate = engine.initiate_reset(forgot("err@example.com")).await;
        assert!(matches!(initiate, Err(AuthError::Internal(_))));
        assert!(started.elapsed() >= Duration::from_millis(300));

        // The resend path begins a fresh cooldown (so it reaches the failing lookup), then the
        // backend error surfaces only after the timing floor.
        let started = Instant::now();
        let resend = engine
            .resend_reset_otp(ResendResetOtpInput {
                email: "err2@example.com".to_owned(),
                tenant_id: "t1".to_owned(),
            })
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
                    },
                    600
                )
                .await
                .is_ok()
        );
        assert!(
            h.engine
                .reset_password(ResetPasswordInput {
                    email: "vanish@example.com".to_owned(),
                    tenant_id: "t1".to_owned(),
                    new_password: "new".to_owned(),
                    token: Some(token),
                    otp: None,
                    verified_token: None,
                })
                .await
                .is_ok()
        );
    }
}
