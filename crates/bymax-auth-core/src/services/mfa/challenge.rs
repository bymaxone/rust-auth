//! [`MfaService::challenge`] (§7.5.3): the public, pre-auth second-factor step. The caller
//! holds only a short-lived temp token; brute-force runs early, the TOTP path fuses the
//! anti-replay mark with the temp-token consume in one atomic Lua, the recovery-code path is
//! a constant-time scan plus a single-use splice, and a success issues full tokens carrying
//! `mfa_verified = true`.

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, AuthResult, AuthUser, MfaContext, SafeAuthUser};

use crate::services::auth::detached::run_after_login;
use crate::services::auth::spawn_guarded;
use crate::services::mfa::{LoginResultMfa, MfaService, repository_error};
use crate::services::session::normalize_session_metadata;
use crate::services::token_manager::MfaTempVerified;
use crate::services::{now_offset, to_hex};
use crate::traits::{HookContext, SessionRecord};

impl MfaService {
    /// Run the MFA challenge (§7.5.3): verify the temp token (not yet consumed), then route by
    /// the token's context. The dashboard path runs the full flow and issues a session; the
    /// platform path is rejected in this phase (platform challenge issuance lands with the
    /// platform identity domain).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] for a bad/expired temp token,
    /// [`AuthError::AccountLocked`] when the challenge counter is tripped,
    /// [`AuthError::MfaNotEnabled`] when MFA is not configured for the account (or a platform
    /// challenge is attempted), [`AuthError::MfaInvalidCode`] for a wrong/replayed code, or an
    /// internal/store [`AuthError`].
    pub async fn challenge(
        &self,
        mfa_temp_token: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<LoginResultMfa, AuthError> {
        let verified = self.tokens.verify_mfa_temp_token(mfa_temp_token).await?;
        match verified.context {
            MfaContext::Dashboard => {
                self.challenge_dashboard(verified, code, ip, user_agent)
                    .await
            }
            // Platform MFA challenge issuance is delivered with the platform identity domain;
            // no platform temp token is minted in this phase, so this is a defensive guard.
            MfaContext::Platform => Err(AuthError::MfaNotEnabled),
        }
    }

    /// The dashboard challenge flow: brute-force gate, fetch + decrypt, TOTP (fused consume) or
    /// recovery-code (scan + standalone consume + splice), then full-token issuance.
    async fn challenge_dashboard(
        &self,
        verified: MfaTempVerified,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<LoginResultMfa, AuthError> {
        let MfaTempVerified { user_id, jti, .. } = verified;
        let bf_id = self.challenge_bf_id(&user_id);
        self.assert_not_locked(&bf_id).await?;

        // Fetch the dashboard user concretely; the combined guard rejects both a missing user
        // and one without MFA configured.
        let user = self
            .user_repo
            .find_by_id(&user_id, None)
            .await
            .map_err(repository_error)?
            .ok_or(AuthError::MfaNotEnabled)?;
        let Some(encrypted_secret) = user.mfa_secret.clone().filter(|_| user.mfa_enabled) else {
            return Err(AuthError::MfaNotEnabled);
        };
        let Some(raw_secret) = self.decrypt(&encrypted_secret) else {
            // A secret that will not decrypt is an opaque failure (no decrypt oracle).
            return Err(AuthError::TokenInvalid);
        };

        // Validate the submitted code. A six-digit code takes the fused TOTP path; anything
        // else is treated as a recovery code. On any invalid code the temp token is left alive
        // (retryable within its TTL) and only the failure counter advances.
        let recovery_index = if is_totp_code(code) {
            if !self.accept_totp(&user_id, &raw_secret, code, &jti).await? {
                return self.reject_code(&bf_id).await;
            }
            None
        } else {
            match self.accept_recovery_code(&user, code) {
                Some(index) => {
                    // The recovery-code path carries no `tu:` marker, so the temp token is
                    // consumed standalone now that the code is confirmed valid.
                    self.tokens.consume_mfa_temp_token(&jti).await?;
                    Some(index)
                }
                None => return self.reject_code(&bf_id).await,
            }
        };

        // Success: clear the failure counter and, for a recovery code, splice it out so it is
        // single-use.
        self.brute_force.reset(&bf_id).await?;
        if let Some(index) = recovery_index {
            self.splice_recovery_code(&user, &encrypted_secret, index)
                .await?;
        }

        // Mint a full session with `mfa_verified = true`.
        let email = user.email.clone();
        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens
            .issue_tokens(&safe, ip, user_agent, true)
            .await?;
        self.enforce_session_limit(&safe, &email, &result, ip, user_agent)
            .await?;
        let hook_ctx = self.hook_context(&user_id, &email, ip, user_agent);
        spawn_guarded(run_after_login(self.hooks.clone(), safe, hook_ctx));
        Ok(LoginResultMfa::Dashboard(result))
    }

    /// Validate a TOTP `code` and, on success, fuse the anti-replay mark with the temp-token
    /// consume in one atomic step. Returns `true` when the code was valid and freshly
    /// consumed, `false` for an invalid code or a losing concurrent same-code submission.
    async fn accept_totp(
        &self,
        user_id: &str,
        raw_secret: &[u8],
        code: &str,
        jti: &str,
    ) -> Result<bool, AuthError> {
        if !bymax_auth_crypto::totp::verify(
            raw_secret,
            code,
            super::current_unix_time(),
            self.totp_window,
        ) {
            return Ok(false);
        }
        // The fused step: mark `tu:{replay}` `NX` and, iff newly marked, `DEL mfa:{jti_hash}`.
        // A losing concurrent submission of the same correct code sees the marker already
        // present and is rejected, so exactly one session is issued.
        let replay = self.replay_id(user_id, code);
        let jti_marker = to_hex(&bymax_auth_crypto::mac::sha256(jti.as_bytes()));
        self.mfa_store
            .challenge_consume(&replay, &jti_marker, super::TOTP_ANTI_REPLAY_TTL_SECONDS)
            .await
    }

    /// Scan the stored recovery-code digests for a constant-time match of `code`, returning
    /// the matched index or `None`.
    fn accept_recovery_code(&self, user: &AuthUser, code: &str) -> Option<usize> {
        let digest = self.hash_recovery_code(code);
        let stored = user.mfa_recovery_codes.clone().unwrap_or_default();
        super::verify_recovery_code(&stored, &digest)
    }

    /// Remove the just-used recovery code from the stored set and persist the smaller set
    /// (preserving the encrypted secret), making the code single-use.
    async fn splice_recovery_code(
        &self,
        user: &AuthUser,
        encrypted_secret: &str,
        index: usize,
    ) -> Result<(), AuthError> {
        let mut codes = user.mfa_recovery_codes.clone().unwrap_or_default();
        if index < codes.len() {
            codes.remove(index);
        }
        self.persist_mfa(
            &user.id,
            MfaContext::Dashboard,
            true,
            Some(encrypted_secret.to_owned()),
            Some(codes),
        )
        .await
    }

    /// Record a failed challenge attempt and return the retryable [`AuthError::MfaInvalidCode`]
    /// (the temp token stays alive; the lockout eventually fires).
    async fn reject_code(&self, bf_id: &str) -> Result<LoginResultMfa, AuthError> {
        self.brute_force.record_failure(bf_id).await?;
        Err(AuthError::MfaInvalidCode)
    }

    /// Enforce the concurrent-session cap (and fire the new-session hook) for the just-issued
    /// dashboard session, mirroring the login path. A no-op when session tracking is disabled.
    async fn enforce_session_limit(
        &self,
        safe: &SafeAuthUser,
        email: &str,
        result: &AuthResult,
        ip: &str,
        user_agent: &str,
    ) -> Result<(), AuthError> {
        if !self.sessions_enabled {
            return Ok(());
        }
        let new_hash = RawRefreshToken::from_raw(result.refresh_token.clone()).redis_hash();
        let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
        let record = SessionRecord {
            user_id: safe.id.clone(),
            tenant_id: Some(safe.tenant_id.clone()),
            role: safe.role.clone(),
            device,
            ip: stored_ip,
            created_at: now_offset(),
        };
        let hook_ctx: HookContext = self.hook_context(&safe.id, email, ip, user_agent);
        self.sessions
            .after_session_created(&record, &new_hash, &hook_ctx)
            .await
    }
}

/// Whether `code` is a six-digit numeric TOTP code (the discriminator between the TOTP and
/// recovery-code challenge paths).
fn is_totp_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}
