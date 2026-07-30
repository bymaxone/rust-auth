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
    /// the token's context. The dashboard path issues a dashboard session; the platform path
    /// issues a platform session (no `tenantId`, platform keyspace). The `context` discriminant
    /// on the temp token — set when the originating login minted it — selects the repository and
    /// the result type, so a dashboard challenge can never issue a platform session or vice
    /// versa.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] for a bad/expired temp token,
    /// [`AuthError::AccountLocked`] when the challenge counter is tripped,
    /// [`AuthError::MfaNotEnabled`] when MFA is not configured for the account, or no platform
    /// repository is wired for a platform challenge, [`AuthError::MfaInvalidCode`] for a
    /// wrong/replayed code, or an internal/store [`AuthError`].
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
            #[cfg(feature = "platform")]
            MfaContext::Platform => {
                self.challenge_platform(verified, code, ip, user_agent)
                    .await
            }
            // A platform challenge in a build without the platform surface fails closed.
            #[cfg(not(feature = "platform"))]
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
        let bf_id = self.challenge_bf_id(MfaContext::Dashboard, &user_id);
        self.assert_not_locked("challenge", &user_id, &bf_id)
            .await?;

        // Fetch the dashboard user concretely; the combined guard rejects both a missing user
        // and one without MFA configured.
        let user = self
            .user_repo
            .find_by_id(&user_id, None)
            .await
            .map_err(repository_error)?
            .ok_or(AuthError::MfaNotEnabled)?;

        // Re-check the account status. Login gated it before minting the temp token, but that
        // token stays valid for its whole TTL: an account blocked in between would otherwise
        // clear the second factor and receive a full session. Revoking access must not depend
        // on how far through the login the holder already was. Gating here also keeps a blocked
        // account from spending the KDF — the recovery-code path costs one derivation per code.
        crate::status_gate::assert_not_blocked(&user.status, &self.blocked_statuses)?;

        let Some(encrypted_secret) = user.mfa_secret.clone().filter(|_| user.mfa_enabled) else {
            return Err(AuthError::MfaNotEnabled);
        };
        let Some((raw_secret, under_retired_key)) =
            self.decrypt_secret_with_rotation(&encrypted_secret)
        else {
            // A secret that will not decrypt is an opaque failure (no decrypt oracle).
            return Err(AuthError::TokenInvalid);
        };

        // Validate the submitted code. A six-digit code takes the fused TOTP path; anything
        // else is treated as a recovery code. On any invalid code the temp token is left alive
        // (retryable within its TTL) and only the failure counter advances.
        let recovery_index = if is_totp_code(code) {
            if !self
                .accept_totp(MfaContext::Dashboard, &user_id, &raw_secret, code, &jti)
                .await?
            {
                return self.reject_code("challenge", &user_id, &bf_id).await;
            }
            None
        } else {
            match self
                .accept_recovery_code(MfaContext::Dashboard, &user, code)
                .await?
            {
                Some(index) => {
                    // The recovery-code path carries no `tu:` marker, so the temp token is
                    // consumed standalone now that the code is confirmed valid — and the
                    // consume must WIN. Two concurrent challenges on one temp token both
                    // observe the marker and both delete it; without gating on which delete
                    // actually removed it, both issued a full session. The fused TOTP step
                    // gets this by construction; this is the recovery path's equivalent.
                    if !self.tokens.consume_mfa_temp_token(&jti).await? {
                        return Err(AuthError::MfaTempTokenInvalid);
                    }
                    Some(index)
                }
                None => return self.reject_code("challenge", &user_id, &bf_id).await,
            }
        };

        // Success: clear the failure counter and, for a recovery code, splice it out so it is
        // single-use.
        self.brute_force.reset(&bf_id).await?;
        // A secret that opened under a retired key is rewritten under the current one, so the
        // rotation drains on its own rather than requiring the retired key to stay configured
        // forever — a key that still opens every stored secret.
        let stored_secret = if under_retired_key {
            self.reencrypt_secret(&raw_secret)?
        } else {
            encrypted_secret.clone()
        };
        if let Some(index) = recovery_index {
            self.splice_recovery_code(&user, &stored_secret, index)
                .await?;
        } else if under_retired_key {
            // A TOTP challenge persists nothing on its own, so the rewrite needs its own write.
            self.persist_mfa(
                &user_id,
                MfaContext::Dashboard,
                true,
                Some(stored_secret),
                user.mfa_recovery_codes.clone(),
            )
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
        tracing::info!(user_id = %user_id, "mfa: challenge passed");
        Ok(LoginResultMfa::Dashboard(result))
    }

    /// The platform challenge flow: brute-force gate, fetch the admin via the platform
    /// repository, decrypt the secret, validate the TOTP/recovery code (the same fused-consume
    /// and constant-time-scan primitives the dashboard path uses), then issue a PLATFORM session
    /// (`mfa_verified = true`, no `tenantId`). Routing here is gated entirely on the temp token's
    /// `context: platform`, so a dashboard admin's challenge can never reach this arm.
    #[cfg(feature = "platform")]
    async fn challenge_platform(
        &self,
        verified: MfaTempVerified,
        code: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<LoginResultMfa, AuthError> {
        let MfaTempVerified { user_id, jti, .. } = verified;
        let bf_id = self.challenge_bf_id(MfaContext::Platform, &user_id);
        self.assert_not_locked("platform challenge", &user_id, &bf_id)
            .await?;

        // The platform repository is required for a platform challenge; without it the build has
        // no platform surface, so the challenge fails closed (never persist a platform secret on
        // a tenant row).
        let repo = self
            .platform_repo
            .as_ref()
            .ok_or(AuthError::MfaNotEnabled)?;
        let admin = repo
            .find_by_id(&user_id)
            .await
            .map_err(super::repository_error)?
            .ok_or(AuthError::MfaNotEnabled)?;

        // Re-check the account status. Login gated it before minting the temp token, but that
        // token stays valid for its whole TTL: an account blocked in between would otherwise
        // clear the second factor and receive a full session. Revoking access must not depend
        // on how far through the login the holder already was. Gating here also keeps a blocked
        // account from spending the KDF — the recovery-code path costs one derivation per code.
        crate::status_gate::assert_not_blocked(&admin.status, &self.blocked_statuses)?;

        let Some(encrypted_secret) = admin.mfa_secret.clone().filter(|_| admin.mfa_enabled) else {
            return Err(AuthError::MfaNotEnabled);
        };
        let Some(raw_secret) = self.decrypt_secret(&encrypted_secret) else {
            return Err(AuthError::TokenInvalid);
        };

        // Validate the submitted code: a six-digit code takes the fused TOTP path, anything else
        // is treated as a recovery code. On any invalid code the temp token is left alive
        // (retryable within its TTL) and only the failure counter advances.
        let recovery_codes = admin.mfa_recovery_codes.clone().unwrap_or_default();
        let recovery_index = if is_totp_code(code) {
            if !self
                .accept_totp(MfaContext::Platform, &user_id, &raw_secret, code, &jti)
                .await?
            {
                return self
                    .reject_code("platform challenge", &user_id, &bf_id)
                    .await;
            }
            None
        } else {
            match self
                .claim_matched_recovery_code(MfaContext::Platform, &user_id, code, &recovery_codes)
                .await?
            {
                Some(index) => {
                    // The recovery-code path carries no `tu:` marker, so the temp token is
                    // consumed standalone now that the code is confirmed valid — and the
                    // consume must WIN, exactly as on the dashboard plane. Two concurrent
                    // challenges on one temp token both observe the marker and both delete
                    // it; without gating on which delete actually removed it, both issue a
                    // full session from one single-use recovery code.
                    if !self.tokens.consume_mfa_temp_token(&jti).await? {
                        return Err(AuthError::MfaTempTokenInvalid);
                    }
                    Some(index)
                }
                None => {
                    return self
                        .reject_code("platform challenge", &user_id, &bf_id)
                        .await;
                }
            }
        };

        // Success: clear the failure counter and, for a recovery code, splice it out so it is
        // single-use, persisting the smaller set through the PLATFORM repository.
        self.brute_force.reset(&bf_id).await?;
        if let Some(index) = recovery_index {
            let mut codes = recovery_codes;
            if index < codes.len() {
                codes.remove(index);
            }
            self.persist_mfa(
                &admin.id,
                MfaContext::Platform,
                true,
                Some(encrypted_secret),
                Some(codes),
            )
            .await?;
        }

        // Mint a full PLATFORM session with `mfa_verified = true`. No dashboard-typed hook fires
        // (the platform domain manages its own notifications); the session carries no tenant.
        let safe = bymax_auth_types::SafeAuthPlatformUser::from(admin);
        let result = self
            .tokens
            .issue_platform_tokens(&safe, ip, user_agent, true)
            .await?;
        tracing::info!(user_id = %user_id, "mfa: platform challenge passed");
        Ok(LoginResultMfa::Platform(result))
    }

    /// Validate a TOTP `code` and, on success, fuse the anti-replay mark with the temp-token
    /// consume in one atomic step. Returns `true` when the code was valid and freshly
    /// consumed, `false` for an invalid code or a losing concurrent same-code submission.
    async fn accept_totp(
        &self,
        ctx: MfaContext,
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
        // The fused step: mark `tu:{replay}` `NX` and, iff newly marked, `DEL mfa:{jti_hash}`,
        // gating success on the deletion. A losing concurrent submission — whether the same code
        // (same marker already present) or a different still-valid code (its marker is fresh but
        // the temp token is already gone) — is rejected, so exactly one session is issued. The
        // anti-replay TTL is derived from the configured window so the marker outlives the code.
        let replay = self.replay_id(ctx, user_id, code);
        let jti_marker = to_hex(&bymax_auth_crypto::mac::sha256(jti.as_bytes()));
        self.mfa_store
            .challenge_consume(&replay, &jti_marker, self.anti_replay_ttl_seconds())
            .await
    }

    /// Scan the stored recovery-code digests for a constant-time match of `code`, returning
    /// the matched index or `None`.
    async fn accept_recovery_code(
        &self,
        ctx: MfaContext,
        user: &AuthUser,
        code: &str,
    ) -> Result<Option<usize>, AuthError> {
        let candidates = self.recovery_code_candidates(code);
        let stored = user.mfa_recovery_codes.clone().unwrap_or_default();
        let Some(index) = super::verify_recovery_code(&stored, &candidates) else {
            return Ok(None);
        };
        // A matched code still has to be CLAIMED. Splicing it out of the stored set is a
        // read-modify-write against the consumer's repository, so two challenges landing
        // together both read the array containing it, both match, and both write — one code
        // minting two sessions, the one property a recovery code has. The engine cannot make
        // that repository atomic; it can be atomic in the store it owns. The loser reads as an
        // invalid code, which is what a code already spent is.
        if !self.claim_recovery_code(ctx, &user.id, code).await? {
            return Ok(None);
        }
        Ok(Some(index))
    }

    /// The plane-shared core of [`Self::accept_recovery_code`]: match the code against a stored
    /// set, then claim it. Split out because the platform path already holds the stored set and
    /// has no `AuthUser` to hand over.
    async fn claim_matched_recovery_code(
        &self,
        ctx: MfaContext,
        user_id: &str,
        code: &str,
        stored: &[String],
    ) -> Result<Option<usize>, AuthError> {
        let Some(index) = super::verify_recovery_code(stored, &self.recovery_code_candidates(code))
        else {
            return Ok(None);
        };
        if !self.claim_recovery_code(ctx, user_id, code).await? {
            return Ok(None);
        }
        Ok(Some(index))
    }

    /// Claim a matched recovery code for exactly one challenge, `SET NX` over an HMAC of plane,
    /// user and code.
    ///
    /// Identical construction to the TOTP anti-replay marker, for identical reasons: the key
    /// discloses neither the user nor the code, and binding the plane stops a dashboard user
    /// and a platform admin who share an id from burning each other's codes.
    ///
    /// The marker is deliberately short-lived. It serializes a race measured in milliseconds;
    /// the durable record of consumption is the repository write. Outliving that write would
    /// turn a failed write into a code the account can still see in its list but can never use.
    async fn claim_recovery_code(
        &self,
        ctx: MfaContext,
        user_id: &str,
        code: &str,
    ) -> Result<bool, AuthError> {
        self.mfa_store
            .claim_recovery_code(
                &self.replay_id(ctx, user_id, code),
                super::RECOVERY_CODE_CLAIM_TTL_SECONDS,
            )
            .await
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
    async fn reject_code(
        &self,
        flow: &str,
        user_id: &str,
        bf_id: &str,
    ) -> Result<LoginResultMfa, AuthError> {
        tracing::warn!(%flow, %user_id, "mfa: invalid code");
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
            mfa_enabled: safe.mfa_enabled,
            // Server-internal family id is not part of the hook/eviction projection.
            family_id: String::new(),
            family_created_at: None,
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

#[cfg(test)]
mod tests {
    use super::is_totp_code;

    #[test]
    fn a_totp_code_is_six_digits_and_nothing_else() {
        // This predicate routes a submitted code to the TOTP verifier or to the recovery-code
        // scan, and both halves of it matter: six characters that are not digits, and digits
        // that are not six characters, are both recovery-code shaped. Asserted directly
        // because the two paths answer the same `MfaInvalidCode` for a wrong code, so a
        // misrouted code is invisible from the outside.
        assert!(is_totp_code("123456"));
        assert!(is_totp_code("000000"));
        // Right length, wrong alphabet.
        assert!(!is_totp_code("abcdef"));
        assert!(!is_totp_code("12345a"));
        // Right alphabet, wrong length.
        assert!(!is_totp_code("12345"));
        assert!(!is_totp_code("1234567"));
        assert!(!is_totp_code(""));
        // A recovery code is neither.
        assert!(!is_totp_code("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z2345"));
    }
}
