//! [`MfaService::disable`] and [`MfaService::regenerate_recovery_codes`] (§7.5.4–§7.5.5): the
//! two authenticated, **TOTP-only** management operations behind a strong re-auth gate on the
//! shared `disable:` brute-force namespace. They diverge intentionally on session handling —
//! `disable` revokes every session (the factor changed); `regenerate` does not (the factor is
//! unchanged, so forcing re-login on a routine hygiene action would be punitive).

use bymax_auth_types::{AuthError, MfaContext, SafeAuthUser};

use crate::services::auth::spawn_guarded;
use crate::services::mfa::{MfaService, MfaUserView, generate_recovery_code, session_kind};

impl MfaService {
    /// Disable MFA after a successful TOTP re-auth (§7.5.4). **Only** a TOTP code is accepted —
    /// a recovery code can never disable MFA by design. On success MFA is cleared and every
    /// session is revoked, so subsequent rotations emit `mfa_verified:false` and stale
    /// `mfa_verified:true` claims are cleared.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`], [`AuthError::AccountLocked`],
    /// [`AuthError::TokenInvalid`] (the secret is unexpectedly absent or undecryptable),
    /// [`AuthError::MfaInvalidCode`] (wrong/replayed code), or an internal/store [`AuthError`].
    pub async fn disable(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
        tenant_id: Option<&str>,
    ) -> Result<(), AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx, tenant_id).await?;
        self.reauth_gate(ctx, user_id, code, &view).await?;
        // The TOTP code verified; clear MFA, revoke sessions, and notify. Serialized against
        // every other MFA transition so a challenge that read the record a moment earlier
        // cannot splice `mfa_enabled: true` and the old secret back on top of this.
        self.transition_mfa_record(user_id, ctx, tenant_id, |_| Some((false, None, None)))
            .await?;
        // Revoke every refresh session AND advance the token epoch: an auth-state change
        // revokes everything issued under the previous state, in both directions — the same
        // rule the password-reset flow applies (see the enable path for the full rationale).
        self.session_store
            .revoke_all(session_kind(ctx), user_id)
            .await?;
        self.session_store
            .bump_epoch(session_kind(ctx), user_id)
            .await?;
        self.notify_disabled(&view, user_id, ip, user_agent);
        Ok(())
    }

    /// Remove a user's second factor WITHOUT their TOTP code — the administrative path, for a
    /// support desk facing a user who has lost both the authenticator and the recovery codes.
    ///
    /// Every self-service exit from MFA needs the factor itself: [`MfaService::disable`] wants a
    /// valid TOTP code and the recovery codes want the codes, so a user who has lost both is
    /// locked out permanently by the control that exists to protect them. ASVS v5 §6.1.1 asks for
    /// an administrative path out for exactly that case.
    ///
    /// **Authorising the caller is the host's job.** No route is exposed for this, the same
    /// decision and for the same reason as `unlock_account`: every route this library ships is
    /// scoped to the caller's own account, and who may reset whom is a question only the host
    /// application can answer.
    ///
    /// Idempotent: resetting an account with no second factor is a no-op, so a support desk
    /// retrying is not told a job already done has failed.
    ///
    /// Three things happen beyond clearing the record, and none of them are optional:
    ///
    /// - **Sessions are revoked and the token epoch is bumped**, so access tokens carrying
    ///   `mfa_verified: true` die with the factor rather than outliving it.
    /// - **The user is notified**, through the same channel [`MfaService::disable`] uses. An
    ///   administrative reset the account holder cannot see is an account-takeover path: an
    ///   attacker who reaches the support desk removes the second factor with nothing reaching
    ///   the owner. The notification is what makes it an event they can detect and dispute.
    /// - **It is logged** under its own target, so an administrative removal is distinguishable
    ///   from a user-initiated one in this library's own trace output.
    ///
    /// The `after_mfa_disabled` hook fires too, so host-side alerting keeps working. It gets no
    /// separate hook: the host is the one calling this, so it already knows — the hooks exist to
    /// report the paths the host does not initiate.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] if no user with that id exists in the given plane
    /// (the same answer the rest of this service gives for an unresolvable subject), or an
    /// internal/store [`AuthError`].
    pub async fn reset_mfa(
        &self,
        user_id: &str,
        ctx: MfaContext,
        tenant_id: Option<&str>,
    ) -> Result<(), AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx, tenant_id).await?;
        if !view.mfa_enabled {
            tracing::info!(
                target: "bymax_auth::mfa",
                user_id, "reset_mfa: no second factor to remove"
            );
            return Ok(());
        }
        self.transition_mfa_record(user_id, ctx, tenant_id, |_| Some((false, None, None)))
            .await?;
        self.session_store
            .revoke_all(session_kind(ctx), user_id)
            .await?;
        self.session_store
            .bump_epoch(session_kind(ctx), user_id)
            .await?;
        tracing::warn!(
            target: "bymax_auth::mfa",
            user_id, "reset_mfa: MFA removed administratively"
        );
        // No request context: this call does not come from one. Empty rather than invented, so a
        // host logging the hook cannot mistake a placeholder for an address someone connected
        // from.
        self.notify_disabled(&view, user_id, "", "");
        Ok(())
    }

    /// Regenerate the recovery-code set after a successful TOTP re-auth (§7.5.5). Same TOTP-only
    /// gate and `disable:` counter as [`MfaService::disable`], **but sessions are intentionally
    /// not invalidated** (the TOTP factor is unchanged). The prior set is replaced wholesale in
    /// a single write — an old recovery code can never coexist with the new set — and the new
    /// plaintext codes are returned **exactly once** (only the digests are persisted).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`], [`AuthError::AccountLocked`],
    /// [`AuthError::TokenInvalid`], [`AuthError::MfaInvalidCode`], or an internal/store
    /// [`AuthError`].
    pub async fn regenerate_recovery_codes(
        &self,
        user_id: &str,
        totp_code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
        tenant_id: Option<&str>,
    ) -> Result<Vec<String>, AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx, tenant_id).await?;
        self.reauth_gate(ctx, user_id, totp_code, &view).await?;
        // Generate a fresh set with the same entropy/format as setup; persist only the digests.
        let plain_codes: Vec<String> = (0..self.recovery_code_count)
            .map(|_| generate_recovery_code())
            .collect();
        let hashed: Vec<String> = plain_codes
            .iter()
            .map(|code| self.hash_recovery_code(code))
            .collect();
        // Preserve the existing encrypted secret and atomically replace the recovery codes.
        //
        // Serialized: the promise that the prior set is replaced wholesale, so an old code can
        // never coexist with the new one, held only until a challenge that had read the old
        // list spliced it back on top of this write. The secret is taken from the record as it
        // stands INSIDE the lock rather than the copy read above, for the same reason.
        let replaced = self
            .transition_mfa_record(user_id, ctx, tenant_id, |current| {
                // MFA was disabled while the new codes were being derived. Writing them would
                // re-enable it with the pre-disable secret, so the transition is abandoned.
                if !current.mfa_enabled {
                    return None;
                }
                current
                    .mfa_secret
                    .clone()
                    .map(|secret| (true, Some(secret), Some(hashed)))
            })
            .await?;
        if !replaced {
            return Err(AuthError::MfaNotEnabled);
        }
        // Sessions are deliberately NOT revoked here (factor unchanged).
        self.notify_regenerated(&view, user_id, ip, user_agent);
        Ok(plain_codes)
    }

    /// The shared TOTP-only re-auth gate for the management ops: fetch fails fast if MFA is
    /// off, the `disable:` counter must not be locked, the secret must be present and
    /// decryptable, and the TOTP code must verify with anti-replay. Records a failure (and
    /// returns [`AuthError::MfaInvalidCode`]) on a wrong code, and resets the counter on
    /// success.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`], [`AuthError::AccountLocked`],
    /// [`AuthError::TokenInvalid`], [`AuthError::MfaInvalidCode`], or a store [`AuthError`].
    async fn reauth_gate(
        &self,
        ctx: MfaContext,
        user_id: &str,
        code: &str,
        view: &MfaUserView,
    ) -> Result<(), AuthError> {
        if !view.mfa_enabled {
            return Err(AuthError::MfaNotEnabled);
        }
        let bf_id = self.disable_bf_id(ctx, user_id);
        self.assert_not_locked("disable", user_id, &bf_id).await?;
        // An enabled account with no stored secret is an inconsistency, not a user error.
        let encrypted = view.mfa_secret.clone().ok_or(AuthError::TokenInvalid)?;
        let raw_secret = self
            .decrypt_secret(&encrypted)
            .ok_or(AuthError::TokenInvalid)?;
        if !self
            .verify_totp_with_anti_replay(ctx, user_id, &raw_secret, code)
            .await?
        {
            tracing::warn!(%user_id, "mfa disable: invalid code");
            self.brute_force.record_failure(&bf_id).await?;
            return Err(AuthError::MfaInvalidCode);
        }
        self.brute_force.reset(&bf_id).await?;
        tracing::info!(%user_id, "mfa: disabled");
        Ok(())
    }

    /// Fire the fire-and-forget "MFA disabled" notifications: the email (both contexts) and the
    /// `after_mfa_disabled` hook (dashboard only).
    fn notify_disabled(&self, view: &MfaUserView, user_id: &str, ip: &str, user_agent: &str) {
        spawn_guarded(run_send_mfa_disabled(
            self.email.clone(),
            view.email_tenant(),
            view.email.clone(),
        ));
        if let Some(safe) = view.dashboard_user.clone() {
            let ctx = self.hook_context(user_id, &view.email, ip, user_agent);
            spawn_guarded(run_after_mfa_disabled(self.hooks.clone(), safe, ctx));
        }
    }

    /// Fire the fire-and-forget `after_mfa_recovery_codes_regenerated` hook (dashboard only;
    /// the plaintext codes are never passed to the hook — they go only to the caller).
    fn notify_regenerated(&self, view: &MfaUserView, user_id: &str, ip: &str, user_agent: &str) {
        if let Some(safe) = view.dashboard_user.clone() {
            let ctx = self.hook_context(user_id, &view.email, ip, user_agent);
            spawn_guarded(run_after_mfa_regenerated(self.hooks.clone(), safe, ctx));
        }
    }
}

/// Send the "MFA disabled" email (a named future so the detached spawn owns its data).
pub(super) async fn run_send_mfa_disabled(
    email: std::sync::Arc<dyn crate::traits::EmailProvider>,
    tenant_id: String,
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email.send_mfa_disabled(&tenant_id, &recipient, None).await
}

/// Invoke the `after_mfa_disabled` hook (a named future so the detached spawn owns its data).
pub(super) async fn run_after_mfa_disabled(
    hooks: std::sync::Arc<dyn crate::traits::AuthHooks>,
    user: SafeAuthUser,
    ctx: crate::traits::HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks.after_mfa_disabled(&user, &ctx).await
}

/// Invoke the `after_mfa_recovery_codes_regenerated` hook (a named future for the spawn).
pub(super) async fn run_after_mfa_regenerated(
    hooks: std::sync::Arc<dyn crate::traits::AuthHooks>,
    user: SafeAuthUser,
    ctx: crate::traits::HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks
        .after_mfa_recovery_codes_regenerated(&user, &ctx)
        .await
}
