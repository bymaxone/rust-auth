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
    ) -> Result<(), AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx).await?;
        self.reauth_gate(user_id, code, &view).await?;
        // The TOTP code verified; clear MFA, revoke sessions, and notify.
        self.persist_mfa(user_id, ctx, false, None, None).await?;
        // Revoke the user's OTHER refresh sessions; the current session continues, so the token
        // epoch is not bumped here (see the enable path for the rationale).
        self.session_store
            .revoke_all(session_kind(ctx), user_id)
            .await?;
        self.notify_disabled(&view, user_id, ip, user_agent);
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
    ) -> Result<Vec<String>, AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx).await?;
        self.reauth_gate(user_id, totp_code, &view).await?;
        // Generate a fresh set with the same entropy/format as setup; persist only the digests.
        let plain_codes: Vec<String> = (0..self.recovery_code_count)
            .map(|_| generate_recovery_code())
            .collect();
        let hashed: Vec<String> = plain_codes
            .iter()
            .map(|code| self.hash_recovery_code(code))
            .collect();
        // Preserve the existing encrypted secret and atomically replace the recovery codes.
        let encrypted_secret = view.mfa_secret.clone().ok_or(AuthError::TokenInvalid)?;
        self.persist_mfa(user_id, ctx, true, Some(encrypted_secret), Some(hashed))
            .await?;
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
        user_id: &str,
        code: &str,
        view: &MfaUserView,
    ) -> Result<(), AuthError> {
        if !view.mfa_enabled {
            return Err(AuthError::MfaNotEnabled);
        }
        let bf_id = self.disable_bf_id(user_id);
        self.assert_not_locked(&bf_id).await?;
        // An enabled account with no stored secret is an inconsistency, not a user error.
        let encrypted = view.mfa_secret.clone().ok_or(AuthError::TokenInvalid)?;
        let raw_secret = self.decrypt(&encrypted).ok_or(AuthError::TokenInvalid)?;
        if !self
            .verify_totp_with_anti_replay(user_id, &raw_secret, code)
            .await?
        {
            self.brute_force.record_failure(&bf_id).await?;
            return Err(AuthError::MfaInvalidCode);
        }
        self.brute_force.reset(&bf_id).await?;
        Ok(())
    }

    /// Fire the fire-and-forget "MFA disabled" notifications: the email (both contexts) and the
    /// `after_mfa_disabled` hook (dashboard only).
    fn notify_disabled(&self, view: &MfaUserView, user_id: &str, ip: &str, user_agent: &str) {
        spawn_guarded(run_send_mfa_disabled(
            self.email.clone(),
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
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email.send_mfa_disabled(&recipient, None).await
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
