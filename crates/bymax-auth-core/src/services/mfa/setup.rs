//! [`MfaService::setup`] and [`MfaService::verify_and_enable`] (§7.5.1–§7.5.2): the
//! idempotent pending-setup record under an atomic `SET NX`, and the atomic `GETDEL`
//! completion gate that admits exactly one enable.

use bymax_auth_types::{AuthError, MfaContext, SafeAuthUser};

use crate::services::auth::spawn_guarded;
use crate::services::internal_error;
use crate::services::mfa::{MfaService, MfaSetupData, MfaSetupResult, session_kind};

impl MfaService {
    /// Begin MFA enrollment for a user (§7.5.1). Idempotent: a user who already has MFA
    /// enabled gets [`AuthError::MfaAlreadyEnabled`], and a repeated call inside the setup
    /// window returns the **same** secret + codes (the fast-path, which also blocks a
    /// CPU-amplification vector via repeated `/mfa/setup`). The plaintext secret and recovery
    /// codes are returned **only** here.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] for a platform context with no platform repository
    /// or a missing account, [`AuthError::MfaAlreadyEnabled`] when MFA is already on, or an
    /// internal/store [`AuthError`].
    pub async fn setup(&self, user_id: &str, ctx: MfaContext) -> Result<MfaSetupResult, AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx).await?;
        if view.mfa_enabled {
            return Err(AuthError::MfaAlreadyEnabled);
        }
        let key = self.setup_key(user_id);

        // Fast-path idempotency: an existing pending record is re-returned verbatim, so a user
        // who refreshes the setup page sees the same secret/QR/codes they may already be
        // scanning, and the AES/CSPRNG work is not re-run on every call.
        if let Some(existing) = self.mfa_store.get_setup(&key).await? {
            return self.setup_result_from_record(&view.email, &existing);
        }

        // First time: generate the material and claim the record atomically. Serializing the
        // record cannot fail; the unreachable error is mapped eagerly (no untestable closure).
        let (raw_secret, plain_codes, data) = self.generate_setup_material()?;
        let json = serde_json::to_string(&data)
            .ok()
            .ok_or(internal_error("mfa setup encode"))?;
        if self
            .mfa_store
            .put_setup_nx(&key, &json, super::MFA_SETUP_TTL_SECONDS)
            .await?
        {
            return Ok(self.build_setup_result(&view.email, &raw_secret, plain_codes));
        }

        // Lost the `SET NX` race: a concurrent `setup` wrote first. Return the winner's record
        // so both callers agree on the secret. A record that vanished in the microsecond gap
        // (expired between the failed NX and this read) is an internal inconsistency.
        let existing = self
            .mfa_store
            .get_setup(&key)
            .await?
            .ok_or_else(|| internal_error("mfa setup record vanished after NX race"))?;
        self.setup_result_from_record(&view.email, &existing)
    }

    /// Complete enrollment by verifying the first TOTP code and enabling MFA (§7.5.2).
    /// Anti-replay applies even here, so an intercepted setup code cannot later be replayed on
    /// the challenge path. The completion is gated by an atomic `GETDEL` of the pending record,
    /// so two concurrent enables cannot both succeed (no duplicate `update_mfa` or duplicate
    /// "MFA enabled" notification). On success every existing session is revoked, forcing
    /// re-auth through the new second factor.
    ///
    /// The success value is `()` — it carries neither the plaintext secret nor the QR URI, so
    /// no read path on this service re-exposes the secret after enable (Security Invariant 5).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaAlreadyEnabled`], [`AuthError::MfaSetupRequired`] (no/corrupt
    /// pending record or a lost completion race), [`AuthError::MfaInvalidCode`] (wrong or
    /// replayed code), [`AuthError::MfaNotEnabled`] (platform misconfig/missing account), or
    /// an internal/store [`AuthError`].
    pub async fn verify_and_enable(
        &self,
        user_id: &str,
        code: &str,
        ip: &str,
        user_agent: &str,
        ctx: MfaContext,
    ) -> Result<(), AuthError> {
        let view = self.fetch_user_mfa(user_id, ctx).await?;
        if view.mfa_enabled {
            return Err(AuthError::MfaAlreadyEnabled);
        }
        let key = self.setup_key(user_id);

        // Load and decrypt the pending record. A missing record, a record that will not parse,
        // and a secret that will not decrypt all collapse to the same opaque `MfaSetupRequired`
        // — no parse/decrypt oracle distinguishes them.
        let record_json = self
            .mfa_store
            .get_setup(&key)
            .await?
            .ok_or(AuthError::MfaSetupRequired)?;
        let data: MfaSetupData =
            serde_json::from_str(&record_json).map_err(|_| AuthError::MfaSetupRequired)?;
        let raw_secret = self
            .decrypt(&data.encrypted_secret)
            .ok_or(AuthError::MfaSetupRequired)?;

        // Verify the code with anti-replay before the completion gate, so an invalid code never
        // consumes the pending record.
        if !self
            .verify_totp_with_anti_replay(user_id, &raw_secret, code)
            .await?
        {
            return Err(AuthError::MfaInvalidCode);
        }

        // Atomic completion gate: only the request that wins the `GETDEL` proceeds to enable.
        if self.mfa_store.take_setup(&key).await?.is_none() {
            return Err(AuthError::MfaSetupRequired);
        }

        // Persist the AES-encrypted secret and the keyed recovery-code digests from the record
        // (never re-encrypted), enable MFA, and force re-auth through the new factor.
        self.persist_mfa(
            user_id,
            ctx,
            true,
            Some(data.encrypted_secret),
            Some(data.hashed_codes),
        )
        .await?;
        self.session_store
            .revoke_all(session_kind(ctx), user_id)
            .await?;

        self.notify_enabled(&view, user_id, ip, user_agent);
        Ok(())
    }

    /// Fire the fire-and-forget "MFA enabled" notifications: the email to the account (both
    /// contexts) and the `after_mfa_enabled` hook (dashboard only — the platform identity
    /// domain wires its own notifications). Both are detached so a slow provider never affects
    /// the enable response.
    fn notify_enabled(&self, view: &super::MfaUserView, user_id: &str, ip: &str, user_agent: &str) {
        spawn_guarded(run_send_mfa_enabled(self.email.clone(), view.email.clone()));
        if let Some(safe) = view.dashboard_user.clone() {
            let ctx = self.hook_context(user_id, &view.email, ip, user_agent);
            spawn_guarded(run_after_mfa_enabled(self.hooks.clone(), safe, ctx));
        }
    }
}

/// Send the "MFA enabled" email (a named future so the detached spawn owns its data).
pub(super) async fn run_send_mfa_enabled(
    email: std::sync::Arc<dyn crate::traits::EmailProvider>,
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email.send_mfa_enabled(&recipient, None).await
}

/// Invoke the `after_mfa_enabled` hook (a named future so the detached spawn owns its data).
pub(super) async fn run_after_mfa_enabled(
    hooks: std::sync::Arc<dyn crate::traits::AuthHooks>,
    user: SafeAuthUser,
    ctx: crate::traits::HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks.after_mfa_enabled(&user, &ctx).await
}
