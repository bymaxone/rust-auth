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
    pub async fn setup(
        &self,
        user_id: &str,
        ctx: MfaContext,
        tenant_id: Option<&str>,
        password: Option<&str>,
    ) -> Result<MfaSetupResult, AuthError> {
        super::require_plane_tenant(ctx, tenant_id)?;
        let view = self.fetch_user_mfa(user_id, ctx, tenant_id).await?;
        if view.mfa_enabled {
            return Err(AuthError::MfaAlreadyEnabled);
        }

        // Re-authenticate before minting a factor. Enabling MFA changes how the account
        // authenticates, and an access token alone is not proof of who is asking: a token
        // lifted by XSS or from a shared machine could otherwise enrol an authenticator the
        // attacker holds — and the enable then revokes every session and bumps the epoch,
        // locking the real owner out of an account they still know the password to, with the
        // recovery codes displayed only to the attacker. ASVS requires re-authentication
        // before an authentication factor changes; `disable` already demands a TOTP code.
        // Gating `setup` rather than `verify_and_enable` means the attacker cannot even obtain
        // a secret they control, and it costs the user one prompt at the natural moment.
        self.assert_reauthenticated(
            ctx,
            tenant_id,
            user_id,
            view.password_hash.as_deref(),
            password,
        )
        .await?;
        let key = self.setup_key(ctx, tenant_id, user_id);

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
            tracing::info!(%user_id, context = ?ctx, "mfa setup: initiated");
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
        tenant_id: Option<&str>,
    ) -> Result<(), AuthError> {
        super::require_plane_tenant(ctx, tenant_id)?;
        let view = self.fetch_user_mfa(user_id, ctx, tenant_id).await?;
        if view.mfa_enabled {
            return Err(AuthError::MfaAlreadyEnabled);
        }
        let key = self.setup_key(ctx, tenant_id, user_id);

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
            .decrypt_secret(&data.encrypted_secret)
            .ok_or(AuthError::MfaSetupRequired)?;

        // Verify the code with anti-replay before the completion gate, so an invalid code never
        // consumes the pending record.
        if !self
            .verify_totp_with_anti_replay(ctx, tenant_id, user_id, &raw_secret, code)
            .await?
        {
            tracing::warn!(%user_id, "mfa setup: invalid TOTP code");
            return Err(AuthError::MfaInvalidCode);
        }

        // Atomic completion gate: only the request that wins the `GETDEL` proceeds to enable.
        if self.mfa_store.take_setup(&key).await?.is_none() {
            tracing::warn!(%user_id, "mfa setup: pending record consumed by a concurrent request");
            return Err(AuthError::MfaSetupRequired);
        }

        // Persist the AES-encrypted secret and the keyed recovery-code digests from the record
        // (never re-encrypted), enable MFA, and force re-auth through the new factor.
        //
        // Serialized against every other MFA transition. The single-shot `take_setup` above
        // already makes the enable one-per-record among concurrent verify calls; this puts it
        // in the same queue as `disable` and the challenge splice, which write the same three
        // fields over the same record.
        self.transition_mfa_record(user_id, ctx, tenant_id, |_| {
            Some((true, Some(data.encrypted_secret), Some(data.hashed_codes)))
        })
        .await?;
        // Revoke every refresh session AND advance the token epoch. Every access token issued
        // before this moment is stamped `mfa_enabled: false`, and the MFA gate refuses only
        // `mfa_enabled && !mfa_verified` — so without the bump, a stolen access token keeps
        // clearing every MFA-gated route for its remaining lifetime, at the exact moment the
        // user enabled a second factor because they suspected that theft. (`revoke_all` kills
        // the current session too, so the "current session continues" this comment once
        // promised was never true — only its access token survived, the one artifact the
        // epoch is able to reach.)
        self.session_store
            .revoke_all(session_kind(ctx), user_id)
            .await?;
        self.session_store
            .bump_epoch(session_kind(ctx), user_id)
            .await?;

        self.notify_enabled(&view, user_id, ip, user_agent);
        tracing::info!(%user_id, context = ?ctx, "mfa setup: enabled");
        Ok(())
    }

    /// Fire the fire-and-forget "MFA enabled" notifications: the email to the account (both
    /// contexts) and the `after_mfa_enabled` hook (dashboard only — the platform identity
    /// domain wires its own notifications). Both are detached so a slow provider never affects
    /// the enable response.
    fn notify_enabled(&self, view: &super::MfaUserView, user_id: &str, ip: &str, user_agent: &str) {
        spawn_guarded(run_send_mfa_enabled(
            self.email.clone(),
            view.email_tenant(),
            view.email.clone(),
        ));
        if let Some(safe) = view.dashboard_user.clone() {
            let ctx = self.hook_context(user_id, &view.email, ip, user_agent);
            spawn_guarded(run_after_mfa_enabled(self.hooks.clone(), safe, ctx));
        }
    }
}

/// Send the "MFA enabled" email (a named future so the detached spawn owns its data).
pub(super) async fn run_send_mfa_enabled(
    email: std::sync::Arc<dyn crate::traits::EmailProvider>,
    tenant_id: String,
    recipient: String,
) -> Result<(), crate::traits::EmailError> {
    email.send_mfa_enabled(&tenant_id, &recipient, None).await
}

/// Invoke the `after_mfa_enabled` hook (a named future so the detached spawn owns its data).
pub(super) async fn run_after_mfa_enabled(
    hooks: std::sync::Arc<dyn crate::traits::AuthHooks>,
    user: SafeAuthUser,
    ctx: crate::traits::HookContext,
) -> Result<(), crate::traits::HookError> {
    hooks.after_mfa_enabled(&user, &ctx).await
}
