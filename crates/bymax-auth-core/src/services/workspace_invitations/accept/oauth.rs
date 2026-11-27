//! Accepting a workspace invitation through an OAuth sign-in: what is checked before the host
//! decides about the account, and what is checked again before the membership is written (layer:
//! service).
//!
//! The flow carries the record id of the invitation, which is the SHA-256 of its token, so the
//! token itself is held nowhere between the two requests. Both steps read the record afresh.

use bymax_auth_types::{AuthError, SafeAuthUser};

use super::{Loaded, load_record};
use crate::config::RegistrationMode;
use crate::engine::AuthEngine;
use crate::normalize::normalize_email;
use crate::services::auth::detached::run_after_invitation_accepted;
use crate::services::auth::spawn_guarded;
use crate::services::workspace::WorkspaceRuntime;
use crate::traits::{HookContext, OAuthLoginResult, OAuthProfile};
use crate::workspace::keys::invitation_record_id;

/// What a callback knows about the invitation its flow was started with.
pub(crate) struct FlowInvitation {
    /// The invitation's record id, when the flow carries one.
    id: Option<String>,
    /// Whether the host's hook asked for a new account.
    creates: bool,
}

impl FlowInvitation {
    /// The flow's invitation id beside what the hook decided about the account.
    pub(crate) fn new(id: Option<String>, decision: &OAuthLoginResult) -> Self {
        let creates = matches!(decision, OAuthLoginResult::Create);
        Self { id, creates }
    }
}

impl AuthEngine {
    /// The record id a flow started with the invitation `token` carries.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidInvitationToken`] when the workspace layer is off, so nothing
    /// could honour the token.
    pub(crate) fn oauth_invitation_id(&self, token: &str) -> Result<String, AuthError> {
        self.oauth_workspaces()?;
        Ok(invitation_record_id(token))
    }

    /// Judges the flow's invitation, if it has one, against what the provider asserts, before
    /// the host's hook decides anything about an account.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidInvitationToken`] for an invitation that cannot be honoured
    /// in `tenant_id`, [`AuthError::InvitationEmailMismatch`] when the provider's address is not
    /// the invited one and [`AuthError::EmailNotVerified`] when it is but the provider does not
    /// report it verified. Nothing is written or spent.
    pub(crate) async fn vet_oauth_invitation(
        &self,
        id: Option<&str>,
        tenant_id: &str,
        profile: &OAuthProfile,
    ) -> Result<(), AuthError> {
        let Some(id) = id else {
            return Ok(());
        };
        let runtime = self.oauth_workspaces()?;
        let loaded = load_record(runtime, id).await?;
        let verified = profile.email_verified;
        assert_tenant_and_address(&loaded, tenant_id, &profile.email, verified)?;
        self.assert_still_grantable(runtime, &loaded).await
    }

    /// Refuses a new account under [`RegistrationMode::InvitationOnly`] unless the flow carries
    /// an invitation, which [`vet_oauth_invitation`](Self::vet_oauth_invitation) has judged.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RegistrationClosed`].
    pub(crate) fn assert_oauth_may_create(&self, flow: &FlowInvitation) -> Result<(), AuthError> {
        let closed = self.config().config().registration == RegistrationMode::InvitationOnly;
        if closed && flow.creates && flow.id.is_none() {
            return Err(AuthError::RegistrationClosed);
        }
        Ok(())
    }

    /// Writes the membership the flow's invitation, if it has one, names for the account being
    /// signed in, and spends it. The record, the inviter's standing and the workspace are judged
    /// again, since the host's hook and the account write ran since the first judgement. The
    /// after-acceptance hook runs when the flow created the account.
    ///
    /// # Errors
    ///
    /// As [`vet_oauth_invitation`](Self::vet_oauth_invitation), judged on the account, and as
    /// [`accept_workspace_invitation`](Self::accept_workspace_invitation) for the write. No
    /// judgement spends the token.
    pub(crate) async fn complete_oauth_invitation(
        &self,
        flow: &FlowInvitation,
        user: &SafeAuthUser,
        hook_ctx: &HookContext,
    ) -> Result<(), AuthError> {
        let Some(id) = flow.id.as_deref() else {
            return Ok(());
        };
        let runtime = self.oauth_workspaces()?;
        let loaded = load_record(runtime, id).await?;
        assert_tenant_and_address(&loaded, &user.tenant_id, &user.email, user.email_verified)?;
        self.assert_still_grantable(runtime, &loaded).await?;
        let mut hook_ctx = hook_ctx.clone();
        hook_ctx.user_id = Some(user.id.clone());
        self.finish_acceptance(runtime, &loaded, user, hook_ctx.clone())
            .await?;
        if flow.creates {
            spawn_guarded(run_after_invitation_accepted(
                self.hooks().clone(),
                user.clone(),
                hook_ctx,
            ));
        }
        Ok(())
    }

    /// The workspace layer, whose absence makes every invitation one that cannot be honoured.
    fn oauth_workspaces(&self) -> Result<&WorkspaceRuntime, AuthError> {
        self.workspaces().ok_or(AuthError::InvalidInvitationToken)
    }
}

/// The invitation's tenant, then its address, then that address being verified.
fn assert_tenant_and_address(
    loaded: &Loaded,
    tenant_id: &str,
    email: &str,
    email_verified: bool,
) -> Result<(), AuthError> {
    if tenant_id != loaded.base.tenant_id {
        return Err(AuthError::InvalidInvitationToken);
    }
    if normalize_email(email) != loaded.base.email {
        return Err(AuthError::InvitationEmailMismatch);
    }
    if !email_verified {
        return Err(AuthError::EmailNotVerified);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
