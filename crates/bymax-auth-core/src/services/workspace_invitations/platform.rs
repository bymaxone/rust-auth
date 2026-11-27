//! Bootstrap invitations: the platform invites an address to own a workspace that does not exist
//! yet, and withdraws that invitation (layer: service).
//!
//! No route is mounted for either: the platform plane's authorization is the host's. The workspace
//! and its owner's membership are written when the invitation is accepted, under the id issuing
//! answers.

use std::num::NonZeroU64;

use bymax_auth_types::AuthError;
use time::{Duration, OffsetDateTime};

use super::{INVITE_TOKEN_BYTES, too_many_requests, withdraw};
use crate::engine::AuthEngine;
use crate::normalize::normalize_email;
use crate::services::new_uuid_v4;
use crate::services::workspace::WorkspaceRuntime;
use crate::services::workspace_writes::{audit_event, now_iso, workspace_name};
use crate::traits::{
    HookContext, Publication, PublishOutcome, WorkspaceInviteData, WorkspaceInviteKind,
};
use crate::workspace::audit::{AuditKind, iso_instant};
use crate::workspace::domain::WorkspaceRef;
use crate::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use crate::workspace::keys::invitation_record_id;

#[cfg(test)]
mod tests;

/// A workspace the platform invites an address to own.
#[derive(Debug, Clone)]
pub struct PlatformWorkspaceInvitation {
    /// The tenant the workspace will live in.
    pub tenant_id: String,
    /// The invited address.
    pub email: String,
    /// The name the workspace will be created with.
    pub workspace_name: String,
    /// The inviter's display name in the message. It is not stored.
    pub inviter_name: String,
}

impl AuthEngine {
    /// Invites an address to own a workspace that does not exist yet, on behalf of the platform,
    /// and answers the id the workspace will be created with. Each call is its own invitation to
    /// its own workspace: nothing is replaced, and nothing is created until it is accepted.
    ///
    /// # Errors
    ///
    /// [`AuthError::Validation`] naming `name` for an unusable workspace name, and
    /// [`AuthError::Internal`] for a repository, store or delivery failure or a disabled layer.
    /// A delivery failure leaves the published invitation to expire.
    pub async fn invite_workspace_as_platform(
        &self,
        input: PlatformWorkspaceInvitation,
        ctx: &HookContext,
    ) -> Result<String, AuthError> {
        let runtime = self.workspace_runtime()?;
        let email = normalize_email(&input.email);
        let name = workspace_name(&input.workspace_name)?;
        let workspace_id = new_uuid_v4();
        let workspace = WorkspaceRef {
            tenant_id: &input.tenant_id,
            workspace_id: &workspace_id,
        };
        let token = bymax_auth_crypto::token::generate_secure_token(INVITE_TOKEN_BYTES);
        let now = OffsetDateTime::now_utc();
        let at = iso_instant(now);
        let record = bootstrap_record(runtime, workspace, &email, &name, &at);
        publish_new(runtime, workspace, &email, &token, &record).await?;
        let account_exists = self.find_account(&input.tenant_id, &email).await?.is_some();
        let ttl = Duration::seconds(
            i64::try_from(runtime.resolved.invitation_ttl_seconds).unwrap_or(i64::MAX),
        );
        let role = record.base().role.clone();
        let data = WorkspaceInviteData::new(
            input.inviter_name,
            name,
            role.clone(),
            token,
            now + ttl,
            account_exists,
            WorkspaceInviteKind::Bootstrap,
        );
        self.deliver(&input.tenant_id, &email, &data).await?;
        let kind = AuditKind::MemberInvited { email, role };
        let event = audit_event(workspace, None, &at, kind);
        self.notify_workspace_event(event, ctx.clone());
        Ok(workspace_id)
    }

    /// Withdraws the bootstrap invitation of `email` to `workspace`, the id
    /// [`invite_workspace_as_platform`](Self::invite_workspace_as_platform) answered. An address
    /// with none, or with a member invitation, is answered as a success and nothing changes.
    ///
    /// # Errors
    ///
    /// [`AuthError::TooManyRequests`] when the address kept changing under every attempt, and
    /// [`AuthError::Internal`] for a store failure or a disabled layer.
    pub async fn revoke_workspace_invitation_as_platform(
        &self,
        workspace: WorkspaceRef<'_>,
        email: &str,
        ctx: &HookContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        let email = normalize_email(email);
        let place = runtime.place(workspace, &email)?;
        let bootstrap =
            |record: &InvitationRecord| matches!(record, InvitationRecord::Bootstrap { .. });
        let Some(role) = withdraw(runtime.invitation_store()?, &place, bootstrap).await? else {
            return Ok(());
        };
        let kind = AuditKind::InvitationRevoked { email, role };
        let event = audit_event(workspace, None, &now_iso(), kind);
        self.notify_workspace_event(event, ctx.clone());
        Ok(())
    }
}

/// The record a platform invitation publishes: the owner role, and the name to create with.
fn bootstrap_record(
    runtime: &WorkspaceRuntime,
    workspace: WorkspaceRef<'_>,
    email: &str,
    name: &str,
    at: &str,
) -> InvitationRecord {
    InvitationRecord::Bootstrap {
        base: InvitationBase {
            email: email.to_owned(),
            role: runtime.resolved.hierarchy.owner_role().to_owned(),
            tenant_id: workspace.tenant_id.to_owned(),
            workspace_id: workspace.workspace_id.to_owned(),
            created_at: at.to_owned(),
            resend_count: 0,
        },
        workspace_name: name.to_owned(),
    }
}

/// Publishes a first invitation. The workspace id is fresh, so nothing can hold its index and no
/// pending cap applies.
async fn publish_new(
    runtime: &WorkspaceRuntime,
    workspace: WorkspaceRef<'_>,
    email: &str,
    token: &str,
    record: &InvitationRecord,
) -> Result<(), AuthError> {
    let place = runtime.place(workspace, email)?;
    let outcome = runtime
        .invitation_store()?
        .publish(Publication {
            place: &place,
            record_key: &record_key(&invitation_record_id(token)),
            record,
            ttl: NonZeroU64::new(runtime.resolved.invitation_ttl_seconds)
                .unwrap_or(NonZeroU64::MIN),
            pending_limit: 0,
            expected_key: None,
        })
        .await?;
    match outcome {
        PublishOutcome::Published => Ok(()),
        _ => Err(too_many_requests()),
    }
}
