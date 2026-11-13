//! What every workspace write shares (layer: service).
//!
//! The audit event is filled in completely before the write: the tenant and the workspace of the
//! call, the actor, one ISO-8601 instant and the kind. The repository persists it in the same
//! transaction as the change. The cached access the change affects is ended by a bump AFTER the
//! change, and only then is the event handed to the host's workspace-event hook, detached. A bump
//! that fails is an error: the change is committed, and it is never reported as invalidated when
//! it was not.
//!
//! What a bump covers is `workspaceMembershipCache.workspaceWideEvents`: scheduling the deletion
//! of, restoring, deleting or suspending a workspace bumps the workspace counter, and a change to
//! one membership bumps that membership's counter only.

use std::fmt;
use std::sync::Arc;

use bymax_auth_types::{AuthError, FieldError, MfaContext, SafeAuthUser};
use time::OffsetDateTime;

use crate::context::{RequestContext, to_safe_user};
use crate::engine::AuthEngine;
use crate::services::auth::spawn_guarded;
use crate::services::membership_cache::{BumpError, bump_membership, bump_workspace};
use crate::services::reauthentication::{ProvingAccount, Reproof};
use crate::services::workspace::{WorkspaceRuntime, internal};
use crate::traits::membership_repository::MemberChangeOutcome;
use crate::traits::workspace_repository::UpdateStatusOutcome;
use crate::traits::{AuthHooks, HookContext, HookPlane};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent, iso_instant};
use crate::workspace::bounds::normalize_workspace_name;
use crate::workspace::domain::{ActingMember, MembershipRef, WorkspaceRef, WorkspaceStatus};

/// The current instant as an audit event carries it.
pub(crate) fn now_iso() -> String {
    iso_instant(OffsetDateTime::now_utc())
}

/// The audit event of a change to `workspace` made by `actor` (`None` for a job) at `at`.
pub(crate) fn audit_event(
    workspace: WorkspaceRef<'_>,
    actor: Option<&str>,
    at: &str,
    kind: AuditKind,
) -> WorkspaceAuditEvent {
    WorkspaceAuditEvent {
        tenant_id: workspace.tenant_id.to_owned(),
        workspace_id: workspace.workspace_id.to_owned(),
        actor_user_id: actor.map(str::to_owned),
        at: at.to_owned(),
        kind,
    }
}

/// The hook context of a request a member of a workspace made.
pub(crate) fn member_hook_context(ctx: &RequestContext, member: &WorkspaceMember) -> HookContext {
    HookContext::from_request(
        HookPlane::Dashboard,
        ctx,
        Some(member.user_id.clone()),
        None,
        Some(member.tenant_id.clone()),
    )
}

/// The member as the repository re-checks them: the role the guard resolved is the role the write
/// was judged against.
pub(crate) fn acting(member: &WorkspaceMember) -> ActingMember<'_> {
    ActingMember {
        user_id: &member.user_id,
        expected_role: &member.role,
    }
}

/// A submitted workspace name in the form it is stored, or `auth.validation` naming `name`.
pub(crate) fn workspace_name(submitted: &str) -> Result<String, AuthError> {
    normalize_workspace_name(submitted).map_err(|refused| AuthError::Validation {
        details: vec![FieldError {
            field: refused.field.to_owned(),
            message: "name must be 1 to 120 characters with no control characters".to_owned(),
        }],
    })
}

/// The answer to a write an actor's role authorized: `Done` goes on, and every refusal is the
/// catalog code the shared contract gives it.
pub(crate) fn member_change(outcome: MemberChangeOutcome) -> Result<(), AuthError> {
    match outcome {
        MemberChangeOutcome::Done => Ok(()),
        MemberChangeOutcome::NotFound => Err(AuthError::WorkspaceNotFound),
        MemberChangeOutcome::LastOwner => Err(AuthError::LastOwner),
        MemberChangeOutcome::ActorChanged => Err(AuthError::InsufficientWorkspaceRole),
    }
}

/// The refusal a status write answered with, or `None` for `Done`. A lost compare-and-set is
/// answered from what the workspace is now: `409 auth.workspace_pending_deletion` when its deletion
/// is scheduled (only the owner reaches the write), the identical 404 otherwise.
pub(crate) fn status_refusal(
    outcome: UpdateStatusOutcome,
    current: Option<WorkspaceStatus>,
) -> Option<AuthError> {
    match outcome {
        UpdateStatusOutcome::Done => None,
        UpdateStatusOutcome::ActorChanged => Some(AuthError::InsufficientWorkspaceRole),
        UpdateStatusOutcome::StatusConflict
            if current == Some(WorkspaceStatus::PendingDeletion) =>
        {
            Some(AuthError::WorkspacePendingDeletion)
        }
        UpdateStatusOutcome::NotFound | UpdateStatusOutcome::StatusConflict => {
            Some(AuthError::WorkspaceNotFound)
        }
    }
}

/// A bump that failed, as the error the change is answered with.
fn bump_failed(error: BumpError) -> AuthError {
    AuthError::Internal(Box::new(error))
}

impl WorkspaceRuntime {
    /// Ends every member's cached access to `workspace`, after a workspace-wide change committed.
    pub(crate) async fn invalidate_workspace(
        &self,
        workspace: WorkspaceRef<'_>,
    ) -> Result<(), AuthError> {
        bump_workspace(self.cache_store.as_ref(), &self.identifier_key, workspace)
            .await
            .map(drop)
            .map_err(bump_failed)
    }

    /// Ends one member's cached access, after a change to that membership committed.
    pub(crate) async fn invalidate_membership(
        &self,
        member: MembershipRef<'_>,
    ) -> Result<(), AuthError> {
        bump_membership(self.cache_store.as_ref(), &self.identifier_key, member)
            .await
            .map(drop)
            .map_err(bump_failed)
    }
}

/// A workspace-event hook that failed, named by the event's type alone: the event can carry an
/// address, and the hook's own error text can quote it.
#[derive(Debug)]
pub(crate) struct WorkspaceEventHookFailed {
    event: &'static str,
}

impl fmt::Display for WorkspaceEventHookFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the workspace-event hook failed for {}", self.event)
    }
}

/// Hands `event` to the host's workspace-event hook; the body the detached task runs.
pub(crate) async fn run_on_workspace_event(
    hooks: Arc<dyn AuthHooks>,
    event: WorkspaceAuditEvent,
    ctx: HookContext,
) -> Result<(), WorkspaceEventHookFailed> {
    let name = event.kind.type_name();
    hooks
        .on_workspace_event(&event, &ctx)
        .await
        .map_err(|_| WorkspaceEventHookFailed { event: name })
}

impl AuthEngine {
    /// Reports a committed change to the host's workspace-event hook, detached: it never delays or
    /// fails the operation.
    pub(crate) fn notify_workspace_event(&self, event: WorkspaceAuditEvent, ctx: HookContext) {
        spawn_guarded(run_on_workspace_event(self.hooks().clone(), event, ctx));
    }

    /// The account behind a verified dashboard credential, without its credentials.
    ///
    /// # Errors
    ///
    /// `auth.token_invalid` when the account no longer exists, `auth.internal` for a repository
    /// failure.
    pub(crate) async fn workspace_caller(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<SafeAuthUser, AuthError> {
        let user = self
            .user_repository()
            .find_by_id(user_id, Some(tenant_id))
            .await
            .map_err(internal)?
            .ok_or(AuthError::TokenInvalid)?;
        Ok(to_safe_user(&user))
    }

    /// Re-proves `member` before a destructive change: their password, or a recent sign-in for an
    /// account with none. Run only after the checks that decide whether they may act at all, so a
    /// caller who may not spends no key derivation and no lockout attempt.
    ///
    /// # Errors
    ///
    /// `auth.token_invalid` when the account no longer exists, then the re-proof's refusals.
    pub(crate) async fn reprove_workspace_member(
        &self,
        member: &WorkspaceMember,
        password: Option<&str>,
    ) -> Result<(), AuthError> {
        let user = self
            .user_repository()
            .find_by_id(&member.user_id, Some(&member.tenant_id))
            .await
            .map_err(internal)?
            .ok_or(AuthError::TokenInvalid)?;
        let reproof = Reproof {
            brute_force: self.brute_force(),
            passwords: self.passwords(),
            session_store: self.session_store().as_ref(),
            identifier_key: self.config().hmac_key(),
        };
        let account = ProvingAccount {
            plane: MfaContext::Dashboard,
            tenant_id: Some(&member.tenant_id),
            user_id: &member.user_id,
            password_hash: user.password_hash.as_deref(),
        };
        reproof.assert(account, password).await
    }
}
