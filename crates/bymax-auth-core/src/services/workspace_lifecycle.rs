//! The life of a workspace: creating one, renaming it, scheduling its deletion, restoring it and
//! finalizing the deletion (layer: service).
//!
//! Every change is written by the repository together with its audit event, in one transaction. A
//! workspace-wide change then ends every member's cached access by bumping the workspace counter,
//! and only after that is the event handed to the host's hook. The writes a member's role
//! authorized (rename, scheduling a deletion, restore) hand the repository the role the guard
//! resolved for the actor, and the repository checks it in the write's own transaction: an actor
//! whose role changed since is answered `auth.insufficient_workspace_role` and nothing changes.
//!
//! Creation is one path shared by the route and by a bootstrap acceptance
//! (`workspaceInvitations.rules.bootstrapCreate`): first the owner cap
//! (`workspaces.max_workspaces_per_user`, counted as the workspaces the account owns with the owner
//! role), then the host's `before_workspace_create`, then the write, which receives the cap so the
//! repository can enforce it exactly. Only `AuthEngine::create_workspace` consults the self-serve switch
//! `workspaces.allow_create` before that path.

use bymax_auth_types::{AuthError, FieldError, SafeAuthUser};
use time::{Duration, OffsetDateTime};

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::new_uuid_v4;
use crate::services::workspace::{WorkspaceRuntime, internal};
use crate::services::workspace_writes::{
    acting, audit_event, member_hook_context, now_iso, status_refusal, workspace_name,
};
use crate::traits::membership_repository::OwnedBy;
use crate::traits::workspace_repository::{
    CreateWorkspaceOutcome, CreateWorkspaceWithOwner, RenameOutcome, RenameWorkspace,
    UpdateStatusOutcome, UpdateWorkspaceStatus,
};
use crate::traits::{BeforeWorkspaceCreateResult, HookContext, HookError, HookPlane};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent, iso_instant};
use crate::workspace::domain::{Workspace, WorkspaceRef, WorkspaceStatus};

/// What the host's `before_workspace_create` refusal tells the caller when it gives no reason:
/// the message `workspaceInvitations.rules.bootstrapCreate` pins.
pub const WORKSPACE_CREATE_REFUSED: &str = "Workspace creation was refused";

/// The seconds in a day, for the deletion grace period.
const DAY_SECONDS: i64 = 86_400;

/// A workspace to create with its owner, through the path the create route and a bootstrap
/// acceptance share.
#[derive(Debug, Clone, Copy)]
pub struct OwnedWorkspace<'a> {
    /// The tenant and the id the workspace will have: one the library generated, or the one a
    /// bootstrap invitation reserved.
    pub workspace: WorkspaceRef<'a>,
    /// The name, as submitted or as the invitation carries it; it is bounded and trimmed here.
    pub name: &'a str,
    /// The account that becomes the owner, in the workspace's tenant.
    pub owner: &'a SafeAuthUser,
}

/// What scheduling a deletion produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledDeletion {
    /// [`WorkspaceStatus::PendingDeletion`], or [`WorkspaceStatus::Deleted`] when the grace
    /// period is `0` and the workspace was deleted at once.
    pub status: WorkspaceStatus,
    /// When the deletion becomes final, `None` when it already is.
    pub deletion_scheduled_at: Option<OffsetDateTime>,
}

/// What [`AuthEngine::finalize_workspace_deletion`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// The workspace is now deleted.
    Deleted,
    /// No such workspace.
    NotFound,
    /// The workspace is not pending deletion.
    NotPending,
    /// Its grace period has not ended; the next run finalizes it.
    NotDue,
}

/// The `403 auth.forbidden` a host refusal answers, naming `name` with `reason`.
fn refused_by_host(reason: Option<String>) -> AuthError {
    AuthError::ForbiddenWithDetails(vec![FieldError {
        field: "name".to_owned(),
        message: reason.unwrap_or_else(|| WORKSPACE_CREATE_REFUSED.to_owned()),
    }])
}

/// The workspace a create wrote, or `auth.workspace_limit_reached` when the repository enforced
/// the owner cap itself.
pub(crate) fn created_workspace(outcome: CreateWorkspaceOutcome) -> Result<Workspace, AuthError> {
    match outcome {
        CreateWorkspaceOutcome::Created(workspace) => Ok(workspace),
        CreateWorkspaceOutcome::LimitReached => Err(AuthError::WorkspaceLimitReached),
    }
}

/// The answer to a rename's write.
pub(crate) fn rename_outcome(outcome: RenameOutcome) -> Result<(), AuthError> {
    match outcome {
        RenameOutcome::Done => Ok(()),
        RenameOutcome::NotFound => Err(AuthError::WorkspaceNotFound),
        RenameOutcome::ActorChanged => Err(AuthError::InsufficientWorkspaceRole),
    }
}

/// Why a workspace read now cannot be finalized, or `None` when its grace period is over.
pub(super) fn finalize_refusal(
    workspace: &Workspace,
    now: OffsetDateTime,
) -> Option<FinalizeOutcome> {
    if workspace.status != WorkspaceStatus::PendingDeletion {
        return Some(FinalizeOutcome::NotPending);
    }
    workspace
        .deletion_scheduled_at
        .is_some_and(|due| due > now)
        .then_some(FinalizeOutcome::NotDue)
}

/// Whether a restore at `now` still applies: the workspace is pending deletion and its scheduled
/// instant, when it has one, is strictly after `now`. At the instant itself the deletion is final.
pub(super) fn restorable(workspace: &Workspace, now: OffsetDateTime) -> bool {
    workspace.status == WorkspaceStatus::PendingDeletion
        && workspace.deletion_scheduled_at.is_none_or(|due| due > now)
}

/// The hook context of a change no request made, such as the job that finalizes a deletion.
fn job_hook_context(tenant_id: &str) -> HookContext {
    HookContext {
        plane: HookPlane::Dashboard,
        user_id: None,
        email: None,
        tenant_id: Some(tenant_id.to_owned()),
        ip: String::new(),
        user_agent: String::new(),
        sanitized_headers: std::collections::BTreeMap::new(),
    }
}

impl WorkspaceRuntime {
    /// Turns a status write into the caller's answer: a refusal is its catalog code, read again
    /// for a lost compare-and-set, and a write that applied ends every member's cached access.
    async fn settle_status(
        &self,
        outcome: UpdateStatusOutcome,
        workspace: WorkspaceRef<'_>,
    ) -> Result<(), AuthError> {
        let current = if outcome == UpdateStatusOutcome::StatusConflict {
            let read = self.workspaces.find_by_id(workspace).await;
            read.map_err(internal)?.map(|found| found.status)
        } else {
            None
        };
        if let Some(refusal) = status_refusal(outcome, current) {
            return Err(refusal);
        }
        self.invalidate_workspace(workspace).await
    }

    /// The workspace as it reads now, when it is active.
    async fn active_workspace(&self, workspace: WorkspaceRef<'_>) -> Result<Workspace, AuthError> {
        match self
            .workspaces
            .find_by_id(workspace)
            .await
            .map_err(internal)?
        {
            Some(found) if found.status.grants_access() => Ok(found),
            _ => Err(AuthError::WorkspaceNotFound),
        }
    }
}

impl AuthEngine {
    /// Creates a workspace owned by the caller (`POST /workspaces`).
    ///
    /// In order: the account behind the credential, the name, the self-serve switch
    /// `workspaces.allow_create`, then the path [`AuthEngine::create_owned_workspace`] runs. The id
    /// is a fresh UUID. The event `workspace.created` is reported to the host after the write.
    ///
    /// # Errors
    ///
    /// `auth.token_invalid` when the account no longer exists, `auth.validation` naming `name`,
    /// `auth.forbidden` when the switch is off, then the shared path's refusals.
    pub async fn create_workspace(
        &self,
        tenant_id: &str,
        user_id: &str,
        name: &str,
        ctx: &RequestContext,
    ) -> Result<Workspace, AuthError> {
        let runtime = self.workspace_runtime()?;
        let owner = self.workspace_caller(tenant_id, user_id).await?;
        let name = workspace_name(name)?;
        if !runtime.resolved.allow_create {
            return Err(AuthError::Forbidden);
        }
        let id = new_uuid_v4();
        let request = OwnedWorkspace {
            workspace: WorkspaceRef {
                tenant_id,
                workspace_id: &id,
            },
            name: &name,
            owner: &owner,
        };
        let hook_ctx = HookContext::from_request(
            HookPlane::Dashboard,
            ctx,
            Some(user_id.to_owned()),
            None,
            Some(tenant_id.to_owned()),
        );
        let (workspace, event) = self
            .write_owned_workspace(runtime, request, &hook_ctx)
            .await?;
        self.notify_workspace_event(event, hook_ctx);
        Ok(workspace)
    }

    /// Creates a workspace and its owner's membership through the path the create route and a
    /// bootstrap acceptance share, in the order `workspaceInvitations.rules.bootstrapCreate` fixes:
    /// the owner cap, then the host's `before_workspace_create`, then one repository call that
    /// writes the workspace, the membership and the `workspace.created` audit event. The
    /// self-serve switch is never consulted here, and nothing is reported to the workspace-event
    /// hook: the caller reports what its own operation did.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `name`, `auth.workspace_limit_reached` at the cap (from the count
    /// or from the repository's write), `auth.forbidden` with a detail naming `name` when the hook
    /// refuses, and `auth.internal` for a repository or hook failure or a disabled layer.
    pub async fn create_owned_workspace(
        &self,
        request: OwnedWorkspace<'_>,
        ctx: &HookContext,
    ) -> Result<Workspace, AuthError> {
        let runtime = self.workspace_runtime()?;
        let (workspace, _) = self.write_owned_workspace(runtime, request, ctx).await?;
        Ok(workspace)
    }

    /// The shared create path, returning the audit event the repository persisted with it.
    async fn write_owned_workspace(
        &self,
        runtime: &WorkspaceRuntime,
        request: OwnedWorkspace<'_>,
        ctx: &HookContext,
    ) -> Result<(Workspace, WorkspaceAuditEvent), AuthError> {
        let name = workspace_name(request.name)?;
        let owner_role = runtime.resolved.hierarchy.owner_role();
        let cap = runtime.resolved.max_workspaces_per_user;
        if cap > 0 {
            let owned = OwnedBy {
                tenant_id: request.workspace.tenant_id,
                user_id: &request.owner.id,
                owner_role,
            };
            let count = runtime.memberships.count_owned(owned).await;
            if count.map_err(internal)? >= u64::from(cap) {
                return Err(AuthError::WorkspaceLimitReached);
            }
        }
        self.admit_workspace_name(request.owner, &name, ctx).await?;
        let kind = AuditKind::WorkspaceCreated;
        let event = audit_event(request.workspace, Some(&request.owner.id), &now_iso(), kind);
        let params = CreateWorkspaceWithOwner {
            workspace: request.workspace,
            name: &name,
            owner_user_id: &request.owner.id,
            owner_role,
            max_workspaces_per_user: cap,
            audit: &event,
        };
        let created = runtime.workspaces.create_with_owner(params).await;
        Ok((created_workspace(created.map_err(internal)?)?, event))
    }

    /// The host's `before_workspace_create` decision about `name` for `owner`.
    async fn admit_workspace_name(
        &self,
        owner: &SafeAuthUser,
        name: &str,
        ctx: &HookContext,
    ) -> Result<(), AuthError> {
        match self.hooks().before_workspace_create(owner, name, ctx).await {
            Ok(BeforeWorkspaceCreateResult::Allow) => Ok(()),
            Ok(BeforeWorkspaceCreateResult::Reject { reason }) => Err(refused_by_host(reason)),
            Err(HookError::Rejected(_)) => Err(refused_by_host(None)),
            Err(HookError::Internal(source)) => Err(AuthError::Internal(source)),
        }
    }

    /// Renames the workspace `member` was admitted to and reads it back. A rename changes nothing
    /// a cached membership holds, so it bumps no counter.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `name`, `auth.workspace_not_found` when the workspace is gone or
    /// no longer active, `auth.insufficient_workspace_role` when the actor's role changed since
    /// the guard read it, and `auth.internal` for a repository failure or a disabled layer.
    pub async fn rename_workspace(
        &self,
        member: &WorkspaceMember,
        name: &str,
        ctx: &RequestContext,
    ) -> Result<Workspace, AuthError> {
        let runtime = self.workspace_runtime()?;
        let name = workspace_name(name)?;
        let workspace = member.workspace();
        let kind = AuditKind::WorkspaceRenamed;
        let event = audit_event(workspace, Some(&member.user_id), &now_iso(), kind);
        let params = RenameWorkspace {
            workspace,
            name: &name,
            actor: acting(member),
            audit: &event,
        };
        rename_outcome(runtime.workspaces.rename(params).await.map_err(internal)?)?;
        self.notify_workspace_event(event, member_hook_context(ctx, member));
        runtime.active_workspace(workspace).await
    }

    /// Re-proves `member`, then schedules the deletion of the workspace they were admitted to,
    /// ending every member's access at once. With `workspaces.deletion_grace_days` of `0` the
    /// workspace is deleted instead.
    ///
    /// # Errors
    ///
    /// The re-proof's refusals (`auth.invalid_credentials`, `auth.account_locked`,
    /// `auth.reauthentication_required`), then `auth.workspace_not_found`,
    /// `auth.workspace_pending_deletion` when it was scheduled meanwhile,
    /// `auth.insufficient_workspace_role` when the actor's role changed, and `auth.internal` for a
    /// repository or cache failure. After a failed bump the deletion is committed.
    pub async fn schedule_workspace_deletion(
        &self,
        member: &WorkspaceMember,
        password: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<ScheduledDeletion, AuthError> {
        let runtime = self.workspace_runtime()?;
        self.reprove_workspace_member(member, password).await?;
        let now = OffsetDateTime::now_utc();
        let days = i64::from(runtime.resolved.deletion_grace_days);
        let (status, scheduled, kind) = if days == 0 {
            (WorkspaceStatus::Deleted, None, AuditKind::WorkspaceDeleted)
        } else {
            let due = now + Duration::seconds(days * DAY_SECONDS);
            let kind = AuditKind::WorkspaceDeletionScheduled;
            (WorkspaceStatus::PendingDeletion, Some(due), kind)
        };
        let workspace = member.workspace();
        let event = audit_event(workspace, Some(&member.user_id), &iso_instant(now), kind);
        let params = UpdateWorkspaceStatus {
            workspace,
            actor: Some(acting(member)),
            status,
            expected_status: WorkspaceStatus::Active,
            expected_deletion_scheduled_at: None,
            deletion_scheduled_at: scheduled,
            audit: &event,
        };
        let outcome = runtime.workspaces.update_status(params).await;
        runtime
            .settle_status(outcome.map_err(internal)?, workspace)
            .await?;
        self.notify_workspace_event(event, member_hook_context(ctx, member));
        Ok(ScheduledDeletion {
            status,
            deletion_scheduled_at: scheduled,
        })
    }

    /// Undoes the scheduled deletion of the workspace `member` was admitted to, while its grace
    /// period has not ended, and ends every member's cached access.
    ///
    /// # Errors
    ///
    /// `auth.workspace_not_found` when the workspace is not pending deletion or its grace period
    /// is over, `auth.insufficient_workspace_role` when the actor's role changed, and
    /// `auth.internal` for a repository or cache failure. After a failed bump the restore is
    /// committed.
    pub async fn restore_workspace(
        &self,
        member: &WorkspaceMember,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        let workspace = member.workspace();
        let read = runtime.workspaces.find_by_id(workspace).await;
        let now = OffsetDateTime::now_utc();
        let open = read
            .map_err(internal)?
            .is_some_and(|found| restorable(&found, now));
        if !open {
            return Err(AuthError::WorkspaceNotFound);
        }
        let kind = AuditKind::WorkspaceRestored;
        let event = audit_event(workspace, Some(&member.user_id), &iso_instant(now), kind);
        let params = UpdateWorkspaceStatus {
            workspace,
            actor: Some(acting(member)),
            status: WorkspaceStatus::Active,
            expected_status: WorkspaceStatus::PendingDeletion,
            expected_deletion_scheduled_at: None,
            deletion_scheduled_at: None,
            audit: &event,
        };
        let outcome = runtime.workspaces.update_status(params).await;
        runtime
            .settle_status(outcome.map_err(internal)?, workspace)
            .await?;
        self.notify_workspace_event(event, member_hook_context(ctx, member));
        Ok(())
    }

    /// Marks a workspace deleted once its grace period is over: the host's job calls it, and
    /// purging the workspace's data is the host's work. The write is conditional on the status and
    /// the scheduled instant this call read, so a deletion restored and scheduled again meanwhile
    /// is not finalized early. The event `workspace.deleted` carries no actor.
    ///
    /// # Errors
    ///
    /// `auth.internal` for a repository or cache failure or a disabled layer. After a failed bump
    /// the deletion is committed.
    pub async fn finalize_workspace_deletion(
        &self,
        workspace: WorkspaceRef<'_>,
    ) -> Result<FinalizeOutcome, AuthError> {
        let runtime = self.workspace_runtime()?;
        let Some(read) = runtime
            .workspaces
            .find_by_id(workspace)
            .await
            .map_err(internal)?
        else {
            return Ok(FinalizeOutcome::NotFound);
        };
        let now = OffsetDateTime::now_utc();
        if let Some(refusal) = finalize_refusal(&read, now) {
            return Ok(refusal);
        }
        let event = audit_event(
            workspace,
            None,
            &iso_instant(now),
            AuditKind::WorkspaceDeleted,
        );
        let params = UpdateWorkspaceStatus {
            workspace,
            actor: None,
            status: WorkspaceStatus::Deleted,
            expected_status: WorkspaceStatus::PendingDeletion,
            expected_deletion_scheduled_at: Some(read.deletion_scheduled_at),
            deletion_scheduled_at: None,
            audit: &event,
        };
        let outcome = runtime.workspaces.update_status(params).await;
        match outcome.map_err(internal)? {
            UpdateStatusOutcome::Done => {}
            UpdateStatusOutcome::NotFound => return Ok(FinalizeOutcome::NotFound),
            _ => return self.finalize_lost(runtime, workspace).await,
        }
        runtime.invalidate_workspace(workspace).await?;
        self.notify_workspace_event(event, job_hook_context(workspace.tenant_id));
        Ok(FinalizeOutcome::Deleted)
    }

    /// What a finalize whose compare-and-set lost answers: the workspace as it reads now, and one
    /// that is still due is left for the next run.
    pub(crate) async fn finalize_lost(
        &self,
        runtime: &WorkspaceRuntime,
        workspace: WorkspaceRef<'_>,
    ) -> Result<FinalizeOutcome, AuthError> {
        let current = runtime.workspaces.find_by_id(workspace).await;
        let now = OffsetDateTime::now_utc();
        Ok(match current.map_err(internal)? {
            None => FinalizeOutcome::NotFound,
            Some(found) => finalize_refusal(&found, now).unwrap_or(FinalizeOutcome::NotDue),
        })
    }
}
