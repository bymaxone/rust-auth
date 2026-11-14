//! Removing every workspace membership of an account the host is about to delete or anonymise, and
//! dropping one membership's cached access by hand (layer: service).
//!
//! The library never deletes a user and wires nothing automatically: the host calls
//! [`AuthEngine::remove_workspace_memberships_for_user`] BEFORE it deletes or anonymises the
//! account (`workspaceAccountRemoval.rules.scope`). The removal covers every membership of the
//! account in the tenant, in every membership status and every workspace status.
//!
//! The order is the contract's: the sole-owned workspaces are read first, only to name blockers
//! to the caller; then ONE repository call removes every membership and persists one
//! `member.removed` event per removal, deciding the last-owner rule again inside its own
//! transaction; then, after the commit, every removed membership's counter is bumped (all of them
//! attempted, even when one fails) and the events are reported to the host's workspace-event hook,
//! detached.

use std::collections::HashMap;

use bymax_auth_types::{AuthError, BlockingWorkspace};

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::workspace::{WorkspaceRuntime, internal, invalid};
use crate::services::workspace_writes::{audit_event, now_iso};
use crate::traits::membership_repository::{
    AccountRemovalAudit, ListSoleOwned, OwnedBy, RemoveAllForUser, RemoveAllOutcome,
    RemovedMembership,
};
use crate::traits::{HookContext, HookPlane};
use crate::workspace::audit::AuditKind;
use crate::workspace::bounds::is_blank;
use crate::workspace::domain::{MembershipRef, WorkspaceRef};

/// The most blocking workspaces a refusal names: `workspaceAccountRemoval.rules.blocking`.
pub const BLOCKING_WORKSPACES_MAX: usize = 100;

/// The most pages of sole-owned workspaces read to name blockers. A page holds at most
/// [`BLOCKING_WORKSPACES_MAX`] workspaces, and a page can hold only workspaces that do not block, so
/// the read stops at this many pages rather than follow a cursor without end.
const SOLE_OWNED_PAGES_MAX: usize = 100;

/// Who authorized an account removal, which is the actor of every audit event it persists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalAuthority<'a> {
    /// The account itself asked for its removal.
    Account,
    /// An administrator, named by user id, removed the account.
    Administrator(&'a str),
    /// A job removed the account: the events carry no actor.
    Job,
}

/// What [`AuthEngine::remove_workspace_memberships_for_user`] removes and on whose authority.
#[derive(Debug, Clone, Copy)]
pub struct AccountRemoval<'a> {
    /// The tenant of the account.
    pub tenant_id: &'a str,
    /// The account whose memberships are removed.
    pub user_id: &'a str,
    /// Who authorized the removal.
    pub authority: RemovalAuthority<'a>,
}

/// An account removal that committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedMemberships {
    /// The memberships removed, ordered by workspace id; empty when the account had none.
    pub memberships: Vec<RemovedMembership>,
    /// The one ISO-8601 UTC instant every `member.removed` event of the call carries.
    pub at: String,
}

/// Why an account removal did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountRemovalError {
    /// The account is the only active owner of workspaces whose status blocks the removal
    /// (`active` or `suspended`). Nothing was written, no audit row was persisted and no cache
    /// counter moved. The host transfers ownership or schedules those workspaces' deletion first.
    #[error("the account is the only owner of {} workspace(s)", .workspaces.len())]
    Blocked {
        /// The blocking workspaces, at most [`BLOCKING_WORKSPACES_MAX`]: `{id, name, status}` for
        /// those read before the write, `{id}` alone for those the repository found during it.
        workspaces: Vec<BlockingWorkspace>,
    },
    /// The removal committed, but the cached access of some removed memberships was not dropped.
    /// Repeating the call finds nothing to remove: the host drops the failed ones with
    /// [`AuthEngine::invalidate_membership`], or waits out the membership cache lifetime.
    #[error("the removal committed but {} membership counter(s) could not be bumped", .failed.len())]
    BumpsFailed {
        /// Every membership removed.
        removed: Vec<RemovedMembership>,
        /// The workspace ids whose membership counter could not be bumped.
        failed: Vec<String>,
    },
    /// Any other failure: a blank identifier, the workspace layer off or a repository failure.
    #[error(transparent)]
    Failed(AuthError),
}

impl From<AccountRemovalError> for AuthError {
    /// The error a route would answer: `409 auth.last_owner` with `details.workspaces` for a
    /// refusal, `auth.internal` for the failed bumps.
    fn from(error: AccountRemovalError) -> Self {
        match error {
            AccountRemovalError::Blocked { workspaces } => Self::LastOwnerWithDetails(workspaces),
            AccountRemovalError::BumpsFailed { .. } => Self::Internal(Box::new(error)),
            AccountRemovalError::Failed(error) => error,
        }
    }
}

/// `auth.validation` naming `field` when it is blank.
fn not_blank(field: &str, value: &str) -> Result<(), AuthError> {
    if is_blank(value) {
        return Err(invalid(field, format!("{field} must not be blank")));
    }
    Ok(())
}

/// The actor of the events: the account itself, the administrator, or nobody.
fn actor_of<'a>(removal: &AccountRemoval<'a>) -> Result<Option<&'a str>, AuthError> {
    match removal.authority {
        RemovalAuthority::Account => Ok(Some(removal.user_id)),
        RemovalAuthority::Administrator(actor) => {
            not_blank("actorUserId", actor)?;
            Ok(Some(actor))
        }
        RemovalAuthority::Job => Ok(None),
    }
}

/// The refusal for the workspaces the repository named: each carries what the read before the
/// write found out about it, or its id alone when the write found it. At most
/// [`BLOCKING_WORKSPACES_MAX`].
fn blocked(ids: Vec<String>, mut read: HashMap<String, BlockingWorkspace>) -> AccountRemovalError {
    let workspaces = ids
        .into_iter()
        .take(BLOCKING_WORKSPACES_MAX)
        .map(|id| {
            read.remove(&id).unwrap_or(BlockingWorkspace {
                id,
                name: None,
                status: None,
            })
        })
        .collect();
    AccountRemovalError::Blocked { workspaces }
}

impl WorkspaceRuntime {
    /// The workspaces the account solely owns whose status blocks a removal, as the callers is
    /// told about them, keyed by id: at most [`BLOCKING_WORKSPACES_MAX`].
    async fn read_blocking_workspaces(
        &self,
        removal: &AccountRemoval<'_>,
    ) -> Result<HashMap<String, BlockingWorkspace>, AuthError> {
        let owner = OwnedBy {
            tenant_id: removal.tenant_id,
            user_id: removal.user_id,
            owner_role: self.resolved.hierarchy.owner_role(),
        };
        let mut blocking = HashMap::new();
        let mut cursor: Option<String> = None;
        for _ in 0..SOLE_OWNED_PAGES_MAX {
            let page = ListSoleOwned {
                owner,
                cursor: cursor.as_deref(),
                limit: 100,
            };
            let page = self.memberships.list_sole_owned(page).await;
            let page = page.map_err(internal)?;
            for workspace in page.items {
                if workspace.status.blocks_account_removal() {
                    let status = Some(workspace.status.as_str().to_owned());
                    let name = Some(workspace.name);
                    let id = workspace.id;
                    blocking.insert(id.clone(), BlockingWorkspace { id, name, status });
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() || blocking.len() >= BLOCKING_WORKSPACES_MAX {
                break;
            }
        }
        Ok(blocking)
    }

    /// Bumps the counter of every membership in `removed`, all of them attempted, and answers the
    /// workspace ids of those that failed.
    async fn bump_removed(
        &self,
        (tenant_id, user_id): (&str, &str),
        removed: &[RemovedMembership],
    ) -> Vec<String> {
        let mut failed = Vec::new();
        for membership in removed {
            let key = MembershipRef {
                tenant_id,
                workspace_id: &membership.workspace_id,
                user_id,
            };
            if self.invalidate_membership(key).await.is_err() {
                failed.push(membership.workspace_id.clone());
            }
        }
        failed
    }
}

impl AuthEngine {
    /// Removes every workspace membership of an account in the tenant, in every membership status
    /// and every workspace status, for a host that is about to delete or anonymise the user.
    ///
    /// The account is refused while it is the only ACTIVE holder of the owner role of a workspace
    /// whose status is `active` or `suspended`; one pending deletion or deleted never blocks, and
    /// the account's membership there is removed with the others. The repository decides the rule
    /// again inside the write, so a workspace that became solely owned after the read that names
    /// the blockers still refuses, with its id alone. After the commit the cached access of every
    /// removed membership is dropped by bumping its counter, and one `member.removed` event per
    /// removal, the ones the repository persisted, is reported to the host's workspace-event hook,
    /// detached: a hook failure never changes the result. The events are reported even when a bump
    /// failed, since the removal they describe committed.
    ///
    /// # Errors
    ///
    /// [`AccountRemovalError::Blocked`] (`409 auth.last_owner`) with nothing written,
    /// [`AccountRemovalError::BumpsFailed`] after a committed removal whose bumps did not all
    /// succeed, and [`AccountRemovalError::Failed`] for a blank identifier, a disabled workspace
    /// layer or a repository failure.
    pub async fn remove_workspace_memberships_for_user(
        &self,
        removal: AccountRemoval<'_>,
        ctx: &RequestContext,
    ) -> Result<RemovedMemberships, AccountRemovalError> {
        let runtime = self
            .workspace_runtime()
            .map_err(AccountRemovalError::Failed)?;
        let actor = checked(&removal).map_err(AccountRemovalError::Failed)?;
        let read = runtime
            .read_blocking_workspaces(&removal)
            .await
            .map_err(AccountRemovalError::Failed)?;
        let at = now_iso();
        let write = RemoveAllForUser {
            tenant_id: removal.tenant_id,
            user_id: removal.user_id,
            owner_role: runtime.resolved.hierarchy.owner_role(),
            audit: AccountRemovalAudit {
                tenant_id: removal.tenant_id,
                actor_user_id: actor,
                user_id: removal.user_id,
                at: &at,
            },
        };
        let outcome = runtime.memberships.remove_all_for_user(write).await;
        let memberships = match outcome.map_err(|e| AccountRemovalError::Failed(internal(e)))? {
            RemoveAllOutcome::LastOwner(ids) => return Err(blocked(ids, read)),
            RemoveAllOutcome::Removed(memberships) => memberships,
        };
        let who = (removal.tenant_id, removal.user_id);
        let failed = runtime.bump_removed(who, &memberships).await;
        self.report_removals(&removal, actor, &at, &memberships, ctx);
        if !failed.is_empty() {
            tracing::warn!(
                failed = failed.len(),
                "account removal committed but some membership counters were not bumped"
            );
            return Err(AccountRemovalError::BumpsFailed {
                removed: memberships,
                failed,
            });
        }
        Ok(RemovedMemberships { memberships, at })
    }

    /// Reports one `member.removed` event per removed membership, detached.
    fn report_removals(
        &self,
        removal: &AccountRemoval<'_>,
        actor: Option<&str>,
        at: &str,
        removed: &[RemovedMembership],
        ctx: &RequestContext,
    ) {
        for membership in removed {
            let workspace = WorkspaceRef {
                tenant_id: removal.tenant_id,
                workspace_id: &membership.workspace_id,
            };
            let kind = AuditKind::MemberRemoved {
                user_id: removal.user_id.to_owned(),
            };
            let event = audit_event(workspace, actor, at, kind);
            let hook_ctx = HookContext::from_request(
                HookPlane::Dashboard,
                ctx,
                actor.map(str::to_owned),
                None,
                Some(removal.tenant_id.to_owned()),
            );
            self.notify_workspace_event(event, hook_ctx);
        }
    }

    /// Drops the cached access of one membership by bumping its counter, for a host that must end
    /// a member's access at once: the memberships an account removal reported as failed, or a
    /// membership the host changed through its own repository. Access then ends at the member's
    /// next request.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `tenantId`, `workspaceId` or `userId` when it is blank, and
    /// `auth.internal` when the workspace layer is off or the store fails.
    pub async fn invalidate_membership(&self, member: MembershipRef<'_>) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        not_blank("tenantId", member.tenant_id)?;
        not_blank("workspaceId", member.workspace_id)?;
        not_blank("userId", member.user_id)?;
        runtime.invalidate_membership(member).await
    }
}

/// The removal's identifiers checked, and its actor.
fn checked<'a>(removal: &AccountRemoval<'a>) -> Result<Option<&'a str>, AuthError> {
    not_blank("tenantId", removal.tenant_id)?;
    not_blank("userId", removal.user_id)?;
    actor_of(removal)
}
