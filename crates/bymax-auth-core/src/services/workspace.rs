//! The workspace guard's decision and the read services behind the workspace routes (layer:
//! service).
//!
//! The tenant and the caller always come from the verified credential, and the workspace from the
//! member the guard admitted: nothing a query or a body carries can name another one. Every path
//! that reads a membership decides its status explicitly, and only an ACTIVE membership of an
//! ACTIVE workspace grants anything.

use std::sync::Arc;

use bymax_auth_types::{AuthError, FieldError};
use zeroize::Zeroizing;

use crate::config::{ResolvedWorkspaces, WorkspacesConfig};
use crate::engine::AuthEngine;
use crate::error::{ConfigError, RepositoryError};
use crate::services::membership_cache::{
    MembershipCache, Repositories, Resolution, ResolveError, resolve_membership,
};
use crate::traits::membership_repository::{ListForUser, ListForWorkspace};
use crate::traits::{MembershipCacheStore, MembershipRepository, WorkspaceRepository};
use crate::workspace::access::{
    AcceptedRoles, ResolvedAccess, SurfaceRules, WorkspaceMember, classify, decide,
};
use crate::workspace::bounds::{
    IDENTIFIER_MAX_CHARS, check_cursor, check_identifier, is_blank, parse_page_limit,
};
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, MembershipWithWorkspace, Page, Workspace,
};

/// The collaborators the builder gathers for the workspace layer.
#[derive(Default)]
pub(crate) struct WorkspaceCollaborators {
    /// The host's workspace repository.
    pub(crate) workspaces: Option<Arc<dyn WorkspaceRepository>>,
    /// The host's membership repository.
    pub(crate) memberships: Option<Arc<dyn MembershipRepository>>,
    /// The store of the versioned membership cache.
    pub(crate) cache_store: Option<Arc<dyn MembershipCacheStore>>,
}

impl WorkspaceCollaborators {
    /// Whether any collaborator was supplied.
    fn any(&self) -> bool {
        self.workspaces.is_some() || self.memberships.is_some() || self.cache_store.is_some()
    }
}

/// The workspace layer as the engine holds it: present exactly when `workspaces.enabled`.
pub(crate) struct WorkspaceRuntime {
    workspaces: Arc<dyn WorkspaceRepository>,
    memberships: Arc<dyn MembershipRepository>,
    cache_store: Arc<dyn MembershipCacheStore>,
    resolved: ResolvedWorkspaces,
    identifier_key: Zeroizing<[u8; 64]>,
}

impl WorkspaceRuntime {
    /// Decides whether the engine gets a workspace layer, from the configuration group, the route
    /// toggle and what the builder was given. `None` when the group is off.
    ///
    /// # Errors
    ///
    /// The [`ConfigError`] of the first rule broken: the group's own validation, the routes on
    /// without the layer, a collaborator supplied without it, or a collaborator missing with it.
    pub(crate) fn assemble(
        config: &WorkspacesConfig,
        controller: bool,
        collaborators: WorkspaceCollaborators,
        identifier_key: &[u8; 64],
    ) -> Result<Option<Self>, ConfigError> {
        let Some(resolved) = config.resolve()? else {
            if controller {
                return Err(ConfigError::WorkspacesControllerWithoutWorkspaces);
            }
            if collaborators.any() {
                return Err(ConfigError::WorkspaceCollaboratorsUnused);
            }
            return Ok(None);
        };
        let WorkspaceCollaborators {
            workspaces,
            memberships,
            cache_store,
        } = collaborators;
        let (Some(workspaces), Some(memberships)) = (workspaces, memberships) else {
            return Err(ConfigError::MissingWorkspaceRepositories);
        };
        let cache_store = cache_store.ok_or(ConfigError::MissingMembershipCacheStore)?;
        Ok(Some(Self {
            workspaces,
            memberships,
            cache_store,
            resolved,
            identifier_key: Zeroizing::new(*identifier_key),
        }))
    }

    /// What the rows say about `member`, read through the versioned cache.
    async fn resolve(&self, member: MembershipRef<'_>) -> Result<ResolvedAccess, AuthError> {
        let rows = Repositories {
            workspaces: self.workspaces.as_ref(),
            memberships: self.memberships.as_ref(),
        };
        let cache = MembershipCache {
            store: self.cache_store.as_ref(),
            identifier_key: &self.identifier_key,
            ttl: self.resolved.ttl,
        };
        let resolution = resolve_membership(&cache, &rows, member)
            .await
            .map_err(resolve_error)?;
        Ok(match resolution {
            Resolution::Member { role, .. } => ResolvedAccess::Member { role },
            Resolution::NotMember(read) => classify(
                read.workspace.as_ref(),
                read.membership.as_ref(),
                self.resolved.hierarchy.owner_role(),
            ),
        })
    }
}

/// A resolution failure as the caller is answered: a blank part of the key can only come from the
/// credential, since the workspace id was checked first, and a repository failure is internal.
fn resolve_error(error: ResolveError) -> AuthError {
    match error {
        ResolveError::BlankPart(_) => AuthError::TokenInvalid,
        ResolveError::Repository(error) => internal(error),
    }
}

/// A repository failure as the opaque internal error, the cause kept for the log.
fn internal(error: RepositoryError) -> AuthError {
    AuthError::Internal(Box::new(error))
}

/// `auth.validation` naming `field`, with the rule it breaks.
fn invalid(field: &str, message: String) -> AuthError {
    AuthError::Validation {
        details: vec![FieldError {
            field: field.to_owned(),
            message,
        }],
    }
}

/// The refusal of a path identifier that is over its bound, blank or carries a control character.
#[must_use]
pub fn invalid_path_identifier(field: &str) -> AuthError {
    invalid(
        field,
        format!(
            "{field} must be 1 to {IDENTIFIER_MAX_CHARS} characters, not blank, with no control \
             characters"
        ),
    )
}

/// What a guarded surface asks of [`AuthEngine::authorize_workspace`].
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceAccessRequest<'a> {
    /// The workspace the request names, as the route captured it.
    pub workspace_id: &'a str,
    /// The roles the surface accepts.
    pub accepted: &'a AcceptedRoles,
    /// Whether the owner of a workspace pending deletion is admitted.
    pub allow_pending: bool,
}

/// The page a list request asks for, as the query carried it. The tenant and the workspace of a
/// list are never part of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageQuery<'a> {
    /// The `nextCursor` of the previous page; `None` for the first.
    pub cursor: Option<&'a str>,
    /// The page size as text; `None` for the default.
    pub limit: Option<&'a str>,
}

impl<'a> PageQuery<'a> {
    /// The page size and the cursor, with the bounds of `requestFieldBounds.pageLimit` applied.
    fn checked(self) -> Result<(u32, Option<&'a str>), AuthError> {
        let limit = parse_page_limit(self.limit).map_err(|refused| {
            invalid(
                refused.field,
                "limit must be a whole number from 1 to 100".to_owned(),
            )
        })?;
        if let Some(cursor) = self.cursor {
            check_cursor(cursor).map_err(|refused| {
                invalid(
                    refused.field,
                    "cursor must be 1 to 4096 characters with no control characters".to_owned(),
                )
            })?;
        }
        Ok((u32::from(limit), self.cursor))
    }
}

/// One page of the caller's own workspaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyWorkspaces {
    /// The caller's active memberships of active workspaces, with each workspace.
    pub items: Vec<MembershipWithWorkspace>,
    /// The cursor of the next page, `None` on the last.
    pub next_cursor: Option<String>,
    /// The workspace the caller last switched to, `None` when none is recorded.
    pub last_active_workspace_id: Option<String>,
}

/// A workspace and the caller's role in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAccessView {
    /// The workspace, which is active.
    pub workspace: Workspace,
    /// The caller's role.
    pub role: String,
}

/// Whether a listed membership grants access: an ACTIVE membership of an ACTIVE workspace.
fn grants(item: &MembershipWithWorkspace) -> bool {
    item.membership.status == MembershipStatus::Active && item.workspace.status.grants_access()
}

impl AuthEngine {
    /// The workspace layer, or the internal error a call reaching it while it is off is.
    fn workspace_runtime(&self) -> Result<&WorkspaceRuntime, AuthError> {
        self.workspaces().ok_or_else(|| {
            AuthError::Internal(Box::new(std::io::Error::other(
                "the workspace layer is not enabled",
            )))
        })
    }

    /// The roles that may list a workspace's members (`workspaces.permissions.view_members`), or
    /// `None` when the workspace layer is off.
    #[must_use]
    pub fn workspace_view_members_roles(&self) -> Option<&AcceptedRoles> {
        self.workspaces()
            .map(|runtime| &runtime.resolved.view_members)
    }

    /// Decides whether the caller may act in the workspace a request names: the guard of every
    /// workspace route.
    ///
    /// In order: a surface that declares no role is refused before anything is read; a blank
    /// tenant or caller is not a credential; the workspace id must be 1 to 128 characters, not
    /// blank and without a control character; then the membership is resolved through the
    /// versioned cache and judged by the access decision.
    ///
    /// # Errors
    ///
    /// `auth.forbidden` for a surface declaring no role, `auth.token_invalid` for a blank tenant
    /// or caller, `auth.validation` naming `workspaceId`, then `auth.workspace_not_found`,
    /// `auth.workspace_pending_deletion` or `auth.insufficient_workspace_role`. A repository
    /// failure, or a call while the workspace layer is off, is `auth.internal`.
    pub async fn authorize_workspace(
        &self,
        tenant_id: &str,
        user_id: &str,
        request: WorkspaceAccessRequest<'_>,
    ) -> Result<WorkspaceMember, AuthError> {
        let runtime = self.workspace_runtime()?;
        if request.accepted.declares_nothing() {
            return Err(AuthError::Forbidden);
        }
        if is_blank(tenant_id) || is_blank(user_id) {
            return Err(AuthError::TokenInvalid);
        }
        let workspace_id = request.workspace_id;
        check_identifier("workspaceId", workspace_id)
            .map_err(|refused| invalid_path_identifier(refused.field))?;
        let member = MembershipRef {
            tenant_id,
            workspace_id,
            user_id,
        };
        let access = runtime.resolve(member).await?;
        let rules = SurfaceRules {
            accepted: request.accepted,
            allow_pending: request.allow_pending,
        };
        let role = decide(&access, rules, &runtime.resolved.hierarchy)
            .map_err(|refusal| refusal.code.to_error())?;
        Ok(WorkspaceMember {
            tenant_id: tenant_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            user_id: user_id.to_owned(),
            role,
        })
    }

    /// One page of the caller's own workspaces and the one they last switched to.
    ///
    /// Only the caller's memberships are listed: the tenant and the member are the credential's,
    /// and the cursor only says where the page starts. A row the repository returns that is not an
    /// active membership of an active workspace is left out.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `limit` or `cursor`, `auth.token_invalid` for a blank tenant or
    /// caller, and `auth.internal` for a repository failure or a disabled workspace layer.
    pub async fn list_my_workspaces(
        &self,
        tenant_id: &str,
        user_id: &str,
        query: PageQuery<'_>,
    ) -> Result<MyWorkspaces, AuthError> {
        let runtime = self.workspace_runtime()?;
        let (limit, cursor) = query.checked()?;
        if is_blank(tenant_id) || is_blank(user_id) {
            return Err(AuthError::TokenInvalid);
        }
        let params = ListForUser {
            tenant_id,
            user_id,
            cursor,
            limit,
        };
        let page = runtime
            .memberships
            .list_for_user(params)
            .await
            .map_err(internal)?;
        let last_active_workspace_id = runtime
            .memberships
            .last_active_workspace_id(tenant_id, user_id)
            .await
            .map_err(internal)?;
        Ok(MyWorkspaces {
            items: page.items.into_iter().filter(grants).collect(),
            next_cursor: page.next_cursor,
            last_active_workspace_id,
        })
    }

    /// The workspace `member` was admitted to, and their role in it.
    ///
    /// # Errors
    ///
    /// `auth.workspace_not_found` when the workspace is gone or no longer active, and
    /// `auth.internal` for a repository failure or a disabled workspace layer.
    pub async fn workspace_access(
        &self,
        member: &WorkspaceMember,
    ) -> Result<WorkspaceAccessView, AuthError> {
        let runtime = self.workspace_runtime()?;
        let workspace = runtime
            .workspaces
            .find_by_id(member.workspace())
            .await
            .map_err(internal)?;
        match workspace {
            Some(workspace) if workspace.status.grants_access() => Ok(WorkspaceAccessView {
                workspace,
                role: member.role.clone(),
            }),
            _ => Err(AuthError::WorkspaceNotFound),
        }
    }

    /// One page of the members of the workspace `member` was admitted to, in every membership
    /// status, so an administrator can see a suspended member.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `limit` or `cursor`, and `auth.internal` for a repository failure
    /// or a disabled workspace layer.
    pub async fn list_workspace_members(
        &self,
        member: &WorkspaceMember,
        query: PageQuery<'_>,
    ) -> Result<Page<Membership>, AuthError> {
        let runtime = self.workspace_runtime()?;
        let (limit, cursor) = query.checked()?;
        let params = ListForWorkspace {
            workspace: member.workspace(),
            cursor,
            limit,
        };
        runtime
            .memberships
            .list_for_workspace(params)
            .await
            .map_err(internal)
    }

    /// Records the workspace `member` was admitted to as the one they last switched to. Nothing
    /// about the session changes: the token carries no workspace.
    ///
    /// # Errors
    ///
    /// `auth.internal` for a repository failure or a disabled workspace layer.
    pub async fn switch_workspace(&self, member: &WorkspaceMember) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        runtime
            .memberships
            .set_last_active_workspace_id(&member.tenant_id, &member.user_id, &member.workspace_id)
            .await
            .map_err(internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{InMemoryMembershipCache, InMemoryWorkspaces};
    use crate::workspace::domain::WorkspaceStatus;
    use crate::workspace::keys::BlankPart;
    use time::OffsetDateTime;

    fn listed(membership: MembershipStatus, workspace: WorkspaceStatus) -> MembershipWithWorkspace {
        let at = OffsetDateTime::UNIX_EPOCH;
        MembershipWithWorkspace {
            membership: Membership {
                tenant_id: "t1".to_owned(),
                workspace_id: "w1".to_owned(),
                user_id: "u1".to_owned(),
                role: "member".to_owned(),
                status: membership,
                invited_by_user_id: None,
                created_at: at,
                updated_at: at,
            },
            workspace: Workspace {
                id: "w1".to_owned(),
                tenant_id: "t1".to_owned(),
                name: "Acme".to_owned(),
                status: workspace,
                created_at: at,
                deletion_scheduled_at: None,
            },
        }
    }

    #[test]
    fn a_listed_row_grants_access_only_as_an_active_membership_of_an_active_workspace() {
        // The repository promises the same filter; the service decides it again so a host that
        // returns more cannot widen the caller's list.
        assert!(grants(&listed(
            MembershipStatus::Active,
            WorkspaceStatus::Active
        )));
        assert!(!grants(&listed(
            MembershipStatus::Suspended,
            WorkspaceStatus::Active
        )));
        for status in [
            WorkspaceStatus::PendingDeletion,
            WorkspaceStatus::Suspended,
            WorkspaceStatus::Deleted,
        ] {
            assert!(
                !grants(&listed(MembershipStatus::Active, status)),
                "{status:?}"
            );
        }
    }

    #[test]
    fn any_one_collaborator_counts_as_supplied() {
        let repo = Arc::new(InMemoryWorkspaces::new());
        assert!(!WorkspaceCollaborators::default().any());
        let only_workspaces = WorkspaceCollaborators {
            workspaces: Some(repo.clone()),
            ..WorkspaceCollaborators::default()
        };
        let only_memberships = WorkspaceCollaborators {
            memberships: Some(repo),
            ..WorkspaceCollaborators::default()
        };
        let only_cache = WorkspaceCollaborators {
            cache_store: Some(Arc::new(InMemoryMembershipCache::new())),
            ..WorkspaceCollaborators::default()
        };
        for collaborators in [only_workspaces, only_memberships, only_cache] {
            assert!(collaborators.any());
        }
    }

    #[test]
    fn a_blank_key_part_is_a_bad_credential_and_a_repository_failure_is_internal() {
        let blank = resolve_error(ResolveError::BlankPart(BlankPart { part: "userId" }));
        assert!(matches!(blank, AuthError::TokenInvalid));
        let failed = resolve_error(ResolveError::Repository(RepositoryError::Conflict(
            "down".to_owned(),
        )));
        assert!(matches!(failed, AuthError::Internal(_)));
    }
}
