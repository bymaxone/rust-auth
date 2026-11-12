//! An in-memory workspace and membership repository that enforces the rules a host's
//! implementation is held to (layer: test double).
//!
//! One value implements both [`WorkspaceRepository`] and [`MembershipRepository`] over one state,
//! because the rules cross them: a rename checks the actor's membership, a creation counts the
//! creator's owned workspaces, and an ownership rule reads every owner of a workspace. Every call
//! restricts its read and write to the tenant, decides the ownership and compare-and-set rules in
//! the same critical section as the write, and persists the audit event with the change; a refused
//! call writes nothing, the audit event included.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::RepositoryError;
use crate::traits::WorkspaceRepository;
use crate::traits::membership_repository::OwnedBy;
use crate::traits::workspace_repository::{
    CreateWorkspaceOutcome, CreateWorkspaceWithOwner, RenameOutcome, RenameWorkspace,
    UpdateStatusOutcome, UpdateWorkspaceStatus,
};
use crate::workspace::audit::WorkspaceAuditEvent;
use crate::workspace::domain::{
    ActingMember, Membership, MembershipRef, MembershipStatus, Page, Workspace, WorkspaceRef,
    WorkspaceStatus,
};

pub(super) type WorkspaceKey = (String, String);
pub(super) type MembershipKey = (String, String, String);

#[derive(Default)]
pub(super) struct State {
    pub(super) workspaces: BTreeMap<WorkspaceKey, Workspace>,
    pub(super) members: BTreeMap<MembershipKey, Membership>,
    pub(super) audit: Vec<WorkspaceAuditEvent>,
    pub(super) last_active: BTreeMap<WorkspaceKey, String>,
    tick: i64,
}

/// The in-memory repository. Creation instants are consecutive seconds from the Unix epoch, so
/// listings are ordered by creation and two rows never share one.
#[derive(Default)]
pub struct InMemoryWorkspaces {
    pub(super) state: Mutex<State>,
}

pub(super) fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn workspace_key(workspace: WorkspaceRef<'_>) -> WorkspaceKey {
    (
        workspace.tenant_id.to_owned(),
        workspace.workspace_id.to_owned(),
    )
}

pub(super) fn membership_key(member: MembershipRef<'_>) -> MembershipKey {
    (
        member.tenant_id.to_owned(),
        member.workspace_id.to_owned(),
        member.user_id.to_owned(),
    )
}

/// The sort key of a row: its creation second, zero-padded, then its id.
pub(super) fn sort_key(created_at: OffsetDateTime, id: &str) -> String {
    format!("{:020}:{id}", created_at.unix_timestamp())
}

/// Whether `cursor` has the shape this double issues; any other value restarts from the first page.
pub(super) fn well_formed(cursor: &str) -> bool {
    cursor.as_bytes().get(20) == Some(&b':') && cursor.bytes().take(20).all(|b| b.is_ascii_digit())
}

/// One page of `rows` (sort key, row) in key order, after `cursor`.
pub(super) fn paginate<T>(mut rows: Vec<(String, T)>, cursor: Option<&str>, limit: u32) -> Page<T> {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let after = cursor.filter(|c| well_formed(c));
    let size = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
    let mut rest: Vec<(String, T)> = rows
        .into_iter()
        .filter(|(key, _)| after.is_none_or(|c| key.as_str() > c))
        .collect();
    let more = rest.len() > size;
    rest.truncate(size);
    let next_cursor = if more {
        rest.last().map(|(key, _)| key.clone())
    } else {
        None
    };
    Page {
        items: rest.into_iter().map(|(_, row)| row).collect(),
        next_cursor,
    }
}

/// The new workspace and its owner's membership, both created at `now`.
fn new_workspace_with_owner(
    params: &CreateWorkspaceWithOwner<'_>,
    now: OffsetDateTime,
) -> (Workspace, Membership) {
    let workspace = Workspace {
        id: params.workspace.workspace_id.to_owned(),
        tenant_id: params.workspace.tenant_id.to_owned(),
        name: params.name.to_owned(),
        status: WorkspaceStatus::Active,
        created_at: now,
        deletion_scheduled_at: None,
    };
    let owner = Membership {
        tenant_id: workspace.tenant_id.clone(),
        workspace_id: workspace.id.clone(),
        user_id: params.owner_user_id.to_owned(),
        role: params.owner_role.to_owned(),
        status: MembershipStatus::Active,
        invited_by_user_id: None,
        created_at: now,
        updated_at: now,
    };
    (workspace, owner)
}

impl State {
    pub(super) fn now(&mut self) -> OffsetDateTime {
        self.tick += 1;
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(self.tick)
    }

    pub(super) fn member(&self, member: MembershipRef<'_>) -> Option<&Membership> {
        self.members.get(&membership_key(member))
    }

    pub(super) fn actor_holds(&self, workspace: WorkspaceRef<'_>, actor: ActingMember<'_>) -> bool {
        self.member(MembershipRef {
            tenant_id: workspace.tenant_id,
            workspace_id: workspace.workspace_id,
            user_id: actor.user_id,
        })
        .is_some_and(|m| m.status == MembershipStatus::Active && m.role == actor.expected_role)
    }

    pub(super) fn active_owners(
        &self,
        workspace: WorkspaceRef<'_>,
        owner_role: &str,
    ) -> Vec<&Membership> {
        self.members
            .values()
            .filter(|m| {
                m.tenant_id == workspace.tenant_id
                    && m.workspace_id == workspace.workspace_id
                    && m.role == owner_role
                    && m.status == MembershipStatus::Active
            })
            .collect()
    }

    /// Whether removing or demoting `member` would leave `workspace` with no active owner.
    pub(super) fn would_orphan(&self, member: MembershipRef<'_>, owner_role: &str) -> bool {
        let owners = self.active_owners(member.workspace(), owner_role);
        owners.len() == 1 && owners.iter().any(|m| m.user_id == member.user_id)
    }

    pub(super) fn owned_by(&self, owner: OwnedBy<'_>) -> Vec<&Workspace> {
        self.members
            .values()
            .filter(|m| {
                m.tenant_id == owner.tenant_id
                    && m.user_id == owner.user_id
                    && m.role == owner.owner_role
                    && m.status == MembershipStatus::Active
            })
            .filter_map(|m| {
                self.workspaces
                    .get(&(m.tenant_id.clone(), m.workspace_id.clone()))
            })
            .filter(|w| w.status != WorkspaceStatus::Deleted)
            .collect()
    }

    pub(super) fn record(&mut self, event: &WorkspaceAuditEvent) {
        self.audit.push(event.clone());
    }
}

impl InMemoryWorkspaces {
    /// An empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a workspace as given, for a state `create_with_owner` cannot produce (a suspended
    /// or pending-deletion workspace). Its creation instant is the one in `workspace`.
    pub fn seed_workspace(&self, workspace: Workspace) {
        let key = (workspace.tenant_id.clone(), workspace.id.clone());
        lock(&self.state).workspaces.insert(key, workspace);
    }

    /// Inserts a membership as given, for a state `create` cannot produce (a suspended member).
    pub fn seed_membership(&self, membership: Membership) {
        let key = (
            membership.tenant_id.clone(),
            membership.workspace_id.clone(),
            membership.user_id.clone(),
        );
        lock(&self.state).members.insert(key, membership);
    }

    /// The audit events persisted so far, in order.
    #[must_use]
    pub fn audit_events(&self) -> Vec<WorkspaceAuditEvent> {
        lock(&self.state).audit.clone()
    }

    /// One membership as stored, in any status.
    #[must_use]
    pub fn membership(&self, member: MembershipRef<'_>) -> Option<Membership> {
        lock(&self.state).member(member).cloned()
    }
}

#[async_trait]
impl WorkspaceRepository for InMemoryWorkspaces {
    async fn create_with_owner(
        &self,
        params: CreateWorkspaceWithOwner<'_>,
    ) -> Result<CreateWorkspaceOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let key = workspace_key(params.workspace);
        if state.workspaces.contains_key(&key) {
            return Err(RepositoryError::Conflict("workspace id in use".to_owned()));
        }
        let owned = state.owned_by(OwnedBy {
            tenant_id: params.workspace.tenant_id,
            user_id: params.owner_user_id,
            owner_role: params.owner_role,
        });
        let cap = u64::from(params.max_workspaces_per_user);
        if cap != 0 && owned.len() as u64 >= cap {
            return Ok(CreateWorkspaceOutcome::LimitReached);
        }
        let (workspace, owner) = new_workspace_with_owner(&params, state.now());
        state.workspaces.insert(key, workspace.clone());
        state.members.insert(membership_key(owner.key()), owner);
        state.record(params.audit);
        Ok(CreateWorkspaceOutcome::Created(workspace))
    }

    async fn find_by_id(
        &self,
        workspace: WorkspaceRef<'_>,
    ) -> Result<Option<Workspace>, RepositoryError> {
        Ok(lock(&self.state)
            .workspaces
            .get(&workspace_key(workspace))
            .cloned())
    }

    async fn rename(&self, params: RenameWorkspace<'_>) -> Result<RenameOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let key = workspace_key(params.workspace);
        if !state.workspaces.contains_key(&key) {
            return Ok(RenameOutcome::NotFound);
        }
        if !state.actor_holds(params.workspace, params.actor) {
            return Ok(RenameOutcome::ActorChanged);
        }
        if let Some(workspace) = state.workspaces.get_mut(&key) {
            workspace.name = params.name.to_owned();
        }
        state.record(params.audit);
        Ok(RenameOutcome::Done)
    }

    async fn update_status(
        &self,
        params: UpdateWorkspaceStatus<'_>,
    ) -> Result<UpdateStatusOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let key = workspace_key(params.workspace);
        let Some(stored) = state.workspaces.get(&key) else {
            return Ok(UpdateStatusOutcome::NotFound);
        };
        if params
            .actor
            .is_some_and(|actor| !state.actor_holds(params.workspace, actor))
        {
            return Ok(UpdateStatusOutcome::ActorChanged);
        }
        let instant_differs = params
            .expected_deletion_scheduled_at
            .is_some_and(|expected| expected != stored.deletion_scheduled_at);
        if stored.status != params.expected_status || instant_differs {
            return Ok(UpdateStatusOutcome::StatusConflict);
        }
        if let Some(workspace) = state.workspaces.get_mut(&key) {
            workspace.status = params.status;
            workspace.deletion_scheduled_at = params.deletion_scheduled_at;
        }
        state.record(params.audit);
        Ok(UpdateStatusOutcome::Done)
    }
}
