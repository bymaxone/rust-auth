//! The membership half of [`InMemoryWorkspaces`](super::InMemoryWorkspaces) (layer: test double).
//!
//! Every ownership rule is decided under the same lock as the write it guards, which is what a
//! host's transaction must do.

use async_trait::async_trait;

use super::workspace::{
    InMemoryWorkspaces, State, lock, membership_key, paginate, query_scope, sort_key,
};
use crate::RepositoryError;
use crate::traits::MembershipRepository;
use crate::traits::membership_repository::{
    ChangeRole, CreateMembership, CreateMembershipOutcome, ListForUser, ListForWorkspace,
    ListSoleOwned, MemberChangeOutcome, OwnedBy, RemoveAllForUser, RemoveAllOutcome,
    RemoveMembership, RemovedMembership, TransferOutcome, TransferOwnership,
};
use crate::workspace::audit::{AuditKind, WorkspaceAuditEvent};
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, MembershipWithWorkspace, Page, Workspace,
    WorkspaceRef, WorkspaceStatus,
};

impl State {
    /// The workspaces `member` is the only active holder of `owner_role` in.
    fn sole_owned(&self, owner: OwnedBy<'_>) -> Vec<&Workspace> {
        self.owned_by(owner)
            .into_iter()
            .filter(|w| {
                let workspace = WorkspaceRef {
                    tenant_id: &w.tenant_id,
                    workspace_id: &w.id,
                };
                self.active_owners(workspace, owner.owner_role).len() == 1
            })
            .collect()
    }

    /// Applies a role change or a removal's preconditions: the actor's standing, then the member's
    /// row and role.
    fn judge(
        &self,
        member: MembershipRef<'_>,
        actor: Option<crate::workspace::domain::ActingMember<'_>>,
        expected_role: Option<&str>,
    ) -> Option<MemberChangeOutcome> {
        if actor.is_some_and(|a| !self.actor_holds(member.workspace(), a)) {
            return Some(MemberChangeOutcome::ActorChanged);
        }
        let Some(held) = self.member(member) else {
            return Some(MemberChangeOutcome::NotFound);
        };
        let role_differs = expected_role.is_some_and(|role| held.role != role);
        let inactive_with_role = expected_role.is_some() && held.status != MembershipStatus::Active;
        (role_differs || inactive_with_role).then_some(MemberChangeOutcome::NotFound)
    }
}

fn audit_for_removal(params: &RemoveAllForUser<'_>, workspace_id: &str) -> WorkspaceAuditEvent {
    WorkspaceAuditEvent {
        tenant_id: params.audit.tenant_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        actor_user_id: params.audit.actor_user_id.map(str::to_owned),
        at: params.audit.at.to_owned(),
        kind: AuditKind::MemberRemoved {
            user_id: params.audit.user_id.to_owned(),
        },
    }
}

#[async_trait]
impl MembershipRepository for InMemoryWorkspaces {
    async fn find(&self, member: MembershipRef<'_>) -> Result<Option<Membership>, RepositoryError> {
        Ok(lock(&self.state).member(member).cloned())
    }

    async fn list_for_user(
        &self,
        params: ListForUser<'_>,
    ) -> Result<Page<MembershipWithWorkspace>, RepositoryError> {
        let state = lock(&self.state);
        let rows = state
            .members
            .values()
            .filter(|m| {
                m.tenant_id == params.tenant_id
                    && m.user_id == params.user_id
                    && m.status == MembershipStatus::Active
            })
            .filter_map(|m| {
                let workspace = state
                    .workspaces
                    .get(&(m.tenant_id.clone(), m.workspace_id.clone()))?;
                (workspace.status == WorkspaceStatus::Active).then(|| {
                    (
                        sort_key(m.created_at, &m.workspace_id),
                        MembershipWithWorkspace {
                            membership: m.clone(),
                            workspace: workspace.clone(),
                        },
                    )
                })
            })
            .collect();
        let scope = query_scope("user", &[params.tenant_id, params.user_id]);
        Ok(paginate(rows, &scope, params.cursor, params.limit))
    }

    async fn list_for_workspace(
        &self,
        params: ListForWorkspace<'_>,
    ) -> Result<Page<Membership>, RepositoryError> {
        let state = lock(&self.state);
        let rows = state
            .members
            .values()
            .filter(|m| {
                m.tenant_id == params.workspace.tenant_id
                    && m.workspace_id == params.workspace.workspace_id
            })
            .map(|m| (sort_key(m.created_at, &m.user_id), m.clone()))
            .collect();
        let workspace = params.workspace;
        let scope = query_scope("workspace", &[workspace.tenant_id, workspace.workspace_id]);
        Ok(paginate(rows, &scope, params.cursor, params.limit))
    }

    async fn create(
        &self,
        params: CreateMembership<'_>,
    ) -> Result<CreateMembershipOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let key = membership_key(params.member);
        if !state
            .workspaces
            .contains_key(&(key.0.clone(), key.1.clone()))
        {
            return Ok(CreateMembershipOutcome::WorkspaceNotFound);
        }
        if state.members.contains_key(&key) {
            return Ok(CreateMembershipOutcome::AlreadyMember);
        }
        let now = state.now();
        state.members.insert(
            key,
            Membership {
                tenant_id: params.member.tenant_id.to_owned(),
                workspace_id: params.member.workspace_id.to_owned(),
                user_id: params.member.user_id.to_owned(),
                role: params.role.to_owned(),
                status: MembershipStatus::Active,
                invited_by_user_id: params.invited_by_user_id.map(str::to_owned),
                created_at: now,
                updated_at: now,
            },
        );
        state.record(params.audit);
        Ok(CreateMembershipOutcome::Done)
    }

    async fn change_role(
        &self,
        params: ChangeRole<'_>,
    ) -> Result<MemberChangeOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let refused = state.judge(
            params.member,
            Some(params.actor),
            Some(params.expected_role),
        );
        if let Some(outcome) = refused {
            return Ok(outcome);
        }
        let demotes = params.expected_role == params.owner_role && params.role != params.owner_role;
        if demotes && state.would_orphan(params.member, params.owner_role) {
            return Ok(MemberChangeOutcome::LastOwner);
        }
        let now = state.now();
        if let Some(held) = state.members.get_mut(&membership_key(params.member)) {
            held.role = params.role.to_owned();
            held.updated_at = now;
        }
        state.record(params.audit);
        Ok(MemberChangeOutcome::Done)
    }

    async fn remove(
        &self,
        params: RemoveMembership<'_>,
    ) -> Result<MemberChangeOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let refused = state.judge(params.member, params.actor, params.expected_role);
        if let Some(outcome) = refused {
            return Ok(outcome);
        }
        if state.would_orphan(params.member, params.owner_role) {
            return Ok(MemberChangeOutcome::LastOwner);
        }
        state.members.remove(&membership_key(params.member));
        state.record(params.audit);
        Ok(MemberChangeOutcome::Done)
    }

    async fn remove_all_for_user(
        &self,
        params: RemoveAllForUser<'_>,
    ) -> Result<RemoveAllOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let mut blocking: Vec<String> = state
            .sole_owned(OwnedBy {
                tenant_id: params.tenant_id,
                user_id: params.user_id,
                owner_role: params.owner_role,
            })
            .into_iter()
            .filter(|w| w.status.blocks_account_removal())
            .map(|w| w.id.clone())
            .collect();
        if !blocking.is_empty() {
            blocking.sort();
            return Ok(RemoveAllOutcome::LastOwner(blocking));
        }
        let mut held: Vec<Membership> = state
            .members
            .values()
            .filter(|m| m.tenant_id == params.tenant_id && m.user_id == params.user_id)
            .cloned()
            .collect();
        held.sort_by(|a, b| a.workspace_id.cmp(&b.workspace_id));
        let mut removed = Vec::with_capacity(held.len());
        for membership in held {
            state.members.remove(&membership_key(membership.key()));
            state.record(&audit_for_removal(&params, &membership.workspace_id));
            removed.push(RemovedMembership {
                workspace_id: membership.workspace_id,
                role: membership.role,
            });
        }
        Ok(RemoveAllOutcome::Removed(removed))
    }

    async fn transfer_ownership(
        &self,
        params: TransferOwnership<'_>,
    ) -> Result<TransferOutcome, RepositoryError> {
        let mut state = lock(&self.state);
        let from = MembershipRef {
            tenant_id: params.workspace.tenant_id,
            workspace_id: params.workspace.workspace_id,
            user_id: params.from_user_id,
        };
        let to = MembershipRef {
            user_id: params.to_user_id,
            ..from
        };
        let from_is_owner = state
            .member(from)
            .is_some_and(|m| m.status == MembershipStatus::Active && m.role == params.owner_role);
        if !from_is_owner {
            return Ok(TransferOutcome::NotFound);
        }
        if state
            .member(to)
            .is_none_or(|m| m.status != MembershipStatus::Active)
        {
            return Ok(TransferOutcome::TargetNotMember);
        }
        let now = state.now();
        // Demote first, so a transfer to oneself ends as an owner rather than as nothing.
        if let Some(role) = params.demote_from_to {
            set_role(&mut state, from, role, now);
        }
        set_role(&mut state, to, params.owner_role, now);
        state.record(params.audit);
        Ok(TransferOutcome::Done)
    }

    async fn count_owned(&self, params: OwnedBy<'_>) -> Result<u64, RepositoryError> {
        Ok(lock(&self.state).owned_by(params).len() as u64)
    }

    async fn list_sole_owned(
        &self,
        params: ListSoleOwned<'_>,
    ) -> Result<Page<Workspace>, RepositoryError> {
        let state = lock(&self.state);
        let rows = state
            .sole_owned(params.owner)
            .into_iter()
            .map(|w| (sort_key(w.created_at, &w.id), w.clone()))
            .collect();
        let owner = params.owner;
        let scope = query_scope("sole", &[owner.tenant_id, owner.user_id, owner.owner_role]);
        Ok(paginate(rows, &scope, params.cursor, params.limit))
    }

    async fn last_active_workspace_id(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, RepositoryError> {
        let key = (tenant_id.to_owned(), user_id.to_owned());
        Ok(lock(&self.state).last_active.get(&key).cloned())
    }

    async fn set_last_active_workspace_id(
        &self,
        tenant_id: &str,
        user_id: &str,
        workspace_id: &str,
    ) -> Result<(), RepositoryError> {
        let key = (tenant_id.to_owned(), user_id.to_owned());
        lock(&self.state)
            .last_active
            .insert(key, workspace_id.to_owned());
        Ok(())
    }
}

fn set_role(state: &mut State, member: MembershipRef<'_>, role: &str, now: time::OffsetDateTime) {
    if let Some(held) = state.members.get_mut(&membership_key(member)) {
        held.role = role.to_owned();
        held.updated_at = now;
    }
}
