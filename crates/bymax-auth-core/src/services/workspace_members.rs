//! Who belongs to a workspace and with which role: changing a member's role, removing a member,
//! leaving, and handing ownership over (layer: service).
//!
//! Every write is made by the repository together with its audit event, and the last-owner rule is
//! decided there, in the same transaction as the write: the last owner cannot leave, be removed or
//! be demoted. A successful write bumps the counter of each membership it changed, so the change
//! takes effect on that member's next request, and a bump that fails is an error.
//!
//! The role ceiling: the owner role acts on any role, other owners included; every other role acts
//! only STRICTLY below itself, on a role it includes and never on its own. It is judged from roles
//! read before the write, so the write carries both, the member's `expected_role` and the actor's,
//! and the repository checks them in its own transaction. Changing a role and removing a member
//! act only on an ACTIVE member; a suspended one answers the identical `404
//! auth.workspace_not_found` (`workspaceInvitations.rules.membershipStatus`).

use bymax_auth_types::AuthError;

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::workspace::{WorkspaceRuntime, internal, invalid, invalid_path_identifier};
use crate::services::workspace_writes::{
    acting, audit_event, member_change, member_hook_context, now_iso,
};
use crate::traits::membership_repository::{
    ChangeRole, RemoveMembership, TransferOutcome, TransferOwnership,
};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::AuditKind;
use crate::workspace::bounds::check_identifier;
use crate::workspace::domain::{ActingMember, Membership, MembershipRef, MembershipStatus};

/// A hand-over of ownership: the member who becomes an owner, the role the giver keeps, and the
/// giver's proof.
#[derive(Debug, Clone, Copy)]
pub struct OwnershipHandOver<'a> {
    /// The active member of the same workspace who becomes an owner.
    pub to_user_id: &'a str,
    /// The role the giver takes afterwards, a role of the hierarchy other than the owner role, or
    /// `None` to keep both as owners.
    pub demote_self_to: Option<&'a str>,
    /// The giver's current password; `None` for an account with no password, which proves a
    /// recent sign-in instead.
    pub password: Option<&'a str>,
}

/// A removal's conditions: the membership, and the roles it was judged against (none when a member
/// leaves).
#[derive(Clone, Copy)]
struct Removal<'a> {
    member: MembershipRef<'a>,
    expected_role: Option<&'a str>,
    actor: Option<ActingMember<'a>>,
}

/// The `400 auth.validation` naming `userId` for a receiver who is not an active member.
fn not_an_active_member() -> AuthError {
    invalid("userId", "userId must be an active member".to_owned())
}

impl WorkspaceRuntime {
    /// Whether a member holding `actor` may act on `other`: the owner role on any role, every
    /// other role only on a role it includes and does not itself hold.
    fn outranks(&self, actor: &str, other: &str) -> bool {
        let hierarchy = &self.resolved.hierarchy;
        actor == hierarchy.owner_role() || (actor != other && hierarchy.satisfies(actor, other))
    }

    /// The ACTIVE member `target` of `member`'s workspace, refused when the actor does not
    /// outrank the role they hold.
    async fn active_target(
        &self,
        member: &WorkspaceMember,
        target: &str,
    ) -> Result<Membership, AuthError> {
        let key = MembershipRef {
            user_id: target,
            ..member.key()
        };
        let found = self.memberships.find(key).await.map_err(internal)?;
        let Some(held) = found.filter(|held| held.status == MembershipStatus::Active) else {
            return Err(AuthError::WorkspaceNotFound);
        };
        if !self.outranks(&member.role, &held.role) {
            return Err(AuthError::InsufficientWorkspaceRole);
        }
        Ok(held)
    }

    /// The membership as it now stands.
    async fn current(&self, key: MembershipRef<'_>) -> Result<Membership, AuthError> {
        self.memberships
            .find(key)
            .await
            .map_err(internal)?
            .ok_or(AuthError::WorkspaceNotFound)
    }

    /// Refuses, from the request alone, a hand-over that cannot succeed: only an owner hands
    /// ownership over, not to themselves, and the role they keep is a role other than the owner
    /// role. Then the receiver must be an ACTIVE member of this workspace, read before anything
    /// costly is spent.
    async fn check_hand_over(
        &self,
        member: &WorkspaceMember,
        hand_over: OwnershipHandOver<'_>,
    ) -> Result<(), AuthError> {
        let hierarchy = &self.resolved.hierarchy;
        if member.role != hierarchy.owner_role() {
            return Err(AuthError::InsufficientWorkspaceRole);
        }
        if hand_over.to_user_id == member.user_id {
            let message = "ownership cannot be handed to oneself".to_owned();
            return Err(invalid("userId", message));
        }
        if let Some(role) = hand_over.demote_self_to
            && (!hierarchy.knows(role) || role == hierarchy.owner_role())
        {
            let message = "demoteSelfTo must be a workspace role other than the owner role";
            return Err(invalid("demoteSelfTo", message.to_owned()));
        }
        if check_identifier("userId", hand_over.to_user_id).is_err() {
            return Err(not_an_active_member());
        }
        let key = MembershipRef {
            user_id: hand_over.to_user_id,
            ..member.key()
        };
        let receiver = self.memberships.find(key).await.map_err(internal)?;
        if receiver.is_none_or(|held| held.status != MembershipStatus::Active) {
            return Err(not_an_active_member());
        }
        Ok(())
    }
}

impl AuthEngine {
    /// Gives `target_user_id`, an active member of the workspace `member` was admitted to, the
    /// role `role`, and answers the membership as it now stands.
    ///
    /// In order: `target_user_id` is a well-formed identifier, `role` is a role of the hierarchy,
    /// the actor outranks it, the target is ACTIVE and the actor outranks the role it holds. A
    /// target who already holds `role` is not written, but their cached access is still ended, so
    /// the retry of a change whose bump failed completes it.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `userId` or `role`, `auth.insufficient_workspace_role` above the
    /// ceiling or when the actor's role changed, `auth.workspace_not_found` for a target who is
    /// not an active member or whose role changed, `auth.last_owner` when it would leave the
    /// workspace without an owner, and `auth.internal` for a repository or cache failure.
    pub async fn change_member_role(
        &self,
        member: &WorkspaceMember,
        target_user_id: &str,
        role: &str,
        ctx: &RequestContext,
    ) -> Result<Membership, AuthError> {
        let runtime = self.workspace_runtime()?;
        check_identifier("userId", target_user_id)
            .map_err(|_| invalid_path_identifier("userId"))?;
        if !runtime.resolved.hierarchy.knows(role) {
            return Err(invalid(
                "role",
                "role must be one of the workspace roles".to_owned(),
            ));
        }
        if !runtime.outranks(&member.role, role) {
            return Err(AuthError::InsufficientWorkspaceRole);
        }
        let held = runtime.active_target(member, target_user_id).await?;
        let key = held.key();
        if held.role == role {
            runtime.invalidate_membership(key).await?;
            return Ok(held);
        }
        let kind = AuditKind::MemberRoleChanged {
            user_id: target_user_id.to_owned(),
            from: held.role.clone(),
            to: role.to_owned(),
        };
        let event = audit_event(member.workspace(), Some(&member.user_id), &now_iso(), kind);
        let params = ChangeRole {
            member: key,
            role,
            expected_role: &held.role,
            actor: acting(member),
            owner_role: runtime.resolved.hierarchy.owner_role(),
            audit: &event,
        };
        member_change(
            runtime
                .memberships
                .change_role(params)
                .await
                .map_err(internal)?,
        )?;
        runtime.invalidate_membership(key).await?;
        self.notify_workspace_event(event, member_hook_context(ctx, member));
        runtime.current(key).await
    }

    /// Removes `target_user_id`, an active member whose role the actor outranks, from the
    /// workspace `member` was admitted to.
    ///
    /// # Errors
    ///
    /// `auth.validation` naming `userId`, `auth.workspace_not_found` for a target who is not an
    /// active member or whose role changed, `auth.insufficient_workspace_role` above the ceiling
    /// or when the actor's role changed, `auth.last_owner`, and `auth.internal` for a repository or
    /// cache failure. Once removed, a retry answers `auth.workspace_not_found`, so after a failed
    /// bump the stale access ends with the cache lifetime.
    pub async fn remove_workspace_member(
        &self,
        member: &WorkspaceMember,
        target_user_id: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        check_identifier("userId", target_user_id)
            .map_err(|_| invalid_path_identifier("userId"))?;
        let held = runtime.active_target(member, target_user_id).await?;
        let removal = Removal {
            member: held.key(),
            expected_role: Some(&held.role),
            actor: Some(acting(member)),
        };
        let kind = AuditKind::MemberRemoved {
            user_id: target_user_id.to_owned(),
        };
        self.apply_removal(runtime, removal, kind, (ctx, member))
            .await
    }

    /// Lets `member` leave the workspace they were admitted to. Reached only through the guard,
    /// which resolves an ACTIVE membership, and authorized by no role, so the write carries none.
    ///
    /// # Errors
    ///
    /// `auth.last_owner` for the last owner, who must hand ownership over or delete the workspace
    /// first, `auth.workspace_not_found` when the membership is gone, and `auth.internal` for a
    /// repository or cache failure.
    pub async fn leave_workspace(
        &self,
        member: &WorkspaceMember,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        let removal = Removal {
            member: member.key(),
            expected_role: None,
            actor: None,
        };
        let kind = AuditKind::MemberLeft {
            user_id: member.user_id.clone(),
        };
        self.apply_removal(runtime, removal, kind, (ctx, member))
            .await
    }

    /// Writes a removal made by `actor` with its audit event, ends the removed member's cached
    /// access and reports the event.
    async fn apply_removal(
        &self,
        runtime: &WorkspaceRuntime,
        removal: Removal<'_>,
        kind: AuditKind,
        (ctx, actor): (&RequestContext, &WorkspaceMember),
    ) -> Result<(), AuthError> {
        let event = audit_event(actor.workspace(), Some(&actor.user_id), &now_iso(), kind);
        let params = RemoveMembership {
            member: removal.member,
            expected_role: removal.expected_role,
            actor: removal.actor,
            owner_role: runtime.resolved.hierarchy.owner_role(),
            audit: &event,
        };
        member_change(runtime.memberships.remove(params).await.map_err(internal)?)?;
        runtime.invalidate_membership(removal.member).await?;
        self.notify_workspace_event(event, member_hook_context(ctx, actor));
        Ok(())
    }

    /// Hands ownership of the workspace `member` was admitted to over to another ACTIVE member,
    /// running the checks from cheapest to costliest: what the request alone decides, then that
    /// the receiver is active, then the giver's re-proof, then one repository write that decides
    /// both again, so there is never a moment with no owner.
    ///
    /// # Errors
    ///
    /// `auth.insufficient_workspace_role` when the actor is not an owner, `auth.validation` naming
    /// `userId` (oneself, or a receiver who is not an active member, checked before the password
    /// and again by the write) or `demoteSelfTo`, the re-proof's refusals,
    /// `auth.workspace_not_found` when the giver is no longer an active owner, and `auth.internal`
    /// for a repository or cache failure.
    pub async fn transfer_workspace_ownership(
        &self,
        member: &WorkspaceMember,
        hand_over: OwnershipHandOver<'_>,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        runtime.check_hand_over(member, hand_over).await?;
        self.reprove_workspace_member(member, hand_over.password)
            .await?;
        let kind = AuditKind::OwnershipTransferred {
            from_user_id: member.user_id.clone(),
            to_user_id: hand_over.to_user_id.to_owned(),
        };
        let event = audit_event(member.workspace(), Some(&member.user_id), &now_iso(), kind);
        let params = TransferOwnership {
            workspace: member.workspace(),
            from_user_id: &member.user_id,
            to_user_id: hand_over.to_user_id,
            owner_role: runtime.resolved.hierarchy.owner_role(),
            demote_from_to: hand_over.demote_self_to,
            audit: &event,
        };
        match runtime
            .memberships
            .transfer_ownership(params)
            .await
            .map_err(internal)?
        {
            TransferOutcome::Done => {}
            TransferOutcome::NotFound => return Err(AuthError::WorkspaceNotFound),
            TransferOutcome::TargetNotMember => return Err(not_an_active_member()),
        }
        let receiver = MembershipRef {
            user_id: hand_over.to_user_id,
            ..member.key()
        };
        runtime.invalidate_membership(member.key()).await?;
        runtime.invalidate_membership(receiver).await?;
        self.notify_workspace_event(event, member_hook_context(ctx, member));
        Ok(())
    }
}
