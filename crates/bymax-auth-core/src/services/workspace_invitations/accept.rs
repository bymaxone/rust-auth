//! Accepting a workspace invitation: by a signed-in account whose address it names, or by a
//! holder with no account yet, who creates one (layer: service).
//!
//! The order is the contract. Everything that can be decided without spending the token is decided
//! first, the membership is written next, and the token is spent only after that. A failure before
//! the membership write leaves the invitation in place. When the spend itself fails after the
//! write, accepting again while signed in finds the membership, which counts as success.

use std::collections::BTreeMap;

use bymax_auth_types::{AuthError, AuthResult, CreateUserData, SafeAuthUser};
use time::OffsetDateTime;

use crate::RepositoryError;
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::normalize::normalize_email;
use crate::services::auth::detached::run_after_invitation_accepted;
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::services::token_manager::CredentialProof;
use crate::services::workspace::{WorkspaceRuntime, internal};
use crate::services::workspace_lifecycle::OwnedWorkspace;
use crate::services::workspace_writes::audit_event;
use crate::traits::membership_repository::{CreateMembership, CreateMembershipOutcome};
use crate::traits::workspace_invitation_store::Removal;
use crate::traits::{HookContext, HookPlane};
use crate::workspace::audit::{AuditKind, iso_instant};
use crate::workspace::domain::{MembershipRef, MembershipStatus, WorkspaceRef, WorkspaceStatus};
use crate::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use crate::workspace::keys::invitation_record_id;

#[cfg(feature = "oauth")]
pub(crate) mod oauth;
#[cfg(test)]
mod tests;

/// Where an account belongs after an acceptance, and as what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWorkspaceInvitation {
    /// The workspace joined.
    pub workspace_id: String,
    /// The role held there, which is the role already held when the account was a member before.
    pub role: String,
}

/// A holder's token and the account to create for the invited address. The `Debug` impl redacts
/// the token and the password.
#[derive(Clone)]
pub struct WorkspaceSignupInput {
    /// The raw invitation token.
    pub token: String,
    /// The new account's display name.
    pub name: String,
    /// The new account's password.
    pub password: String,
}

impl std::fmt::Debug for WorkspaceSignupInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceSignupInput")
            .field("token", &"[REDACTED]")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// What a signup acceptance answers: the new account's session and where it now belongs. The
/// `Debug` impl redacts the session, which carries both tokens and the address.
#[derive(Clone)]
pub struct WorkspaceSignup {
    /// The session, issued as a sign-in would.
    pub result: AuthResult,
    /// The workspace joined and the role held there.
    pub accepted: AcceptedWorkspaceInvitation,
}

impl std::fmt::Debug for WorkspaceSignup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceSignup")
            .field("result", &"[REDACTED]")
            .field("accepted", &self.accepted)
            .finish()
    }
}

/// An invitation read by its token, with the key it is stored under.
struct Loaded {
    key: String,
    base: InvitationBase,
    grant: Grant,
}

/// What an invitation grants, and what stands behind it.
enum Grant {
    /// A seat in an existing workspace, on a member's authority.
    Member { inviter_user_id: String },
    /// A workspace to create and own, on the platform's authority.
    Bootstrap { workspace_name: String },
}

impl Loaded {
    fn workspace(&self) -> WorkspaceRef<'_> {
        WorkspaceRef {
            tenant_id: &self.base.tenant_id,
            workspace_id: &self.base.workspace_id,
        }
    }

    fn member<'a>(&'a self, user_id: &'a str) -> MembershipRef<'a> {
        MembershipRef {
            tenant_id: &self.base.tenant_id,
            workspace_id: &self.base.workspace_id,
            user_id,
        }
    }
}

impl AuthEngine {
    /// Accepts the invitation `token` names for the signed-in account `user_id` of `tenant_id`,
    /// and answers the role the account holds in the workspace, which is the role it already held
    /// when it was an active member before.
    ///
    /// A bootstrap invitation creates its workspace with the account as owner, applying the owner
    /// cap and the host's `before_workspace_create` and never the self-serve switch. Accepting
    /// again after the workspace was created, by its active owner, is a success.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInvitationToken`] for a token that cannot be honoured, whatever the
    /// reason; [`AuthError::TokenInvalid`] when the account is gone;
    /// [`AuthError::InvitationEmailMismatch`] when the account's address is not the invited one
    /// and [`AuthError::EmailNotVerified`] when it is but is not verified;
    /// [`AuthError::WorkspaceLimitReached`] and [`AuthError::ForbiddenWithDetails`] when a
    /// bootstrap invitation's workspace may not be created. None of these spends the token.
    /// [`AuthError::Internal`] for a repository, hook or store failure or a disabled layer.
    pub async fn accept_workspace_invitation(
        &self,
        tenant_id: &str,
        user_id: &str,
        token: &str,
        ctx: &RequestContext,
    ) -> Result<AcceptedWorkspaceInvitation, AuthError> {
        let runtime = self.workspace_runtime()?;
        let loaded = load(runtime, token).await?;
        let user = self
            .user_repository()
            .find_by_id(user_id, Some(tenant_id))
            .await
            .map_err(internal)?
            .ok_or(AuthError::TokenInvalid)?;
        if user.tenant_id != loaded.base.tenant_id {
            return Err(AuthError::InvalidInvitationToken);
        }
        if normalize_email(&user.email) != loaded.base.email {
            return Err(AuthError::InvitationEmailMismatch);
        }
        if !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }
        self.assert_still_grantable(runtime, &loaded).await?;
        let hook_ctx = HookContext::from_request(
            HookPlane::Dashboard,
            ctx,
            Some(user.id.clone()),
            None,
            Some(user.tenant_id.clone()),
        );
        self.finish_acceptance(runtime, &loaded, &SafeAuthUser::from(user), hook_ctx)
            .await
    }

    /// Accepts the invitation `input.token` names by creating the account it was addressed
    /// to, verified and with no role of its own, and signs that account in.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInvitationToken`] as for
    /// [`accept_workspace_invitation`](Self::accept_workspace_invitation);
    /// [`AuthError::EmailAlreadyExists`] when the address already has an account, whose holder
    /// signs in and accepts; whatever the password policy refuses; and [`AuthError::Internal`]
    /// for a repository, hashing or store failure. A refusal before the account is created writes
    /// nothing and spends nothing. A bootstrap invitation refused at the creation of its
    /// workspace leaves the account created and the token unspent, so its holder signs in and
    /// accepts.
    pub async fn accept_workspace_invitation_signup(
        &self,
        input: WorkspaceSignupInput,
        ip: &str,
        user_agent: &str,
        headers: BTreeMap<String, String>,
    ) -> Result<WorkspaceSignup, AuthError> {
        let runtime = self.workspace_runtime()?;
        let loaded = load(runtime, &input.token).await?;
        self.assert_still_grantable(runtime, &loaded).await?;
        let (email, tenant_id) = (&loaded.base.email, &loaded.base.tenant_id);
        if self.find_account(tenant_id, email).await?.is_some() {
            return Err(AuthError::EmailAlreadyExists);
        }
        // Judged before anything is written: a refused password is the invitee's to correct, and
        // the invitation has to be there when they do.
        self.passwords()
            .assert_acceptable(&input.password, "password")
            .await?;
        let user = self.create_invited_account(&loaded.base, input).await?;
        let ctx = RequestContext::new(ip.to_owned(), user_agent.to_owned(), headers);
        let hook_ctx = HookContext::from_request(
            HookPlane::Dashboard,
            &ctx,
            Some(user.id.clone()),
            Some(user.email.clone()),
            Some(user.tenant_id.clone()),
        );
        let accepted = self
            .finish_acceptance(runtime, &loaded, &user, hook_ctx.clone())
            .await?;
        let result = self.sign_in_invited(user, ip, user_agent, hook_ctx).await?;
        Ok(WorkspaceSignup { result, accepted })
    }
}

impl AuthEngine {
    /// Re-checks what the invitation rests on. A bootstrap invitation is accepted before its
    /// workspace exists, or again once it was created and the token not yet spent.
    async fn assert_still_grantable(
        &self,
        runtime: &WorkspaceRuntime,
        loaded: &Loaded,
    ) -> Result<(), AuthError> {
        let found = runtime.workspaces.find_by_id(loaded.workspace()).await;
        let status = found.map_err(internal)?.map(|row| row.status);
        match (&loaded.grant, status) {
            (Grant::Bootstrap { .. }, None | Some(WorkspaceStatus::Active)) => Ok(()),
            (Grant::Member { inviter_user_id }, Some(WorkspaceStatus::Active)) => {
                self.assert_inviter_stands(runtime, loaded, inviter_user_id)
                    .await
            }
            _ => Err(AuthError::InvalidInvitationToken),
        }
    }

    /// An invitation delegates its inviter's authority, and authority is revocable. Every failure
    /// answers as an invalid token, since the reason would describe someone else's account.
    async fn assert_inviter_stands(
        &self,
        runtime: &WorkspaceRuntime,
        loaded: &Loaded,
        inviter_user_id: &str,
    ) -> Result<(), AuthError> {
        let tenant_id = &loaded.base.tenant_id;
        let inviter = self
            .user_repository()
            .find_by_id(inviter_user_id, Some(tenant_id))
            .await
            .map_err(internal)?;
        let seat = runtime
            .memberships
            .find(loaded.member(inviter_user_id))
            .await
            .map_err(internal)?;
        let stands = inviter.is_some_and(|inviter| {
            self.assert_user_not_blocked(&inviter.status).is_ok() && inviter.tenant_id == *tenant_id
        }) && seat.is_some_and(|seat| {
            seat.status == MembershipStatus::Active
                && runtime.outranks(&seat.role, &loaded.base.role)
        });
        if !stands {
            tracing::warn!(
                event = "RUST_AUTH_INVITATION_INVITER_CANNOT_GRANT",
                "invitation: the inviter can no longer grant this invitation"
            );
            return Err(AuthError::InvalidInvitationToken);
        }
        Ok(())
    }

    /// Writes the membership, creating a bootstrap invitation's workspace with it, then spends
    /// the token, then ends the cached access and reports the
    /// event. A revoke or a resend landing between the write and the spend cannot undo the
    /// acceptance: the event says the spend lost.
    async fn finish_acceptance(
        &self,
        runtime: &WorkspaceRuntime,
        loaded: &Loaded,
        user: &SafeAuthUser,
        hook_ctx: HookContext,
    ) -> Result<AcceptedWorkspaceInvitation, AuthError> {
        let user_id = user.id.as_str();
        let role = match &loaded.grant {
            Grant::Member { inviter_user_id } => {
                join(runtime, loaded, inviter_user_id, user_id).await?
            }
            Grant::Bootstrap { workspace_name } => {
                self.own_invited_workspace(runtime, loaded, workspace_name, user, &hook_ctx)
                    .await?
            }
        };
        let place = runtime.place(loaded.workspace(), &loaded.base.email)?;
        let spent = runtime
            .invitation_store()?
            .remove(&place, &loaded.key, Removal::Spend)
            .await?;
        runtime
            .invalidate_membership(loaded.member(user_id))
            .await?;
        let kind = accepted_kind(loaded, user_id, &role, !spent);
        let at = iso_instant(OffsetDateTime::now_utc());
        let event = audit_event(loaded.workspace(), Some(user_id), &at, kind);
        self.notify_workspace_event(event, hook_ctx);
        Ok(AcceptedWorkspaceInvitation {
            workspace_id: loaded.base.workspace_id.clone(),
            role,
        })
    }

    /// Creates a bootstrap invitation's workspace with `owner` as its owner, and answers the
    /// role held there. A workspace an earlier attempt created without spending the token is a
    /// success for its active owner alone, with no cap and no hook.
    async fn own_invited_workspace(
        &self,
        runtime: &WorkspaceRuntime,
        loaded: &Loaded,
        name: &str,
        owner: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<String, AuthError> {
        let role = loaded.base.role.clone();
        let existing = runtime.workspaces.find_by_id(loaded.workspace()).await;
        if let Some(existing) = existing.map_err(internal)? {
            let seat = runtime.memberships.find(loaded.member(&owner.id)).await;
            let owns = existing.status == WorkspaceStatus::Active
                && seat.map_err(internal)?.is_some_and(|seat| {
                    seat.status == MembershipStatus::Active && seat.role == role
                });
            return owns
                .then_some(role)
                .ok_or(AuthError::InvalidInvitationToken);
        }
        let request = OwnedWorkspace {
            workspace: loaded.workspace(),
            name,
            owner,
        };
        self.create_owned_workspace(request, ctx).await?;
        Ok(role)
    }

    /// Creates the invited account. The invitation reached its address, which is what
    /// verification proves.
    async fn create_invited_account(
        &self,
        invited: &InvitationBase,
        input: WorkspaceSignupInput,
    ) -> Result<SafeAuthUser, AuthError> {
        let password_hash = self.passwords().hash(&input.password).await?;
        let created = self
            .user_repository()
            .create(CreateUserData {
                email: invited.email.clone(),
                name: input.name,
                password_hash: Some(password_hash),
                role: None,
                status: None,
                tenant_id: invited.tenant_id.clone(),
                email_verified: Some(true),
            })
            .await;
        match created {
            Ok(user) => Ok(SafeAuthUser::from(user)),
            Err(error) => {
                let taken = self
                    .find_account(&invited.tenant_id, &invited.email)
                    .await?;
                Err(create_failure(error, taken.is_some()))
            }
        }
    }

    /// Issues the new account's session as a sign-in does, and fires the host's after-acceptance
    /// hook without waiting for it.
    async fn sign_in_invited(
        &self,
        user: SafeAuthUser,
        ip: &str,
        user_agent: &str,
        hook_ctx: HookContext,
    ) -> Result<AuthResult, AuthError> {
        // The invitee proved both the emailed token and the password they just set.
        let result = self
            .tokens()
            .issue_tokens(&user, ip, user_agent, false, CredentialProof::Proved)
            .await?;
        self.enforce_sessions_after_issue(&result, ip, user_agent, &hook_ctx)
            .await?;
        spawn_guarded(run_after_invitation_accepted(
            self.hooks().clone(),
            user,
            hook_ctx,
        ));
        Ok(result)
    }
}

/// The invitation `token` names.
async fn load(runtime: &WorkspaceRuntime, token: &str) -> Result<Loaded, AuthError> {
    load_record(runtime, &invitation_record_id(token)).await
}

/// The invitation stored under the record id `id`: a member one granting a role of the hierarchy,
/// or a bootstrap one granting the owner role.
async fn load_record(runtime: &WorkspaceRuntime, id: &str) -> Result<Loaded, AuthError> {
    let key = record_key(id);
    let record = runtime.invitation_store()?.read_record(&key).await?;
    let hierarchy = &runtime.resolved.hierarchy;
    let (base, grant) = match record {
        Some(InvitationRecord::Member {
            base,
            inviter_user_id,
        }) if hierarchy.knows(&base.role) => (base, Grant::Member { inviter_user_id }),
        Some(InvitationRecord::Bootstrap {
            base,
            workspace_name,
        }) if base.role == hierarchy.owner_role() => (base, Grant::Bootstrap { workspace_name }),
        _ => return Err(AuthError::InvalidInvitationToken),
    };
    Ok(Loaded { key, base, grant })
}

/// The persisted and reported form of an acceptance.
fn accepted_kind(loaded: &Loaded, user_id: &str, role: &str, lost: bool) -> AuditKind {
    AuditKind::InvitationAccepted {
        email: loaded.base.email.clone(),
        role: role.to_owned(),
        user_id: user_id.to_owned(),
        lost_consume_race: lost,
    }
}

/// Makes the account a member of the workspace and answers the role it holds there.
async fn join(
    runtime: &WorkspaceRuntime,
    loaded: &Loaded,
    inviter_user_id: &str,
    user_id: &str,
) -> Result<String, AuthError> {
    let kind = accepted_kind(loaded, user_id, &loaded.base.role, false);
    let at = iso_instant(OffsetDateTime::now_utc());
    let audit = audit_event(loaded.workspace(), Some(user_id), &at, kind);
    let outcome = runtime
        .memberships
        .create(CreateMembership {
            member: loaded.member(user_id),
            role: &loaded.base.role,
            invited_by_user_id: Some(inviter_user_id),
            audit: &audit,
        })
        .await
        .map_err(internal)?;
    match outcome {
        CreateMembershipOutcome::Done => Ok(loaded.base.role.clone()),
        CreateMembershipOutcome::WorkspaceNotFound => Err(AuthError::InvalidInvitationToken),
        // Already a member: the invitation changes nothing, so the answer is the role they hold.
        // A membership that is not active is not one an invitation can reinstate.
        CreateMembershipOutcome::AlreadyMember => runtime
            .memberships
            .find(loaded.member(user_id))
            .await
            .map_err(internal)?
            .filter(|seat| seat.status == MembershipStatus::Active)
            .map(|seat| seat.role)
            .ok_or(AuthError::InvalidInvitationToken),
    }
}

/// The answer to a failed account creation, given whether the address has an account now: a
/// concurrent creation of the same address reads as the account that already exists.
fn create_failure(error: RepositoryError, now_exists: bool) -> AuthError {
    if now_exists {
        return AuthError::EmailAlreadyExists;
    }
    map_repository_error(error)
}
