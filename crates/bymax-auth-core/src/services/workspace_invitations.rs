//! Workspace invitations: invite an address, resend, revoke, list the pending ones, and tell a
//! token holder what a token is for (layer: service).
//!
//! A token is 32 random bytes and only its SHA-256 is stored, so a resend mints a new token and
//! retires the old one. One address has one live invitation per workspace, and inviting it again is
//! a resend held to the resend limits. The role ceiling is the member ceiling: the owner role
//! invites to any role, every other role only to a role strictly below its own, and acts only on
//! invitations to such roles. An invitation the actor may not act on reads as absent, so a resend
//! or a revoke confirms nothing about it.
//!
//! A creation time that is not an instant never reaches this module: the record refuses it when it
//! is read. What does reach it is an index that names a key holding such a value, which is an
//! internal error on an invitation and a resend and is never read as a cooldown that has elapsed.

use std::num::NonZeroU64;

use bymax_auth_types::AuthError;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::normalize::{mask_email, normalize_email};
use crate::services::internal_error;
use crate::services::workspace::{PageQuery, WorkspaceRuntime, internal, invalid};
use crate::services::workspace_writes::{audit_event, member_hook_context};
use crate::traits::workspace_invitation_store::{
    InvitationPlace, PendingInvitation, Publication, PublishOutcome, Removal,
};
use crate::traits::{
    EmailError, WorkspaceInvitationStore, WorkspaceInviteData, WorkspaceInviteKind,
};
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::{AuditKind, iso_instant};
use crate::workspace::domain::{MembershipRef, Page, Workspace, WorkspaceRef, WorkspaceStatus};
use crate::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use crate::workspace::keys::{
    BlankPart, invitation_index_id, invitation_record_id, invitation_set_id, inviter_rate_id,
};
use crate::workspace::limits::{
    INVITATION_MAX_RESENDS, INVITATION_RESEND_COOLDOWN_SECONDS, INVITATIONS_PER_INVITER_PER_WINDOW,
};
use crate::workspace::roles::RoleHierarchy;

/// The token a holder previews: what it is for, without signing in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationPreview {
    /// A member of an existing workspace invited the address to it.
    Member {
        /// The workspace's name.
        workspace_name: String,
        /// The inviter's display name.
        inviter_name: String,
        /// The role offered.
        role: String,
        /// The address with all but its first character and its domain hidden.
        masked_email: String,
        /// Whether the address already has an account in the tenant.
        account_exists: bool,
    },
    /// The platform invited the address to own a workspace that does not exist yet.
    Bootstrap {
        /// The name the workspace will be created with.
        workspace_name: String,
        /// The role offered, the owner role.
        role: String,
        /// The address with all but its first character and its domain hidden.
        masked_email: String,
        /// Whether the address already has an account in the tenant.
        account_exists: bool,
    },
}

/// One pending member invitation of a workspace. The token is never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceInvitationView {
    /// The invitee's address.
    pub email: String,
    /// The role offered.
    pub role: String,
    /// The member who issued the current token.
    pub inviter_user_id: String,
    /// When the current token was issued, as an RFC 3339 instant.
    pub created_at: String,
    /// When it stops being valid, as an RFC 3339 instant.
    pub expires_at: String,
    /// How many times the address has been invited again since the first invitation.
    pub resend_count: u64,
}

/// What an address's index held when it was read.
struct Standing {
    /// The record key the index named, `None` when there was no index. The publication writes only
    /// while the index still holds exactly this.
    expected: Option<String>,
    /// The live record under it, `None` when there was none.
    live: Option<InvitationRecord>,
}

/// The address a preview looks up when a token names nothing.
/// The size of a token in bytes: 64 hex characters.
const INVITE_TOKEN_BYTES: usize = 32;

const STAND_IN_EMAIL: &str = "no-invitation@invalid.invalid";

impl WorkspaceRuntime {
    /// The invitation store, or the internal error its absence is.
    fn invitation_store(&self) -> Result<&dyn WorkspaceInvitationStore, AuthError> {
        self.invitations.as_deref().ok_or_else(|| {
            AuthError::Internal(Box::new(std::io::Error::other(
                "workspace invitations are not configured",
            )))
        })
    }

    /// Whether `actor` may act on an invitation to `role`: the owner role on any, every other role
    /// only on a role it includes and does not itself hold.
    fn may_act_on(&self, actor: &str, role: &str) -> bool {
        let hierarchy = &self.resolved.hierarchy;
        actor == hierarchy.owner_role() || (actor != role && hierarchy.satisfies(actor, role))
    }

    /// Refuses a role outside the hierarchy, or one above what `actor` may grant.
    fn assert_may_grant(&self, actor: &str, role: &str) -> Result<(), AuthError> {
        if !self.resolved.hierarchy.knows(role) {
            return Err(invalid(
                "role",
                "role must be a role of the workspace".to_owned(),
            ));
        }
        if self.may_act_on(actor, role) {
            Ok(())
        } else {
            Err(AuthError::InsufficientWorkspaceRole)
        }
    }

    /// The index and the set of an address's invitation in `workspace`.
    fn place(
        &self,
        workspace: WorkspaceRef<'_>,
        email: &str,
    ) -> Result<InvitationPlace, AuthError> {
        if email.is_empty() {
            return Err(invalid("email", "email must not be blank".to_owned()));
        }
        let key = &*self.identifier_key;
        let (tenant, id) = (workspace.tenant_id, workspace.workspace_id);
        let index_id = invitation_index_id(key, tenant, id, email).map_err(blank)?;
        let set_id = invitation_set_id(key, tenant, id).map_err(blank)?;
        Ok(InvitationPlace { index_id, set_id })
    }

    /// Counts one invitation against the inviter's hour and refuses the one past the limit.
    async fn take_inviter_slot(&self, member: &WorkspaceMember) -> Result<(), AuthError> {
        let store = self.invitation_store()?;
        let rate_id = inviter_rate_id(&self.identifier_key, &member.tenant_id, &member.user_id)
            .map_err(blank)?;
        if store.count_inviter(&rate_id).await? > u64::from(INVITATIONS_PER_INVITER_PER_WINDOW) {
            return Err(too_many_requests());
        }
        Ok(())
    }

    /// What the address's index holds; an index over a value that is not a record is an error.
    async fn standing(&self, place: &InvitationPlace) -> Result<Standing, AuthError> {
        let Some(indexed) = self.invitation_store()?.read_index(place).await? else {
            return Ok(Standing {
                expected: None,
                live: None,
            });
        };
        if indexed.unreadable {
            return Err(AuthError::Internal(Box::new(std::io::Error::other(
                "a workspace invitation record is unreadable",
            ))));
        }
        Ok(Standing {
            expected: Some(indexed.record_key),
            live: indexed.record,
        })
    }

    /// Refuses to replace an invitation the actor may not act on, or one sent too recently or too
    /// often. A creation time in the future counts as inside the cooldown.
    pub(super) fn assert_may_reissue(
        &self,
        actor: &str,
        record: &InvitationRecord,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let base = record.base();
        if !self.may_act_on(actor, &base.role) {
            return Err(AuthError::InsufficientWorkspaceRole);
        }
        let issued = OffsetDateTime::parse(&base.created_at, &Rfc3339).map_err(|_| {
            AuthError::Internal(Box::new(std::io::Error::other(
                "a workspace invitation has no valid creation time",
            )))
        })?;
        let cooling = now - issued < Duration::seconds(cooldown_seconds());
        if cooling || base.resend_count >= u64::from(INVITATION_MAX_RESENDS) {
            return Err(too_many_requests());
        }
        Ok(())
    }
}

/// The resend cooldown as a signed number of seconds.
fn cooldown_seconds() -> i64 {
    i64::try_from(INVITATION_RESEND_COOLDOWN_SECONDS).unwrap_or(i64::MAX)
}

/// `auth.too_many_requests` with no retry hint: the limit and the lost write both answer it.
fn too_many_requests() -> AuthError {
    AuthError::TooManyRequests {
        retry_after_seconds: None,
    }
}

/// A blank part of a key, named as the part that was blank.
fn blank(error: BlankPart) -> AuthError {
    invalid(error.part, format!("{} must not be blank", error.part))
}

/// Everything one issue needs, so the step that writes it takes one argument.
struct Issue<'a> {
    member: &'a WorkspaceMember,
    email: String,
    role: String,
    place: InvitationPlace,
    standing: Standing,
    account_exists: bool,
    ctx: &'a RequestContext,
}

impl AuthEngine {
    /// Invites an address to the workspace, or sends again to one already invited.
    ///
    /// # Errors
    ///
    /// `auth.validation` for a role outside the hierarchy, `auth.insufficient_workspace_role` above
    /// the actor's ceiling, `auth.already_member` for an address with a membership in any status,
    /// `auth.too_many_requests` at a limit or when the address changed under the call,
    /// `auth.workspace_not_found` when the workspace is not active, and `auth.internal` when the
    /// store, a repository or the email provider fails.
    pub async fn invite_workspace_member(
        &self,
        member: &WorkspaceMember,
        email: &str,
        role: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        runtime.invitation_store()?;
        runtime.assert_may_grant(&member.role, role)?;
        let email = normalize_email(email);
        runtime.take_inviter_slot(member).await?;
        let place = runtime.place(member.workspace(), &email)?;
        let standing = runtime.standing(&place).await?;
        if let Some(live) = &standing.live {
            runtime.assert_may_reissue(&member.role, live, OffsetDateTime::now_utc())?;
        }
        let account_exists = self.assert_not_member(runtime, member, &email).await?;
        let role = role.to_owned();
        self.issue(Issue {
            member,
            email,
            role,
            place,
            standing,
            account_exists,
            ctx,
        })
        .await
    }

    /// Sends a pending invitation again under a new token. An address with no pending invitation,
    /// or one the actor may not act on, is answered as a success and nothing changes.
    ///
    /// # Errors
    ///
    /// `auth.too_many_requests` inside the cooldown, past the resend limit, at the inviter's hourly
    /// limit or when the address changed under the call, and `auth.internal` when the store, a
    /// repository or the email provider fails or the record is unreadable.
    pub async fn resend_workspace_invitation(
        &self,
        member: &WorkspaceMember,
        email: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        runtime.invitation_store()?;
        let email = normalize_email(email);
        let place = runtime.place(member.workspace(), &email)?;
        let standing = runtime.standing(&place).await?;
        let Some(live) = &standing.live else {
            return Ok(());
        };
        if !runtime.may_act_on(&member.role, &live.base().role) {
            return Ok(());
        }
        runtime.assert_may_reissue(&member.role, live, OffsetDateTime::now_utc())?;
        runtime.take_inviter_slot(member).await?;
        let account_exists = self.account_exists(member, &email).await?;
        let role = live.base().role.clone();
        self.issue(Issue {
            member,
            email,
            role,
            place,
            standing,
            account_exists,
            ctx,
        })
        .await
    }

    /// Withdraws a pending invitation. An address with none, or one the actor may not act on, is
    /// answered as a success and nothing changes.
    ///
    /// # Errors
    ///
    /// `auth.internal` when the store fails.
    pub async fn revoke_workspace_invitation(
        &self,
        member: &WorkspaceMember,
        email: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        let store = runtime.invitation_store()?;
        let email = normalize_email(email);
        let place = runtime.place(member.workspace(), &email)?;
        let Some(indexed) = store.read_index(&place).await? else {
            return Ok(());
        };
        let Some(record) = indexed.record else {
            return Ok(());
        };
        let role = record.base().role.clone();
        if !runtime.may_act_on(&member.role, &role) {
            return Ok(());
        }
        store
            .remove(&place, &indexed.record_key, Removal::Owned)
            .await?;
        let kind = AuditKind::InvitationRevoked { email, role };
        self.report(member, kind, ctx, &iso_instant(OffsetDateTime::now_utc()));
        Ok(())
    }

    /// The workspace's pending member invitations, oldest first.
    ///
    /// # Errors
    ///
    /// `auth.validation` for a page size or a cursor outside its bounds, `auth.internal` when the
    /// store fails.
    pub async fn list_workspace_invitations(
        &self,
        member: &WorkspaceMember,
        page: PageQuery<'_>,
    ) -> Result<Page<WorkspaceInvitationView>, AuthError> {
        let runtime = self.workspace_runtime()?;
        let store = runtime.invitation_store()?;
        let (limit, cursor) = page.checked()?;
        let workspace = member.workspace();
        let set_id = invitation_set_id(
            &runtime.identifier_key,
            workspace.tenant_id,
            workspace.workspace_id,
        )
        .map_err(blank)?;
        let place = InvitationPlace {
            index_id: String::new(),
            set_id,
        };
        let pending = store.pending(&place).await?;
        Ok(page_of(pending, limit, cursor, OffsetDateTime::now_utc()))
    }

    /// Tells a token holder what the token is for. Every token that cannot be previewed is
    /// answered with the same error after the same repository reads.
    ///
    /// # Errors
    ///
    /// `auth.invalid_invitation_token` for a token that cannot be previewed, `auth.internal` when
    /// the store or a repository fails.
    pub async fn preview_workspace_invitation(
        &self,
        token: &str,
    ) -> Result<InvitationPreview, AuthError> {
        let runtime = self.workspace_runtime()?;
        let store = runtime.invitation_store()?;
        let record = store
            .read_record(&record_key(&invitation_record_id(token)))
            .await?;
        self.previewed(runtime, record).await
    }
}

impl AuthEngine {
    /// The account of `email` in the member's tenant.
    async fn find_account(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<bymax_auth_types::AuthUser>, AuthError> {
        self.user_repository()
            .find_by_email(email, tenant_id)
            .await
            .map_err(internal)
    }

    /// Whether the address has an account in the member's tenant.
    async fn account_exists(
        &self,
        member: &WorkspaceMember,
        email: &str,
    ) -> Result<bool, AuthError> {
        Ok(self.find_account(&member.tenant_id, email).await?.is_some())
    }

    /// Refuses an address that already has a membership of the workspace, in any status: a
    /// suspended member is still a member, and an invitation cannot reinstate one. Returns whether
    /// the address has an account.
    async fn assert_not_member(
        &self,
        runtime: &WorkspaceRuntime,
        member: &WorkspaceMember,
        email: &str,
    ) -> Result<bool, AuthError> {
        let Some(account) = self.find_account(&member.tenant_id, email).await? else {
            return Ok(false);
        };
        let key = MembershipRef {
            user_id: &account.id,
            ..member.key()
        };
        if runtime
            .memberships
            .find(key)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(AuthError::AlreadyMember);
        }
        Ok(true)
    }

    /// Hands an event to the host's hook, detached.
    fn report(&self, member: &WorkspaceMember, kind: AuditKind, ctx: &RequestContext, at: &str) {
        let event = audit_event(member.workspace(), Some(&member.user_id), at, kind);
        self.notify_workspace_event(event, member_hook_context(ctx, member));
    }

    /// Mints a token, publishes its record in place of the one it replaces, and mails it.
    async fn issue(&self, plan: Issue<'_>) -> Result<(), AuthError> {
        let runtime = self.workspace_runtime()?;
        let member = plan.member;
        let loaded = runtime
            .workspaces
            .find_by_id(member.workspace())
            .await
            .map_err(internal)?;
        let Some(workspace) = loaded.filter(|row| row.status == WorkspaceStatus::Active) else {
            return Err(AuthError::WorkspaceNotFound);
        };
        let inviter = self
            .user_repository()
            .find_by_id(&member.user_id, Some(&member.tenant_id))
            .await
            .map_err(internal)?
            .ok_or(AuthError::TokenInvalid)?;
        let token = bymax_auth_crypto::token::generate_secure_token(INVITE_TOKEN_BYTES);
        let now = OffsetDateTime::now_utc();
        let record = member_record(&plan, now);
        publish(
            runtime,
            &plan,
            &record_key(&invitation_record_id(&token)),
            &record,
        )
        .await?;
        let ttl = Duration::seconds(
            i64::try_from(runtime.resolved.invitation_ttl_seconds).unwrap_or(i64::MAX),
        );
        let data = WorkspaceInviteData::new(
            inviter.name,
            workspace.name,
            plan.role.clone(),
            token,
            now + ttl,
            plan.account_exists,
            WorkspaceInviteKind::Member,
        );
        self.deliver(&member.tenant_id, &plan.email, &data).await?;
        let (email, role) = (plan.email, plan.role);
        let kind = if plan.standing.live.is_some() {
            AuditKind::InvitationResent { email, role }
        } else {
            AuditKind::MemberInvited { email, role }
        };
        self.report(member, kind, plan.ctx, &record.base().created_at);
        Ok(())
    }

    /// Mails the token. A failure is answered as an internal error that carries nothing the
    /// provider wrote: a relay can quote the body it rejected, and that body holds the token.
    async fn deliver(
        &self,
        tenant_id: &str,
        email: &str,
        data: &WorkspaceInviteData,
    ) -> Result<(), AuthError> {
        match self
            .email_provider()
            .send_workspace_invitation(tenant_id, email, data, None)
            .await
        {
            Ok(()) => Ok(()),
            Err(EmailError::Unsupported) => {
                tracing::error!(
                    event = "RUST_AUTH_WORKSPACE_INVITATION_EMAIL_UNSUPPORTED",
                    "the email provider does not implement workspace invitations"
                );
                Err(internal_error(
                    "workspace invitation delivery is unsupported",
                ))
            }
            Err(_) => {
                tracing::warn!(
                    event = "RUST_AUTH_WORKSPACE_INVITATION_DELIVERY_FAILED",
                    "workspace invitation delivery failed"
                );
                Err(internal_error("workspace invitation delivery failed"))
            }
        }
    }

    /// The preview of `record`, after the same three reads for every token.
    async fn previewed(
        &self,
        runtime: &WorkspaceRuntime,
        record: Option<InvitationRecord>,
    ) -> Result<InvitationPreview, AuthError> {
        let (tenant, workspace_id, inviter_id, email) = lookup_of(record.as_ref());
        let workspace_ref = WorkspaceRef {
            tenant_id: &tenant,
            workspace_id: &workspace_id,
        };
        let workspace = runtime
            .workspaces
            .find_by_id(workspace_ref)
            .await
            .map_err(internal)?;
        let inviter = self
            .user_repository()
            .find_by_id(&inviter_id, Some(&tenant))
            .await
            .map_err(internal)?;
        let account = self.find_account(&tenant, &email).await?;
        let Some(record) = record else {
            return Err(AuthError::InvalidInvitationToken);
        };
        let found = Found {
            workspace,
            inviter,
            account_exists: account.is_some(),
        };
        preview_of(record, found, &runtime.resolved.hierarchy)
    }
}

/// What the three reads of a preview found.
struct Found {
    workspace: Option<Workspace>,
    inviter: Option<bymax_auth_types::AuthUser>,
    account_exists: bool,
}

/// The preview of `record` given what was found. A role the hierarchy does not know is a record
/// that was tampered with or outlived a configuration change, and a bootstrap invitation is always
/// to own the workspace.
fn preview_of(
    record: InvitationRecord,
    found: Found,
    hierarchy: &RoleHierarchy,
) -> Result<InvitationPreview, AuthError> {
    let base = record.base();
    let (role, masked_email) = (base.role.clone(), mask_email(&base.email));
    let account_exists = found.account_exists;
    let owner_only = matches!(record, InvitationRecord::Bootstrap { .. });
    if !hierarchy.knows(&role) || (owner_only && role != hierarchy.owner_role()) {
        return Err(AuthError::InvalidInvitationToken);
    }
    match record {
        InvitationRecord::Bootstrap { workspace_name, .. } => {
            // Its workspace does not exist yet; one that exists and is not active names nothing
            // usable.
            if found
                .workspace
                .is_some_and(|row| row.status != WorkspaceStatus::Active)
            {
                return Err(AuthError::InvalidInvitationToken);
            }
            Ok(InvitationPreview::Bootstrap {
                workspace_name,
                role,
                masked_email,
                account_exists,
            })
        }
        InvitationRecord::Member { .. } => {
            let (Some(workspace), Some(inviter)) = (found.workspace, found.inviter) else {
                return Err(AuthError::InvalidInvitationToken);
            };
            if workspace.status != WorkspaceStatus::Active {
                return Err(AuthError::InvalidInvitationToken);
            }
            Ok(InvitationPreview::Member {
                workspace_name: workspace.name,
                inviter_name: inviter.name,
                role,
                masked_email,
                account_exists,
            })
        }
    }
}

/// The values a preview looks up for a record: its own, or ones that match nothing where the token
/// names nothing or the record has no inviter, so every token costs the same three reads.
fn lookup_of(record: Option<&InvitationRecord>) -> (String, String, String, String) {
    let Some(record) = record else {
        return (
            String::new(),
            String::new(),
            String::new(),
            STAND_IN_EMAIL.to_owned(),
        );
    };
    let base = record.base();
    let inviter = match record {
        InvitationRecord::Member {
            inviter_user_id, ..
        } => inviter_user_id.clone(),
        InvitationRecord::Bootstrap { .. } => String::new(),
    };
    (
        base.tenant_id.clone(),
        base.workspace_id.clone(),
        inviter,
        base.email.clone(),
    )
}

/// The record an invitation publishes: a first one starts at no resends, a resend carries on.
fn member_record(plan: &Issue<'_>, now: OffsetDateTime) -> InvitationRecord {
    let member = plan.member;
    let resend_count = plan
        .standing
        .live
        .as_ref()
        .map_or(0, |live| live.base().resend_count.saturating_add(1));
    InvitationRecord::Member {
        base: InvitationBase {
            email: plan.email.clone(),
            role: plan.role.clone(),
            tenant_id: member.tenant_id.clone(),
            workspace_id: member.workspace_id.clone(),
            created_at: iso_instant(now),
            resend_count,
        },
        inviter_user_id: member.user_id.clone(),
    }
}

/// Publishes `record` in place of the one the index named when it was read. A replacement takes
/// the place of the record it retires, so only a first invitation is counted against the cap.
async fn publish(
    runtime: &WorkspaceRuntime,
    plan: &Issue<'_>,
    key: &str,
    record: &InvitationRecord,
) -> Result<(), AuthError> {
    let store = runtime.invitation_store()?;
    let first = plan.standing.live.is_none();
    let ttl = NonZeroU64::new(runtime.resolved.invitation_ttl_seconds).unwrap_or(NonZeroU64::MIN);
    let outcome = store
        .publish(Publication {
            place: &plan.place,
            record_key: key,
            record,
            ttl,
            pending_limit: if first {
                runtime.resolved.max_pending_invitations_per_workspace
            } else {
                0
            },
            expected_key: plan.standing.expected.as_deref(),
        })
        .await?;
    match outcome {
        PublishOutcome::Published => Ok(()),
        _ => Err(too_many_requests()),
    }
}

/// One page of the member invitations among `pending`, ordered by the instant each was issued and
/// then by record key, so the order is total whatever offset or precision the stored times use.
fn page_of(
    pending: Vec<PendingInvitation>,
    limit: u32,
    cursor: Option<&str>,
    now: OffsetDateTime,
) -> Page<WorkspaceInvitationView> {
    let mut members: Vec<(String, WorkspaceInvitationView)> = pending
        .into_iter()
        .filter_map(|entry| member_entry(entry, now))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let after: Vec<_> = members
        .into_iter()
        .filter(|(position, _)| cursor.is_none_or(|cursor| position.as_str() > cursor))
        .collect();
    let size = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = after.len() > size;
    let taken: Vec<_> = after.into_iter().take(size).collect();
    let next_cursor = taken
        .last()
        .filter(|_| more)
        .map(|(position, _)| position.clone());
    let items = taken.into_iter().map(|(_, view)| view).collect();
    Page { items, next_cursor }
}

/// Added to a time before the epoch (in nanoseconds) so every position is a non-negative number
/// that sorts as text; it exceeds the earliest year a record can name.
const POSITION_SHIFT: i128 = 1_000_000_000_000_000_000_000_000_000_000;

/// A pending member invitation as its place in the order and its listing; `None` for a bootstrap
/// invitation, which is not listed, and for a record whose creation time is not an instant, which
/// a parsed record never holds.
fn member_entry(
    entry: PendingInvitation,
    now: OffsetDateTime,
) -> Option<(String, WorkspaceInvitationView)> {
    let InvitationRecord::Member {
        base,
        inviter_user_id,
    } = entry.record
    else {
        return None;
    };
    let issued = OffsetDateTime::parse(&base.created_at, &Rfc3339).ok()?;
    let position = format!(
        "{:040}|{}",
        issued.unix_timestamp_nanos() + POSITION_SHIFT,
        entry.record_key
    );
    let left = Duration::seconds(i64::try_from(entry.ttl_seconds).unwrap_or(i64::MAX));
    let view = WorkspaceInvitationView {
        email: base.email,
        role: base.role,
        inviter_user_id,
        created_at: base.created_at,
        expires_at: iso_instant(now.saturating_add(left)),
        resend_count: base.resend_count,
    };
    Some((position, view))
}
