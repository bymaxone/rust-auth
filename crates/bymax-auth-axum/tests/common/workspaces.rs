//! The workspace doubles of the harness: the in-memory repositories and membership cache an engine
//! built with `EngineSpec::workspaces` reads, and the rows a test seeds into them (layer: test
//! support).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use bymax_auth_core::testing::{
    InMemoryMembershipCache, InMemoryWorkspaceInvitations, InMemoryWorkspaces,
};
use bymax_auth_core::traits::{EmailError, EmailProvider, InviteData, WorkspaceInviteData};
use bymax_auth_core::workspace::domain::{
    Membership, MembershipStatus, Workspace, WorkspaceStatus,
};
use bymax_auth_core::{AuthConfig, AuthEngineBuilder};
use time::{Duration, OffsetDateTime};

use super::TENANT;

/// The workspace invitation messages the engine sent. Every other message is accepted and
/// dropped.
#[derive(Default)]
pub struct InvitationMails {
    sent: Mutex<Vec<(String, String)>>,
}

impl InvitationMails {
    /// The recipient and the raw token of every invitation sent, oldest first.
    pub fn sent(&self) -> Vec<(String, String)> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl EmailProvider for InvitationMails {
    async fn send_workspace_invitation(
        &self,
        _tenant_id: &str,
        email: &str,
        invite: &WorkspaceInviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((email.to_owned(), invite.invite_token.clone()));
        }
        Ok(())
    }

    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _new_email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _email: &str,
        _invite: &InviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
}

/// The repositories and the cache of the workspace layer, shared with the engine.
#[derive(Default)]
pub struct WorkspaceDoubles {
    /// Both repositories, over one state.
    pub repo: Arc<InMemoryWorkspaces>,
    /// The membership cache.
    pub cache: Arc<InMemoryMembershipCache>,
    /// The invitation store.
    pub invitations: Arc<InMemoryWorkspaceInvitations>,
    /// The invitation messages sent. This provider replaces the harness's mailbox on an engine
    /// with the workspace layer on.
    pub mails: Arc<InvitationMails>,
    tick: AtomicI64,
}

impl WorkspaceDoubles {
    /// Switches the workspace layer and its routes on: owner over admin over member.
    pub(super) fn enable(config: &mut AuthConfig) {
        config.workspaces.enabled = true;
        config.workspaces.roles.hierarchy = BTreeMap::from([
            (
                "owner".to_owned(),
                vec!["admin".to_owned(), "member".to_owned()],
            ),
            ("admin".to_owned(), vec!["member".to_owned()]),
            ("member".to_owned(), Vec::new()),
        ]);
        config.workspaces.roles.owner_role = "owner".to_owned();
        config.controllers.workspaces = true;
    }

    /// Hands the doubles to the engine.
    pub(super) fn wire(&self, builder: AuthEngineBuilder) -> AuthEngineBuilder {
        builder
            .workspace_repositories(self.repo.clone(), self.repo.clone())
            .membership_cache_store(self.cache.clone())
            .workspace_invitation_store(self.invitations.clone())
            .email_provider(self.mails.clone())
    }

    /// The next creation instant, so seeded rows sort in the order they were seeded.
    fn next_instant(&self) -> OffsetDateTime {
        let tick = self.tick.fetch_add(1, Ordering::SeqCst) + 1;
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(tick)
    }

    /// Seeds a workspace of `tenant` in `status`.
    pub fn seed_workspace_in(&self, tenant: &str, id: &str, status: WorkspaceStatus) {
        self.repo.seed_workspace(Workspace {
            id: id.to_owned(),
            tenant_id: tenant.to_owned(),
            name: format!("Workspace {id}"),
            status,
            created_at: self.next_instant(),
            deletion_scheduled_at: None,
        });
    }

    /// Seeds a workspace of the test tenant in `status`.
    pub fn seed_workspace(&self, id: &str, status: WorkspaceStatus) {
        self.seed_workspace_in(TENANT, id, status);
    }

    /// Seeds a membership of `user` in `tenant`/`workspace`.
    pub fn seed_member_in(
        &self,
        (tenant, workspace): (&str, &str),
        user: &str,
        role: &str,
        status: MembershipStatus,
    ) {
        let at = self.next_instant();
        self.repo.seed_membership(Membership {
            tenant_id: tenant.to_owned(),
            workspace_id: workspace.to_owned(),
            user_id: user.to_owned(),
            role: role.to_owned(),
            status,
            invited_by_user_id: None,
            created_at: at,
            updated_at: at,
        });
    }

    /// Seeds a membership of `user` in the test tenant's `workspace`.
    pub fn seed_member(&self, workspace: &str, user: &str, role: &str, status: MembershipStatus) {
        self.seed_member_in((TENANT, workspace), user, role, status);
    }
}
