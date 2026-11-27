//! Who may create an account: anyone, or only the holder of an invitation (layer: configuration).

use crate::error::ConfigError;

/// How an account may come into being (`registration`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Anyone may sign up with a password or through OAuth. The default.
    #[default]
    Open,
    /// An account is created only on an invitation. The password sign-up is refused with
    /// `auth.registration_closed`, and so is an OAuth sign-in that would create an account,
    /// unless its flow carries a workspace invitation. Signing in and linking an existing
    /// account are unaffected.
    InvitationOnly,
}

/// What the deployment has wired that can turn an invitation into an account.
#[derive(Clone, Copy)]
pub(crate) struct InvitationPaths {
    /// Tenant invitations are enabled.
    pub(crate) tenant: bool,
    /// The workspace layer is enabled, its routes are mounted and its invitation store is wired.
    pub(crate) workspace: bool,
}

/// Refuses [`RegistrationMode::InvitationOnly`] when no invitation can be accepted, since no
/// account could ever be created.
pub(crate) fn assert_invitation_path(
    mode: RegistrationMode,
    paths: InvitationPaths,
) -> Result<(), ConfigError> {
    let closed = mode == RegistrationMode::InvitationOnly;
    if closed && !paths.tenant && !paths.workspace {
        return Err(ConfigError::RegistrationWithoutInvitationPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::Environment;
    use crate::engine::AuthEngine;
    use crate::services::auth::test_support::base_config;
    use crate::testing::{
        InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository,
        InMemoryWorkspaceInvitations, InMemoryWorkspaces,
    };

    #[test]
    fn invitation_only_needs_one_way_to_accept_an_invitation() {
        use RegistrationMode::{InvitationOnly, Open};
        let cases = [
            (Open, false, false, true),
            (InvitationOnly, false, false, false),
            (InvitationOnly, true, false, true),
            (InvitationOnly, false, true, true),
            (InvitationOnly, true, true, true),
        ];
        for (mode, tenant, workspace, accepted) in cases {
            let outcome = assert_invitation_path(mode, InvitationPaths { tenant, workspace });
            assert_eq!(
                outcome.is_ok(),
                accepted,
                "{mode:?} tenant={tenant} workspace={workspace}"
            );
        }
    }

    /// Whether an invitation-only engine boots with the workspace layer wired except for what
    /// `without` takes away.
    fn boots(without: Option<&str>) -> Result<(), ConfigError> {
        let mut config = base_config();
        config.registration = RegistrationMode::InvitationOnly;
        config.workspaces.enabled = true;
        config.workspaces.roles.hierarchy =
            [("owner".to_owned(), Vec::new())].into_iter().collect();
        config.workspaces.roles.owner_role = "owner".to_owned();
        config.controllers.workspaces = without != Some("routes");
        let repo = Arc::new(InMemoryWorkspaces::new());
        let mut builder = AuthEngine::builder()
            .config(config)
            .environment(Environment::Test)
            .user_repository(Arc::new(InMemoryUserRepository::new()))
            .redis_stores(Arc::new(InMemoryStores::new()))
            .workspace_repositories(repo.clone(), repo)
            .membership_cache_store(Arc::new(InMemoryMembershipCache::new()));
        if without != Some("store") {
            builder =
                builder.workspace_invitation_store(Arc::new(InMemoryWorkspaceInvitations::new()));
        }
        builder.build().map(|_| ())
    }

    #[test]
    fn the_engine_refuses_invitation_only_without_a_mounted_and_stored_workspace_path() {
        let wired = boots(None);
        assert!(wired.is_ok(), "{wired:?}");
        for missing in ["routes", "store"] {
            let refused = boots(Some(missing));
            assert!(
                matches!(refused, Err(ConfigError::RegistrationWithoutInvitationPath)),
                "without {missing}: {refused:?}"
            );
        }
    }
}
