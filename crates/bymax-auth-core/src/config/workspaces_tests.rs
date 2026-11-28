//! The workspace group's defaults and its startup validation (layer: configuration, tests).

use std::collections::BTreeMap;

use super::workspaces::{
    AccessDeniedEventsConfig, WorkspacePermission, WorkspacePermissionsConfig,
    WorkspaceRolesConfig, WorkspacesConfig,
};
use crate::error::ConfigError;
use crate::workspace::access::AcceptedRoles;
use crate::workspace::roles::RoleHierarchyError;

/// An enabled group with a valid hierarchy: owner over member.
fn enabled() -> WorkspacesConfig {
    let roles = WorkspaceRolesConfig {
        hierarchy: BTreeMap::from([
            ("owner".to_owned(), vec!["member".to_owned()]),
            ("member".to_owned(), Vec::new()),
        ]),
        owner_role: "owner".to_owned(),
    };
    WorkspacesConfig {
        enabled: true,
        roles,
        ..WorkspacesConfig::default()
    }
}

#[test]
fn the_group_is_off_by_default_with_the_contracts_cache_lifetime_and_any_member_listing() {
    let config = WorkspacesConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.membership_cache_ttl_seconds, 60);
    assert_eq!(config.permissions, WorkspacePermissionsConfig::default());
    assert_eq!(config.permissions.view_members, AcceptedRoles::AnyMember);
    // Nothing is checked while the group is off, so an empty hierarchy is not refused.
    assert!(matches!(config.resolve(), Ok(None)));
}

#[test]
fn an_enabled_group_resolves_to_its_hierarchy_lifetime_and_permission() {
    let resolved = enabled().resolve();
    assert!(matches!(resolved, Ok(Some(_))));
    let Ok(Some(resolved)) = resolved else { unreachable!() };
    assert_eq!(resolved.hierarchy.owner_role(), "owner");
    assert_eq!(resolved.ttl.seconds(), 60);
    assert_eq!(resolved.permissions.view_members, AcceptedRoles::AnyMember);
}

#[test]
fn an_enabled_group_names_the_rule_it_breaks() {
    let mut no_roles = enabled();
    no_roles.roles.hierarchy.clear();
    assert!(matches!(
        no_roles.resolve(),
        Err(ConfigError::WorkspaceRoles(RoleHierarchyError::Empty))
    ));

    let mut unknown = enabled();
    unknown.permissions.view_members = AcceptedRoles::roles(["member", "ghost"]);
    let refused = unknown.resolve();
    assert!(matches!(
        &refused,
        Err(ConfigError::WorkspacePermissionUnknownRole { action: "viewMembers", role })
            if role == "ghost"
    ));
    let message = refused.err().map(|error| error.to_string());
    assert_eq!(
        message.as_deref(),
        Some("workspaces.permissions.viewMembers names 'ghost', which is not a workspace role")
    );

    // The lifetime's bound is the contract's: 3600 is accepted, 3601 is not, and 0 disables.
    for (seconds, accepted) in [(0, true), (3_600, true), (3_601, false)] {
        let mut config = enabled();
        config.membership_cache_ttl_seconds = seconds;
        assert_eq!(config.resolve().is_ok(), accepted, "{seconds}");
    }
    let mut too_long = enabled();
    too_long.membership_cache_ttl_seconds = 3_601;
    assert!(matches!(
        too_long.resolve(),
        Err(ConfigError::WorkspaceMembershipCacheTtl(refused)) if refused.seconds == 3_601
    ));
}

#[test]
fn the_write_options_default_to_the_owner_role_an_open_switch_no_cap_and_fourteen_days() {
    let config = WorkspacesConfig::default();
    assert!(config.allow_create);
    assert_eq!(config.max_workspaces_per_user, 0);
    assert_eq!(config.deletion_grace_days, 14);
    let resolved = enabled().resolve();
    let Ok(Some(resolved)) = resolved else { unreachable!() };
    let owner = AcceptedRoles::roles(["owner"]);
    for permission in [
        WorkspacePermission::ManageWorkspace,
        WorkspacePermission::DeleteWorkspace,
        WorkspacePermission::ManageMembers,
    ] {
        assert_eq!(
            resolved.permissions.roles(permission),
            &owner,
            "{permission:?}"
        );
    }
    assert_eq!(
        resolved.permissions.roles(WorkspacePermission::ViewMembers),
        &AcceptedRoles::AnyMember
    );
    assert!(resolved.allow_create);
    assert_eq!(
        (
            resolved.max_workspaces_per_user,
            resolved.deletion_grace_days
        ),
        (0, 14)
    );
}

#[test]
fn a_named_permission_is_kept_and_a_role_outside_the_hierarchy_is_refused_by_its_name() {
    let mut named = enabled();
    named.permissions.manage_members = Some(vec!["member".to_owned()]);
    named.permissions.manage_workspace = Some(Vec::new());
    let Ok(Some(resolved)) = named.resolve() else { unreachable!() };
    let roles = |p| resolved.permissions.roles(p).clone();
    assert_eq!(
        roles(WorkspacePermission::ManageMembers),
        AcceptedRoles::roles(["member"])
    );
    assert!(roles(WorkspacePermission::ManageWorkspace).declares_nothing());
    for (action, set) in [
        ("manageWorkspace", 0),
        ("deleteWorkspace", 1),
        ("manageMembers", 2),
    ] {
        let mut config = enabled();
        let ghost = Some(vec!["ghost".to_owned()]);
        match set {
            0 => config.permissions.manage_workspace = ghost,
            1 => config.permissions.delete_workspace = ghost,
            _ => config.permissions.manage_members = ghost,
        }
        assert!(
            matches!(
                config.resolve(),
                Err(ConfigError::WorkspacePermissionUnknownRole { action: named, ref role })
                    if named == action && role == "ghost"
            ),
            "{action}"
        );
    }
}

#[test]
fn the_owner_cap_and_the_grace_period_are_bounded() {
    for (cap, accepted) in [(0, true), (1_000_000, true), (1_000_001, false)] {
        let mut config = enabled();
        config.max_workspaces_per_user = cap;
        assert_eq!(config.resolve().is_ok(), accepted, "{cap}");
    }
    for (days, accepted) in [(0, true), (365, true), (366, false)] {
        let mut config = enabled();
        config.deletion_grace_days = days;
        assert_eq!(config.resolve().is_ok(), accepted, "{days}");
    }
    let mut over = enabled();
    over.deletion_grace_days = 366;
    let message = over.resolve().err().map(|error| error.to_string());
    assert_eq!(
        message.as_deref(),
        Some("workspaces.deletionGraceDays must be at most 365")
    );
    let mut capped = enabled();
    capped.max_workspaces_per_user = 1_000_001;
    assert!(matches!(
        capped.resolve(),
        Err(ConfigError::WorkspaceOptionOutOfRange {
            option: "maxWorkspacesPerUser",
            max: 1_000_000
        })
    ));
    let disabled = WorkspacesConfig {
        deletion_grace_days: 9_999,
        ..WorkspacesConfig::default()
    };
    assert!(matches!(disabled.resolve(), Ok(None)));
}

#[test]
fn the_invitation_options_default_to_a_week_and_a_hundred_pending() {
    let config = WorkspacesConfig::default();
    assert_eq!(config.invitation_ttl_seconds, 604_800);
    assert_eq!(config.max_pending_invitations_per_workspace, 100);
    let Ok(Some(resolved)) = enabled().resolve() else { unreachable!() };
    assert_eq!(
        (
            resolved.invitation_ttl_seconds,
            resolved.max_pending_invitations_per_workspace
        ),
        (604_800, 100)
    );
}

#[test]
fn the_invitation_lifetime_and_the_pending_cap_are_bounded_on_both_sides() {
    for (seconds, accepted) in [
        (0, false),
        (59, false),
        (60, true),
        (2_592_000, true),
        (2_592_001, false),
    ] {
        let mut config = enabled();
        config.invitation_ttl_seconds = seconds;
        assert_eq!(config.resolve().is_ok(), accepted, "ttl {seconds}");
    }
    for (cap, accepted) in [(0, false), (1, true), (10_000, true), (10_001, false)] {
        let mut config = enabled();
        config.max_pending_invitations_per_workspace = cap;
        assert_eq!(config.resolve().is_ok(), accepted, "cap {cap}");
    }
}

#[test]
fn a_refused_invitation_option_is_named_with_its_bound() {
    let message = |edit: &dyn Fn(&mut WorkspacesConfig)| {
        let mut config = enabled();
        edit(&mut config);
        config.resolve().err().map(|error| error.to_string())
    };
    assert_eq!(
        message(&|c| c.invitation_ttl_seconds = 59).as_deref(),
        Some("workspaces.invitationTtlSeconds must be at least 60")
    );
    assert_eq!(
        message(&|c| c.invitation_ttl_seconds = 2_592_001).as_deref(),
        Some("workspaces.invitationTtlSeconds must be at most 2592000")
    );
    assert_eq!(
        message(&|c| c.max_pending_invitations_per_workspace = 0).as_deref(),
        Some("workspaces.maxPendingInvitationsPerWorkspace must be at least 1")
    );
    assert_eq!(
        message(&|c| c.max_pending_invitations_per_workspace = 10_001).as_deref(),
        Some("workspaces.maxPendingInvitationsPerWorkspace must be at most 10000")
    );
}

#[test]
fn the_access_denied_budget_defaults_and_bounds_are_the_contracts() {
    let default = AccessDeniedEventsConfig::default();
    assert_eq!((default.max, default.window_seconds), (10, 60));
    let refused = |max: u32, window_seconds: u32| {
        let mut config = enabled();
        config.access_denied_events = AccessDeniedEventsConfig {
            max,
            window_seconds,
        };
        config.resolve().err().map(|error| error.to_string())
    };
    for (max, window) in [(1, 1), (10_000, 3_600)] {
        assert_eq!(refused(max, window), None);
    }
    let max = "workspaces.accessDeniedEvents.max must be an integer from 1 to 10000.";
    let window = "workspaces.accessDeniedEvents.windowSeconds must be an integer from 1 to 3600.";
    for (given, message) in [
        ((0, 60), max),
        ((10_001, 60), max),
        ((10, 0), window),
        ((10, 3_601), window),
    ] {
        assert_eq!(
            refused(given.0, given.1).as_deref(),
            Some(message),
            "{given:?}"
        );
    }
}
