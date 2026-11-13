//! The workspace group's defaults and its startup validation (layer: configuration, tests).

use std::collections::BTreeMap;

use super::workspaces::{WorkspacePermissionsConfig, WorkspaceRolesConfig, WorkspacesConfig};
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
    let Ok(Some(resolved)) = resolved else { return };
    assert_eq!(resolved.hierarchy.owner_role(), "owner");
    assert_eq!(resolved.ttl.seconds(), 60);
    assert_eq!(resolved.view_members, AcceptedRoles::AnyMember);
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
