//! Configuration of the workspace layer and its startup validation (layer: configuration).
//!
//! The group carries the role hierarchy and its owner role, the lifetime of a cached membership,
//! which roles may perform each action the library's routes perform, the self-serve create switch,
//! the per-account owner cap and the deletion grace period. Nothing is validated while the group
//! is off, so a host that never opts in is not asked for a hierarchy.

use std::collections::BTreeMap;

use crate::error::ConfigError;
use crate::workspace::access::AcceptedRoles;
use crate::workspace::bounds::is_valid_owner_role;
use crate::workspace::limits::{
    DELETION_GRACE_DAYS_DEFAULT, DELETION_GRACE_DAYS_MAX, MAX_WORKSPACES_PER_USER_LIMIT,
    MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS,
};
use crate::workspace::membership_cache::MembershipCacheTtl;
use crate::workspace::roles::RoleHierarchy;

/// The workspace layer: workspaces inside a tenant, memberships with a role in each, and the
/// versioned cache a membership is resolved through. Opt-in.
///
/// Enabling it requires a [`WorkspaceRepository`](crate::traits::WorkspaceRepository) and a
/// [`MembershipRepository`](crate::traits::MembershipRepository) and a
/// [`MembershipCacheStore`](crate::traits::MembershipCacheStore) on the builder, whatever the
/// cache lifetime; supplying any of them without enabling it is refused too, so a half-configured
/// feature fails at startup instead of serving nothing.
///
/// `#[non_exhaustive]`: build it from [`WorkspacesConfig::default`] and set the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspacesConfig {
    /// Enables the layer. Default: `false`.
    pub enabled: bool,
    /// The workspace role hierarchy and the role that owns a workspace. Required when enabled.
    pub roles: WorkspaceRolesConfig,
    /// Which roles may perform each action the library's routes perform.
    pub permissions: WorkspacePermissionsConfig,
    /// How long a resolved membership stays cached, in seconds: 0 to 3600, default 60. `0`
    /// disables the cache, and every request then reads the repositories.
    pub membership_cache_ttl_seconds: u64,
    /// Whether an account may create a workspace for itself (`POST /workspaces`). Default:
    /// `true`. A refusal is `403 auth.forbidden`. The create path a bootstrap acceptance shares
    /// never consults it: the platform already decided that account may own a workspace.
    pub allow_create: bool,
    /// The most workspaces one account may own, counted as the workspaces in which it is an
    /// active member holding the owner role and that are not deleted, so one pending deletion
    /// still counts. `0` (the default) is no limit; at most 1 000 000. The library counts before
    /// creating, which is advisory under concurrency; the repository's create receives the value
    /// and may enforce it exactly.
    pub max_workspaces_per_user: u32,
    /// How many days a workspace whose deletion was scheduled can still be restored: 0 to 365,
    /// default 14. `0` deletes the workspace when the deletion is asked for.
    pub deletion_grace_days: u32,
}

impl Default for WorkspacesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            roles: WorkspaceRolesConfig::default(),
            permissions: WorkspacePermissionsConfig::default(),
            membership_cache_ttl_seconds: MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS,
            allow_create: true,
            max_workspaces_per_user: 0,
            deletion_grace_days: DELETION_GRACE_DAYS_DEFAULT,
        }
    }
}

/// The workspace role hierarchy (`workspaces.roles`).
///
/// `#[non_exhaustive]`: build it from [`WorkspaceRolesConfig::default`] and set the fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceRolesConfig {
    /// Every role and the roles it includes, one level and explicit: the owner role lists every
    /// other role, and no other role lists the owner.
    pub hierarchy: BTreeMap<String, Vec<String>>,
    /// The role that owns a workspace, a key of `hierarchy`.
    pub owner_role: String,
}

/// Which roles may perform each action (`workspaces.permissions`).
///
/// `#[non_exhaustive]`: build it from [`WorkspacePermissionsConfig::default`] and set the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspacePermissionsConfig {
    /// Who may list a workspace's members. Default: every active member.
    pub view_members: AcceptedRoles,
    /// Who may rename a workspace. `None` (the default) is the owner role alone.
    pub manage_workspace: Option<Vec<String>>,
    /// Who may schedule a workspace's deletion and restore it. `None` (the default) is the owner
    /// role alone.
    pub delete_workspace: Option<Vec<String>>,
    /// Who may change a member's role and remove a member. `None` (the default) is the owner role
    /// alone.
    pub manage_members: Option<Vec<String>>,
}

impl Default for WorkspacePermissionsConfig {
    fn default() -> Self {
        Self {
            view_members: AcceptedRoles::AnyMember,
            manage_workspace: None,
            delete_workspace: None,
            manage_members: None,
        }
    }
}

/// An action whose roles `workspaces.permissions` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspacePermission {
    /// Renaming a workspace (`manage_workspace`).
    ManageWorkspace,
    /// Scheduling a workspace's deletion and restoring it (`delete_workspace`).
    DeleteWorkspace,
    /// Changing a member's role and removing a member (`manage_members`).
    ManageMembers,
    /// Listing a workspace's members (`view_members`).
    ViewMembers,
}

/// The roles each permission accepts, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedPermissions {
    pub(crate) view_members: AcceptedRoles,
    pub(crate) manage_workspace: AcceptedRoles,
    pub(crate) delete_workspace: AcceptedRoles,
    pub(crate) manage_members: AcceptedRoles,
}

impl ResolvedPermissions {
    /// The roles `permission` accepts.
    pub(crate) fn roles(&self, permission: WorkspacePermission) -> &AcceptedRoles {
        match permission {
            WorkspacePermission::ManageWorkspace => &self.manage_workspace,
            WorkspacePermission::DeleteWorkspace => &self.delete_workspace,
            WorkspacePermission::ManageMembers => &self.manage_members,
            WorkspacePermission::ViewMembers => &self.view_members,
        }
    }
}

/// The group with every rule checked: what the engine keeps of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedWorkspaces {
    /// The validated hierarchy and its owner role.
    pub(crate) hierarchy: RoleHierarchy,
    /// The validated lifetime of a cached membership.
    pub(crate) ttl: MembershipCacheTtl,
    /// The roles each permission accepts.
    pub(crate) permissions: ResolvedPermissions,
    /// Whether an account may create a workspace for itself.
    pub(crate) allow_create: bool,
    /// The owner cap, `0` for none.
    pub(crate) max_workspaces_per_user: u32,
    /// The deletion grace period in days, `0` to delete at once.
    pub(crate) deletion_grace_days: u32,
}

/// One permission's roles: the list given, or the owner role alone when none is.
fn owner_unless(
    action: &'static str,
    given: Option<&Vec<String>>,
    hierarchy: &RoleHierarchy,
) -> Result<AcceptedRoles, ConfigError> {
    let roles = given.map_or_else(
        || AcceptedRoles::roles([hierarchy.owner_role()]),
        |list| AcceptedRoles::roles(list.iter().cloned()),
    );
    known_roles(action, roles, hierarchy)
}

/// `roles`, refused when it names a role outside `hierarchy`.
fn known_roles(
    action: &'static str,
    roles: AcceptedRoles,
    hierarchy: &RoleHierarchy,
) -> Result<AcceptedRoles, ConfigError> {
    if let Some(role) = roles.unknown_role(hierarchy) {
        return Err(ConfigError::WorkspacePermissionUnknownRole {
            action,
            role: role.to_owned(),
        });
    }
    Ok(roles)
}

/// `value`, refused when it is over `max`.
fn at_most(option: &'static str, value: u32, max: u32) -> Result<u32, ConfigError> {
    if value > max {
        return Err(ConfigError::WorkspaceOptionOutOfRange { option, max });
    }
    Ok(value)
}

impl WorkspacePermissionsConfig {
    /// Resolves every permission against `hierarchy`.
    fn resolve(&self, hierarchy: &RoleHierarchy) -> Result<ResolvedPermissions, ConfigError> {
        let view_members = known_roles("viewMembers", self.view_members.clone(), hierarchy)?;
        let manage = self.manage_workspace.as_ref();
        Ok(ResolvedPermissions {
            view_members,
            manage_workspace: owner_unless("manageWorkspace", manage, hierarchy)?,
            delete_workspace: owner_unless(
                "deleteWorkspace",
                self.delete_workspace.as_ref(),
                hierarchy,
            )?,
            manage_members: owner_unless("manageMembers", self.manage_members.as_ref(), hierarchy)?,
        })
    }
}

impl WorkspacesConfig {
    /// Validates an enabled group; `None` when the group is off.
    ///
    /// # Errors
    ///
    /// [`ConfigError::WorkspaceOwnerRole`] for an owner role outside the name rule,
    /// [`ConfigError::WorkspaceRoles`] for a hierarchy the rules refuse,
    /// [`ConfigError::WorkspacePermissionUnknownRole`] for a permission naming a role outside it,
    /// [`ConfigError::WorkspaceMembershipCacheTtl`] for a lifetime over the maximum, and
    /// [`ConfigError::WorkspaceOptionOutOfRange`] for an owner cap or a grace period over its
    /// bound.
    pub(crate) fn resolve(&self) -> Result<Option<ResolvedWorkspaces>, ConfigError> {
        if !self.enabled {
            return Ok(None);
        }
        // The shape rule runs before the hierarchy rules so a malformed owner role is reported as
        // that, not as an unknown owner (an empty name matches no key). It binds the owner role
        // alone: other roles keep whatever shape the host gives them.
        if !is_valid_owner_role(&self.roles.owner_role) {
            return Err(ConfigError::WorkspaceOwnerRole {
                value: self.roles.owner_role.clone(),
            });
        }
        let hierarchy = RoleHierarchy::new(self.roles.hierarchy.clone(), &self.roles.owner_role)
            .map_err(ConfigError::WorkspaceRoles)?;
        let permissions = self.permissions.resolve(&hierarchy)?;
        let ttl = MembershipCacheTtl::new(self.membership_cache_ttl_seconds)
            .map_err(ConfigError::WorkspaceMembershipCacheTtl)?;
        let max_workspaces_per_user = at_most(
            "maxWorkspacesPerUser",
            self.max_workspaces_per_user,
            MAX_WORKSPACES_PER_USER_LIMIT,
        )?;
        let deletion_grace_days = at_most(
            "deletionGraceDays",
            self.deletion_grace_days,
            DELETION_GRACE_DAYS_MAX,
        )?;
        Ok(Some(ResolvedWorkspaces {
            hierarchy,
            ttl,
            permissions,
            allow_create: self.allow_create,
            max_workspaces_per_user,
            deletion_grace_days,
        }))
    }
}
