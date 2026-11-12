//! Configuration of the workspace layer and its startup validation (layer: configuration).
//!
//! The group carries what the workspace read surface needs: the role hierarchy and its owner role,
//! the lifetime of a cached membership, and which roles may list a workspace's members. Nothing is
//! validated while the group is off, so a host that never opts in is not asked for a hierarchy.

use std::collections::BTreeMap;

use crate::error::ConfigError;
use crate::workspace::access::AcceptedRoles;
use crate::workspace::limits::MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS;
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
}

impl Default for WorkspacesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            roles: WorkspaceRolesConfig::default(),
            permissions: WorkspacePermissionsConfig::default(),
            membership_cache_ttl_seconds: MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS,
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
}

impl Default for WorkspacePermissionsConfig {
    fn default() -> Self {
        Self {
            view_members: AcceptedRoles::AnyMember,
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
    /// The roles that may list a workspace's members.
    pub(crate) view_members: AcceptedRoles,
}

impl WorkspacesConfig {
    /// Validates an enabled group; `None` when the group is off.
    ///
    /// # Errors
    ///
    /// [`ConfigError::WorkspaceRoles`] for a hierarchy the rules refuse,
    /// [`ConfigError::WorkspacePermissionUnknownRole`] for a permission naming a role outside it,
    /// and [`ConfigError::WorkspaceMembershipCacheTtl`] for a lifetime over the maximum.
    pub(crate) fn resolve(&self) -> Result<Option<ResolvedWorkspaces>, ConfigError> {
        if !self.enabled {
            return Ok(None);
        }
        let hierarchy = RoleHierarchy::new(self.roles.hierarchy.clone(), &self.roles.owner_role)
            .map_err(ConfigError::WorkspaceRoles)?;
        let view_members = &self.permissions.view_members;
        if let Some(role) = view_members.unknown_role(&hierarchy) {
            return Err(ConfigError::WorkspacePermissionUnknownRole {
                action: "viewMembers",
                role: role.to_owned(),
            });
        }
        let ttl = MembershipCacheTtl::new(self.membership_cache_ttl_seconds)
            .map_err(ConfigError::WorkspaceMembershipCacheTtl)?;
        Ok(Some(ResolvedWorkspaces {
            hierarchy,
            ttl,
            view_members: view_members.clone(),
        }))
    }
}
