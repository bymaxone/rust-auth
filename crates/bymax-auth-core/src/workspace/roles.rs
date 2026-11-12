//! The workspace role hierarchy and the owner role (layer: domain).
//!
//! The hierarchy names every role and, for each, the roles it includes. Inclusion is one level and
//! explicit: a role holds another only when its own list names it, which is why the owner must list
//! every other role.

use std::collections::BTreeMap;

/// Why a hierarchy was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleHierarchyError {
    /// No role is named.
    #[error("workspaces.roles.hierarchy is required and must name at least one role")]
    Empty,
    /// A role's list names something that is not a role of the hierarchy.
    #[error(
        "workspaces.roles.hierarchy.{role} must list only roles that are keys of the hierarchy"
    )]
    UnknownIncluded {
        /// The role whose list is wrong.
        role: String,
    },
    /// The owner role is not a role of the hierarchy.
    #[error("workspaces.roles.ownerRole must be a role of the hierarchy")]
    UnknownOwner,
    /// A role other than the owner includes the owner role, so it would hold every owner permission.
    #[error("workspaces.roles.hierarchy: '{role}' must not include the owner role")]
    IncludesOwner {
        /// The role that includes the owner.
        role: String,
    },
    /// The owner role does not include some other role; the owner is the top of the hierarchy.
    #[error(
        "workspaces.roles.ownerRole must include every other role, and does not include '{role}'"
    )]
    OwnerMissesRole {
        /// The role the owner does not include.
        role: String,
    },
}

/// A validated role hierarchy with its owner role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleHierarchy {
    includes: BTreeMap<String, Vec<String>>,
    owner_role: String,
}

impl RoleHierarchy {
    /// Validates `includes` (role to the roles it includes) and `owner_role`.
    ///
    /// # Errors
    ///
    /// A [`RoleHierarchyError`] naming the first rule the input breaks.
    pub fn new(
        includes: BTreeMap<String, Vec<String>>,
        owner_role: &str,
    ) -> Result<Self, RoleHierarchyError> {
        if includes.is_empty() {
            return Err(RoleHierarchyError::Empty);
        }
        for (role, list) in &includes {
            if list.iter().any(|name| !includes.contains_key(name)) {
                return Err(RoleHierarchyError::UnknownIncluded { role: role.clone() });
            }
        }
        let Some(owner_list) = includes.get(owner_role) else {
            return Err(RoleHierarchyError::UnknownOwner);
        };
        for (role, list) in &includes {
            if role != owner_role && list.iter().any(|name| name == owner_role) {
                return Err(RoleHierarchyError::IncludesOwner { role: role.clone() });
            }
        }
        if let Some(role) = includes
            .keys()
            .find(|role| *role != owner_role && !owner_list.contains(role))
        {
            return Err(RoleHierarchyError::OwnerMissesRole { role: role.clone() });
        }
        Ok(Self {
            includes,
            owner_role: owner_role.to_owned(),
        })
    }

    /// The role that owns a workspace.
    #[must_use]
    pub fn owner_role(&self) -> &str {
        &self.owner_role
    }

    /// Whether `role` is a role of the hierarchy.
    #[must_use]
    pub fn knows(&self, role: &str) -> bool {
        self.includes.contains_key(role)
    }

    /// Whether a member holding `held` satisfies a requirement for `required`: the same role, or a
    /// role whose list names it. A role outside the hierarchy satisfies nothing but itself.
    #[must_use]
    pub fn satisfies(&self, held: &str, required: &str) -> bool {
        held == required
            || self
                .includes
                .get(held)
                .is_some_and(|list| list.iter().any(|name| name == required))
    }
}
