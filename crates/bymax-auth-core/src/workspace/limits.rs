//! Lifetimes and limits of the workspace keyspaces (layer: domain).
//!
//! The values are pinned by `workspaceMembershipCache` and `workspaceInvitations` in the shared
//! contract, which the tests read from the file.

/// How long a workspace or membership version counter stays readable, in seconds (30 days).
///
/// A counter must outlive every cache entry written under it: one that expires while an entry
/// keyed by its old value is alive would restart at `0` and make that stale entry current again.
/// It is the token-epoch retention, so every counter in the keyspace keeps one retention rule.
pub const VERSION_RETENTION_SECONDS: u64 = crate::traits::TOKEN_EPOCH_RETENTION_SECS;

/// The default lifetime of a cached membership entry, in seconds.
pub const MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS: u64 = 60;

/// The longest configurable lifetime of a cached membership entry, in seconds.
pub const MEMBERSHIP_CACHE_TTL_MAX_SECONDS: u64 = 3_600;

/// The minimum time between two invitations of one address to one workspace, in seconds.
pub const INVITATION_RESEND_COOLDOWN_SECONDS: u64 = 60;

/// How many times one address may be invited again after the first invitation.
pub const INVITATION_MAX_RESENDS: u32 = 5;

/// How many invitations one inviter may issue per window.
pub const INVITATIONS_PER_INVITER_PER_WINDOW: u32 = 20;

/// The window of [`INVITATIONS_PER_INVITER_PER_WINDOW`], in seconds.
pub const INVITER_WINDOW_SECONDS: u64 = 3_600;

/// The largest `workspaces.max_workspaces_per_user` a deployment may set; `0` is no limit.
pub const MAX_WORKSPACES_PER_USER_LIMIT: u32 = 1_000_000;

/// The default number of days a workspace whose deletion was scheduled can still be restored.
pub const DELETION_GRACE_DAYS_DEFAULT: u32 = 14;

/// The longest configurable deletion grace period, in days; `0` deletes at once.
pub const DELETION_GRACE_DAYS_MAX: u32 = 365;
