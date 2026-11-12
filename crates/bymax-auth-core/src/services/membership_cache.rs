//! Resolving a workspace membership through the versioned cache, and invalidating it (layer:
//! service).
//!
//! THE ORDER IS THE REQUIREMENT: a reader reads the workspace counter, then the membership counter,
//! then the entry those two values name, then, on a miss, the repositories, and refills the entry
//! under the versions it read FIRST. A change that lands after the version reads moves a counter,
//! so the refill sits under a name nobody reads. A writer changes the repository first and bumps
//! after, and a failed bump is an error.
//!
//! The cache is advisory: when the store fails, the answer comes from the repositories and nothing
//! is written. The repository reads must come from the primary or be read-your-writes, since a
//! lagging replica would cache a removed member as present under the new version.

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::RepositoryError;
use crate::services::error_chain;
use crate::traits::{MembershipCacheStore, MembershipRepository, WorkspaceRepository};
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceRef,
};
use crate::workspace::keys::{BlankPart, membership_version_id, workspace_version_id};
use crate::workspace::membership_cache::{MembershipCacheIds, MembershipCacheTtl};

/// The two rows a membership is decided from, read together whatever the first one says, so a
/// missing workspace, an inactive one and a non-member cost the same repository work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRowsRead {
    /// The workspace, in any status, or `None` when none matches the key.
    pub workspace: Option<Workspace>,
    /// The membership, in any status, or `None` when none matches the key.
    pub membership: Option<Membership>,
}

impl MembershipRowsRead {
    /// The role of an ACTIVE membership of an ACTIVE workspace; `None` for every other state,
    /// which reads as "not a member".
    #[must_use]
    pub fn active_role(&self) -> Option<&str> {
        let workspace_active = self
            .workspace
            .as_ref()
            .is_some_and(|workspace| workspace.status.grants_access());
        let membership = self.membership.as_ref()?;
        (workspace_active && membership.status == MembershipStatus::Active)
            .then_some(membership.role.as_str())
    }
}

/// Where the repository rows of a membership come from.
#[async_trait]
pub trait MembershipRows: Send + Sync {
    /// Reads the workspace and the membership `member` names.
    ///
    /// # Errors
    ///
    /// [`RepositoryError`] on a datastore failure.
    async fn read_rows(
        &self,
        member: MembershipRef<'_>,
    ) -> Result<MembershipRowsRead, RepositoryError>;
}

/// The host's two repositories as a [`MembershipRows`].
#[derive(Clone, Copy)]
pub struct Repositories<'a> {
    /// The workspace repository.
    pub workspaces: &'a dyn WorkspaceRepository,
    /// The membership repository.
    pub memberships: &'a dyn MembershipRepository,
}

#[async_trait]
impl MembershipRows for Repositories<'_> {
    async fn read_rows(
        &self,
        member: MembershipRef<'_>,
    ) -> Result<MembershipRowsRead, RepositoryError> {
        let workspace = self.workspaces.find_by_id(member.workspace()).await?;
        let membership = self.memberships.find(member).await?;
        Ok(MembershipRowsRead {
            workspace,
            membership,
        })
    }
}

/// The cache a resolution goes through: the store, the identifier-HMAC key and the lifetime.
pub struct MembershipCache<'a, S: ?Sized> {
    /// The store holding the counters and the entries.
    pub store: &'a S,
    /// The identifier-HMAC key every key is derived with.
    pub identifier_key: &'a [u8; 64],
    /// The entry lifetime; [`MembershipCacheTtl::DISABLED`] reads the repositories every time.
    pub ttl: MembershipCacheTtl,
}

/// Where an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    /// A cached entry under the current versions.
    Cache,
    /// The repositories.
    Repository,
}

/// What a resolution found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// An active member of an active workspace.
    Member {
        /// The member's role in the workspace.
        role: String,
        /// Where the answer came from.
        source: ResolutionSource,
    },
    /// Anything else, decided from the repositories: the rows read, for an access decision that
    /// tells a pending deletion's owner apart without reading them again.
    NotMember(Box<MembershipRowsRead>),
}

/// Why a resolution failed.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// A part of the key is blank; nothing was read.
    #[error(transparent)]
    BlankPart(#[from] BlankPart),
    /// The repositories failed. A store failure is never this: the cache is advisory.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Why a bump failed. The change it follows must not be reported as invalidated.
#[derive(Debug, thiserror::Error)]
pub enum BumpError {
    /// A part of the key is blank; nothing was bumped.
    #[error(transparent)]
    BlankPart(#[from] BlankPart),
    /// The store failed to bump the counter.
    #[error("the membership cache counter could not be bumped")]
    Store(#[source] AuthError),
}

/// Resolves `member` through the cache: the versions, then the entry they name, then on a miss the
/// repositories, refilling under the versions read first when the rows say an active member of an
/// active workspace.
///
/// With the cache disabled the store is neither read nor written. A store failure on the read
/// answers from the repositories and writes nothing; a failed fill still answers.
///
/// # Errors
///
/// [`ResolveError::BlankPart`] before anything is read, and [`ResolveError::Repository`] when the
/// repositories fail.
pub async fn resolve_membership<S, R>(
    cache: &MembershipCache<'_, S>,
    rows: &R,
    member: MembershipRef<'_>,
) -> Result<Resolution, ResolveError>
where
    S: MembershipCacheStore + ?Sized,
    R: MembershipRows + ?Sized,
{
    let ids = MembershipCacheIds::derive(cache.identifier_key, member)?;
    let Some(ttl) = cache.ttl.entry_ttl() else {
        return from_rows(rows, member).await;
    };
    let read = match cache.store.read(&ids).await {
        Ok(read) => Some(read),
        Err(error) => {
            unavailable(&error, "reading the repositories");
            None
        }
    };
    if let Some(role) = read.as_ref().and_then(|read| read.cached_role()) {
        let source = ResolutionSource::Cache;
        return Ok(Resolution::Member { role, source });
    }
    let resolution = from_rows(rows, member).await?;
    if let (Some(read), Resolution::Member { role, .. }) = (read, &resolution)
        && let Err(error) = cache.store.fill(&ids, read.versions, role, ttl).await
    {
        unavailable(&error, "the answer was not cached");
    }
    Ok(resolution)
}

/// Decides `member` from the repositories alone.
async fn from_rows<R: MembershipRows + ?Sized>(
    rows: &R,
    member: MembershipRef<'_>,
) -> Result<Resolution, ResolveError> {
    let read = rows.read_rows(member).await?;
    Ok(match read.active_role() {
        Some(role) => Resolution::Member {
            role: role.to_owned(),
            source: ResolutionSource::Repository,
        },
        None => Resolution::NotMember(Box::new(read)),
    })
}

/// Logs a store failure the cache absorbs. No identifier is logged.
fn unavailable(error: &AuthError, outcome: &'static str) {
    tracing::warn!(
        error = %error_chain(error),
        "workspace membership cache unavailable; {outcome}"
    );
}

/// Drops the cached access of EVERY member of `workspace`, for an event that changes the whole
/// workspace (deleting it, scheduling or undoing its deletion, suspending it). Call it after the
/// repository change has committed.
///
/// # Errors
///
/// [`BumpError::BlankPart`] before anything is written, [`BumpError::Store`] when the bump fails.
pub async fn bump_workspace<S: MembershipCacheStore + ?Sized>(
    store: &S,
    identifier_key: &[u8; 64],
    workspace: WorkspaceRef<'_>,
) -> Result<u64, BumpError> {
    let id = workspace_version_id(identifier_key, workspace.tenant_id, workspace.workspace_id)?;
    store.bump_workspace(&id).await.map_err(BumpError::Store)
}

/// Drops the cached access of one membership, after a change to it has committed.
///
/// # Errors
///
/// [`BumpError::BlankPart`] before anything is written, [`BumpError::Store`] when the bump fails.
pub async fn bump_membership<S: MembershipCacheStore + ?Sized>(
    store: &S,
    identifier_key: &[u8; 64],
    member: MembershipRef<'_>,
) -> Result<u64, BumpError> {
    let id = membership_version_id(
        identifier_key,
        member.tenant_id,
        member.workspace_id,
        member.user_id,
    )?;
    store.bump_membership(&id).await.map_err(BumpError::Store)
}
