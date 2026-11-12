//! The membership resolver's rules the contract scenarios do not reach (layer: service, tests):
//! a disabled cache, a store that fails, blank key parts, members who are not active, and the
//! host's repositories as the source of the rows.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bymax_auth_types::AuthError;
use time::OffsetDateTime;

use super::membership_cache::{
    BumpError, MembershipCache, MembershipRows, MembershipRowsRead, Repositories, Resolution,
    ResolutionSource, ResolveError, bump_membership, bump_workspace, resolve_membership,
};
use crate::RepositoryError;
use crate::testing::{InMemoryMembershipCache, InMemoryWorkspaces};
use crate::traits::MembershipCacheStore;
use crate::workspace::domain::{
    Membership, MembershipRef, MembershipStatus, Workspace, WorkspaceRef, WorkspaceStatus,
};
use crate::workspace::keys::BlankPart;
use crate::workspace::membership_cache::{MembershipCacheIds, MembershipCacheTtl};

const KEY: [u8; 64] = [3; 64];
const MEMBER: MembershipRef<'static> = MembershipRef {
    tenant_id: "t1",
    workspace_id: "w1",
    user_id: "u1",
};

fn workspace(status: WorkspaceStatus) -> Workspace {
    Workspace {
        id: MEMBER.workspace_id.to_owned(),
        tenant_id: MEMBER.tenant_id.to_owned(),
        name: "W".to_owned(),
        status,
        created_at: OffsetDateTime::UNIX_EPOCH,
        deletion_scheduled_at: None,
    }
}

fn membership(status: MembershipStatus) -> Membership {
    Membership {
        tenant_id: MEMBER.tenant_id.to_owned(),
        workspace_id: MEMBER.workspace_id.to_owned(),
        user_id: MEMBER.user_id.to_owned(),
        role: "editor".to_owned(),
        status,
        invited_by_user_id: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Rows that answer a fixed read, or fail, and count the reads.
struct Rows {
    answer: Mutex<Option<MembershipRowsRead>>,
    reads: AtomicUsize,
}

impl Rows {
    fn of(workspace: Option<Workspace>, membership: Option<Membership>) -> Self {
        let read = MembershipRowsRead {
            workspace,
            membership,
        };
        Self {
            answer: Mutex::new(Some(read)),
            reads: AtomicUsize::new(0),
        }
    }

    fn active() -> Self {
        Self::of(
            Some(workspace(WorkspaceStatus::Active)),
            Some(membership(MembershipStatus::Active)),
        )
    }

    fn failing() -> Self {
        Self {
            answer: Mutex::new(None),
            reads: AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MembershipRows for Rows {
    async fn read_rows(&self, _: MembershipRef<'_>) -> Result<MembershipRowsRead, RepositoryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let answer = self.answer.lock().ok().and_then(|answer| answer.clone());
        answer.ok_or_else(|| RepositoryError::Backend("down".into()))
    }
}

fn cache<S: MembershipCacheStore>(store: &S, ttl: MembershipCacheTtl) -> MembershipCache<'_, S> {
    MembershipCache {
        store,
        identifier_key: &KEY,
        ttl,
    }
}

fn member_from(source: ResolutionSource) -> Resolution {
    Resolution::Member {
        role: "editor".to_owned(),
        source,
    }
}

#[tokio::test]
async fn a_resolution_fills_on_a_miss_and_answers_from_the_entry_after() {
    let store = InMemoryMembershipCache::new();
    let rows = Rows::active();
    let cache = cache(&store, MembershipCacheTtl::default());
    let first = resolve_membership(&cache, &rows, MEMBER).await;
    assert_eq!(first.ok(), Some(member_from(ResolutionSource::Repository)));
    let second = resolve_membership(&cache, &rows, MEMBER).await;
    assert_eq!(second.ok(), Some(member_from(ResolutionSource::Cache)));
    assert_eq!(rows.reads(), 1);
    assert_eq!(store.operations(), ["read", "fill", "read"]);
}

#[tokio::test]
async fn a_disabled_cache_is_neither_read_nor_written() {
    let store = InMemoryMembershipCache::new();
    let rows = Rows::active();
    let cache = cache(&store, MembershipCacheTtl::DISABLED);
    for _ in 0..2 {
        let answer = resolve_membership(&cache, &rows, MEMBER).await;
        assert_eq!(answer.ok(), Some(member_from(ResolutionSource::Repository)));
    }
    assert_eq!(rows.reads(), 2);
    assert!(store.operations().is_empty());
}

#[tokio::test]
async fn an_unreachable_store_answers_from_the_repositories_and_writes_nothing() {
    let store = InMemoryMembershipCache::new();
    store.set_unavailable(true);
    let rows = Rows::active();
    let answer =
        resolve_membership(&cache(&store, MembershipCacheTtl::default()), &rows, MEMBER).await;
    assert_eq!(answer.ok(), Some(member_from(ResolutionSource::Repository)));
    assert_eq!(store.operations(), ["read"]);
    store.set_unavailable(false);
    let ids = MembershipCacheIds::derive(&KEY, MEMBER).ok();
    let read = match &ids {
        Some(ids) => store.read(ids).await.ok(),
        None => None,
    };
    assert!(read.is_some_and(|read| read.entry.is_none()));
}

#[tokio::test]
async fn a_failed_fill_still_answers() {
    let store = InMemoryMembershipCache::new();
    store.set_fills_failing(true);
    let rows = Rows::active();
    let answer =
        resolve_membership(&cache(&store, MembershipCacheTtl::default()), &rows, MEMBER).await;
    assert_eq!(answer.ok(), Some(member_from(ResolutionSource::Repository)));
    assert_eq!(store.operations(), ["read", "fill"]);
    // Nothing was cached, so the next resolution reads the repositories again.
    store.set_fills_failing(false);
    let cache = cache(&store, MembershipCacheTtl::default());
    let again = resolve_membership(&cache, &rows, MEMBER);
    assert_eq!(
        again.await.ok(),
        Some(member_from(ResolutionSource::Repository))
    );
    assert_eq!(rows.reads(), 2);
}

#[tokio::test]
async fn only_an_active_member_of_an_active_workspace_is_a_member_and_nothing_else_is_cached() {
    let cases = [
        Rows::of(
            Some(workspace(WorkspaceStatus::PendingDeletion)),
            Some(membership(MembershipStatus::Active)),
        ),
        Rows::of(
            Some(workspace(WorkspaceStatus::Suspended)),
            Some(membership(MembershipStatus::Active)),
        ),
        Rows::of(
            Some(workspace(WorkspaceStatus::Deleted)),
            Some(membership(MembershipStatus::Active)),
        ),
        Rows::of(
            Some(workspace(WorkspaceStatus::Active)),
            Some(membership(MembershipStatus::Suspended)),
        ),
        Rows::of(None, Some(membership(MembershipStatus::Active))),
        Rows::of(Some(workspace(WorkspaceStatus::Active)), None),
    ];
    for rows in cases {
        let store = InMemoryMembershipCache::new();
        let answer =
            resolve_membership(&cache(&store, MembershipCacheTtl::default()), &rows, MEMBER).await;
        let expected = rows.answer.lock().ok().and_then(|answer| answer.clone());
        assert!(
            matches!(&answer, Ok(Resolution::NotMember(read)) if Some(read.as_ref()) == expected.as_ref())
        );
        assert_eq!(store.operations(), ["read"]);
    }
}

#[tokio::test]
async fn a_repository_failure_is_an_error_and_writes_nothing() {
    let store = InMemoryMembershipCache::new();
    let answer = resolve_membership(
        &cache(&store, MembershipCacheTtl::default()),
        &Rows::failing(),
        MEMBER,
    )
    .await;
    assert!(matches!(answer, Err(ResolveError::Repository(_))));
    assert_eq!(store.operations(), ["read"]);
}

#[tokio::test]
async fn a_blank_part_is_refused_before_the_store_or_the_repositories_are_touched() {
    let store = InMemoryMembershipCache::new();
    let rows = Rows::active();
    let blank = MembershipRef {
        user_id: " ",
        ..MEMBER
    };
    let answer =
        resolve_membership(&cache(&store, MembershipCacheTtl::default()), &rows, blank).await;
    assert!(matches!(
        answer,
        Err(ResolveError::BlankPart(BlankPart { part: "userId" }))
    ));
    let disabled =
        resolve_membership(&cache(&store, MembershipCacheTtl::DISABLED), &rows, blank).await;
    assert!(matches!(disabled, Err(ResolveError::BlankPart(_))));
    let bumped = bump_membership(&store, &KEY, blank).await;
    assert!(matches!(
        bumped,
        Err(BumpError::BlankPart(BlankPart { part: "userId" }))
    ));
    let workspace = WorkspaceRef {
        tenant_id: "t1",
        workspace_id: "",
    };
    let bumped = bump_workspace(&store, &KEY, workspace).await;
    assert!(matches!(
        bumped,
        Err(BumpError::BlankPart(BlankPart {
            part: "workspaceId"
        }))
    ));
    assert_eq!(rows.reads(), 0);
    assert!(store.operations().is_empty());
}

#[tokio::test]
async fn a_failed_bump_is_an_error() {
    let store = InMemoryMembershipCache::new();
    store.set_unavailable(true);
    let bumped = bump_membership(&store, &KEY, MEMBER).await;
    assert!(matches!(
        bumped,
        Err(BumpError::Store(AuthError::Internal(_)))
    ));
    let bumped = bump_workspace(&store, &KEY, MEMBER.workspace()).await;
    assert!(bumped.is_err_and(|error| error.to_string().contains("could not be bumped")));
}

#[tokio::test]
async fn a_bump_hides_the_entry_filled_before_it() {
    let store = InMemoryMembershipCache::new();
    let rows = Rows::active();
    let cache = cache(&store, MembershipCacheTtl::default());
    assert!(resolve_membership(&cache, &rows, MEMBER).await.is_ok());
    assert!(matches!(
        bump_workspace(&store, &KEY, MEMBER.workspace()).await,
        Ok(1)
    ));
    let after = resolve_membership(&cache, &rows, MEMBER).await;
    assert_eq!(after.ok(), Some(member_from(ResolutionSource::Repository)));
    assert!(matches!(bump_membership(&store, &KEY, MEMBER).await, Ok(1)));
    let after = resolve_membership(&cache, &rows, MEMBER).await;
    assert_eq!(after.ok(), Some(member_from(ResolutionSource::Repository)));
    assert_eq!(rows.reads(), 3);
}

#[tokio::test]
async fn the_host_repositories_are_read_together_through_the_adapter() {
    let repositories = InMemoryWorkspaces::new();
    repositories.seed_workspace(workspace(WorkspaceStatus::Active));
    repositories.seed_membership(membership(MembershipStatus::Active));
    let rows = Repositories {
        workspaces: &repositories,
        memberships: &repositories,
    };
    let store = InMemoryMembershipCache::new();
    let answer =
        resolve_membership(&cache(&store, MembershipCacheTtl::default()), &rows, MEMBER).await;
    assert_eq!(answer.ok(), Some(member_from(ResolutionSource::Repository)));
    let stranger = MembershipRef {
        user_id: "u2",
        ..MEMBER
    };
    let answer = resolve_membership(
        &cache(&store, MembershipCacheTtl::default()),
        &rows,
        stranger,
    )
    .await;
    assert!(matches!(answer, Ok(Resolution::NotMember(read))
        if read.workspace.is_some() && read.membership.is_none()));
}

#[tokio::test]
async fn a_store_failure_the_cache_absorbs_is_reported_as_a_warning_with_its_cause() {
    let (events, guard) = crate::log_capture::capture_events();
    let unreachable = InMemoryMembershipCache::new();
    unreachable.set_unavailable(true);
    let rows = Rows::active();
    let down = cache(&unreachable, MembershipCacheTtl::default());
    assert!(resolve_membership(&down, &rows, MEMBER).await.is_ok());
    let failing = InMemoryMembershipCache::new();
    failing.set_fills_failing(true);
    let refusing = cache(&failing, MembershipCacheTtl::default());
    assert!(resolve_membership(&refusing, &rows, MEMBER).await.is_ok());
    drop(guard);
    let warn = tracing::Level::WARN;
    assert!(events.contains_at(
        warn,
        "membership cache unavailable; reading the repositories"
    ));
    assert!(events.contains_at(
        warn,
        "membership cache unavailable; the answer was not cached"
    ));
    // The cause is on the line; no identifier is.
    assert!(events.contains_at(warn, "membership cache fill refused"));
    let lines = events.iter();
    assert_eq!(lines.len(), 2, "{lines:?}");
    let named = |line: &crate::log_capture::CapturedEvent| {
        line.rendered.contains("u1") || line.rendered.contains("t1")
    };
    assert!(!lines.iter().any(named));
}
