//! The workspace guard's decision through the engine: the access decision over the in-memory
//! repositories and cache, the path-parameter rule ahead of any lookup, and the startup rules of
//! the layer (layer: service, tests).

use std::sync::Arc;

use bymax_auth_types::AuthError;

use super::workspace_test_support::{
    Fixture, Seat, active, authorize, build, config, membership, workspace,
};
use crate::config::Environment;
use crate::engine::{AuthEngine, AuthEngineBuilder};
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;
use crate::services::membership_cache::bump_membership;
use crate::testing::{
    InMemoryMembershipCache, InMemoryStores, InMemoryUserRepository, InMemoryWorkspaces,
};
use crate::workspace::access::AcceptedRoles;
use crate::workspace::domain::{MembershipRef, MembershipStatus, WorkspaceStatus};

const ANY: AcceptedRoles = AcceptedRoles::AnyMember;

/// The pinned shared contract.
fn contract() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)
}

/// One workspace per status in `t1`, with `u1` an active owner of each, `u2` an active admin of
/// the pending one and a suspended member of the active one.
fn seeded() -> Option<Fixture> {
    let f = build(config())?;
    for (tick, (id, status)) in [
        ("w-active", WorkspaceStatus::Active),
        ("w-pending", WorkspaceStatus::PendingDeletion),
        ("w-suspended", WorkspaceStatus::Suspended),
        ("w-deleted", WorkspaceStatus::Deleted),
    ]
    .into_iter()
    .enumerate()
    {
        let tick = i64::try_from(tick).unwrap_or_default();
        f.repo.seed_workspace(workspace("t1", id, status, tick));
        f.repo
            .seed_membership(membership(&active("t1", id, "u1", "owner"), tick));
    }
    f.repo
        .seed_membership(membership(&active("t1", "w-pending", "u2", "admin"), 9));
    let suspended = Seat {
        status: MembershipStatus::Suspended,
        ..active("t1", "w-active", "u2", "owner")
    };
    f.repo.seed_membership(membership(&suspended, 10));
    Some(f)
}

#[tokio::test]
async fn every_caller_who_may_not_see_a_workspace_gets_the_identical_404() {
    let Some(f) = seeded() else { return };
    for (label, user, workspace) in [
        ("a stranger", "u3", "w-active"),
        ("a suspended member", "u2", "w-active"),
        ("a workspace that does not exist", "u1", "w-missing"),
        ("a suspended workspace", "u1", "w-suspended"),
        ("a deleted workspace", "u1", "w-deleted"),
        (
            "a non-owner of a workspace pending deletion",
            "u2",
            "w-pending",
        ),
    ] {
        let refused = authorize(&f, ("t1", user, workspace), &ANY, false).await;
        assert!(
            matches!(refused, Err(AuthError::WorkspaceNotFound)),
            "{label}: {refused:?}"
        );
        // Even a surface admitting pending workspaces tells none of them more.
        let refused = authorize(&f, ("t1", user, workspace), &ANY, true).await;
        assert!(
            matches!(refused, Err(AuthError::WorkspaceNotFound)),
            "{label}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn the_owner_of_a_workspace_pending_deletion_is_told_unless_the_surface_admits_it() {
    let Some(f) = seeded() else { return };
    let refused = authorize(&f, ("t1", "u1", "w-pending"), &ANY, false).await;
    assert!(matches!(refused, Err(AuthError::WorkspacePendingDeletion)));
    let admitted = authorize(&f, ("t1", "u1", "w-pending"), &ANY, true).await;
    assert!(matches!(admitted, Ok(member) if member.role == "owner"));
}

#[tokio::test]
async fn the_role_is_judged_through_the_hierarchy_after_the_membership() {
    let Some(f) = seeded() else { return };
    f.repo
        .seed_membership(membership(&active("t1", "w-active", "u4", "member"), 11));
    f.repo
        .seed_membership(membership(&active("t1", "w-active", "u5", "admin"), 12));
    let admins = AcceptedRoles::roles(["admin"]);
    let members = AcceptedRoles::roles(["member"]);
    let below = authorize(&f, ("t1", "u4", "w-active"), &admins, false).await;
    assert!(matches!(below, Err(AuthError::InsufficientWorkspaceRole)));
    let included = authorize(&f, ("t1", "u5", "w-active"), &members, false).await;
    assert!(matches!(&included, Ok(member) if member.role == "admin"));
    let Ok(member) = included else { return };
    assert_eq!(
        (
            member.tenant_id.as_str(),
            member.workspace_id.as_str(),
            member.user_id.as_str()
        ),
        ("t1", "w-active", "u5")
    );
}

#[tokio::test]
async fn a_surface_declaring_no_role_and_a_blank_credential_are_refused_before_any_lookup() {
    let Some(f) = seeded() else { return };
    let nothing = AcceptedRoles::Roles(Vec::new());
    let forbidden = authorize(&f, ("t1", "u1", "\u{0}"), &nothing, false).await;
    assert!(matches!(forbidden, Err(AuthError::Forbidden)));
    for (tenant, user) in [(" ", "u1"), ("t1", "\u{feff}"), ("", "u1")] {
        let refused = authorize(&f, (tenant, user, "w-active"), &ANY, false).await;
        assert!(
            matches!(refused, Err(AuthError::TokenInvalid)),
            "{tenant:?} {user:?}"
        );
    }
    assert!(
        f.cache.operations().is_empty(),
        "{:?}",
        f.cache.operations()
    );
}

/// The detail of a validation refusal, or `None` for any other answer.
fn validation_field(
    result: &Result<crate::workspace::access::WorkspaceMember, AuthError>,
) -> Option<String> {
    match result {
        Err(AuthError::Validation { details }) if details.len() == 1 => {
            details.first().map(|detail| detail.field.clone())
        }
        _ => None,
    }
}

/// The workspace-id bound, read from `requestFieldBounds.pathParameters`, after checking the two
/// rules that state it say it is applied ahead of any lookup.
fn workspace_id_bound() -> usize {
    let root = contract();
    let rule = root["workspaceRealtime"]["rules"]["workspaceIdField"]
        .as_str()
        .unwrap_or_default();
    assert!(rule.contains("1 to 128 code points, not blank, with no control character"));
    assert!(rule.contains("ahead of any lookup"));
    let bound = &root["requestFieldBounds"]["pathParameters"];
    let comment = bound["$comment"].as_str().unwrap_or_default();
    assert!(comment.contains("ahead of authorization"));
    assert!(comment.contains("`Blank` means only JS `\\s` whitespace"));
    assert_eq!(bound["workspaceId"]["min"].as_u64(), Some(1));
    usize::try_from(bound["workspaceId"]["max"].as_u64().unwrap_or_default()).unwrap_or(0)
}

#[tokio::test]
async fn a_malformed_workspace_id_is_refused_naming_it_ahead_of_any_lookup() {
    let Some(f) = seeded() else { return };
    let max = workspace_id_bound();
    assert!(max > 0);
    let over = "a".repeat(max + 1);
    let astral_over = "\u{1F600}".repeat(max + 1);
    // Blank is JS whitespace (U+FEFF included); a control character is C0, DEL or C1 anywhere.
    let blank = ["", " ", "\t", "\u{a0}", "\u{3000}", "\u{feff}", "\u{2028}"];
    let controls = ["a\u{0}b", "a\u{1f}", "a\u{7f}", "\u{85}", "a\u{9f}"];
    let long = [over.as_str(), astral_over.as_str()];
    for id in blank.into_iter().chain(controls).chain(long) {
        let got = authorize(&f, ("t1", "u1", id), &ANY, false).await;
        let field = validation_field(&got);
        assert_eq!(field.as_deref(), Some("workspaceId"), "{id:?}");
    }
    let operations = f.cache.operations();
    assert!(operations.is_empty(), "{operations:?}");
}

#[tokio::test]
async fn a_well_formed_workspace_id_that_names_nothing_is_the_identical_404() {
    let Some(f) = seeded() else { return };
    let max = workspace_id_bound();
    // At the bound, counted in code points, and with characters JS does not count as blank.
    let at = "a".repeat(max);
    let astral_at = "\u{1F600}".repeat(max);
    let ids = [
        at.as_str(),
        astral_at.as_str(),
        "\u{200b}",
        "\u{180e}",
        "w-unknown",
    ];
    for id in ids {
        let got = authorize(&f, ("t1", "u1", id), &ANY, false).await;
        let not_found = matches!(got, Err(AuthError::WorkspaceNotFound));
        assert!(not_found, "{id:?}: {got:?}");
    }
}

#[tokio::test]
async fn a_workspace_or_a_member_of_another_tenant_is_not_reachable_by_a_homonym() {
    let Some(f) = seeded() else { return };
    f.repo
        .seed_workspace(workspace("t2", "w-active", WorkspaceStatus::Active, 20));
    f.repo
        .seed_membership(membership(&active("t2", "w-active", "u9", "owner"), 21));
    // u1 owns t1/w-active, not t2/w-active; u9 owns t2/w-active, not t1/w-active.
    let across = authorize(&f, ("t2", "u1", "w-active"), &ANY, false).await;
    assert!(matches!(across, Err(AuthError::WorkspaceNotFound)));
    let back = authorize(&f, ("t1", "u9", "w-active"), &ANY, false).await;
    assert!(matches!(back, Err(AuthError::WorkspaceNotFound)));
    let own = authorize(&f, ("t2", "u9", "w-active"), &ANY, false).await;
    assert!(matches!(own, Ok(member) if member.tenant_id == "t2"));
}

#[tokio::test]
async fn only_an_active_membership_of_an_active_workspace_is_cached_and_read_back() {
    let Some(f) = seeded() else { return };
    let admitted = authorize(&f, ("t1", "u1", "w-active"), &ANY, false).await;
    assert!(admitted.is_ok());
    assert_eq!(f.cache.operations(), ["read", "fill"]);
    // Every refusal reads the cache and fills nothing.
    for (user, workspace) in [
        ("u2", "w-active"),
        ("u1", "w-pending"),
        ("u1", "w-suspended"),
    ] {
        let _ = authorize(&f, ("t1", user, workspace), &ANY, false).await;
    }
    assert_eq!(
        f.cache.operations(),
        ["read", "fill", "read", "read", "read"]
    );
    // The entry answers until the membership's counter moves: a change the writer did not bump is
    // still served from the cache, and after the bump the repository decides.
    let demoted = Seat {
        status: MembershipStatus::Suspended,
        ..active("t1", "w-active", "u1", "owner")
    };
    f.repo.seed_membership(membership(&demoted, 30));
    let cached = authorize(&f, ("t1", "u1", "w-active"), &ANY, false).await;
    assert!(cached.is_ok());
    let key = MembershipRef {
        tenant_id: "t1",
        workspace_id: "w-active",
        user_id: "u1",
    };
    let bumped = bump_membership(f.cache.as_ref(), f.engine.config().hmac_key(), key).await;
    assert!(bumped.is_ok());
    let refused = authorize(&f, ("t1", "u1", "w-active"), &ANY, false).await;
    assert!(matches!(refused, Err(AuthError::WorkspaceNotFound)));
}

#[tokio::test]
async fn a_disabled_cache_reads_the_repositories_every_time_and_touches_no_store() {
    let mut cfg = config();
    cfg.workspaces.membership_cache_ttl_seconds = 0;
    let Some(f) = build(cfg) else { return };
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Active, 1));
    f.repo
        .seed_membership(membership(&active("t1", "w1", "u1", "member"), 2));
    for _ in 0..2 {
        let admitted = authorize(&f, ("t1", "u1", "w1"), &ANY, false).await;
        assert!(matches!(admitted, Ok(member) if member.role == "member"));
    }
    assert!(f.cache.operations().is_empty());
}

/// Adds collaborators to a builder.
type Wire = fn(AuthEngineBuilder) -> AuthEngineBuilder;

/// An engine over `config` given only the collaborators `wire` adds.
fn assemble(config: crate::config::AuthConfig, wire: Wire) -> Result<AuthEngine, ConfigError> {
    let builder = AuthEngine::builder()
        .config(config)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()));
    wire(builder).build()
}

fn repositories(builder: AuthEngineBuilder) -> AuthEngineBuilder {
    let repo = Arc::new(InMemoryWorkspaces::new());
    builder.workspace_repositories(repo.clone(), repo)
}

fn cache(builder: AuthEngineBuilder) -> AuthEngineBuilder {
    builder.membership_cache_store(Arc::new(InMemoryMembershipCache::new()))
}

#[test]
fn a_half_configured_layer_fails_at_startup() {
    let mut routes_only = base_config();
    routes_only.controllers.workspaces = true;
    let refused = assemble(routes_only, |builder| builder);
    assert!(matches!(
        refused,
        Err(ConfigError::WorkspacesControllerWithoutWorkspaces)
    ));
    let partial: [Wire; 2] = [repositories, cache];
    for wire in partial {
        let refused = assemble(base_config(), wire);
        assert!(matches!(
            refused,
            Err(ConfigError::WorkspaceCollaboratorsUnused)
        ));
    }
    let refused = assemble(config(), cache);
    assert!(matches!(
        refused,
        Err(ConfigError::MissingWorkspaceRepositories)
    ));
    let refused = assemble(config(), repositories);
    assert!(matches!(
        refused,
        Err(ConfigError::MissingMembershipCacheStore)
    ));
    let mut bad_roles = config();
    bad_roles.workspaces.roles.owner_role = "ghost".to_owned();
    let refused = assemble(bad_roles, |builder| cache(repositories(builder)));
    assert!(matches!(refused, Err(ConfigError::WorkspaceRoles(_))));
    let built = assemble(config(), |builder| cache(repositories(builder)));
    assert!(matches!(built, Ok(engine) if engine.workspaces_enabled()));
    // Off, with nothing supplied, the layer is simply absent.
    let off = assemble(base_config(), |builder| builder);
    assert!(matches!(off, Ok(engine) if !engine.workspaces_enabled()));
}
