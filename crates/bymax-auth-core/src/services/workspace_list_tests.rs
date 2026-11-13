//! The workspace read services through the engine: the two lists, the access view and the switch
//! (layer: service, tests).
//!
//! The tenant and the workspace of a list always come from the credential and the admitted
//! member; the page bounds are `requestFieldBounds.pageLimit`, read from the shared contract.

use bymax_auth_types::AuthError;

use super::workspace_test_support::{Fixture, Seat, active, build, config, membership, workspace};
use std::sync::Arc;

use crate::engine::AuthEngine;
use crate::services::auth::test_support::{base_config, ctx};
use crate::services::workspace::{MyWorkspaces, PageQuery, WorkspaceAccessRequest};
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::workspace::access::{AcceptedRoles, WorkspaceMember};
use crate::workspace::bounds::CURSOR_MAX_CHARS;
use crate::workspace::domain::{MembershipStatus, WorkspaceStatus};

/// The pinned shared contract.
fn contract() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)
}

/// `u1` of `t1` in five workspaces created in order (the second suspended for u1, the fourth
/// pending deletion), `u2` in the first, and `u1`'s homonym in `t2`.
fn seeded() -> Option<Fixture> {
    let f = build(config())?;
    for tick in 1..=5 {
        let id = format!("w{tick}");
        let status = if tick == 4 {
            WorkspaceStatus::PendingDeletion
        } else {
            WorkspaceStatus::Active
        };
        f.repo.seed_workspace(workspace("t1", &id, status, tick));
        let seat = Seat {
            status: if tick == 2 {
                MembershipStatus::Suspended
            } else {
                MembershipStatus::Active
            },
            ..active("t1", &id, "u1", "member")
        };
        f.repo.seed_membership(membership(&seat, 10 + tick));
    }
    f.repo
        .seed_membership(membership(&active("t1", "w1", "u2", "owner"), 20));
    f.repo
        .seed_workspace(workspace("t2", "w9", WorkspaceStatus::Active, 30));
    f.repo
        .seed_membership(membership(&active("t2", "w9", "u1", "owner"), 31));
    Some(f)
}

fn ids(page: &MyWorkspaces) -> Vec<&str> {
    page.items
        .iter()
        .map(|item| item.workspace.id.as_str())
        .collect()
}

fn page<'a>(cursor: Option<&'a str>, limit: Option<&'a str>) -> PageQuery<'a> {
    PageQuery { cursor, limit }
}

#[tokio::test]
async fn the_callers_list_holds_only_its_active_memberships_of_active_workspaces_in_order() {
    let Some(f) = seeded() else { return };
    let mine = f
        .engine
        .list_my_workspaces("t1", "u1", page(None, None))
        .await;
    assert!(mine.is_ok(), "{mine:?}");
    let Ok(mine) = mine else { return };
    assert_eq!(ids(&mine), ["w1", "w3", "w5"]);
    assert!(
        mine.items
            .iter()
            .all(|item| item.membership.user_id == "u1")
    );
    assert_eq!(mine.next_cursor, None);
    assert_eq!(mine.last_active_workspace_id, None);
    // The homonym in another tenant is another account with its own list.
    let other = f
        .engine
        .list_my_workspaces("t2", "u1", page(None, None))
        .await;
    assert!(
        matches!(&other, Ok(list) if ids(list) == ["w9"]),
        "{other:?}"
    );
}

#[tokio::test]
async fn a_page_continues_where_its_cursor_says_and_a_foreign_cursor_never_widens_the_list() {
    let Some(f) = seeded() else { return };
    let first = f
        .engine
        .list_my_workspaces("t1", "u1", page(None, Some("1")))
        .await;
    let Ok(first) = first else { return };
    assert_eq!(ids(&first), ["w1"]);
    let cursor = first.next_cursor.clone().unwrap_or_default();
    assert!(!cursor.is_empty());
    let second = f
        .engine
        .list_my_workspaces("t1", "u1", page(Some(&cursor), Some("1")))
        .await;
    assert!(
        matches!(&second, Ok(list) if ids(list) == ["w3"]),
        "{second:?}"
    );
    // u2 replaying u1's cursor reads its own list from the start, never u1's rows.
    let replayed = f
        .engine
        .list_my_workspaces("t1", "u2", page(Some(&cursor), None))
        .await;
    assert!(
        matches!(&replayed, Ok(list) if ids(list) == ["w1"]),
        "{replayed:?}"
    );
    let Ok(replayed) = replayed else { return };
    assert!(
        replayed
            .items
            .iter()
            .all(|item| item.membership.user_id == "u2")
    );
}

/// The field a single-entry validation refusal names.
fn refused_field<T>(result: &Result<T, AuthError>) -> Option<String> {
    match result {
        Err(AuthError::Validation { details }) if details.len() == 1 => {
            details.first().map(|detail| detail.field.clone())
        }
        _ => None,
    }
}

#[tokio::test]
async fn the_page_limit_bounds_are_the_contracts_and_refuse_without_clamping() {
    let Some(f) = seeded() else { return };
    let root = contract();
    let bound = &root["requestFieldBounds"]["pageLimit"];
    let min = bound["min"].as_u64().unwrap_or(0);
    let max = bound["max"].as_u64().unwrap_or(0);
    assert_eq!(bound["default"].as_u64(), Some(50));
    let (below, above) = ((min - 1).to_string(), (max + 1).to_string());
    for limit in [
        below.as_str(),
        above.as_str(),
        "",
        "05",
        "+5",
        " 5",
        "5.0",
        "1e2",
    ] {
        let got = f
            .engine
            .list_my_workspaces("t1", "u1", page(None, Some(limit)))
            .await;
        assert_eq!(refused_field(&got).as_deref(), Some("limit"), "{limit:?}");
    }
    for limit in [min.to_string(), max.to_string()] {
        let got = f
            .engine
            .list_my_workspaces("t1", "u1", page(None, Some(&limit)))
            .await;
        assert!(got.is_ok(), "{limit}");
    }
    let blank = f
        .engine
        .list_my_workspaces(" ", "u1", page(None, None))
        .await;
    assert!(matches!(blank, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn the_cursor_bounds_are_the_contracts_and_a_cursor_names_no_scope() {
    let Some(f) = seeded() else { return };
    let root = contract();
    let rule = root["requestFieldBounds"]["pageLimit"]["$comment"]
        .as_str()
        .unwrap_or_default();
    assert!(rule.contains(&format!("1 to {CURSOR_MAX_CHARS} characters")));
    assert!(rule.contains("always come from the credential and the route"));
    let long = "c".repeat(CURSOR_MAX_CHARS + 1);
    for cursor in ["", "a\u{0}", "a\u{85}", long.as_str()] {
        let got = f
            .engine
            .list_my_workspaces("t1", "u1", page(Some(cursor), None))
            .await;
        assert_eq!(refused_field(&got).as_deref(), Some("cursor"), "{cursor:?}");
    }
    // A well-formed cursor the repository did not issue restarts the caller's own list.
    let at = "c".repeat(CURSOR_MAX_CHARS);
    let got = f
        .engine
        .list_my_workspaces("t1", "u1", page(Some(&at), None))
        .await;
    assert!(
        matches!(&got, Ok(list) if ids(list) == ["w1", "w3", "w5"]),
        "{got:?}"
    );
}

fn admitted(workspace: &str, user: &str, role: &str) -> WorkspaceMember {
    WorkspaceMember {
        tenant_id: "t1".to_owned(),
        workspace_id: workspace.to_owned(),
        user_id: user.to_owned(),
        role: role.to_owned(),
    }
}

#[tokio::test]
async fn the_members_list_holds_every_status_of_the_admitted_workspace_only() {
    let Some(f) = seeded() else { return };
    f.repo
        .seed_membership(membership(&active("t1", "w2", "u3", "admin"), 40));
    f.repo
        .seed_membership(membership(&active("t2", "w2", "u4", "owner"), 41));
    let member = admitted("w2", "u3", "admin");
    let listed = f
        .engine
        .list_workspace_members(&member, page(None, None))
        .await;
    assert!(listed.is_ok(), "{listed:?}");
    let Ok(listed) = listed else { return };
    let rows: Vec<(&str, MembershipStatus)> = listed
        .items
        .iter()
        .map(|m| (m.user_id.as_str(), m.status))
        .collect();
    assert_eq!(
        rows,
        [
            ("u1", MembershipStatus::Suspended),
            ("u3", MembershipStatus::Active)
        ]
    );
    let first = f
        .engine
        .list_workspace_members(&member, page(None, Some("1")))
        .await;
    assert!(matches!(&first, Ok(p) if p.items.len() == 1 && p.next_cursor.is_some()));
    let bad = f
        .engine
        .list_workspace_members(&member, page(None, Some("0")))
        .await;
    assert_eq!(refused_field(&bad).as_deref(), Some("limit"));
}

#[tokio::test]
async fn the_access_view_rereads_the_workspace_and_answers_404_once_it_is_not_active() {
    let Some(f) = seeded() else { return };
    let member = admitted("w1", "u1", "member");
    let view = f.engine.workspace_access(&member).await;
    assert!(matches!(&view, Ok(v) if v.workspace.id == "w1" && v.role == "member"));
    f.repo
        .seed_workspace(workspace("t1", "w1", WorkspaceStatus::Suspended, 1));
    let gone = f.engine.workspace_access(&member).await;
    assert!(matches!(gone, Err(AuthError::WorkspaceNotFound)));
    let missing = f
        .engine
        .workspace_access(&admitted("w-none", "u1", "member"))
        .await;
    assert!(matches!(missing, Err(AuthError::WorkspaceNotFound)));
}

#[tokio::test]
async fn a_switch_is_recorded_for_the_caller_and_listed_as_its_last_active_workspace() {
    let Some(f) = seeded() else { return };
    let switched = f
        .engine
        .switch_workspace(&admitted("w3", "u1", "member"), &ctx())
        .await;
    assert!(switched.is_ok());
    let mine = f
        .engine
        .list_my_workspaces("t1", "u1", page(None, None))
        .await;
    assert!(matches!(&mine, Ok(list) if list.last_active_workspace_id.as_deref() == Some("w3")));
    // Another member of the same tenant has recorded nothing.
    let theirs = f
        .engine
        .list_my_workspaces("t1", "u2", page(None, None))
        .await;
    assert!(matches!(&theirs, Ok(list) if list.last_active_workspace_id.is_none()));
}

#[tokio::test]
async fn every_workspace_call_on_an_engine_without_the_layer_is_internal() {
    let engine = AuthEngine::builder()
        .config(base_config())
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .build();
    assert!(engine.is_ok());
    let Ok(engine) = engine else { return };
    assert!(!engine.workspaces_enabled());
    assert!(engine.workspace_view_members_roles().is_none());
    let member = admitted("w1", "u1", "member");
    let request = WorkspaceAccessRequest {
        workspace_id: "w1",
        accepted: &AcceptedRoles::AnyMember,
        allow_pending: false,
    };
    let internal = |result: Result<(), AuthError>| matches!(result, Err(AuthError::Internal(_)));
    let guard = engine.authorize_workspace("t1", "u1", request).await;
    assert!(internal(guard.map(drop)));
    let mine = engine
        .list_my_workspaces("t1", "u1", PageQuery::default())
        .await;
    assert!(internal(mine.map(drop)));
    assert!(internal(engine.workspace_access(&member).await.map(drop)));
    let members = engine
        .list_workspace_members(&member, PageQuery::default())
        .await;
    assert!(internal(members.map(drop)));
    assert!(internal(engine.switch_workspace(&member, &ctx()).await));
}
