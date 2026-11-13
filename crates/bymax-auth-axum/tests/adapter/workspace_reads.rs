//! The workspace read routes over HTTP: the access decision's answers byte for byte, the path
//! parameter rule ahead of authorization, the list scope that only the credential and the route
//! decide, the page query read as text, and the wire shape of each answer. Shares the fixtures of
//! the parent test file.

use bymax_auth_core::workspace::domain::{MembershipStatus, WorkspaceStatus};
use serde_json::Value;

use super::*;

const PASSWORD: &str = "glidingwalnut42";

/// A router over a workspace-enabled harness with every limit generous, the caller's id and its
/// access cookie.
async fn signed_in() -> Option<(common::Harness, axum::Router, String, String)> {
    let h = build(EngineSpec {
        workspaces: true,
        ..EngineSpec::default()
    })?;
    let mut config =
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
    let generous = Some(bymax_auth_axum::RateLimit::new(10_000, 60));
    for setter in ALL_LIMIT_SETTERS {
        setter(&mut config.rate_limits, generous);
    }
    let app = router_with(&h, config);
    let user = seed_user(&h, "ws@e.com", PASSWORD, "USER").await;
    let access = login_access_cookie(&app, "ws@e.com", PASSWORD).await;
    Some((h, app, user, access))
}

async fn get(app: &axum::Router, path: &str, access: &str) -> Captured {
    Req::get(path)
        .cookie("access_token", access)
        .send(app)
        .await
}

/// The three routes a workspace guard admits to, for one workspace id.
async fn every_guarded_route(app: &axum::Router, id: &str, access: &str) -> Vec<Captured> {
    vec![
        get(app, &format!("/auth/workspaces/{id}/access"), access).await,
        get(app, &format!("/auth/workspaces/{id}/members"), access).await,
        Req::post(&format!("/auth/workspaces/{id}/switch"))
            .cookie("access_token", access)
            .send(app)
            .await,
    ]
}

/// The caller in each state the disclosure rule hides, by workspace id.
fn seed_hidden_states(h: &common::Harness, user: &str) {
    let w = &h.workspaces;
    for (id, status, role) in [
        ("w-suspended", WorkspaceStatus::Suspended, "owner"),
        ("w-deleted", WorkspaceStatus::Deleted, "owner"),
        ("w-pending", WorkspaceStatus::PendingDeletion, "admin"),
    ] {
        w.seed_workspace(id, status);
        w.seed_member(id, user, role, MembershipStatus::Active);
    }
    w.seed_workspace("w-stranger", WorkspaceStatus::Active);
    w.seed_member(
        "w-stranger",
        "someone-else",
        "owner",
        MembershipStatus::Active,
    );
    w.seed_workspace("w-held", WorkspaceStatus::Active);
    w.seed_member("w-held", user, "owner", MembershipStatus::Suspended);
}

#[tokio::test]
async fn every_hidden_state_is_the_same_404_byte_for_byte_on_every_route() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    seed_hidden_states(&h, &user);
    let reference = every_guarded_route(&app, "w-missing", &access).await;
    for answer in &reference {
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
        assert_eq!(answer.json()["error"]["code"], "auth.workspace_not_found");
    }
    for id in [
        "w-stranger",
        "w-held",
        "w-suspended",
        "w-deleted",
        "w-pending",
    ] {
        let answers = every_guarded_route(&app, id, &access).await;
        for (answer, expected) in answers.iter().zip(&reference) {
            assert_eq!(answer.status, expected.status, "{id}");
            assert_eq!(answer.body, expected.body, "{id}");
        }
    }
}

#[tokio::test]
async fn the_owner_of_a_pending_workspace_is_answered_409_on_every_read_route() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    h.workspaces
        .seed_workspace("w-pending", WorkspaceStatus::PendingDeletion);
    h.workspaces
        .seed_member("w-pending", &user, "owner", MembershipStatus::Active);
    for answer in every_guarded_route(&app, "w-pending", &access).await {
        assert_eq!(answer.status, StatusCode::CONFLICT);
        assert_eq!(
            answer.json()["error"]["code"],
            "auth.workspace_pending_deletion"
        );
    }
}

fn named(answer: &Captured) -> Vec<String> {
    answer.json()["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail["field"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn a_malformed_workspace_id_is_refused_naming_it_after_the_credential_and_before_any_lookup()
{
    let Some((_, app, _, access)) = signed_in().await else { return };
    let long = "a".repeat(129);
    for id in [
        "%20",
        "%E3%80%80",
        "%EF%BB%BF",
        "a%00b",
        "a%7F",
        long.as_str(),
    ] {
        for answer in every_guarded_route(&app, id, &access).await {
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{id}");
            assert_eq!(answer.json()["error"]["code"], "auth.validation", "{id}");
            assert_eq!(named(&answer), ["workspaceId"], "{id}");
        }
    }
    // Without a credential the request is refused as unauthenticated, whatever the id.
    let anonymous = Req::get("/auth/workspaces/%20/access").send(&app).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    // At the bound, the id is well formed and names nothing: the identical 404.
    let at = "a".repeat(128);
    for answer in every_guarded_route(&app, &at, &access).await {
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
    }
}

/// `{id, name, status, createdAt, deletionScheduledAt}` of a workspace answer.
fn workspace_keys(workspace: &Value) -> Vec<String> {
    let mut keys: Vec<String> = workspace
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

#[tokio::test]
async fn the_access_route_answers_the_workspace_and_the_callers_role() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    h.workspaces.seed_workspace("w1", WorkspaceStatus::Active);
    h.workspaces
        .seed_member("w1", &user, "admin", MembershipStatus::Active);
    let answer = get(&app, "/auth/workspaces/w1/access", &access).await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = answer.json();
    assert_eq!(body["role"], "admin");
    assert_eq!(
        workspace_keys(&body["workspace"]),
        ["createdAt", "deletionScheduledAt", "id", "name", "status"]
    );
    assert_eq!(body["workspace"]["id"], "w1");
    assert_eq!(body["workspace"]["status"], "active");
    assert_eq!(body["workspace"]["createdAt"], "1970-01-01T00:00:01.000Z");
    assert!(body["workspace"]["deletionScheduledAt"].is_null());
    // The status gate of the account applies before the workspace guard.
    set_status(&h, &user, "BANNED").await;
    let banned = get(&app, "/auth/workspaces/w1/access", &access).await;
    assert_eq!(banned.json()["error"]["code"], "auth.account_banned");
}

#[tokio::test]
async fn the_access_route_answers_404_when_the_workspace_left_active_after_the_guard_admitted() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    h.workspaces.seed_workspace("w1", WorkspaceStatus::Active);
    h.workspaces
        .seed_member("w1", &user, "admin", MembershipStatus::Active);
    let first = get(&app, "/auth/workspaces/w1/access", &access).await;
    assert_eq!(first.status, StatusCode::OK);
    // A suspension the writer has not bumped: the guard still admits from the cached entry, and
    // the handler's own read of the workspace is what refuses.
    h.workspaces
        .seed_workspace("w1", WorkspaceStatus::Suspended);
    let refused = get(&app, "/auth/workspaces/w1/access", &access).await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
    assert_eq!(refused.json()["error"]["code"], "auth.workspace_not_found");
    let operations = h.workspaces.cache.operations();
    assert_eq!(operations, ["read", "fill", "read"], "{operations:?}");
}

/// The caller in w1, w2 and w3 (w2 suspended for it), and another account in w1.
fn seed_lists(h: &common::Harness, user: &str) {
    let w = &h.workspaces;
    for id in ["w1", "w2", "w3"] {
        w.seed_workspace(id, WorkspaceStatus::Active);
    }
    w.seed_member("w1", user, "owner", MembershipStatus::Active);
    w.seed_member("w2", user, "owner", MembershipStatus::Suspended);
    w.seed_member("w3", user, "member", MembershipStatus::Active);
    w.seed_member("w1", "other", "member", MembershipStatus::Suspended);
}

fn listed_ids(answer: &Captured) -> Vec<String> {
    answer.json()["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["workspace"]["id"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_list_holds_the_callers_own_workspaces_in_pages_and_its_last_switch() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    seed_lists(&h, &user);
    let all = get(&app, "/auth/workspaces", &access).await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(listed_ids(&all), ["w1", "w3"]);
    assert_eq!(all.json()["items"][0]["role"], "owner");
    assert!(all.json()["nextCursor"].is_null());
    assert!(all.json()["lastActiveWorkspaceId"].is_null());
    let first = get(&app, "/auth/workspaces?limit=1", &access).await;
    assert_eq!(listed_ids(&first), ["w1"]);
    let cursor = first.json()["nextCursor"].as_str().unwrap_or("").to_owned();
    assert!(!cursor.is_empty());
    let query = serde_urlencoded::to_string([("limit", "1"), ("cursor", cursor.as_str())]);
    let next = get(
        &app,
        &format!("/auth/workspaces?{}", query.unwrap_or_default()),
        &access,
    )
    .await;
    assert_eq!(listed_ids(&next), ["w3"]);
    let switched = Req::post("/auth/workspaces/w3/switch")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(switched.status, StatusCode::NO_CONTENT);
    assert!(switched.body.is_empty());
    let after = get(&app, "/auth/workspaces", &access).await;
    assert_eq!(after.json()["lastActiveWorkspaceId"], "w3");
}

#[tokio::test]
async fn a_query_cannot_name_the_tenant_or_the_workspace_of_a_list() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    seed_lists(&h, &user);
    for (query, field) in [
        ("tenantId=t2", "tenantId"),
        ("userId=other", "userId"),
        ("workspaceId=w2", "workspaceId"),
    ] {
        for path in ["/auth/workspaces", "/auth/workspaces/w1/members"] {
            let answer = get(&app, &format!("{path}?{query}"), &access).await;
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{path}?{query}");
            assert_eq!(named(&answer), [field], "{path}?{query}");
        }
    }
}

#[tokio::test]
async fn the_page_query_is_read_as_text_and_refused_without_clamping() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    seed_lists(&h, &user);
    for path in ["/auth/workspaces", "/auth/workspaces/w1/members"] {
        for (query, field) in [
            ("limit=05", "limit"),
            ("limit=%2B5", "limit"),
            ("limit=0", "limit"),
            ("limit=101", "limit"),
            ("limit=", "limit"),
            ("limit=5.0", "limit"),
            ("cursor=", "cursor"),
            ("cursor=a%00b", "cursor"),
        ] {
            let answer = get(&app, &format!("{path}?{query}"), &access).await;
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{path}?{query}");
            assert_eq!(named(&answer), [field], "{path}?{query}");
        }
        let fine = get(&app, &format!("{path}?limit=100"), &access).await;
        assert_eq!(fine.status, StatusCode::OK, "{path}");
    }
    // The guard is read before the query: a bad workspace id is the one reported.
    let both = get(&app, "/auth/workspaces/%20/members?limit=0", &access).await;
    assert_eq!(named(&both), ["workspaceId"]);
}

#[tokio::test]
async fn the_members_route_lists_every_status_of_the_guarded_workspace() {
    let Some((h, app, user, access)) = signed_in().await else { return };
    seed_lists(&h, &user);
    h.workspaces
        .seed_member_in(("t2", "w1"), "homonym", "owner", MembershipStatus::Active);
    let answer = get(&app, "/auth/workspaces/w1/members", &access).await;
    assert_eq!(answer.status, StatusCode::OK);
    let body = answer.json();
    let items = body["items"].as_array().cloned().unwrap_or_default();
    let rows: Vec<(String, String)> = items
        .iter()
        .map(|m| {
            (
                m["userId"].as_str().unwrap_or("").to_owned(),
                m["status"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (user.clone(), "active".to_owned()),
            ("other".to_owned(), "suspended".to_owned())
        ]
    );
    let mut keys: Vec<String> = items[0]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["createdAt", "invitedByUserId", "role", "status", "userId"]
    );
    assert!(items[0]["invitedByUserId"].is_null());
    assert!(body["nextCursor"].is_null());
    // A suspended member is listed but not admitted.
    let held = get(&app, "/auth/workspaces/w2/members", &access).await;
    assert_eq!(held.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn each_workspace_route_is_served_under_the_limit_it_declares() {
    // Anonymous requests are enough: the limiter runs before the credential is read, so a 401 is
    // still a request the route's budget paid for. The counter lives in the engine's store, so
    // each narrowed limit gets an engine of its own.
    let spec = || EngineSpec {
        workspaces: true,
        ..EngineSpec::default()
    };
    let routes: [(LimitSetter, &str); 4] = [
        (|c, v| c.workspace_list = v, "/auth/workspaces"),
        (|c, v| c.workspace_access = v, "/auth/workspaces/w1/access"),
        (
            |c, v| c.workspace_members = v,
            "/auth/workspaces/w1/members",
        ),
        (|c, v| c.workspace_switch = v, "/auth/workspaces/w1/switch"),
    ];
    let request = |path: &str| {
        if path.ends_with("/switch") {
            Req::post(path)
        } else {
            Req::get(path)
        }
    };
    for (narrow, path) in routes {
        let Some(h) = build(spec()) else { return };
        let app = router_with_one_narrow_limit(&h, narrow);
        assert!(trips_on_second_call(&app, || request(path)).await, "{path}");
        // Every other workspace route keeps its own budget.
        for (_, other) in routes.iter().filter(|(_, p)| *p != path) {
            let trips = trips_on_second_call(&app, || request(other)).await;
            assert!(!trips, "{other} under the limit of {path}");
        }
    }
}
