//! The workspace write routes over HTTP: each route's status and answer, the permission its guard
//! applies, the order of the path parameter checks ahead of authorization, the host hook's refusal
//! and the events the host is told, and the limit each route is served under. The rules each
//! service decides are probed in the core's own tests; these probe the wire. Shares the fixtures
//! of the parent test file.

use std::sync::{Arc, Mutex};

use bymax_auth_core::traits::{AuthHooks, BeforeWorkspaceCreateResult, HookContext, HookError};
use bymax_auth_core::workspace::audit::WorkspaceAuditEvent;
use bymax_auth_core::workspace::domain::{MembershipStatus, WorkspaceStatus};
use bymax_auth_types::SafeAuthUser;
use serde_json::{Value, json};

use super::*;

const PASSWORD: &str = "glidingwalnut42";
const ACTIVE: MembershipStatus = MembershipStatus::Active;

/// Hooks that refuse a workspace named `Refused` and record every workspace event.
#[derive(Default)]
struct Hooks {
    events: Mutex<Vec<WorkspaceAuditEvent>>,
}

impl Hooks {
    /// The types of the events reported so far, waiting for `count`, since delivery is detached.
    async fn types(&self, count: usize) -> Vec<&'static str> {
        for _ in 0..500 {
            let seen: Vec<&'static str> = self
                .events
                .lock()
                .map(|e| e.iter().map(|event| event.kind.type_name()).collect())
                .unwrap_or_default();
            if seen.len() >= count {
                return seen;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Vec::new()
    }
}

#[async_trait::async_trait]
impl AuthHooks for Hooks {
    async fn before_workspace_create(
        &self,
        _user: &SafeAuthUser,
        name: &str,
        _ctx: &HookContext,
    ) -> Result<BeforeWorkspaceCreateResult, HookError> {
        Ok(if name == "Refused" {
            BeforeWorkspaceCreateResult::Reject {
                reason: Some("Upgrade your plan".to_owned()),
            }
        } else {
            BeforeWorkspaceCreateResult::Allow
        })
    }

    async fn on_workspace_event(
        &self,
        event: &WorkspaceAuditEvent,
        _ctx: &HookContext,
    ) -> Result<(), HookError> {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
        Ok(())
    }
}

/// A signed-in owner of `w1`, with an admin `a`, a member `m` and a suspended `s` in it.
struct Owner {
    h: common::Harness,
    app: axum::Router,
    hooks: Arc<Hooks>,
    user: String,
    access: String,
}

async fn owner() -> Option<Owner> {
    let hooks = Arc::new(Hooks::default());
    let h = build(EngineSpec {
        workspaces: true,
        hooks: Some(hooks.clone()),
        ..EngineSpec::default()
    })?;
    let mut config =
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
    let generous = Some(bymax_auth_axum::RateLimit::new(10_000, 60));
    for setter in ALL_LIMIT_SETTERS {
        setter(&mut config.rate_limits, generous);
    }
    let app = router_with(&h, config);
    let user = seed_user(&h, "owner@e.com", PASSWORD, "USER").await;
    let access = login_access_cookie(&app, "owner@e.com", PASSWORD).await;
    let w = &h.workspaces;
    w.seed_workspace("w1", WorkspaceStatus::Active);
    w.seed_member("w1", &user, "owner", ACTIVE);
    w.seed_member("w1", "a", "admin", ACTIVE);
    w.seed_member("w1", "m", "member", ACTIVE);
    w.seed_member("w1", "s", "member", MembershipStatus::Suspended);
    Some(Owner {
        h,
        app,
        hooks,
        user,
        access,
    })
}

impl Owner {
    async fn send(&self, method: http::Method, path: &str, body: Option<Value>) -> Captured {
        let request = Req::new(method, path).cookie("access_token", &self.access);
        let request = match body {
            Some(body) => request.json(body),
            None => request,
        };
        request.send(&self.app).await
    }
}

fn code(answer: &Captured) -> String {
    answer.json()["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn named(answer: &Captured) -> Vec<String> {
    answer.json()["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail["field"].as_str().map(str::to_owned))
        .collect()
}

use http::Method;

#[tokio::test]
async fn a_workspace_is_created_with_201_and_a_hook_refusal_is_403_with_its_reason() {
    let Some(o) = owner().await else { return };
    let created = o
        .send(
            Method::POST,
            "/auth/workspaces",
            Some(json!({ "name": "  Acme  " })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.json());
    let body = created.json();
    assert_eq!(body["name"], "Acme");
    assert_eq!(body["status"], "active");
    assert!(body["deletionScheduledAt"].is_null());
    // The creator can reach it at once, as its owner.
    let id = body["id"].as_str().unwrap_or_default().to_owned();
    let access = o
        .send(Method::GET, &format!("/auth/workspaces/{id}/access"), None)
        .await;
    assert_eq!(access.json()["role"], "owner");
    let refused = o
        .send(
            Method::POST,
            "/auth/workspaces",
            Some(json!({ "name": "Refused" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(code(&refused), "auth.forbidden");
    assert_eq!(
        refused.json()["error"]["details"],
        json!([{ "field": "name", "message": "Upgrade your plan" }])
    );
    assert_eq!(o.hooks.types(1).await, ["workspace.created"]);
}

#[tokio::test]
async fn a_name_is_bounded_as_submitted_and_refused_blank_after_trimming() {
    let Some(o) = owner().await else { return };
    let long = "a".repeat(121);
    for name in [long.as_str(), "\tAcme", "   ", ""] {
        for (method, path) in [
            (Method::POST, "/auth/workspaces"),
            (Method::PATCH, "/auth/workspaces/w1"),
        ] {
            let answer = o.send(method, path, Some(json!({ "name": name }))).await;
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{name:?} {path}");
            assert_eq!(named(&answer), ["name"], "{name:?} {path}");
        }
    }
    let renamed = o
        .send(
            Method::PATCH,
            "/auth/workspaces/w1",
            Some(json!({ "name": " New " })),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::OK);
    assert_eq!(renamed.json()["name"], "New");
    assert_eq!(renamed.json()["id"], "w1");
}

#[tokio::test]
async fn each_write_route_admits_only_the_roles_its_permission_names() {
    let Some(o) = owner().await else { return };
    let member_id = seed_user(&o.h, "member@e.com", PASSWORD, "USER").await;
    let member_access = login_access_cookie(&o.app, "member@e.com", PASSWORD).await;
    o.h.workspaces
        .seed_member("w1", &member_id, "member", ACTIVE);
    for (method, path, body) in [
        (
            Method::PATCH,
            "/auth/workspaces/w1",
            Some(json!({ "name": "X" })),
        ),
        (
            Method::POST,
            "/auth/workspaces/w1/schedule-deletion",
            Some(json!({})),
        ),
        (
            Method::PATCH,
            "/auth/workspaces/w1/members/m",
            Some(json!({ "role": "admin" })),
        ),
        (Method::DELETE, "/auth/workspaces/w1/members/m", None),
    ] {
        let request = Req::new(method, path).cookie("access_token", &member_access);
        let request = match body {
            Some(body) => request.json(body),
            None => request,
        };
        let answer = request.send(&o.app).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(code(&answer), "auth.insufficient_workspace_role", "{path}");
    }
    // Transfer admits any member, and the engine refuses one who is not an owner.
    let transfer = Req::post("/auth/workspaces/w1/transfer-ownership")
        .cookie("access_token", &member_access)
        .json(json!({ "userId": "a", "password": PASSWORD }))
        .send(&o.app)
        .await;
    assert_eq!(code(&transfer), "auth.insufficient_workspace_role");
}

#[tokio::test]
async fn a_member_routes_user_id_is_checked_after_the_workspace_id_and_before_authorization() {
    let Some(o) = owner().await else { return };
    for (method, body) in [
        (Method::PATCH, Some(json!({ "role": "admin" }))),
        (Method::DELETE, None),
    ] {
        for user in ["%20", "%E3%80%80", "a%00b", &"u".repeat(129)] {
            // A stranger's workspace: the bad id is still what is reported, not the 404.
            let path = format!("/auth/workspaces/w-none/members/{user}");
            let answer = o.send(method.clone(), &path, body.clone()).await;
            assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(named(&answer), ["userId"], "{path}");
        }
        // Both bad: only `workspaceId` is named.
        let both = o
            .send(
                method.clone(),
                "/auth/workspaces/%20/members/%20",
                body.clone(),
            )
            .await;
        assert_eq!(named(&both), ["workspaceId"]);
        // Well formed and naming a suspended member: the identical 404.
        let held = o
            .send(
                method.clone(),
                "/auth/workspaces/w1/members/s",
                body.clone(),
            )
            .await;
        assert_eq!(held.status, StatusCode::NOT_FOUND);
        assert_eq!(code(&held), "auth.workspace_not_found");
    }
}

#[tokio::test]
async fn a_role_change_answers_the_membership_and_a_removal_204() {
    let Some(o) = owner().await else { return };
    let changed = o
        .send(
            Method::PATCH,
            "/auth/workspaces/w1/members/m",
            Some(json!({ "role": "admin" })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.json());
    let body = changed.json();
    assert_eq!(
        (&body["userId"], &body["role"], &body["status"]),
        (&json!("m"), &json!("admin"), &json!("active"))
    );
    let unknown = o
        .send(
            Method::PATCH,
            "/auth/workspaces/w1/members/m",
            Some(json!({ "role": "ghost" })),
        )
        .await;
    assert_eq!(named(&unknown), ["role"]);
    let removed = o
        .send(Method::DELETE, "/auth/workspaces/w1/members/m", None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert!(removed.body.is_empty());
    let types = o.hooks.types(2).await;
    assert_eq!(types, ["member.role_changed", "member.removed"]);
}

#[tokio::test]
async fn the_last_owner_cannot_leave_and_a_hand_over_needs_an_active_receiver_first() {
    let Some(o) = owner().await else { return };
    let leave = o
        .send(Method::POST, "/auth/workspaces/w1/leave", None)
        .await;
    assert_eq!(leave.status, StatusCode::CONFLICT);
    assert_eq!(code(&leave), "auth.last_owner");
    // The receiver is judged before the password: a wrong password is not what is reported.
    let suspended = o
        .send(
            Method::POST,
            "/auth/workspaces/w1/transfer-ownership",
            Some(json!({ "userId": "s", "password": "wrong-password" })),
        )
        .await;
    assert_eq!(suspended.status, StatusCode::BAD_REQUEST);
    assert_eq!(named(&suspended), ["userId"]);
    let wrong = o
        .send(
            Method::POST,
            "/auth/workspaces/w1/transfer-ownership",
            Some(json!({ "userId": "a", "password": "wrong-password" })),
        )
        .await;
    assert_eq!(code(&wrong), "auth.invalid_credentials");
    let handed = o
        .send(
            Method::POST,
            "/auth/workspaces/w1/transfer-ownership",
            Some(json!({ "userId": "a", "demoteSelfTo": "member", "password": PASSWORD })),
        )
        .await;
    assert_eq!(handed.status, StatusCode::NO_CONTENT, "{}", handed.json());
    let left = o
        .send(Method::POST, "/auth/workspaces/w1/leave", None)
        .await;
    assert_eq!(left.status, StatusCode::NO_CONTENT);
    assert_eq!(
        o.hooks.types(2).await,
        ["ownership.transferred", "member.left"]
    );
}

#[tokio::test]
async fn a_scheduled_deletion_is_restored_only_by_the_owner_on_the_restore_route() {
    let Some(o) = owner().await else { return };
    let wrong = o
        .send(
            Method::POST,
            "/auth/workspaces/w1/schedule-deletion",
            Some(json!({ "password": "wrong-password" })),
        )
        .await;
    assert_eq!(code(&wrong), "auth.invalid_credentials");
    let scheduled = o
        .send(
            Method::POST,
            "/auth/workspaces/w1/schedule-deletion",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(
        scheduled.status,
        StatusCode::NO_CONTENT,
        "{}",
        scheduled.json()
    );
    // Every other route answers the owner 409; a non-owner is a stranger.
    let read = o
        .send(Method::GET, "/auth/workspaces/w1/access", None)
        .await;
    assert_eq!(code(&read), "auth.workspace_pending_deletion");
    let restored = o
        .send(Method::POST, "/auth/workspaces/w1/restore", None)
        .await;
    assert_eq!(
        restored.status,
        StatusCode::NO_CONTENT,
        "{}",
        restored.json()
    );
    let read = o
        .send(Method::GET, "/auth/workspaces/w1/access", None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let not_pending = o
        .send(Method::POST, "/auth/workspaces/w1/restore", None)
        .await;
    assert_eq!(code(&not_pending), "auth.workspace_not_found");
    let expected = ["workspace.deletion_scheduled", "workspace.restored"];
    assert_eq!(o.hooks.types(2).await, expected);
}

#[tokio::test]
async fn a_switch_is_reported_to_the_workspace_event_hook() {
    let Some(o) = owner().await else { return };
    let switched = o
        .send(Method::POST, "/auth/workspaces/w1/switch", None)
        .await;
    assert_eq!(switched.status, StatusCode::NO_CONTENT);
    assert_eq!(o.hooks.types(1).await, ["workspace.switched"]);
    assert!(!o.user.is_empty());
}

/// Each write route, by method and path, and the limit it declares.
const WRITE_ROUTES: [(LimitSetter, &str, &str); 8] = [
    (|c, v| c.workspace_create = v, "POST", "/auth/workspaces"),
    (
        |c, v| c.workspace_rename = v,
        "PATCH",
        "/auth/workspaces/w1",
    ),
    (
        |c, v| c.workspace_schedule_deletion = v,
        "POST",
        "/auth/workspaces/w1/schedule-deletion",
    ),
    (
        |c, v| c.workspace_restore = v,
        "POST",
        "/auth/workspaces/w1/restore",
    ),
    (
        |c, v| c.workspace_change_role = v,
        "PATCH",
        "/auth/workspaces/w1/members/m",
    ),
    (
        |c, v| c.workspace_remove_member = v,
        "DELETE",
        "/auth/workspaces/w1/members/m",
    ),
    (
        |c, v| c.workspace_leave = v,
        "POST",
        "/auth/workspaces/w1/leave",
    ),
    (
        |c, v| c.workspace_transfer_ownership = v,
        "POST",
        "/auth/workspaces/w1/transfer-ownership",
    ),
];

/// An anonymous request to `path`: the limiter runs before the credential is read.
fn anonymous(method: &str, path: &str) -> Req {
    Req::new(method.parse().unwrap_or(Method::POST), path)
}

#[tokio::test]
async fn each_write_route_is_served_under_the_limit_it_declares() {
    for (narrow, method, path) in WRITE_ROUTES {
        let spec = EngineSpec {
            workspaces: true,
            ..EngineSpec::default()
        };
        let Some(h) = build(spec) else { return };
        let app = router_with_one_narrow_limit(&h, narrow);
        assert!(
            trips_on_second_call(&app, || anonymous(method, path)).await,
            "{method} {path}"
        );
        // Every other write route keeps its own budget.
        for (_, other_method, other) in WRITE_ROUTES {
            if (other_method, other) != (method, path) {
                let trips = trips_on_second_call(&app, || anonymous(other_method, other)).await;
                assert!(
                    !trips,
                    "{other_method} {other} under the limit of {method} {path}"
                );
            }
        }
    }
}
