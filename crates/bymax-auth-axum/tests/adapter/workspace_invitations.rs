//! The workspace invitation routes over HTTP: each route's status and answer, the permission its
//! guard applies, the body rules, and the limit each route is served under (layer: HTTP adapter,
//! tests). The rules the service decides are probed in the core's own tests; these probe the wire.
//! Shares the fixtures of the parent test file.

use bymax_auth_core::traits::{InvitationPlace, Publication, WorkspaceInvitationStore};
use bymax_auth_core::workspace::domain::{MembershipStatus, WorkspaceStatus};
use bymax_auth_core::workspace::invitation::{InvitationBase, InvitationRecord, record_key};
use bymax_auth_core::workspace::keys::invitation_record_id;
use serde_json::{Value, json};

use super::*;

const PASSWORD: &str = "glidingwalnut42";
const INVITATIONS: &str = "/auth/workspaces/w1/invitations";
const RESEND: &str = "/auth/workspaces/w1/invitations/resend";
const REVOKE: &str = "/auth/workspaces/w1/invitations/revoke";
const PREVIEW: &str = "/auth/workspaces/invitations/preview";

/// The workspace `w1` with a signed-in owner, a signed-in admin and a signed-in plain member.
struct Team {
    h: common::Harness,
    app: axum::Router,
    owner_id: String,
    owner: String,
    admin: String,
    member: String,
}

async fn team() -> Option<Team> {
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
    h.workspaces.seed_workspace("w1", WorkspaceStatus::Active);
    let mut signed_in = Vec::new();
    for (email, role) in [
        ("owner@e.com", "owner"),
        ("admin@e.com", "admin"),
        ("member@e.com", "member"),
    ] {
        let id = seed_user(&h, email, PASSWORD, "USER").await;
        h.workspaces
            .seed_member("w1", &id, role, MembershipStatus::Active);
        signed_in.push((id, login_access_cookie(&app, email, PASSWORD).await));
    }
    let [(owner_id, owner), (_, admin), (_, member)] = <[_; 3]>::try_from(signed_in).ok()?;
    Some(Team {
        h,
        app,
        owner_id,
        owner,
        admin,
        member,
    })
}

impl Team {
    async fn post(&self, access: &str, path: &str, body: Value) -> Captured {
        Req::new(Method::POST, path)
            .cookie("access_token", access)
            .json(body)
            .send(&self.app)
            .await
    }

    async fn invite(&self, email: &str, role: &str) -> Captured {
        let body = json!({ "email": email, "role": role });
        self.post(&self.owner, INVITATIONS, body).await
    }

    async fn pending(&self, query: &str) -> Captured {
        Req::new(Method::GET, &format!("{INVITATIONS}{query}"))
            .cookie("access_token", &self.owner)
            .send(&self.app)
            .await
    }

    /// The token of the last invitation sent.
    fn last_token(&self) -> String {
        self.h
            .workspaces
            .mails
            .sent()
            .pop()
            .map(|(_, token)| token)
            .unwrap_or_default()
    }

    /// A preview carries no credential.
    async fn preview(&self, token: &str) -> Captured {
        Req::new(Method::POST, PREVIEW)
            .json(json!({ "token": token }))
            .send(&self.app)
            .await
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

fn answered_nothing(answer: &Captured) -> bool {
    answer.status == StatusCode::NO_CONTENT && answer.body.is_empty()
}

#[tokio::test]
async fn an_invitation_is_listed_under_the_canonical_address_without_its_token() {
    let Some(team) = team().await else { return };
    let invited = team.invite("  New@E.com ", "member").await;
    assert!(answered_nothing(&invited), "{}", invited.json());
    let listed = team.pending("").await;
    assert_eq!(listed.status, StatusCode::OK);
    let body = listed.json();
    assert_eq!(body["nextCursor"], Value::Null);
    let item = &body["items"][0];
    let keys: Vec<&String> = item
        .as_object()
        .into_iter()
        .flat_map(|o| o.keys())
        .collect();
    assert_eq!(
        keys,
        [
            "createdAt",
            "email",
            "expiresAt",
            "inviterUserId",
            "resendCount",
            "role"
        ]
    );
    assert_eq!(item["email"], "new@e.com");
    assert_eq!(item["role"], "member");
    assert_eq!(item["inviterUserId"], team.owner_id.as_str());
    assert_eq!(item["resendCount"], 0);
    assert_eq!(team.last_token().len(), 64);
    assert!(!body.to_string().contains(&team.last_token()));
}

#[tokio::test]
async fn the_list_is_paged_by_its_query() {
    let Some(team) = team().await else { return };
    for email in ["a@e.com", "b@e.com"] {
        assert!(answered_nothing(&team.invite(email, "member").await));
    }
    let first = team.pending("?limit=1").await.json();
    assert_eq!(first["items"].as_array().map(Vec::len), Some(1));
    let cursor = first["nextCursor"].as_str().unwrap_or_default().to_owned();
    let cursor: String = cursor.bytes().map(|b| format!("%{b:02X}")).collect();
    let second = team
        .pending(&format!("?limit=1&cursor={cursor}"))
        .await
        .json();
    assert_eq!(second["items"].as_array().map(Vec::len), Some(1));
    assert_ne!(second["items"][0]["email"], first["items"][0]["email"]);
    assert_eq!(second["nextCursor"], Value::Null);
    let refused = team.pending("?limit=101").await;
    assert_eq!(named(&refused), ["limit"]);
}

#[tokio::test]
async fn invite_and_a_resend_or_revoke_with_nothing_pending_answer_the_same_with_or_without_an_account()
 {
    let Some(team) = team().await else { return };
    seed_user(&team.h, "known@e.com", PASSWORD, "USER").await;
    let addresses = ["known@e.com", "unknown@e.com"];
    for email in addresses {
        for path in [RESEND, REVOKE] {
            let absent = team
                .post(&team.owner, path, json!({ "email": email }))
                .await;
            assert!(answered_nothing(&absent), "{path} {email}");
        }
    }
    for email in addresses {
        let invited = team.invite(email, "member").await;
        assert!(answered_nothing(&invited), "{email}");
    }
    let revoked = team
        .post(&team.owner, REVOKE, json!({ "email": "KNOWN@E.com" }))
        .await;
    assert!(answered_nothing(&revoked));
    let left = team.pending("").await.json();
    assert_eq!(left["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(left["items"][0]["email"], "unknown@e.com");
}

#[tokio::test]
async fn a_resend_inside_the_cooldown_is_a_limit() {
    let Some(team) = team().await else { return };
    assert!(answered_nothing(&team.invite("a@e.com", "member").await));
    let again = team
        .post(&team.owner, RESEND, json!({ "email": "a@e.com" }))
        .await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(code(&again), "auth.too_many_requests");
}

#[tokio::test]
async fn a_preview_says_what_the_token_is_for_and_nothing_once_revoked() {
    let Some(team) = team().await else { return };
    assert!(answered_nothing(&team.invite("new@e.com", "member").await));
    let token = team.last_token();
    let preview = team.preview(&token).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(
        preview.json(),
        json!({
            "kind": "member",
            "workspaceName": "Workspace w1",
            "inviterName": "Seed User",
            "role": "member",
            "maskedEmail": "n***@e.com",
            "accountExists": false,
        })
    );
    let revoked = team
        .post(&team.owner, REVOKE, json!({ "email": "new@e.com" }))
        .await;
    assert!(answered_nothing(&revoked));
    let gone = team.preview(&token).await;
    let never = team.preview(&"0".repeat(64)).await;
    assert_eq!(code(&gone), "auth.invalid_invitation_token");
    assert_eq!((gone.status, gone.json()), (never.status, never.json()));
}

#[tokio::test]
async fn the_role_ceiling_and_an_existing_membership_are_refused() {
    let Some(team) = team().await else { return };
    let above = team
        .post(
            &team.admin,
            INVITATIONS,
            json!({ "email": "x@e.com", "role": "owner" }),
        )
        .await;
    assert_eq!(above.status, StatusCode::FORBIDDEN);
    assert_eq!(code(&above), "auth.insufficient_workspace_role");
    let member = team.invite("member@e.com", "member").await;
    assert_eq!(member.status, StatusCode::CONFLICT);
    assert_eq!(code(&member), "auth.already_member");
}

#[tokio::test]
async fn managing_invitations_needs_a_credential_and_the_permission() {
    let Some(team) = team().await else { return };
    let calls = [
        (Method::GET, INVITATIONS, None),
        (
            Method::POST,
            INVITATIONS,
            Some(json!({ "email": "x@e.com", "role": "member" })),
        ),
        (Method::POST, RESEND, Some(json!({ "email": "x@e.com" }))),
        (Method::POST, REVOKE, Some(json!({ "email": "x@e.com" }))),
    ];
    for (method, path, body) in calls {
        let request = |access: Option<&str>| {
            let request = Req::new(method.clone(), path);
            let request = match access {
                Some(access) => request.cookie("access_token", access),
                None => request,
            };
            match &body {
                Some(body) => request.json(body.clone()),
                None => request,
            }
        };
        let anonymous = request(None).send(&team.app).await;
        assert_eq!(
            anonymous.status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        let member = request(Some(&team.member)).send(&team.app).await;
        assert_eq!(member.status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    assert!(team.h.workspaces.mails.sent().is_empty());
}

/// Publishes a bootstrap invitation under `token`, for a workspace that does not exist yet.
async fn seed_bootstrap(team: &Team, token: &str) -> bool {
    let record = InvitationRecord::Bootstrap {
        base: InvitationBase {
            email: "first@e.com".to_owned(),
            role: "owner".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "wb".to_owned(),
            created_at: "2026-01-01T00:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        workspace_name: "Acme Inc".to_owned(),
    };
    // A preview reads the record alone, so where the invitation is placed is not under test.
    let place = InvitationPlace {
        index_id: "index".to_owned(),
        set_id: "set".to_owned(),
    };
    let publication = Publication {
        place: &place,
        record_key: &record_key(&invitation_record_id(token)),
        record: &record,
        ttl: std::num::NonZeroU64::new(600).unwrap_or(std::num::NonZeroU64::MIN),
        pending_limit: 0,
        expected_key: None,
    };
    team.h
        .workspaces
        .invitations
        .publish(publication)
        .await
        .is_ok()
}

#[tokio::test]
async fn a_bootstrap_preview_names_no_inviter() {
    let Some(team) = team().await else { return };
    let token = "b".repeat(64);
    assert!(seed_bootstrap(&team, &token).await);
    let previewed = team.preview(&token).await;
    assert_eq!(previewed.status, StatusCode::OK, "{}", previewed.json());
    assert_eq!(
        previewed.json(),
        json!({
            "kind": "bootstrap",
            "workspaceName": "Acme Inc",
            "role": "owner",
            "maskedEmail": "f***@e.com",
            "accountExists": false,
        })
    );
}

/// One body per shared rule, each breaking only that rule, with the field the refusal names.
fn refused_bodies() -> Vec<(&'static str, Value, &'static str)> {
    // A well-formed address of 257 characters, so the length is the one rule it breaks.
    let long = format!(
        "{}@{}.{}.{}.com",
        "a".repeat(64),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(60)
    );
    let injected = "a@e.com\r\nBcc: x@e.com";
    let invite = |email: &str, role: &str| json!({ "email": email, "role": role });
    let address = |email: &str| json!({ "email": email });
    let token = |length: usize| json!({ "token": "t".repeat(length) });
    let extra = json!({ "email": "a@e.com", "workspaceId": "w2" });
    vec![
        (INVITATIONS, invite(injected, "member"), "email"),
        (INVITATIONS, invite(&long, "member"), "email"),
        (INVITATIONS, invite("a@e.com", ""), "role"),
        (INVITATIONS, invite("a@e.com", "me\nmber"), "role"),
        (INVITATIONS, invite("a@e.com", &"r".repeat(65)), "role"),
        (RESEND, address(injected), "email"),
        (REVOKE, address(&long), "email"),
        (PREVIEW, token(63), "token"),
        (PREVIEW, token(65), "token"),
        (RESEND, extra, "workspaceId"),
    ]
}

#[tokio::test]
async fn a_body_outside_the_shared_rules_is_refused_by_field() {
    let Some(team) = team().await else { return };
    for (path, body, field) in refused_bodies() {
        let refused = team.post(&team.owner, path, body.clone()).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{path} {body}");
        assert_eq!(code(&refused), "auth.validation", "{path} {body}");
        assert_eq!(named(&refused), [field], "{path} {body}");
    }
    assert!(team.h.workspaces.mails.sent().is_empty());
}

/// Each invitation route with the one limit it is served under.
const ROUTES: &[(LimitSetter, &str, &str)] = &[
    (|c, v| c.workspace_invite = v, "POST", INVITATIONS),
    (|c, v| c.workspace_invitations = v, "GET", INVITATIONS),
    (|c, v| c.workspace_invitation_resend = v, "POST", RESEND),
    (|c, v| c.workspace_invitation_revoke = v, "POST", REVOKE),
    (|c, v| c.workspace_invitation_preview = v, "POST", PREVIEW),
];

#[tokio::test]
async fn each_invitation_route_is_served_under_the_limit_it_declares() {
    for (narrow, method, path) in ROUTES {
        let Some(h) = build(EngineSpec {
            workspaces: true,
            ..EngineSpec::default()
        }) else {
            return;
        };
        let app = router_with_one_narrow_limit(&h, *narrow);
        let anonymous =
            |method: &str, path: &str| Req::new(method.parse().unwrap_or(Method::POST), path);
        assert!(
            trips_on_second_call(&app, || anonymous(method, path)).await,
            "{method} {path}"
        );
        for (_, other_method, other) in ROUTES {
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
