//! The two acceptance routes over HTTP: the status and body each answers, the credential each
//! asks for, and that a refusal leaves the token usable (layer: HTTP adapter, tests). The order
//! of the checks is the service's and is probed in the core; these probe the wire. Shares the
//! fixtures of the parent test file.

use bymax_auth_core::config::TokenDelivery as DeliveryMode;
use bymax_auth_core::traits::{UserRepository, WorkspaceInvitationStore};
use bymax_auth_types::CreateUserData;

use super::*;

const TOKEN_REFUSED: &str = "auth.invalid_invitation_token";

/// Invites `email` as a member and answers the token that was mailed.
async fn invited(team: &Team, email: &str) -> String {
    assert!(answered_nothing(&team.invite(email, "member").await));
    team.last_token()
}

/// A signed-in account of the tenant that is no member of any workspace.
async fn outsider(team: &Team, email: &str) -> (String, String) {
    let id = seed_user(&team.h, email, PASSWORD, "USER").await;
    let access = login_access_cookie(&team.app, email, PASSWORD).await;
    (id, access)
}

fn signup_body(token: &str) -> Value {
    json!({ "token": token, "name": "Jo Doe", "password": PASSWORD })
}

async fn sign_up(app: &axum::Router, body: Value) -> Captured {
    Req::new(Method::POST, SIGNUP).json(body).send(app).await
}

fn keys(body: &Value) -> Vec<&str> {
    body.as_object()
        .into_iter()
        .flat_map(|object| object.keys().map(String::as_str))
        .collect()
}

fn uncached(answer: &Captured) -> bool {
    answer
        .headers
        .get(header::CACHE_CONTROL)
        .is_some_and(|value| value == "no-store")
}

#[tokio::test]
async fn the_invited_account_joins_and_is_told_where_and_as_what() {
    let Some(team) = team().await else { unreachable!() };
    let token = invited(&team, "a@e.com").await;
    let (_, access) = outsider(&team, "a@e.com").await;
    let accepted = team.post(&access, ACCEPT, json!({ "token": token })).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.json());
    assert_eq!(
        accepted.json(),
        json!({ "workspaceId": "w1", "role": "member" })
    );
    assert!(uncached(&accepted));
    assert!(accepted.set_cookies.is_empty());
    let again = team.post(&access, ACCEPT, json!({ "token": token })).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&again), TOKEN_REFUSED);
}

#[tokio::test]
async fn accepting_without_a_usable_session_is_refused_and_spends_nothing() {
    let Some(team) = team().await else { unreachable!() };
    let token = invited(&team, "a@e.com").await;
    let body = json!({ "token": token });
    let anonymous = Req::new(Method::POST, ACCEPT)
        .json(body.clone())
        .send(&team.app)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let (id, access) = outsider(&team, "a@e.com").await;
    set_status(&team.h, &id, "BANNED").await;
    let banned = team.post(&access, ACCEPT, body).await;
    assert_eq!(banned.status, StatusCode::FORBIDDEN, "{}", banned.json());
    assert_eq!(code(&banned), "auth.account_banned");
    assert_eq!(team.preview(&token).await.status, StatusCode::OK);
}

/// A signed-in account holding `email` without having verified it.
async fn unverified(team: &Team, email: &str) -> String {
    let created = team
        .h
        .users
        .create(CreateUserData {
            email: email.to_owned(),
            name: "Un Verified".to_owned(),
            password_hash: Some(common::hash_password(PASSWORD)),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(false),
        })
        .await;
    assert!(created.is_ok());
    login_access_cookie(&team.app, email, PASSWORD).await
}

#[tokio::test]
async fn another_address_or_an_unverified_one_is_refused_and_spends_nothing() {
    let Some(team) = team().await else { unreachable!() };
    let token = invited(&team, "a@e.com").await;
    let body = json!({ "token": token });
    let other = team.post(&team.member, ACCEPT, body.clone()).await;
    assert_eq!(other.status, StatusCode::FORBIDDEN, "{}", other.json());
    assert_eq!(code(&other), "auth.invitation_email_mismatch");
    let access = unverified(&team, "a@e.com").await;
    let refused = team.post(&access, ACCEPT, body).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.json());
    assert_eq!(code(&refused), "auth.email_not_verified");
    assert_eq!(team.preview(&token).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_signup_creates_the_account_and_signs_it_in() {
    let Some(team) = team().await else { unreachable!() };
    let token = invited(&team, "new@e.com").await;
    let created = sign_up(&team.app, signup_body(&token)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.json());
    let body = created.json();
    assert_eq!(keys(&body), ["role", "user", "workspaceId"]);
    assert_eq!(body["workspaceId"], "w1");
    assert_eq!(body["role"], "member");
    assert_eq!(body["user"]["email"], "new@e.com");
    assert_eq!(body["user"]["emailVerified"], true);
    assert!(uncached(&created));
    let access = created.cookie_value("access_token").unwrap_or_default();
    let listed = Req::new(Method::GET, "/auth/workspaces")
        .cookie("access_token", &access)
        .send(&team.app)
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.json());
    assert_eq!(listed.json()["items"][0]["workspace"]["id"], "w1");
}

#[tokio::test]
async fn a_signup_for_an_address_with_an_account_is_a_conflict_and_spends_nothing() {
    let Some(team) = team().await else { unreachable!() };
    let token = invited(&team, "a@e.com").await;
    seed_user(&team.h, "a@e.com", PASSWORD, "USER").await;
    let refused = sign_up(&team.app, signup_body(&token)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.json());
    assert_eq!(code(&refused), "auth.email_already_exists");
    assert!(refused.set_cookies.is_empty());
    assert_eq!(team.preview(&token).await.status, StatusCode::OK);
}

/// A router in `delivery` mode with one member invitation for `new@e.com` already published
/// under `token`, so that nobody has to sign in through a cookie to send it.
async fn published_for(delivery: DeliveryMode, token: &str) -> Option<axum::Router> {
    let h = build(EngineSpec {
        workspaces: true,
        delivery,
        ..EngineSpec::default()
    })?;
    h.workspaces.seed_workspace("w1", WorkspaceStatus::Active);
    let owner = seed_user(&h, "owner@e.com", PASSWORD, "USER").await;
    h.workspaces
        .seed_member("w1", &owner, "owner", MembershipStatus::Active);
    let record = InvitationRecord::Member {
        base: InvitationBase {
            email: "new@e.com".to_owned(),
            role: "member".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: "2026-01-01T00:00:00.000Z".to_owned(),
            resend_count: 0,
        },
        inviter_user_id: owner,
    };
    let place = InvitationPlace {
        index_id: "index".to_owned(),
        set_id: "set".to_owned(),
    };
    let publication = Publication {
        place: &place,
        record_key: &record_key(&invitation_record_id(token)),
        record: &record,
        ttl: std::num::NonZeroU64::new(600)?,
        pending_limit: 0,
        expected_key: None,
    };
    h.workspaces.invitations.publish(publication).await.ok()?;
    Some(router(&h))
}

#[tokio::test]
async fn a_signup_delivers_the_session_the_way_the_deployment_is_configured_to() {
    let token = "c".repeat(64);
    for (delivery, cookies) in [(DeliveryMode::Bearer, false), (DeliveryMode::Both, true)] {
        let Some(app) = published_for(delivery, &token).await else { unreachable!() };
        let created = sign_up(&app, signup_body(&token)).await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.json());
        let body = created.json();
        assert_eq!(
            keys(&body),
            ["accessToken", "refreshToken", "role", "user", "workspaceId"]
        );
        assert_eq!(created.has_cookie_value("access_token"), cookies);
        assert_eq!(!created.set_cookies.is_empty(), cookies);
    }
}
