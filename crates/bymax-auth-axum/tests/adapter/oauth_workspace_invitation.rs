//! Starting an OAuth sign-in that carries a workspace invitation: what the query accepts, what
//! the answer says and which header it adds (layer: HTTP adapter, tests). What the callback does
//! with the invitation is probed in the core. Shares the fixtures of the parent test file.

use super::*;

fn app_of(workspaces: bool) -> Option<axum::Router> {
    let h = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        workspaces,
        ..EngineSpec::default()
    })?;
    Some(router(&h))
}

async fn start(app: &axum::Router, invitation: Option<&str>) -> Captured {
    let query = invitation.map_or_else(String::new, |t| format!("&workspaceInvitation={t}"));
    Req::get(&format!("/auth/oauth/google?tenantId=t1{query}"))
        .send(app)
        .await
}

fn referrer_policy(answer: &Captured) -> Option<&str> {
    answer
        .headers
        .get(header::REFERRER_POLICY)
        .and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn only_the_start_that_carries_a_token_asks_the_browser_to_send_no_referrer() {
    let Some(app) = app_of(true) else { unreachable!() };
    let with = start(&app, Some(&"a".repeat(64))).await;
    assert_eq!(with.status, StatusCode::FOUND);
    assert_eq!(referrer_policy(&with), Some("no-referrer"));
    let without = start(&app, None).await;
    assert_eq!(without.status, StatusCode::FOUND);
    assert_eq!(referrer_policy(&without), None);
}

#[tokio::test]
async fn a_token_that_is_not_64_characters_is_a_validation_error() {
    let Some(app) = app_of(true) else { unreachable!() };
    for token in [String::new(), "a".repeat(63), "a".repeat(65)] {
        let answer = start(&app, Some(&token)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", token.len());
        assert_eq!(answer.json()["error"]["code"], "auth.validation");
    }
}

#[tokio::test]
async fn a_token_is_refused_while_the_workspace_layer_is_off() {
    let Some(app) = app_of(false) else { unreachable!() };
    let answer = start(&app, Some(&"a".repeat(64))).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        answer.json()["error"]["code"],
        "auth.invalid_invitation_token"
    );
}
