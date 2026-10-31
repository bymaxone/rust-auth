//! The routes that act with the caller's authority beyond their own session — moving the
//! account's address and minting or withdrawing invitations — answer to the same account gate
//! as the session routes: a blocked status is refused, and so is an unproven address when the
//! deployment requires verification. Shares the fixtures of the parent test file.

use super::*;
use bymax_auth_core::traits::UserRepository;
use common::build_failing_invitation_index;

/// Log `email` in (cookie mode) and return its access cookie value.
async fn access_for(app: &axum::Router, email: &str) -> String {
    login_access_cookie(app, email, "glidingwalnut42").await
}

/// The three gated writes, each as the request a signed-in caller would send.
fn gated_requests(access: &str) -> Vec<(&'static str, Req)> {
    vec![
        (
            "/auth/email/change",
            Req::post("/auth/email/change")
                .cookie("access_token", access)
                .json(serde_json::json!({
                    "newEmail": "moved@e.com", "currentPassword": "glidingwalnut42"
                })),
        ),
        (
            "/auth/invitations",
            Req::post("/auth/invitations")
                .cookie("access_token", access)
                .json(serde_json::json!({ "email": "invitee@e.com", "role": "USER" })),
        ),
        (
            "/auth/invitations/revoke",
            Req::post("/auth/invitations/revoke")
                .cookie("access_token", access)
                .json(serde_json::json!({ "email": "invitee@e.com" })),
        ),
    ]
}

/// The error code an answer carried, or an empty string.
fn code_of(response: &Captured) -> String {
    response.json()["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

#[tokio::test]
async fn a_blocked_account_cannot_move_its_address_or_touch_invitations() {
    let Some(h) = build(EngineSpec {
        email_change: true,
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let id = seed_user(&h, "gate@e.com", "glidingwalnut42", "ADMIN").await;
    let access = access_for(&app, "gate@e.com").await;

    // While the account is in good standing every route is reachable.
    for (path, request) in gated_requests(&access) {
        let ok = request.send(&app).await;
        assert_eq!(
            ok.status,
            StatusCode::NO_CONTENT,
            "{path} refused a good account"
        );
    }

    // The token outlives the status change; the gate reads the account, not the token.
    set_status(&h, &id, "BANNED").await;
    for (path, request) in gated_requests(&access) {
        let denied = request.send(&app).await;
        assert_eq!(
            denied.status,
            StatusCode::FORBIDDEN,
            "{path} served a banned account"
        );
        assert_eq!(code_of(&denied), "auth.account_banned", "{path}");
    }
}

#[tokio::test]
async fn an_unverified_address_cannot_move_itself_or_touch_invitations_when_verification_is_required()
 {
    let Some(h) = build(EngineSpec {
        email_change: true,
        invitations: true,
        verification_required: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let id = seed_user(&h, "unproven@e.com", "glidingwalnut42", "ADMIN").await;
    let access = access_for(&app, "unproven@e.com").await;

    // Registration mints a session before the address is verified; model it by unverifying the
    // account after the session exists.
    let _ = h.users.update_email_verified(&id, TENANT, false).await;
    for (path, request) in gated_requests(&access) {
        let denied = request.send(&app).await;
        assert_eq!(
            denied.status,
            StatusCode::FORBIDDEN,
            "{path} served an unproven address"
        );
        assert_eq!(code_of(&denied), "auth.email_not_verified", "{path}");
    }
}

#[tokio::test]
async fn a_store_failure_while_revoking_is_reported_after_the_account_gate_passes() {
    // The account gate runs first and passes for a good account; what the handler then answers
    // is the store's failure, not a silent 204.
    let Some(h) = build_failing_invitation_index() else { return };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "revoker@e.com", "password": "glidingwalnut42", "name": "Rv", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let revoke = Req::post("/auth/invitations/revoke")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "invitee@e.com" }))
        .send(&app)
        .await;
    assert_eq!(revoke.status, StatusCode::INTERNAL_SERVER_ERROR);
}
