//! A failed invitation email answers the generic 500 `auth.internal`, and nothing the mail
//! channel wrote reaches the response. Shares the fixtures of the parent test file.

use super::*;

#[tokio::test]
async fn a_failed_invitation_send_answers_500_auth_internal_with_the_generic_body() {
    let Some(h) = build(EngineSpec {
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    seed_user(&h, "inviter@e.com", "glidingwalnut42", "ADMIN").await;
    let login = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "inviter@e.com", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = login.cookie_value("access_token").unwrap_or_default();
    h.emails.fail_invitations();

    let failed = Req::post("/auth/invitations")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "email": "invitee@e.com", "role": "USER" }))
        .send(&app)
        .await;

    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.json()["error"]["code"], "auth.internal");
    let body = String::from_utf8_lossy(&failed.body).into_owned();
    assert!(
        !body.contains("relay rejected"),
        "the channel's text reached the body: {body}"
    );
    assert!(
        !body.contains("token="),
        "the token reached the body: {body}"
    );
}
