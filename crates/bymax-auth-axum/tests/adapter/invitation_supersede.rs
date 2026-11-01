//! Re-inviting an address over HTTP: a caller who does not outrank the pending invitation gets
//! the role error and the pending invitation survives; one who does replaces it. Shares the
//! fixtures of the parent test file.

use super::*;

/// Log `email` in and return its access cookie.
async fn access_for(app: &axum::Router, email: &str) -> String {
    login_access_cookie(app, email, "glidingwalnut42").await
}

/// `POST /auth/invitations` for `invitee` at `role`, as the holder of `access`.
async fn invite(app: &axum::Router, access: &str, invitee: &str, role: &str) -> Captured {
    Req::post("/auth/invitations")
        .cookie("access_token", access)
        .json(serde_json::json!({ "email": invitee, "role": role }))
        .send(app)
        .await
}

#[tokio::test]
async fn a_lower_ranked_caller_cannot_replace_a_pending_higher_ranked_invitation() {
    let Some(h) = build(EngineSpec {
        invitations: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let _ = seed_user(&h, "boss@e.com", "glidingwalnut42", "ADMIN").await;
    let _ = seed_user(&h, "member@e.com", "glidingwalnut42", "USER").await;
    let boss = access_for(&app, "boss@e.com").await;
    let member = access_for(&app, "member@e.com").await;

    assert_eq!(
        invite(&app, &boss, "bob@e.com", "ADMIN").await.status,
        StatusCode::NO_CONTENT
    );

    // The member asks for a lower role, which the role check alone would allow.
    let refused = invite(&app, &member, "bob@e.com", "USER").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json()["error"]["code"], "auth.insufficient_role");

    // An address with nothing pending is still open to the member, and the admin can replace
    // their own pending invitation.
    assert_eq!(
        invite(&app, &member, "carol@e.com", "USER").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        invite(&app, &boss, "bob@e.com", "ADMIN").await.status,
        StatusCode::NO_CONTENT
    );
}
