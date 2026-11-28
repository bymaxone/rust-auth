//! A refresh whose session family already has an entry still delivers the rotated pair: a family
//! can hold two sessions, and ending one must not spend the other's refresh token for nothing.
//! The entry keeps refusing the access token. Shares the fixtures of the parent test file.

use super::*;
use bymax_auth_core::traits::{SessionKind, SessionStore};

#[tokio::test]
async fn a_platform_refresh_in_an_ended_family_answers_the_pair_and_the_admin() {
    let Some(h) = build(EngineSpec {
        platform: true,
        ..EngineSpec::default()
    }) else {
        unreachable!()
    };
    let app = router(&h);
    seed_admin(&h, "fam@e.com", "SUPER_ADMIN").await;
    let session = platform_login(&app, "fam@e.com").await;
    let claims = h
        .engine
        .verify_platform_token(&platform_access(&session))
        .await;
    let Some(sid) = claims.ok().and_then(|claims| claims.sid) else { unreachable!() };
    let store: &dyn SessionStore = h.stores.as_ref();
    let ended = store
        .revoke_session_access(SessionKind::Platform, &sid, 60)
        .await;
    assert!(ended.is_ok());

    let rotated = Req::post("/auth/platform/refresh")
        .json(serde_json::json!({ "refreshToken": platform_refresh(&session) }))
        .send(&app)
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert_eq!(rotated.json()["admin"]["email"], "fam@e.com");
    let me = Req::get("/auth/platform/me")
        .bearer(&platform_access(&rotated))
        .send(&app)
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}
