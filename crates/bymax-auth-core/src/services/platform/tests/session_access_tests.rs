//! The platform plane ends a session's access tokens the same way the dashboard plane does, under
//! its own entry.

use super::*;
use crate::traits::SessionStore;
use bymax_auth_types::PlatformAuthResult;

const KIND: SessionKind = SessionKind::Platform;
/// The default fifteen-minute access lifetime plus the sixty seconds the entry outlives it by.
const ENTRY_TTL: u64 = 960;

fn refresh_hash(raw: &str) -> String {
    bymax_auth_jwt::RawRefreshToken::from_raw(raw.to_owned()).redis_hash()
}

/// A signed-in admin and the session its access token names.
async fn with_session() -> Option<(PlatformHarness, PlatformAuthResult, String)> {
    let h = harness(platform_config())?;
    seed_admin(&h.admins, "ended@admin.io", "pw");
    let svc = h.engine.platform_auth()?;
    let Ok(PlatformLoginResult::Success(auth)) =
        svc.login("ended@admin.io", "pw", "1.2.3.4", "agent").await
    else {
        return None;
    };
    let claims = h
        .engine
        .tokens()
        .verify_platform_access(&auth.access_token)
        .await
        .ok()?;
    let sid = claims.sid?;
    Some((h, *auth, sid))
}

#[tokio::test]
async fn a_platform_logout_writes_the_platform_entry_for_its_session() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(
        h.stores.peek_session_access_ttl(KIND, &sid),
        Some(ENTRY_TTL)
    );
    assert_eq!(h.stores.ended_session_count(), 1);
}

#[tokio::test]
async fn a_platform_logout_that_could_not_write_the_entry_fails_and_its_retry_writes_it() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let Some(svc) = h.engine.platform_auth() else { unreachable!() };
    h.stores.fail_next_session_access_writes(1);
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_err()
    );
    assert!(
        svc.logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(
        h.stores.peek_session_access_ttl(KIND, &sid),
        Some(ENTRY_TTL)
    );
}

#[tokio::test]
async fn a_replayed_platform_refresh_token_writes_the_entry_for_the_family() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let tokens = h.engine.tokens();
    let rotated = tokens
        .reissue_platform_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    assert!(rotated.is_ok());
    let store: &dyn SessionStore = h.stores.as_ref();
    assert!(
        store
            .delete_grace_pointer(KIND, &refresh_hash(&auth.refresh_token))
            .await
            .is_ok()
    );
    let replay = tokens
        .reissue_platform_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    assert!(matches!(replay, Err(AuthError::RefreshTokenInvalid)));
    assert_eq!(
        h.stores.peek_session_access_ttl(KIND, &sid),
        Some(ENTRY_TTL)
    );
}

#[tokio::test]
async fn a_platform_access_token_of_an_ended_session_is_refused() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let store: &dyn SessionStore = h.stores.as_ref();
    assert!(store.revoke_session_access(KIND, &sid, 60).await.is_ok());
    let verified = h
        .engine
        .tokens()
        .verify_platform_access(&auth.access_token)
        .await;
    assert!(
        matches!(verified, Err(AuthError::TokenRevoked)),
        "{verified:?}"
    );
}

#[tokio::test]
async fn a_platform_access_token_is_not_accepted_while_the_entry_cannot_be_read() {
    let Some((h, auth, _sid)) = with_session().await else { unreachable!() };
    h.stores.fail_session_access_reads(true);
    let verified = h
        .engine
        .tokens()
        .verify_platform_access(&auth.access_token)
        .await;
    assert!(
        matches!(verified, Err(AuthError::Internal(_))),
        "{verified:?}"
    );
}
