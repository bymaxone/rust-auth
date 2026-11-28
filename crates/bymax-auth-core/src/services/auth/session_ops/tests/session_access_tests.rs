//! A session that ends takes its access tokens with it: the paths that end one session write the
//! entry naming its family, and every check of an access token or of a WebSocket ticket refuses a
//! session that has one.
//!
//! Layer: unit tests of the dashboard flows over the in-memory doubles.

use super::logout_failure_tests::{signed_in, signed_in_with};
use super::*;
use crate::traits::SessionStore;
use bymax_auth_types::AuthResult;

const KIND: SessionKind = SessionKind::Dashboard;
/// The default fifteen-minute access lifetime plus the sixty seconds the entry outlives it by.
const ENTRY_TTL: u64 = 960;

fn refresh_hash(raw: &str) -> String {
    bymax_auth_jwt::RawRefreshToken::from_raw(raw.to_owned()).redis_hash()
}

/// The claims of a freshly issued access token.
async fn claims_of(h: &Harness, access: &str) -> Option<DashboardClaims> {
    h.engine.tokens().verify_access(access).await.ok()
}

/// A signed-in account and the session its access token names.
async fn with_session() -> Option<(Harness, AuthResult, String)> {
    let (h, auth) = signed_in(None).await?;
    let sid = claims_of(&h, &auth.access_token).await?.sid?;
    Some((h, auth, sid))
}

fn entry(h: &Harness, sid: &str) -> Option<u64> {
    h.stores.peek_session_access_ttl(KIND, sid)
}

/// Mark `sid` ended without touching anything else the checks read.
async fn end(h: &Harness, sid: &str) -> bool {
    let store: &dyn SessionStore = h.stores.as_ref();
    store.revoke_session_access(KIND, sid, 60).await.is_ok()
}

#[tokio::test]
async fn a_logout_writes_the_entry_for_its_session() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    assert!(
        h.engine
            .logout(&auth.access_token, &auth.refresh_token)
            .await
            .is_ok()
    );
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn a_logout_without_an_access_token_writes_the_entry_too() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    assert!(h.engine.logout("", &auth.refresh_token).await.is_ok());
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn a_logout_that_could_not_write_the_entry_fails_and_its_retry_writes_it() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    h.stores.fail_next_session_access_writes(1);
    let first = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(first.is_err());
    let marker = h
        .stores
        .peek_logout_pending(KIND, &refresh_hash(&auth.refresh_token));
    assert_eq!(
        marker.and_then(|(owner, _)| owner.family_id),
        Some(sid.clone())
    );
    assert_eq!(entry(&h, &sid), None);

    let retried = h
        .engine
        .logout(&auth.access_token, &auth.refresh_token)
        .await;
    assert!(retried.is_ok());
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn a_session_evicted_over_the_cap_gets_the_entry_and_the_one_kept_does_not() {
    let tune = |cfg: &mut crate::config::AuthConfig| {
        cfg.sessions.enabled = true;
        cfg.sessions.default_max_sessions = 1;
    };
    let Some((h, first)) = signed_in_with(None, tune).await else { unreachable!() };
    let Some(old) = claims_of(&h, &first.access_token).await else { unreachable!() };
    let Ok(LoginResult::Success(second)) = h
        .engine
        .login(login_input("out@example.com", "pw"), &ctx())
        .await
    else {
        unreachable!()
    };

    let old = old.sid.unwrap_or_default();
    assert_eq!(entry(&h, &old), Some(ENTRY_TTL));
    assert_eq!(h.stores.ended_session_count(), 1);
    assert!(claims_of(&h, &second.access_token).await.is_some());
}

#[tokio::test]
async fn an_eviction_whose_entry_cannot_be_written_does_not_fail_the_login() {
    let tune = |cfg: &mut crate::config::AuthConfig| {
        cfg.sessions.enabled = true;
        cfg.sessions.default_max_sessions = 1;
    };
    let Some((h, _first)) = signed_in_with(None, tune).await else { unreachable!() };
    h.stores.fail_next_session_access_writes(1);
    let second = h
        .engine
        .login(login_input("out@example.com", "pw"), &ctx())
        .await;
    assert!(matches!(second, Ok(LoginResult::Success(_))));
}

/// A signed-in account whose first refresh token has been rotated away and is past its grace
/// window, so presenting it again is a replay.
async fn replayable() -> Option<(Harness, AuthResult, String)> {
    let (h, auth, sid) = with_session().await?;
    h.engine
        .tokens()
        .reissue_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await
        .ok()?;
    let store: &dyn SessionStore = h.stores.as_ref();
    store
        .delete_grace_pointer(KIND, &refresh_hash(&auth.refresh_token))
        .await
        .ok()?;
    Some((h, auth, sid))
}

#[tokio::test]
async fn a_replayed_refresh_token_writes_the_entry_for_the_family() {
    let Some((h, auth, sid)) = replayable().await else { unreachable!() };
    let replay = h
        .engine
        .tokens()
        .reissue_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    assert!(matches!(replay, Err(AuthError::RefreshTokenInvalid)));
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn a_replay_whose_entry_cannot_be_written_raises_the_store_failure() {
    let Some((h, auth, _sid)) = replayable().await else { unreachable!() };
    h.stores.fail_next_session_access_writes(1);
    let replay = h
        .engine
        .tokens()
        .reissue_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await;
    assert!(matches!(replay, Err(AuthError::Internal(_))), "{replay:?}");
}

/// The account's epoch, which a bump raises for every access token it holds.
async fn epoch(h: &Harness, user_id: &str) -> u64 {
    let subject = h.engine.session_subject(KIND, Some("t1"), user_id);
    h.engine
        .session_store()
        .current_epoch(KIND, &subject)
        .await
        .unwrap_or(u64::MAX)
}

#[tokio::test]
async fn revoking_one_session_writes_its_entry_and_leaves_the_account_epoch() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let hash = refresh_hash(&auth.refresh_token);
    let revoked = h
        .engine
        .revoke_user_session("t1", &auth.user.id, &hash)
        .await;
    assert!(revoked.is_ok());
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
    assert_eq!(epoch(&h, &auth.user.id).await, 0);
}

#[tokio::test]
async fn the_session_service_revoke_writes_the_entry() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let hash = refresh_hash(&auth.refresh_token);
    let revoked = h
        .engine
        .sessions()
        .revoke_session("t1", &auth.user.id, &hash)
        .await;
    assert!(revoked.is_ok());
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn revoking_a_session_whose_entry_cannot_be_written_fails() {
    let Some((h, auth, _sid)) = with_session().await else { unreachable!() };
    let hash = refresh_hash(&auth.refresh_token);
    h.stores.fail_next_session_access_writes(1);
    let revoked = h
        .engine
        .revoke_user_session("t1", &auth.user.id, &hash)
        .await;
    assert!(
        matches!(revoked, Err(AuthError::Internal(_))),
        "{revoked:?}"
    );
}

#[tokio::test]
async fn revoking_a_session_whose_record_cannot_be_read_bumps_the_epoch_instead() {
    let Some((h, auth, _sid)) = with_session().await else { unreachable!() };
    let hash = refresh_hash(&auth.refresh_token);
    h.stores.fail_next_session_lookups(1);
    let revoked = h
        .engine
        .revoke_user_session("t1", &auth.user.id, &hash)
        .await;
    assert!(revoked.is_ok());
    assert_eq!(h.stores.ended_session_count(), 0);
    assert_eq!(epoch(&h, &auth.user.id).await, 1);
}

#[tokio::test]
async fn an_access_token_of_an_ended_session_is_refused() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    assert!(end(&h, &sid).await);
    let verified = h.engine.tokens().verify_access(&auth.access_token).await;
    assert!(
        matches!(verified, Err(AuthError::TokenRevoked)),
        "{verified:?}"
    );
}

#[tokio::test]
async fn an_access_token_is_not_accepted_while_the_entry_cannot_be_read() {
    let Some((h, auth, _sid)) = with_session().await else { unreachable!() };
    h.stores.fail_session_access_reads(true);
    let verified = h.engine.tokens().verify_access(&auth.access_token).await;
    assert!(
        matches!(verified, Err(AuthError::Internal(_))),
        "{verified:?}"
    );
}

/// A ticket minted from the signed-in account's access token.
async fn ticket() -> Option<(Harness, String, String)> {
    let (h, auth, sid) = with_session().await?;
    let claims = claims_of(&h, &auth.access_token).await?;
    let ticket = h.engine.issue_ws_ticket(&claims).await.ok()?.ticket;
    Some((h, ticket, sid))
}

#[tokio::test]
async fn a_redeemed_ticket_names_the_session_it_was_minted_from() {
    let Some((h, ticket, sid)) = ticket().await else { unreachable!() };
    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert_eq!(redeemed.ok().and_then(|claims| claims.sid), Some(sid));
}

#[tokio::test]
async fn a_ticket_of_an_ended_session_is_refused() {
    let Some((h, ticket, sid)) = ticket().await else { unreachable!() };
    assert!(end(&h, &sid).await);
    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(
        matches!(redeemed, Err(AuthError::TokenInvalid)),
        "{redeemed:?}"
    );
}

#[tokio::test]
async fn a_ticket_is_not_redeemed_while_the_entry_cannot_be_read() {
    let Some((h, ticket, _sid)) = ticket().await else { unreachable!() };
    h.stores.fail_session_access_reads(true);
    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(
        matches!(redeemed, Err(AuthError::Internal(_))),
        "{redeemed:?}"
    );
}

/// A sign-in holding two live sessions: one refresh token presented twice, the second time inside
/// its grace window. Returns the two refresh tokens.
async fn two_sessions(h: &Harness, auth: &AuthResult) -> Option<(String, String)> {
    let tokens = h.engine.tokens();
    let rotated = tokens
        .reissue_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await
        .ok()?;
    let recovered = tokens
        .reissue_tokens(&auth.refresh_token, "10.0.0.1", "agent/1.0")
        .await
        .ok()?;
    Some((rotated.refresh_token, recovered.refresh_token))
}

async fn refuses_refresh(h: &Harness, raw: &str) -> bool {
    let refreshed = h.engine.refresh(raw, "1.2.3.4", "agent").await;
    matches!(refreshed, Err(AuthError::RefreshTokenInvalid))
}

#[tokio::test]
async fn a_logout_of_one_session_leaves_the_other_of_its_sign_in_unable_to_refresh() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let Some((one, other)) = two_sessions(&h, &auth).await else { unreachable!() };
    assert!(h.engine.logout("", &one).await.is_ok());
    assert!(refuses_refresh(&h, &other).await);
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn revoking_one_session_leaves_the_other_of_its_sign_in_unable_to_refresh() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    let Some((one, other)) = two_sessions(&h, &auth).await else { unreachable!() };
    let revoked = h
        .engine
        .revoke_user_session("t1", &auth.user.id, &refresh_hash(&one))
        .await;
    assert!(revoked.is_ok(), "{revoked:?}");
    assert!(refuses_refresh(&h, &other).await);
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn an_eviction_past_the_cap_ends_every_session_of_the_evicted_sign_in() {
    let tune = |cfg: &mut crate::config::AuthConfig| {
        cfg.sessions.enabled = true;
        cfg.sessions.default_max_sessions = 2;
    };
    let Some((h, auth)) = signed_in_with(None, tune).await else { unreachable!() };
    let Some((one, other)) = two_sessions(&h, &auth).await else { unreachable!() };
    let second = h
        .engine
        .login(login_input("out@example.com", "pw"), &ctx())
        .await;
    assert!(matches!(second, Ok(LoginResult::Success(_))));
    assert!(refuses_refresh(&h, &one).await);
    assert!(refuses_refresh(&h, &other).await);
    assert_eq!(h.stores.ended_session_count(), 1);
}

#[tokio::test]
async fn a_logout_that_could_not_remove_the_family_fails_and_writes_no_entry() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    h.stores.fail_next_family_removals(1);
    let first = h.engine.logout("", &auth.refresh_token).await;
    assert!(first.is_err());
    assert_eq!(entry(&h, &sid), None);

    assert!(h.engine.logout("", &auth.refresh_token).await.is_ok());
    assert_eq!(entry(&h, &sid), Some(ENTRY_TTL));
}

#[tokio::test]
async fn revoking_a_session_whose_family_cannot_be_removed_fails_and_writes_no_entry() {
    let Some((h, auth, sid)) = with_session().await else { unreachable!() };
    h.stores.fail_next_family_removals(1);
    let revoked = h
        .engine
        .revoke_user_session("t1", &auth.user.id, &refresh_hash(&auth.refresh_token))
        .await;
    assert!(revoked.is_err(), "{revoked:?}");
    assert_eq!(entry(&h, &sid), None);
}
