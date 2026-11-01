//! A WebSocket ticket is refused at redemption exactly when the access token it was minted from
//! would be: blacklisted by a logout, or stamped below the account's current epoch. A ticket
//! whose record lacks the identifiers to check that by is not a ticket.
//!
//! Layer: unit tests of the engine's ticket surface over the in-memory doubles, sharing the
//! fixtures of the parent test module.

use super::*;
use crate::traits::SessionKind;

/// Mint a ticket for `claims` and return it.
async fn minted(
    h: &crate::services::auth::test_support::Harness,
    claims: &DashboardClaims,
) -> String {
    h.engine
        .issue_ws_ticket(claims)
        .await
        .map(|issued| issued.ticket)
        .unwrap_or_default()
}

fn dashboard_subject(
    h: &crate::services::auth::test_support::Harness,
    claims: &DashboardClaims,
) -> String {
    h.engine
        .session_subject(SessionKind::Dashboard, Some(&claims.tenant_id), &claims.sub)
}

#[tokio::test]
async fn a_live_session_redeems_its_ticket() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    assert!(!ticket.is_empty());

    let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(matches!(&redeemed, Ok(c) if c.sub == claims.sub));
}

#[tokio::test]
async fn a_ticket_minted_before_logout_is_refused() {
    // Logout blacklists the jti of the token it was handed; the ticket carries that jti.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    assert!(
        h.engine
            .session_store()
            .blacklist_access(&claims.jti, 900)
            .await
            .is_ok()
    );

    let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(matches!(redeemed, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_ticket_minted_before_an_epoch_bump_is_refused() {
    // A password reset or sign-out-everywhere bumps the account's epoch.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    assert!(
        h.engine
            .session_store()
            .bump_epoch(SessionKind::Dashboard, &dashboard_subject(&h, &claims))
            .await
            .is_ok()
    );

    let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(matches!(redeemed, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_ticket_minted_after_an_epoch_bump_from_a_current_token_is_accepted() {
    // The comparison is "current epoch above the ticket's": a token stamped with the bumped
    // epoch mints a ticket that redeems.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let bumped = h
        .engine
        .session_store()
        .bump_epoch(SessionKind::Dashboard, &dashboard_subject(&h, &claims))
        .await
        .unwrap_or_default();
    let current = DashboardClaims {
        epoch: bumped,
        ..claims
    };
    let ticket = minted(&h, &current).await;

    assert!(h.engine.redeem_ws_ticket(&ticket).await.is_ok());
}

/// Store `snapshot` directly, as a writer of any age could, and return the raw ticket.
async fn stored(
    h: &crate::services::auth::test_support::Harness,
    snapshot: &WsTicketSnapshot,
) -> String {
    match h.engine.ws_ticket_store() {
        Some(store) => store.mint(snapshot, 30).await.unwrap_or_default(),
        None => String::new(),
    }
}

fn snapshot(tenant_id: Option<&str>, jti: &str, epoch: u64) -> WsTicketSnapshot {
    WsTicketSnapshot {
        sub: "u1".to_owned(),
        tenant_id: tenant_id.map(str::to_owned),
        role: "USER".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_verified: false,
        jti: jti.to_owned(),
        epoch,
    }
}

#[tokio::test]
async fn a_ticket_without_an_identifier_to_check_is_refused() {
    let Some(h) = harness(base_config(), None) else { return };
    let ticket = stored(&h, &snapshot(Some("t1"), "", 0)).await;

    let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
    assert!(matches!(redeemed, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_ticket_that_names_no_usable_tenant_is_refused() {
    // This engine mints only dashboard tickets, so a snapshot without a tenant, or with an empty
    // one, was not written by it. Redemption would otherwise hand the socket dashboard claims
    // whose tenant is the empty string. Every other field is live, and the answer is the one an
    // unknown ticket gets.
    let Some(h) = harness(base_config(), None) else { return };
    for tenant in [None, Some("")] {
        let ticket = stored(&h, &snapshot(tenant, "jti-live", 0)).await;
        let redeemed = h.engine.redeem_ws_ticket(&ticket).await;
        assert!(
            matches!(redeemed, Err(AuthError::TokenInvalid)),
            "tenant {tenant:?} was redeemed"
        );
    }
}

#[tokio::test]
async fn a_revoked_ticket_gets_the_answer_of_an_unknown_one() {
    // No oracle: a revoked ticket and a ticket that never existed are the same refusal.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    assert!(
        h.engine
            .session_store()
            .blacklist_access(&claims.jti, 900)
            .await
            .is_ok()
    );

    let revoked = h.engine.redeem_ws_ticket(&ticket).await;
    let unknown = h.engine.redeem_ws_ticket(&"0".repeat(64)).await;
    assert!(matches!(
        (revoked, unknown),
        (Err(AuthError::TokenInvalid), Err(AuthError::TokenInvalid))
    ));
}

/// A ticket store that remembers the TTL it was asked to mint with.
struct RecordingTicketStore {
    ttls: std::sync::Mutex<Vec<u64>>,
}

#[async_trait::async_trait]
impl crate::traits::WsTicketStore for RecordingTicketStore {
    async fn mint(&self, _snapshot: &WsTicketSnapshot, ttl_secs: u64) -> Result<String, AuthError> {
        if let Ok(mut ttls) = self.ttls.lock() {
            ttls.push(ttl_secs);
        }
        Ok("0".repeat(64))
    }
    async fn redeem(&self, _ticket: &str) -> Result<Option<WsTicketSnapshot>, AuthError> {
        Ok(None)
    }
}

/// The TTLs `issue_ws_ticket` minted with for tokens that expire in `lifetimes` seconds.
async fn minted_ttls(lifetimes: &[i64]) -> Vec<Option<u64>> {
    use crate::config::Environment;
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::UserRepository as _;
    use std::sync::Arc;

    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let recorder = Arc::new(RecordingTicketStore {
        ttls: std::sync::Mutex::new(Vec::new()),
    });
    let created = users
        .create(bymax_auth_types::CreateUserData {
            email: "ttl@example.com".to_owned(),
            name: "Ttl".to_owned(),
            password_hash: None,
            role: None,
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    let built = AuthEngine::builder()
        .config(base_config())
        .environment(Environment::Test)
        .user_repository(users)
        .session_store(stores.clone())
        .otp_store(stores.clone())
        .brute_force_store(stores)
        .ws_ticket_store(recorder.clone())
        .build();
    let (Ok(user), Ok(engine)) = (created, built) else { return Vec::new() };

    let mut out = Vec::new();
    for lifetime in lifetimes {
        let claims = DashboardClaims {
            sub: user.id.clone(),
            exp: now_unix() + lifetime,
            ..sample_claims()
        };
        let before = recorder.ttls.lock().map(|t| t.len()).unwrap_or(0);
        let issued = engine.issue_ws_ticket(&claims).await;
        let after = recorder.ttls.lock().map(|t| t.clone()).unwrap_or_default();
        out.push(match issued {
            Ok(minted) => {
                // The lifetime reported to the caller is the one the store was given.
                assert_eq!(Some(minted.expires_in), after.get(before).copied());
                after.get(before).copied()
            }
            Err(_) => None,
        });
    }
    out
}

#[test]
fn a_ticket_expires_before_the_token_that_minted_it() {
    // The lifetime is the lesser of the ticket ceiling and the token's remaining life less one
    // second, so the ticket ends before the token does on clocks that count whole seconds.
    assert_eq!(ticket_ttl(1_000, 100), Some(WS_TICKET_TTL_SECONDS));
    assert_eq!(ticket_ttl(105, 100), Some(4));
    assert_eq!(ticket_ttl(131, 100), Some(WS_TICKET_TTL_SECONDS));
    assert_eq!(ticket_ttl(130, 100), Some(WS_TICKET_TTL_SECONDS - 1));

    // Every remaining life from "expired" to past the ceiling: a lifetime is only ever granted
    // when it ends strictly before the expiry.
    for exp in 90..=200_i64 {
        if let Some(ttl) = ticket_ttl(exp, 100) {
            assert!(ttl > 0 && ttl <= WS_TICKET_TTL_SECONDS);
            assert!(
                i64::try_from(ttl).unwrap_or(i64::MAX) < exp - 100,
                "exp {exp}: ttl {ttl}"
            );
        }
    }
}

#[test]
fn a_token_with_no_lifetime_left_has_no_ticket_lifetime() {
    assert_eq!(ticket_ttl(101, 100), None);
    assert_eq!(ticket_ttl(100, 100), None);
    assert_eq!(ticket_ttl(97, 100), None);
    assert_eq!(ticket_ttl(i64::MIN, 100), None);
}

#[tokio::test]
async fn the_engine_mints_with_the_capped_lifetime() {
    // Wiring only: the arithmetic is pinned above without a clock. A 900 s token mints with the
    // ceiling whichever way a second boundary falls.
    assert_eq!(minted_ttls(&[900]).await, vec![Some(WS_TICKET_TTL_SECONDS)]);
}

#[tokio::test]
async fn a_token_with_no_lifetime_left_mints_no_ticket() {
    // 1 s left is nothing whichever way a second boundary falls.
    assert_eq!(minted_ttls(&[1, 0, -3]).await, vec![None, None, None]);
}
