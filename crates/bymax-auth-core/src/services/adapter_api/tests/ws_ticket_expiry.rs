//! A WebSocket ticket carries the expiry of the token that minted it, is held to the tenant the
//! caller expects, and is redeemed only while its account is still usable.
//!
//! Layer: unit tests of the engine's ticket surface over the in-memory doubles, sharing the
//! fixtures of the parent test module.

use super::*;
use crate::services::auth::test_support::Harness;
use crate::traits::UserRepository as _;

/// Store a record for `claims`' account carrying `exp`, as any writer of the keyspace could.
async fn stored(h: &Harness, claims: &DashboardClaims, exp: Option<u64>) -> String {
    let snapshot = WsTicketSnapshot {
        sub: claims.sub.clone(),
        tenant_id: Some(claims.tenant_id.clone()),
        role: claims.role.clone(),
        status: claims.status.clone(),
        mfa_enabled: false,
        mfa_verified: false,
        jti: claims.jti.clone(),
        epoch: claims.epoch,
        exp,
    };
    match h.engine.ws_ticket_store() {
        Some(store) => store.mint(&snapshot, 30).await.unwrap_or_default(),
        None => String::new(),
    }
}

async fn minted(h: &Harness, claims: &DashboardClaims) -> String {
    h.engine
        .issue_ws_ticket(claims)
        .await
        .map(|issued| issued.ticket)
        .unwrap_or_default()
}

/// The current second, as a stored expiry counts it.
fn now_seconds() -> u64 {
    u64::try_from(now_unix()).unwrap_or(0)
}

#[tokio::test]
async fn a_redeemed_ticket_carries_the_expiry_of_the_token_that_minted_it() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;

    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(matches!(&redeemed, Ok(c) if c.exp == claims.exp));
}

#[tokio::test]
async fn a_record_is_not_redeemed_from_its_expiry_on() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    for exp in [now_seconds(), now_seconds().saturating_sub(60), 0] {
        let ticket = stored(&h, &claims, Some(exp)).await;
        let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
        assert!(
            matches!(redeemed, Err(AuthError::TokenInvalid)),
            "exp {exp} was redeemed"
        );
    }
}

#[tokio::test]
async fn a_record_without_an_expiry_is_accepted_for_the_ticket_lifetime() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = stored(&h, &claims, None).await;

    let before = now_unix();
    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    let ceiling = i64::try_from(WS_TICKET_TTL_SECONDS).unwrap_or(0);
    let after = now_unix();
    assert!(matches!(&redeemed, Ok(c) if c.exp >= before + ceiling && c.exp <= after + ceiling));
}

#[tokio::test]
async fn a_ticket_of_the_expected_tenant_is_redeemed() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;

    let redeemed = h
        .engine
        .redeem_ws_ticket(&ticket, Some(&claims.tenant_id))
        .await;
    assert!(matches!(&redeemed, Ok(c) if c.tenant_id == claims.tenant_id));
}

#[tokio::test]
async fn a_ticket_of_another_tenant_is_refused_and_consumed() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    for expected in ["other", ""] {
        let ticket = minted(&h, &claims).await;

        let refused = h.engine.redeem_ws_ticket(&ticket, Some(expected)).await;
        let again = h.engine.redeem_ws_ticket(&ticket, None).await;
        assert!(matches!(refused, Err(AuthError::TokenInvalid)));
        assert!(matches!(again, Err(AuthError::TokenInvalid)));
    }
}

#[tokio::test]
async fn a_ticket_whose_account_is_gone_is_refused() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = DashboardClaims {
        sub: "nobody".to_owned(),
        ..sample_claims()
    };
    let ticket = stored(&h, &claims, None).await;

    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(matches!(redeemed, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_ticket_whose_account_was_blocked_after_the_mint_answers_the_status() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    assert!(
        h.users
            .update_status(&claims.sub, &claims.tenant_id, "BANNED")
            .await
            .is_ok()
    );

    let redeemed = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(matches!(redeemed, Err(AuthError::AccountBanned)));
}

#[tokio::test]
async fn a_token_with_no_lifetime_left_is_refused_before_the_account_is_read() {
    // The account is blocked, so an answer that read it would name the status.
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    assert!(
        h.users
            .update_status(&claims.sub, &claims.tenant_id, "BANNED")
            .await
            .is_ok()
    );
    let spent = DashboardClaims {
        exp: now_unix(),
        ..claims
    };

    let issued = h.engine.issue_ws_ticket(&spent).await;
    assert!(matches!(issued, Err(AuthError::TokenInvalid)));
}

#[tokio::test]
async fn a_failed_account_read_fails_the_redemption_and_consumes_the_ticket() {
    let Some(h) = harness(base_config(), None) else { return };
    let claims = seeded_claims(&h).await;
    let ticket = minted(&h, &claims).await;
    h.users.fail_next_reads(1);

    let failed = h.engine.redeem_ws_ticket(&ticket, None).await;
    let again = h.engine.redeem_ws_ticket(&ticket, None).await;
    assert!(matches!(failed, Err(AuthError::Internal(_))));
    assert!(matches!(again, Err(AuthError::TokenInvalid)));
}
