//! The cached account-status gate: what the cache answers, when it stops, and what happens when
//! the cache itself fails. Layer: unit tests over the in-memory doubles.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::config::{AuthConfig, Environment};
use crate::engine::AuthEngine;
use crate::services::auth::test_support::{Harness, SeedUser, base_config, harness};
use crate::traits::{UserRepository, UserStatusCacheStore};

const TENANT: &str = "t1";

/// A seeded active account and its id.
async fn seeded(h: &Harness) -> String {
    h.seed(SeedUser::active("c@example.com", "pw123456")).await
}

async fn ban(h: &Harness, id: &str) {
    assert!(h.users.update_status(id, TENANT, "BANNED").await.is_ok());
}

#[tokio::test]
async fn a_cached_status_answers_until_the_account_is_invalidated() {
    let Some(h) = harness(base_config(), None) else { return };
    let id = seeded(&h).await;
    assert!(h.engine.assert_user_active(&id, TENANT).await.is_ok());

    // The repository now says banned, but the gate still answers from the cache.
    ban(&h, &id).await;
    assert!(h.engine.assert_user_active(&id, TENANT).await.is_ok());

    assert!(
        h.engine
            .invalidate_account_status(&id, TENANT)
            .await
            .is_ok()
    );
    let refused = h.engine.assert_user_active(&id, TENANT).await;
    assert!(
        matches!(refused, Err(AuthError::AccountBanned)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_zero_ttl_turns_the_cache_off() {
    let mut cfg = base_config();
    cfg.user_status_cache_ttl = Duration::ZERO;
    let Some(h) = harness(cfg, None) else { return };
    let id = seeded(&h).await;
    assert!(h.engine.assert_user_active(&id, TENANT).await.is_ok());
    ban(&h, &id).await;
    let refused = h.engine.assert_user_active(&id, TENANT).await;
    assert!(
        matches!(refused, Err(AuthError::AccountBanned)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_account_that_is_gone_is_token_invalid_and_is_not_cached() {
    let Some(h) = harness(base_config(), None) else { return };
    let id = seeded(&h).await;
    assert!(h.users.remove(&id));
    let gone = h.engine.assert_user_active(&id, TENANT).await;
    assert!(matches!(gone, Err(AuthError::TokenInvalid)), "{gone:?}");
    let cached = h.stores.get_status(TENANT, &id).await;
    assert!(matches!(cached, Ok(None)), "{cached:?}");
}

#[tokio::test]
async fn the_cache_is_scoped_by_tenant() {
    let Some(h) = harness(base_config(), None) else { return };
    assert!(h.stores.put_status("t1", "u1", "BANNED", 60).await.is_ok());
    let other = h.stores.get_status("t2", "u1").await;
    assert!(matches!(other, Ok(None)), "{other:?}");
    let own = h.stores.get_status("t1", "u1").await;
    assert!(matches!(&own, Ok(Some(s)) if s == "BANNED"), "{own:?}");
}

#[tokio::test]
async fn an_entry_stops_answering_when_its_ttl_has_run_out() {
    let Some(h) = harness(base_config(), None) else { return };
    assert!(h.stores.put_status(TENANT, "u1", "ACTIVE", 0).await.is_ok());
    let expired = h.stores.get_status(TENANT, "u1").await;
    assert!(matches!(expired, Ok(None)), "{expired:?}");
}

fn verification_required() -> AuthConfig {
    let mut cfg = base_config();
    cfg.email_verification.required = true;
    cfg
}

#[tokio::test]
async fn the_verified_flag_is_cached_only_where_verification_is_required() {
    let mut not_required = base_config();
    not_required.email_verification.required = false;
    let Some(h) = harness(not_required, None) else { return };
    let id = seeded(&h).await;
    assert!(
        h.engine
            .assert_user_active_and_verified(&id, TENANT)
            .await
            .is_ok()
    );
    let flag = h.stores.get_verified(TENANT, &id).await;
    assert!(matches!(flag, Ok(None)), "{flag:?}");

    let Some(h) = harness(verification_required(), None) else { return };
    let id = seeded(&h).await;
    assert!(
        h.engine
            .assert_user_active_and_verified(&id, TENANT)
            .await
            .is_ok()
    );
    let flag = h.stores.get_verified(TENANT, &id).await;
    assert!(matches!(flag, Ok(Some(true))), "{flag:?}");
}

#[tokio::test]
async fn a_cached_unverified_flag_refuses_until_the_account_is_invalidated() {
    let Some(h) = harness(verification_required(), None) else { return };
    let id = h
        .seed(SeedUser {
            email_verified: false,
            ..SeedUser::active("u@example.com", "pw123456")
        })
        .await;
    let unverified = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(
        matches!(unverified, Err(AuthError::EmailNotVerified)),
        "{unverified:?}"
    );

    // Verified in the repository, still refused from the cache, until invalidated.
    assert!(
        h.users
            .update_email_verified(&id, TENANT, true)
            .await
            .is_ok()
    );
    let stale = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(
        matches!(stale, Err(AuthError::EmailNotVerified)),
        "{stale:?}"
    );
    assert!(
        h.engine
            .invalidate_account_status(&id, TENANT)
            .await
            .is_ok()
    );
    assert!(
        h.engine
            .assert_user_active_and_verified(&id, TENANT)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_blocked_status_is_reported_before_an_unverified_address() {
    // Both facts refuse this account; the status is the one the caller is told.
    let Some(h) = harness(verification_required(), None) else { return };
    let id = h
        .seed(SeedUser {
            status: "BANNED".to_owned(),
            email_verified: false,
            ..SeedUser::active("b@example.com", "pw123456")
        })
        .await;
    let banned = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(
        matches!(banned, Err(AuthError::AccountBanned)),
        "{banned:?}"
    );
    // The same answer from the cache on the second call.
    let cached = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(
        matches!(cached, Err(AuthError::AccountBanned)),
        "{cached:?}"
    );
}

#[tokio::test]
async fn the_status_only_gate_does_not_ask_for_the_verified_flag() {
    let Some(h) = harness(verification_required(), None) else { return };
    let id = h
        .seed(SeedUser {
            email_verified: false,
            ..SeedUser::active("s@example.com", "pw123456")
        })
        .await;
    assert!(h.engine.assert_user_active(&id, TENANT).await.is_ok());
}

#[tokio::test]
async fn an_empty_id_has_nothing_to_invalidate() {
    let Some(h) = harness(base_config(), None) else { return };
    assert!(h.stores.put_status(TENANT, "", "BANNED", 60).await.is_ok());
    assert!(h.engine.invalidate_account_status("", TENANT).await.is_ok());
    assert!(
        h.engine
            .invalidate_account_status(" ", TENANT)
            .await
            .is_ok()
    );
    assert!(h.engine.invalidate_account_status("u1", "").await.is_ok());
    // The no-op left the entry in place.
    let kept = h.stores.get_status(TENANT, "").await;
    assert!(matches!(&kept, Ok(Some(_))), "{kept:?}");
}

/// A cache whose every call fails, standing in for an unreachable Redis.
struct DownCache;

fn down() -> AuthError {
    AuthError::Internal(Box::new(std::io::Error::other("cache unavailable")))
}

#[async_trait]
impl UserStatusCacheStore for DownCache {
    async fn get_status(&self, _: &str, _: &str) -> Result<Option<String>, AuthError> {
        Err(down())
    }
    async fn get_verified(&self, _: &str, _: &str) -> Result<Option<bool>, AuthError> {
        Err(down())
    }
    async fn put_status(&self, _: &str, _: &str, _: &str, _: u64) -> Result<(), AuthError> {
        Err(down())
    }
    async fn put_verified(&self, _: &str, _: &str, _: bool, _: u64) -> Result<(), AuthError> {
        Err(down())
    }
    async fn invalidate(&self, _: &str, _: &str) -> Result<(), AuthError> {
        Err(down())
    }
}

/// An engine over the harness's stores whose status cache is [`DownCache`].
fn engine_with_down_cache(h: &Harness, cfg: AuthConfig) -> Option<AuthEngine> {
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(h.users.clone())
        .email_provider(h.emails.clone())
        .redis_stores(h.stores.clone())
        .user_status_cache(Arc::new(DownCache))
        .build();
    // Asserted, not skipped: a builder that dropped the cache would otherwise make every test
    // that uses this helper return early and pass.
    assert!(
        built.is_ok(),
        "the engine must build: {:?}",
        built.as_ref().err()
    );
    built.ok()
}

#[tokio::test]
async fn a_failing_cache_is_reported_by_the_gate_and_logged_by_a_best_effort_drop() {
    let Some(h) = harness(base_config(), None) else { return };
    let id = seeded(&h).await;
    let Some(engine) = engine_with_down_cache(&h, base_config()) else { return };

    // The gate does not wave a request through because the cache is down.
    let gate = engine.assert_user_active(&id, TENANT).await;
    assert!(matches!(gate, Err(AuthError::Internal(_))), "{gate:?}");
    let dropped = engine.invalidate_account_status(&id, TENANT).await;
    assert!(
        matches!(dropped, Err(AuthError::Internal(_))),
        "{dropped:?}"
    );

    // A flow that has already committed logs the failure instead of surfacing it.
    let (events, capture) = crate::log_capture::capture_events();
    engine.drop_cached_account_facts(&id, "t\n1").await;
    drop(capture);
    assert!(events.contains_at(tracing::Level::ERROR, "invalidation failed"));
    assert!(
        !events.contains("t\n1"),
        "the tenant reached the log unsanitized"
    );
}

#[tokio::test]
async fn verifying_the_address_drops_the_cached_flag_so_the_next_request_passes() {
    let Some(h) = harness(verification_required(), None) else { return };
    let id = h
        .seed(SeedUser {
            email_verified: false,
            ..SeedUser::active("v@example.com", "pw123456")
        })
        .await;
    let before = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(
        matches!(before, Err(AuthError::EmailNotVerified)),
        "{before:?}"
    );

    assert!(
        h.engine
            .send_verification_otp(TENANT, "v@example.com", &id)
            .await
            .is_ok()
    );
    let mailed = crate::services::auth::test_support::await_verification_code(&h).await;
    let Some(code) = mailed else { return };
    let ctx = crate::services::auth::test_support::ctx();
    assert!(
        h.engine
            .verify_email(Some(TENANT), "v@example.com", &code, &ctx)
            .await
            .is_ok()
    );

    // No invalidate call from the test: verify_email dropped the stale "0" itself.
    let after = h.engine.assert_user_active_and_verified(&id, TENANT).await;
    assert!(after.is_ok(), "{after:?}");
}

#[tokio::test]
async fn a_zero_ttl_never_reaches_the_cache_at_all() {
    // With the cache off, a cache that would fail every call is never asked: the gate reads the
    // repository and `invalidate` has nothing to do.
    let mut cfg = base_config();
    cfg.user_status_cache_ttl = Duration::ZERO;
    let Some(h) = harness(cfg.clone(), None) else { return };
    let id = seeded(&h).await;
    let Some(engine) = engine_with_down_cache(&h, cfg) else { return };
    assert!(engine.assert_user_active(&id, TENANT).await.is_ok());
    assert!(engine.invalidate_account_status(&id, TENANT).await.is_ok());
}
