//! `AuthEngine::login_lockout` reports what real failed logins did to the counter, and changes
//! nothing itself.

use bymax_auth_types::AuthError;

use super::LoginInput;
use super::LoginLockout;
use super::test_support::{Harness, SeedUser, base_config, ctx, harness};

fn input(email: &str, password: &str, tenant: &str) -> LoginInput {
    LoginInput {
        email: email.to_owned(),
        password: password.to_owned(),
        tenant_id: Some(tenant.to_owned()),
    }
}

/// Fail a login for `email` in `tenant` once and require the credential refusal.
async fn fail_once(h: &Harness, email: &str, tenant: &str) -> bool {
    matches!(
        h.engine.login(input(email, "wrong", tenant), &ctx()).await,
        Err(AuthError::InvalidCredentials)
    )
}

async fn lockout(h: &Harness, tenant: &str, email: &str) -> Result<LoginLockout, AuthError> {
    h.engine.login_lockout(tenant, email).await
}

#[tokio::test]
async fn an_untouched_account_is_not_locked() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("free@example.com", "right")).await;

    let state = lockout(&h, "t1", "free@example.com").await?;

    assert!(!state.locked);
    assert_eq!(state.retry_after_secs, 0);
    Ok(())
}

#[tokio::test]
async fn failed_logins_lock_the_account_at_the_cap_and_report_the_window() -> Result<(), AuthError>
{
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("lock@example.com", "right")).await;
    let cap = base_config().brute_force.max_attempts;

    for _ in 0..cap - 1 {
        assert!(fail_once(&h, "lock@example.com", "t1").await);
    }
    assert!(!lockout(&h, "t1", "lock@example.com").await?.locked);

    assert!(fail_once(&h, "lock@example.com", "t1").await);
    let state = lockout(&h, "t1", "lock@example.com").await?;

    assert!(state.locked);
    assert!(state.retry_after_secs > 0);
    assert!(state.retry_after_secs <= base_config().brute_force.window.as_secs());
    Ok(())
}

#[tokio::test]
async fn the_address_is_read_the_way_login_reads_it() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("case@example.com", "right")).await;
    for _ in 0..base_config().brute_force.max_attempts {
        assert!(fail_once(&h, "case@example.com", "t1").await);
    }

    assert!(lockout(&h, "t1", "  CASE@Example.com ").await?.locked);
    Ok(())
}

#[tokio::test]
async fn another_tenant_and_another_address_are_not_locked() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("a@example.com", "right")).await;
    for _ in 0..base_config().brute_force.max_attempts {
        assert!(fail_once(&h, "a@example.com", "t1").await);
    }

    assert!(!lockout(&h, "t2", "a@example.com").await?.locked);
    assert!(!lockout(&h, "t1", "b@example.com").await?.locked);
    Ok(())
}

#[tokio::test]
async fn an_unknown_address_answers_exactly_as_a_known_one_does() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("known@example.com", "right")).await;
    let cap = base_config().brute_force.max_attempts;
    for _ in 0..cap {
        assert!(fail_once(&h, "known@example.com", "t1").await);
        assert!(fail_once(&h, "ghost@example.com", "t1").await);
    }

    let known = lockout(&h, "t1", "known@example.com").await?;
    let ghost = lockout(&h, "t1", "ghost@example.com").await?;

    assert!(known.locked && ghost.locked);
    Ok(())
}

#[tokio::test]
async fn reading_the_state_never_moves_it() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("ro@example.com", "right")).await;
    let cap = base_config().brute_force.max_attempts;
    for _ in 0..cap - 1 {
        assert!(fail_once(&h, "ro@example.com", "t1").await);
    }

    for _ in 0..cap * 3 {
        assert!(!lockout(&h, "t1", "ro@example.com").await?.locked);
    }

    // One more real failure still trips it: the reads added nothing to the count.
    assert!(fail_once(&h, "ro@example.com", "t1").await);
    assert!(lockout(&h, "t1", "ro@example.com").await?.locked);
    Ok(())
}

#[tokio::test]
async fn an_unlock_is_visible() -> Result<(), AuthError> {
    let Some(h) = harness(base_config(), None) else { return Ok(()) };
    let _ = h.seed(SeedUser::active("un@example.com", "right")).await;
    for _ in 0..base_config().brute_force.max_attempts {
        assert!(fail_once(&h, "un@example.com", "t1").await);
    }
    h.engine.unlock_account("un@example.com", "t1").await?;

    assert!(!lockout(&h, "t1", "un@example.com").await?.locked);
    Ok(())
}
