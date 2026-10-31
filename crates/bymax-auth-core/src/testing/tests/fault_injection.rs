//! The fault injectors count exactly, and the tenant toggle changes what it says it changes.
//!
//! A consumer test arms an injector with a count of one and then looks at a single call, so
//! it passes whether the injector fails once or for ever, and whether the toggle works or is a
//! no-op. These tests read the injectors back across the whole armed window and the call after
//! it, which is the contract every consumer relies on.

use super::*;

#[tokio::test]
async fn fail_next_reads_fails_exactly_that_many_lookups() {
    let repo = InMemoryUserRepository::new();
    repo.fail_next_reads(2);

    for _ in 0..2 {
        assert!(matches!(
            repo.find_by_id("missing", None).await,
            Err(RepositoryError::Backend(_))
        ));
    }
    assert!(matches!(repo.find_by_id("missing", None).await, Ok(None)));
}

#[tokio::test]
async fn ignoring_the_tenant_on_email_returns_the_other_tenants_account() {
    let repo = InMemoryUserRepository::new();
    assert!(repo.create(create_data()).await.is_ok());

    // Scoped by default: the account lives in `t1`, so `t2` does not see it.
    assert!(matches!(
        repo.find_by_email("user@example.com", "t2").await,
        Ok(None)
    ));

    repo.ignore_tenant_on_email();

    // Misconfigured, as a consumer repository might be: `t2` is handed the `t1` account.
    assert!(matches!(
        repo.find_by_email("user@example.com", "t2").await,
        Ok(Some(user)) if user.tenant_id == "t1"
    ));
    assert!(matches!(
        repo.find_by_email("user@example.com", "t1").await,
        Ok(Some(_))
    ));
}

#[tokio::test]
async fn fail_lockout_reads_skips_then_fails_exactly_count() {
    let stores = InMemoryStores::new();
    stores.fail_lockout_reads(2, 2);

    let mut failed = Vec::new();
    for _ in 0..6 {
        failed.push(stores.is_locked("who", 5).await.is_err());
    }

    assert_eq!(failed, [false, false, true, true, false, false]);
}

#[tokio::test]
async fn fail_next_lockout_ttl_reads_fails_exactly_that_many_then_reads() {
    let stores = InMemoryStores::new();
    assert!(stores.record_failure("who", 900).await.is_ok());
    stores.fail_next_lockout_ttl_reads(2);

    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(stores.remaining_lockout_secs("who").await.ok());
    }

    assert_eq!(answers, [None, None, Some(900), Some(900)]);
}

#[tokio::test]
async fn refuse_next_recovered_writes_refuses_exactly_that_many_then_writes() {
    let stores = InMemoryStores::new();
    let kind = SessionKind::Dashboard;
    let detail = record_in_family("u1", "");
    // The index entry is the witness that no revoke-all ran since the recovery began.
    assert!(
        stores
            .create_session(kind, &subject("u1"), "seed", &detail, 60)
            .await
            .is_ok()
    );

    stores.refuse_next_recovered_writes(2);
    for _ in 0..2 {
        assert!(matches!(
            stores
                .create_recovered_session(kind, &subject("u1"), "t", &detail, 60)
                .await,
            Ok(false)
        ));
    }
    assert!(matches!(
        stores
            .create_recovered_session(kind, &subject("u1"), "t", &detail, 60)
            .await,
        Ok(true)
    ));

    // Without the witness the write is refused: the account was swept while it was in flight.
    assert!(matches!(
        stores
            .create_recovered_session(kind, &subject("swept"), "t", &detail, 60)
            .await,
        Ok(false)
    ));
}

#[tokio::test]
async fn fail_next_epoch_bumps_fails_exactly_that_many_then_counts_up() {
    let stores = InMemoryStores::new();
    stores.fail_next_epoch_bumps(2);

    for _ in 0..2 {
        assert!(
            stores
                .bump_epoch(SessionKind::Dashboard, &subject("u1"))
                .await
                .is_err()
        );
    }
    assert!(matches!(
        stores
            .bump_epoch(SessionKind::Dashboard, &subject("u1"))
            .await,
        Ok(1)
    ));
    assert!(matches!(
        stores
            .bump_epoch(SessionKind::Dashboard, &subject("u1"))
            .await,
        Ok(2)
    ));
}
