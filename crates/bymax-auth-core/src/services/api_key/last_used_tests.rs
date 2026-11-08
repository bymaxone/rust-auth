//! Last-used instants are coalesced in memory, kept newest-first, written in one batch on request,
//! and retried after a failed write without losing a newer instant.

use time::Duration;

use super::test_support::{TestResult, fixture};
use crate::config::ApiKeyAuditMode;

fn last_used(f: &super::test_support::Fixture, id: &str) -> Option<time::OffsetDateTime> {
    f.repo.row(id).and_then(|row| row.last_used_at)
}

#[tokio::test]
async fn a_verified_key_is_written_on_flush_and_not_before() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    let runtime = f.engine.enabled_api_keys()?;

    runtime.verify(Some(&issued.key)).await?;
    assert_eq!(last_used(&f, &issued.record.id), None);

    f.engine.flush_api_key_last_used().await?;
    assert_eq!(last_used(&f, &issued.record.id), Some(f.clock_now()));
    Ok(())
}

#[tokio::test]
async fn a_refused_key_is_never_recorded_as_used() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.engine.revoke_api_key(&issued.record.id).await?;
    let runtime = f.engine.enabled_api_keys()?;

    runtime.verify(Some(&issued.key)).await?;
    f.engine.flush_api_key_last_used().await?;

    assert_eq!(last_used(&f, &issued.record.id), None);
    Ok(())
}

#[tokio::test]
async fn the_newest_instant_wins_within_a_batch() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    let runtime = f.engine.enabled_api_keys()?;
    let early = f.clock_now();
    f.clock.advance(Duration::minutes(5));
    let late = f.clock_now();

    runtime.verify(Some(&issued.key)).await?;
    f.clock.set(early);
    runtime.verify(Some(&issued.key)).await?;
    f.engine.flush_api_key_last_used().await?;

    assert_eq!(last_used(&f, &issued.record.id), Some(late));
    Ok(())
}

#[tokio::test]
async fn a_failed_flush_leaves_the_instant_queued_for_the_next_one() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.engine
        .enabled_api_keys()?
        .verify(Some(&issued.key))
        .await?;

    f.repo.set_failing(true);
    assert!(f.engine.flush_api_key_last_used().await.is_err());
    f.repo.set_failing(false);
    f.engine.flush_api_key_last_used().await?;

    assert_eq!(last_used(&f, &issued.record.id), Some(f.clock_now()));
    Ok(())
}

#[tokio::test]
async fn a_failed_flush_is_retried_and_keeps_a_newer_instant_recorded_meanwhile() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    let runtime = f.engine.enabled_api_keys()?;
    runtime.verify(Some(&issued.key)).await?;

    f.repo.set_failing(true);
    assert!(f.engine.flush_api_key_last_used().await.is_err());
    f.repo.set_failing(false);
    f.clock.advance(Duration::minutes(1));
    runtime.verify(Some(&issued.key)).await?;
    f.engine.flush_api_key_last_used().await?;

    assert_eq!(last_used(&f, &issued.record.id), Some(f.clock_now()));
    Ok(())
}

#[tokio::test]
async fn flushing_with_nothing_pending_does_not_touch_the_store() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    f.repo.set_failing(true);

    f.engine.flush_api_key_last_used().await?;
    Ok(())
}
