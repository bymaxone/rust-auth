//! The in-memory API-key repository behaves as the port documents: it returns revoked and
//! expired rows, keeps `last_used_at` monotonic, and fails like an outage when told to.

use time::{Duration, OffsetDateTime};

use super::InMemoryApiKeyRepository;
use crate::RepositoryError;
use crate::traits::{ApiKeyRepository, ApiKeySummary, NewApiKey};

fn new_key(id: &str, label: &str, now: OffsetDateTime) -> NewApiKey {
    NewApiKey {
        id: id.to_owned(),
        label: label.to_owned(),
        digest: "0".repeat(64),
        scopes: vec!["reports:read".to_owned()],
        created_at: now,
        expires_at: None,
    }
}

#[tokio::test]
async fn a_created_row_is_found_with_nothing_revoked_or_used() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();

    let stored = repo.create(new_key("a", "billing", now)).await?;
    let found = repo.find_by_id("a").await?;

    assert_eq!(found.as_ref(), Some(&stored));
    assert!(stored.revoked_at.is_none() && stored.last_used_at.is_none());
    assert!(repo.find_by_id("missing").await?.is_none());
    assert_eq!(repo.reads(), 2);
    assert_eq!(repo.row("a"), Some(stored));
    Ok(())
}

#[tokio::test]
async fn a_duplicate_id_is_a_conflict() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;

    let again = repo.create(new_key("a", "other", now)).await;

    assert!(matches!(again, Err(RepositoryError::Conflict(_))));
    Ok(())
}

#[tokio::test]
async fn revoking_and_limiting_the_expiry_keep_the_row_readable() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;

    assert!(repo.mark_revoked("a", now).await?);
    // A second revocation is not an error and does not move the first instant.
    assert!(repo.mark_revoked("a", now + Duration::hours(1)).await?);
    assert!(repo.limit_expiry("a", now + Duration::days(1)).await?);

    let row = repo.find_by_id("a").await?;
    assert_eq!(row.as_ref().and_then(|k| k.revoked_at), Some(now));
    assert_eq!(
        row.and_then(|k| k.expires_at),
        Some(now + Duration::days(1))
    );
    assert!(!repo.mark_revoked("nope", now).await?);
    assert!(!repo.limit_expiry("nope", now).await?);
    Ok(())
}

#[tokio::test]
async fn last_used_never_moves_backwards() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;
    let late = now + Duration::minutes(5);

    repo.touch_last_used(&[("a".to_owned(), late)]).await?;
    repo.touch_last_used(&[("a".to_owned(), now), ("unknown".to_owned(), now)])
        .await?;

    assert_eq!(repo.row("a").and_then(|k| k.last_used_at), Some(late));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_last_allowed_call_is_spent_by_exactly_one_caller() {
    // A budget of one, spent by many callers at once: refusing a spent budget and counting a
    // positive one down are a single step, so no two callers can both take the last call.
    for _ in 0..300 {
        let repo = std::sync::Arc::new(InMemoryApiKeyRepository::new());
        repo.fail_after(1);
        let calls: Vec<_> = (0..16)
            .map(|_| {
                let repo = repo.clone();
                tokio::spawn(async move { repo.list_by_label("billing").await.is_ok() })
            })
            .collect();
        let mut admitted = 0;
        for call in calls {
            admitted += usize::from(call.await.unwrap_or(false));
        }
        assert_eq!(admitted, 1);
    }
}

#[tokio::test]
async fn last_used_advances_to_a_later_instant() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;
    let late = now + Duration::minutes(5);

    repo.touch_last_used(&[("a".to_owned(), now)]).await?;
    repo.touch_last_used(&[("a".to_owned(), late)]).await?;

    assert_eq!(repo.row("a").and_then(|k| k.last_used_at), Some(late));
    Ok(())
}

#[tokio::test]
async fn listing_by_label_returns_every_key_oldest_first() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("b", "billing", now + Duration::seconds(1)))
        .await?;
    repo.create(new_key("a", "billing", now)).await?;
    repo.create(new_key("c", "other", now)).await?;
    repo.mark_revoked("a", now).await?;

    let listed = repo.list_by_label("billing").await?;

    let ids: Vec<&str> = listed.iter().map(|k| k.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
    Ok(())
}

#[tokio::test]
async fn keys_issued_at_the_same_instant_list_in_id_order() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    // Sixteen ties, so a listing that fell back on the map's own order would come out sorted
    // only by a chance of one in 16!.
    let ids: Vec<String> = (0..16)
        .map(|n| format!("key-{:02}", (n * 7) % 16))
        .collect();
    for id in &ids {
        repo.create(new_key(id, "billing", now)).await?;
    }

    let listed: Vec<String> = repo
        .list_by_label("billing")
        .await?
        .into_iter()
        .map(|key| key.id)
        .collect();

    let mut expected = ids;
    expected.sort();
    assert_eq!(listed, expected);
    Ok(())
}

#[tokio::test]
async fn a_summary_carries_everything_but_the_digest() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    let stored = repo.create(new_key("a", "billing", now)).await?;

    let summary = ApiKeySummary::from(stored.clone());

    assert_eq!(summary.id, stored.id);
    assert_eq!(summary.label, stored.label);
    assert_eq!(summary.scopes, stored.scopes);
    assert_eq!(summary.created_at, stored.created_at);
    assert_eq!(summary.expires_at, stored.expires_at);
    assert_eq!(summary.revoked_at, stored.revoked_at);
    assert_eq!(summary.last_used_at, stored.last_used_at);
    Ok(())
}

#[tokio::test]
async fn a_failing_repository_answers_every_call_with_a_backend_error() {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.set_failing(true);

    assert!(matches!(
        repo.find_by_id("a").await,
        Err(RepositoryError::Backend(_))
    ));
    assert!(repo.create(new_key("a", "x", now)).await.is_err());
    assert!(repo.mark_revoked("a", now).await.is_err());
    assert!(repo.limit_expiry("a", now).await.is_err());
    assert!(repo.touch_last_used(&[]).await.is_err());
    assert!(repo.list_by_label("x").await.is_err());

    repo.set_failing(false);
    assert!(repo.find_by_id("a").await.is_ok());
}

#[tokio::test]
async fn limiting_the_expiry_only_ever_moves_it_earlier() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;

    // The shorter limit lands first, then a stale caller with a longer one: the shorter stays.
    repo.limit_expiry("a", now + Duration::seconds(60)).await?;
    repo.limit_expiry("a", now + Duration::seconds(3600))
        .await?;
    assert_eq!(
        repo.row("a").and_then(|k| k.expires_at),
        Some(now + Duration::seconds(60))
    );

    // And an earlier one still wins.
    repo.limit_expiry("a", now + Duration::seconds(5)).await?;
    assert_eq!(
        repo.row("a").and_then(|k| k.expires_at),
        Some(now + Duration::seconds(5))
    );
    Ok(())
}
