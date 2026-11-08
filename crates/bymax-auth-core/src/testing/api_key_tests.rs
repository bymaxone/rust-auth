//! The in-memory API-key repository behaves as the port documents: it returns revoked and
//! expired rows, keeps `last_used_at` monotonic, and fails like an outage when told to.

use time::{Duration, OffsetDateTime};

use super::InMemoryApiKeyRepository;
use crate::RepositoryError;
use crate::traits::{ApiKeyRepository, NewApiKey};

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
async fn revoking_and_expiring_keep_the_row_readable() -> Result<(), RepositoryError> {
    let repo = InMemoryApiKeyRepository::new();
    let now = OffsetDateTime::now_utc();
    repo.create(new_key("a", "billing", now)).await?;

    assert!(repo.mark_revoked("a", now).await?);
    // A second revocation is not an error and does not move the first instant.
    assert!(repo.mark_revoked("a", now + Duration::hours(1)).await?);
    assert!(repo.set_expiry("a", now + Duration::days(1)).await?);

    let row = repo.find_by_id("a").await?;
    assert_eq!(row.as_ref().and_then(|k| k.revoked_at), Some(now));
    assert_eq!(
        row.and_then(|k| k.expires_at),
        Some(now + Duration::days(1))
    );
    assert!(!repo.mark_revoked("nope", now).await?);
    assert!(!repo.set_expiry("nope", now).await?);
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
    assert!(repo.set_expiry("a", now).await.is_err());
    assert!(repo.touch_last_used(&[]).await.is_err());
    assert!(repo.list_by_label("x").await.is_err());

    repo.set_failing(false);
    assert!(repo.find_by_id("a").await.is_ok());
}
