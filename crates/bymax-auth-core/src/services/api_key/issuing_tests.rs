//! Issuing, revoking and rotating keys: what is validated, what is stored, and what the plaintext
//! key is allowed to reveal.

use bymax_auth_crypto::api_key;
use bymax_auth_types::AuthError;
use time::Duration;

use super::test_support::{PEPPER, TestResult, fixture};
use super::{ApiKeyVerdict, IssueApiKeyInput, RotateApiKeyInput};
use crate::config::{ApiKeyAuditMode, Environment};
use crate::engine::AuthEngine;
use crate::services::auth::test_support::base_config;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::{ApiKeyRepository, NewApiKey};

fn is_validation_of(error: &AuthError, field: &str) -> bool {
    matches!(error, AuthError::Validation { details } if details.iter().any(|d| d.field == field))
}

fn input(label: &str, scopes: &[&str]) -> IssueApiKeyInput {
    IssueApiKeyInput::new(label, scopes.iter().map(|s| (*s).to_owned()).collect())
}

#[tokio::test]
async fn a_minted_key_parses_and_the_store_holds_only_its_digest() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f
        .engine
        .issue_api_key(input("billing", &["reports:read"]))
        .await?;

    let parsed = api_key::parse(&issued.key, "bak");
    let stored = f.repo.row(&issued.record.id);

    assert!(
        parsed
            .as_ref()
            .is_some_and(|p| p.key_id == issued.record.id)
    );
    let digest = parsed.as_ref().map(|p| api_key::digest(p.secret, PEPPER));
    assert_eq!(stored.map(|row| row.digest), digest);
    assert_eq!(issued.record.label, "billing");
    assert_eq!(issued.record.scopes, vec!["reports:read".to_owned()]);
    assert_eq!(issued.record.created_at, f.clock_now());
    assert!(issued.record.revoked_at.is_none() && issued.record.last_used_at.is_none());
    Ok(())
}

#[tokio::test]
async fn the_plaintext_key_never_appears_in_debug_output() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;

    let rendered = format!("{issued:?}");

    assert!(!rendered.contains(&issued.key));
    assert!(rendered.contains("<redacted>"));
    Ok(())
}

#[tokio::test]
async fn a_label_is_one_to_128_visible_characters() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    for bad in [
        String::new(),
        "   ".to_owned(),
        "x".repeat(129),
        "line\nbreak".to_owned(),
        "zero\u{200B}width".to_owned(),
        "sep\u{2028}arator".to_owned(),
        "bom\u{FEFF}".to_owned(),
    ] {
        let error = f.engine.issue_api_key(input(&bad, &["admin"])).await.err();
        assert!(
            error.as_ref().is_some_and(|e| is_validation_of(e, "label")),
            "{bad:?}"
        );
    }
    for good in ["x".repeat(128), "Ünï côde ✓".to_owned(), "a b".to_owned()] {
        assert!(
            f.engine
                .issue_api_key(input(&good, &["admin"]))
                .await
                .is_ok(),
            "{good:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn scopes_are_non_empty_from_the_vocabulary_and_distinct() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    for bad in [
        vec![],
        vec!["outside"],
        vec!["admin", "outside"],
        vec!["admin", "admin"],
    ] {
        let error = f.engine.issue_api_key(input("billing", &bad)).await.err();
        assert!(
            error
                .as_ref()
                .is_some_and(|e| is_validation_of(e, "scopes")),
            "{bad:?}"
        );
    }
    assert!(
        f.engine
            .issue_api_key(input("billing", &["admin", "reports:read"]))
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn an_expiry_must_lie_in_the_future() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    for at in [f.clock_now() - Duration::hours(1), f.clock_now()] {
        let mut bad = input("billing", &["admin"]);
        bad.expires_at = Some(at);
        let error = f.engine.issue_api_key(bad).await.err();
        assert!(
            error
                .as_ref()
                .is_some_and(|e| is_validation_of(e, "expiresAt"))
        );
    }
    let mut good = input("billing", &["admin"]);
    good.expires_at = Some(f.clock_now() + Duration::seconds(1));
    let issued = f.engine.issue_api_key(good).await?;
    assert_eq!(
        issued.record.expires_at,
        Some(f.clock_now() + Duration::seconds(1))
    );
    Ok(())
}

#[tokio::test]
async fn revoking_stops_the_key_and_an_unknown_id_is_not_found() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;

    f.engine.revoke_api_key(&issued.record.id).await?;

    let row = f.repo.row(&issued.record.id);
    assert_eq!(row.and_then(|r| r.revoked_at), Some(f.clock_now()));
    for id in [
        "00000000-0000-4000-8000-0000000000aa",
        "not-a-uuid",
        "",
        "ABCDEF00-0000-4000-8000-0000000000AA",
    ] {
        let error = f.engine.revoke_api_key(id).await.err();
        assert!(matches!(error, Some(AuthError::ApiKeyNotFound)), "{id:?}");
    }
    Ok(())
}

#[tokio::test]
async fn rotating_with_no_overlap_retires_the_old_key_at_once() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let old = f.issue(&["reports:read", "admin"]).await?;

    let new = f
        .engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(0))
        .await?;

    assert_ne!(new.record.id, old.record.id);
    assert_eq!(new.record.label, "billing");
    assert_eq!(new.record.scopes, old.record.scopes);
    let runtime = f.engine.enabled_api_keys()?;
    assert!(matches!(
        runtime.verify(Some(&new.key)).await?,
        ApiKeyVerdict::Accepted(_)
    ));
    assert!(matches!(
        runtime.verify(Some(&old.key)).await?,
        ApiKeyVerdict::Rejected { .. }
    ));
    assert_eq!(
        f.repo.row(&old.record.id).and_then(|r| r.revoked_at),
        Some(f.clock_now())
    );
    Ok(())
}

#[tokio::test]
async fn rotating_with_an_overlap_keeps_both_until_the_old_one_lapses() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let old = f.issue(&["admin"]).await?;

    let new = f
        .engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(3600))
        .await?;

    let retire = f.clock_now() + Duration::seconds(3600);
    assert_eq!(
        f.repo.row(&old.record.id).and_then(|r| r.expires_at),
        Some(retire)
    );
    let runtime = f.engine.enabled_api_keys()?;
    assert!(matches!(
        runtime.verify(Some(&old.key)).await?,
        ApiKeyVerdict::Accepted(_)
    ));
    f.clock.advance(Duration::seconds(3600));
    assert!(matches!(
        runtime.verify(Some(&old.key)).await?,
        ApiKeyVerdict::Rejected { .. }
    ));
    assert!(matches!(
        runtime.verify(Some(&new.key)).await?,
        ApiKeyVerdict::Accepted(_)
    ));
    Ok(())
}

#[tokio::test]
async fn an_overlap_never_extends_an_earlier_expiry_of_the_old_key() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let mut soon = input("billing", &["admin"]);
    soon.expires_at = Some(f.clock_now() + Duration::seconds(60));
    let old = f.engine.issue_api_key(soon).await?;

    f.engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(3600))
        .await?;

    assert_eq!(
        f.repo.row(&old.record.id).and_then(|r| r.expires_at),
        Some(f.clock_now() + Duration::seconds(60))
    );
    Ok(())
}

#[tokio::test]
async fn rotation_validates_the_overlap_the_new_expiry_and_the_old_key() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let old = f.issue(&["admin"]).await?;

    let too_long = RotateApiKeyInput::new(2_592_001);
    let error = f
        .engine
        .rotate_api_key(&old.record.id, too_long)
        .await
        .err();
    assert!(
        error
            .as_ref()
            .is_some_and(|e| is_validation_of(e, "overlapSeconds"))
    );
    assert!(
        f.engine
            .rotate_api_key(&old.record.id, RotateApiKeyInput::new(2_592_000))
            .await
            .is_ok()
    );

    let mut past = RotateApiKeyInput::new(0);
    past.expires_at = Some(f.clock_now());
    let error = f.engine.rotate_api_key(&old.record.id, past).await.err();
    assert!(
        error
            .as_ref()
            .is_some_and(|e| is_validation_of(e, "expiresAt"))
    );

    for id in ["00000000-0000-4000-8000-0000000000aa", "not-a-uuid"] {
        let error = f
            .engine
            .rotate_api_key(id, RotateApiKeyInput::new(0))
            .await
            .err();
        assert!(matches!(error, Some(AuthError::ApiKeyNotFound)), "{id:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_revoked_or_lapsed_key_cannot_be_rotated() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let revoked = f.issue(&["admin"]).await?;
    f.engine.revoke_api_key(&revoked.record.id).await?;
    let mut expiring = input("billing", &["admin"]);
    expiring.expires_at = Some(f.clock_now() + Duration::seconds(5));
    let lapsed = f.engine.issue_api_key(expiring).await?;
    f.clock.advance(Duration::seconds(5));

    for id in [&revoked.record.id, &lapsed.record.id] {
        let error = f
            .engine
            .rotate_api_key(id, RotateApiKeyInput::new(0))
            .await
            .err();
        assert!(matches!(error, Some(AuthError::ApiKeyNotFound)), "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn rotation_is_held_to_the_current_scope_vocabulary() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let stale = f
        .repo
        .create(NewApiKey {
            id: "11111111-1111-4111-8111-111111111111".to_owned(),
            label: "legacy".to_owned(),
            digest: "0".repeat(64),
            scopes: vec!["retired:scope".to_owned()],
            created_at: f.clock_now(),
            expires_at: None,
        })
        .await?;

    let error = f
        .engine
        .rotate_api_key(&stale.id, RotateApiKeyInput::new(0))
        .await
        .err();

    assert!(
        error
            .as_ref()
            .is_some_and(|e| is_validation_of(e, "scopes"))
    );
    // Nothing was retired: the failed rotation left the old key as it was.
    assert!(
        f.repo
            .row(&stale.id)
            .is_some_and(|r| r.revoked_at.is_none())
    );
    Ok(())
}

#[tokio::test]
async fn a_failing_store_is_an_internal_error_on_every_operation() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.repo.set_failing(true);

    assert!(matches!(
        f.engine
            .issue_api_key(input("billing", &["admin"]))
            .await
            .err(),
        Some(AuthError::Internal(_))
    ));
    assert!(matches!(
        f.engine.revoke_api_key(&issued.record.id).await.err(),
        Some(AuthError::Internal(_))
    ));
    assert!(matches!(
        f.engine
            .rotate_api_key(&issued.record.id, RotateApiKeyInput::new(0))
            .await
            .err(),
        Some(AuthError::Internal(_))
    ));
    Ok(())
}

#[tokio::test]
async fn an_id_that_is_not_a_key_id_never_reaches_the_store() -> TestResult {
    // With the store down, the only way revoke and rotate answer "not found" is by refusing the
    // id before the store is asked: a malformed id is the host repository's input otherwise.
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    f.repo.set_failing(true);

    for id in [
        "not-a-uuid",
        "",
        // Hex digits, but not 36 characters: the length alone must refuse it.
        "abc",
        // 36 characters, but uppercase and a stray letter: the shape alone must refuse it.
        "ABCDEF00-0000-4000-8000-0000000000AA",
        "0000000g-0000-4000-8000-0000000000aa",
    ] {
        let revoked = f.engine.revoke_api_key(id).await.err();
        assert!(matches!(revoked, Some(AuthError::ApiKeyNotFound)), "{id:?}");
        let rotated = f
            .engine
            .rotate_api_key(id, RotateApiKeyInput::new(0))
            .await
            .err();
        assert!(matches!(rotated, Some(AuthError::ApiKeyNotFound)), "{id:?}");
    }

    // The control: a well-formed id does reach the store, which is down.
    let well_formed = "00000000-0000-4000-8000-0000000000aa";
    assert!(matches!(
        f.engine.revoke_api_key(well_formed).await.err(),
        Some(AuthError::Internal(_))
    ));
    Ok(())
}

#[tokio::test]
async fn a_failure_while_retiring_the_old_key_is_reported() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let old = f.issue(&["admin"]).await?;
    f.repo.fail_after(2);

    let revoke_leg = f
        .engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(0))
        .await
        .err();
    f.repo.fail_after(2);
    let expiry_leg = f
        .engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(60))
        .await
        .err();

    assert!(matches!(revoke_leg, Some(AuthError::Internal(_))));
    assert!(matches!(expiry_leg, Some(AuthError::Internal(_))));
    Ok(())
}

#[tokio::test]
async fn every_entry_point_answers_internal_when_api_keys_are_off() -> TestResult {
    let engine = AuthEngine::builder()
        .config(base_config())
        .environment(Environment::Test)
        .user_repository(std::sync::Arc::new(InMemoryUserRepository::new()))
        .redis_stores(std::sync::Arc::new(InMemoryStores::new()))
        .build()?;

    assert!(matches!(
        engine
            .issue_api_key(input("billing", &["admin"]))
            .await
            .err(),
        Some(AuthError::Internal(_))
    ));
    assert!(matches!(
        engine
            .revoke_api_key("00000000-0000-4000-8000-0000000000aa")
            .await
            .err(),
        Some(AuthError::Internal(_))
    ));
    assert!(matches!(
        engine.flush_api_key_last_used().await.err(),
        Some(AuthError::Internal(_))
    ));
    Ok(())
}

#[tokio::test]
async fn a_longer_overlap_never_pushes_back_the_deadline_a_shorter_one_set() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let old = f.issue(&["admin"]).await?;

    f.engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(60))
        .await?;
    f.engine
        .rotate_api_key(&old.record.id, RotateApiKeyInput::new(3600))
        .await?;

    assert_eq!(
        f.repo.row(&old.record.id).and_then(|r| r.expires_at),
        Some(f.clock_now() + Duration::seconds(60))
    );
    Ok(())
}
