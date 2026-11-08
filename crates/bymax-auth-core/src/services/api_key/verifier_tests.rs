//! Every outcome of verifying a presented key takes the same steps (one repository read) and
//! names its reason; a valid key is valid strictly before its expiry; only an accepted key is
//! remembered as used.

use time::Duration;

use super::test_support::{TestResult, bad_credentials, fixture};
use super::{ApiKeyRejection, ApiKeyVerdict, IssueApiKeyInput};
use crate::config::ApiKeyAuditMode;

fn id_of(key: &str) -> String {
    key.split('_').nth(1).unwrap_or_default().to_owned()
}

fn rejection(verdict: ApiKeyVerdict) -> Option<(ApiKeyRejection, Option<String>)> {
    match verdict {
        ApiKeyVerdict::Rejected { reason, key } => Some((reason, key.map(|k| k.id))),
        ApiKeyVerdict::Accepted(_) => None,
    }
}

async fn verify(
    f: &super::test_support::Fixture,
    header: Option<&str>,
) -> Result<ApiKeyVerdict, Box<dyn std::error::Error>> {
    Ok(f.engine.enabled_api_keys()?.verify(header).await?)
}

#[tokio::test]
async fn a_valid_key_is_accepted() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["reports:read"]).await?;

    let verdict = verify(&f, Some(&issued.key)).await?;

    assert!(matches!(verdict, ApiKeyVerdict::Accepted(row) if row.id == issued.record.id));
    assert_eq!(f.repo.reads(), 1);
    Ok(())
}

#[tokio::test]
async fn every_refusal_reads_exactly_one_row_and_names_its_reason() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let cases = bad_credentials(&f).await?;

    for case in cases {
        let before = f.repo.reads();
        let verdict = verify(&f, case.header.as_deref()).await?;
        assert_eq!(
            rejection(verdict),
            Some((case.rejection, case.identified)),
            "{:?}",
            case.header
        );
        assert_eq!(
            f.repo.reads(),
            before + 1,
            "{:?} must read one row",
            case.rejection
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_key_is_valid_strictly_before_its_expiry() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let mut input = IssueApiKeyInput::new("billing", vec!["admin".to_owned()]);
    input.expires_at = Some(f.clock_now() + Duration::minutes(10));
    let issued = f.engine.issue_api_key(input).await?;

    f.clock
        .advance(Duration::minutes(10) - Duration::nanoseconds(1));
    assert!(matches!(
        verify(&f, Some(&issued.key)).await?,
        ApiKeyVerdict::Accepted(_)
    ));
    f.clock.advance(Duration::nanoseconds(1));
    assert!(matches!(
        rejection(verify(&f, Some(&issued.key)).await?),
        Some((ApiKeyRejection::Expired, _))
    ));
    Ok(())
}

#[tokio::test]
async fn a_key_with_another_prefix_is_malformed() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    let other = issued.key.replacen("bak_", "svc_", 1);

    assert!(matches!(
        rejection(verify(&f, Some(&other)).await?),
        Some((ApiKeyRejection::Malformed, None))
    ));
    assert_eq!(id_of(&issued.key), issued.record.id);
    Ok(())
}

#[tokio::test]
async fn a_store_failure_is_an_error_not_a_verdict() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    f.repo.set_failing(true);

    assert!(verify(&f, Some(&issued.key)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn the_repository_never_holds_the_secret() -> TestResult {
    let f = fixture(ApiKeyAuditMode::BestEffort)?;
    let issued = f.issue(&["admin"]).await?;
    // The secret may itself contain '_', so split on the first two separators only.
    let secret = issued
        .key
        .splitn(3, '_')
        .nth(2)
        .unwrap_or_default()
        .to_owned();

    let row = f.repo.row(&issued.record.id);

    assert!(row.is_some_and(|r| r.digest != secret && r.digest.len() == 64));
    Ok(())
}
