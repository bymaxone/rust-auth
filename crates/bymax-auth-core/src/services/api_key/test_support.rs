//! A fixture for the API-key tests: an engine with the feature on over the in-memory repository,
//! a clock the test moves by hand, and hooks that record every audit event.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};

use crate::config::{ApiKeyAuditMode, Environment};
use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::error::ConfigError;
use crate::services::api_key::{IssueApiKeyInput, IssuedApiKey};
use crate::services::auth::test_support::base_config;
use crate::testing::{
    InMemoryApiKeyRepository, InMemoryStores, InMemoryUserRepository, ManualApiKeyClock,
};
use crate::traits::{ApiKeyAccessEvent, AuthHooks, HookContext, HookError};
use bymax_auth_types::AuthError;

/// The pepper every fixture engine uses.
pub(super) const PEPPER: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The scope vocabulary every fixture engine uses.
pub(super) const SCOPES: [&str; 3] = ["reports:read", "reports:write", "admin"];

/// Records each `on_api_key_request` call and can be told to fail.
#[derive(Default)]
pub(super) struct RecordingHooks {
    calls: Mutex<Vec<(ApiKeyAccessEvent, HookContext)>>,
    failing: Mutex<bool>,
}

impl RecordingHooks {
    pub(super) fn set_failing(&self, failing: bool) {
        *self
            .failing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = failing;
    }

    pub(super) fn calls(&self) -> Vec<(ApiKeyAccessEvent, HookContext)> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Wait (by yielding) until `count` calls arrived: the best-effort hook runs detached.
    pub(super) async fn wait_for(&self, count: usize) -> Vec<(ApiKeyAccessEvent, HookContext)> {
        for _ in 0..200 {
            if self.calls().len() >= count {
                break;
            }
            tokio::task::yield_now().await;
        }
        self.calls()
    }
}

#[async_trait]
impl AuthHooks for RecordingHooks {
    async fn on_api_key_request(
        &self,
        event: &ApiKeyAccessEvent,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((event.clone(), ctx.clone()));
        if *self
            .failing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return Err(HookError::Internal("audit store down".into()));
        }
        Ok(())
    }
}

/// An engine with API keys enabled and the collaborators a test inspects.
pub(super) struct Fixture {
    pub(super) engine: AuthEngine,
    pub(super) repo: Arc<InMemoryApiKeyRepository>,
    pub(super) clock: Arc<ManualApiKeyClock>,
    pub(super) hooks: Arc<RecordingHooks>,
}

/// The instant every fixture clock starts at.
pub(super) fn start() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

/// What a test returns: any error fails it with its message.
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fixture with the given audit mode.
pub(super) fn fixture(mode: ApiKeyAuditMode) -> Result<Fixture, ConfigError> {
    let mut cfg = base_config();
    cfg.api_keys.enabled = true;
    cfg.api_keys.pepper = SecretString::from(PEPPER.to_owned());
    cfg.api_keys.scopes = SCOPES.iter().map(|s| (*s).to_owned()).collect();
    cfg.api_keys.audit_mode = mode;
    let repo = Arc::new(InMemoryApiKeyRepository::new());
    let clock = Arc::new(ManualApiKeyClock::new(start()));
    let hooks = Arc::new(RecordingHooks::default());
    let built = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()))
        .hooks(hooks.clone())
        .api_key_repository(repo.clone())
        .api_key_clock(clock.clone())
        .build()?;
    Ok(Fixture {
        engine: built,
        repo,
        clock,
        hooks,
    })
}

impl Fixture {
    /// The fixture clock's current instant.
    pub(super) fn clock_now(&self) -> OffsetDateTime {
        use crate::services::api_key::ApiKeyClock;
        self.clock.now()
    }

    /// Issue a key with the given scopes under the label `billing`.
    pub(super) async fn issue(&self, scopes: &[&str]) -> Result<IssuedApiKey, AuthError> {
        let scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        self.engine
            .issue_api_key(IssueApiKeyInput::new("billing", scopes))
            .await
    }
}

/// A request context with a fixed address and one extra sanitized header.
pub(super) fn request_context() -> RequestContext {
    RequestContext::new(
        "203.0.113.9",
        "machine/1.0",
        BTreeMap::from([
            (
                "x-api-key".to_owned(),
                "must-not-reach-the-audit".to_owned(),
            ),
            ("x-request-id".to_owned(), "req-1".to_owned()),
        ]),
    )
}

/// One credential a guarded route must refuse: what to present, why, and the key it identifies.
pub(super) struct BadCredential {
    pub(super) header: Option<String>,
    pub(super) rejection: super::ApiKeyRejection,
    pub(super) identified: Option<String>,
}

/// A key the verifier cannot accept, with a different one for each of the six reasons (two
/// spellings of "malformed"). The clock is advanced past the lapsing key's expiry, so call it
/// once per fixture.
pub(super) async fn bad_credentials(f: &Fixture) -> Result<Vec<BadCredential>, AuthError> {
    use super::ApiKeyRejection as Why;
    use bymax_auth_crypto::api_key;

    let live = f.issue(&["admin"]).await?;
    let revoked = f.issue(&["admin"]).await?;
    f.engine.revoke_api_key(&revoked.record.id).await?;
    let mut lapsing = IssueApiKeyInput::new("billing", vec!["admin".to_owned()]);
    lapsing.expires_at = Some(f.clock_now() + Duration::seconds(30));
    let lapsed = f.engine.issue_api_key(lapsing).await?;
    f.clock.advance(Duration::seconds(30));

    let case = |header: Option<String>, rejection, identified: Option<&str>| BadCredential {
        header,
        rejection,
        identified: identified.map(str::to_owned),
    };
    let forged = |id: &str| Some(api_key::format("bak", id, &api_key::generate_secret()));
    Ok(vec![
        case(None, Why::Missing, None),
        case(Some("junk".to_owned()), Why::Malformed, None),
        case(Some(String::new()), Why::Malformed, None),
        case(
            forged("00000000-0000-4000-8000-0000000000aa"),
            Why::Unknown,
            None,
        ),
        case(
            forged(&live.record.id),
            Why::WrongSecret,
            Some(&live.record.id),
        ),
        case(Some(revoked.key), Why::Revoked, Some(&revoked.record.id)),
        case(Some(lapsed.key), Why::Expired, Some(&lapsed.record.id)),
    ])
}
