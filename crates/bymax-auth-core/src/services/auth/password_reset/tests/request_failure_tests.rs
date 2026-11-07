//! What a reset request does when a step fails: a failure before the account is known answers
//! `500` after the floor, a failure after it is logged and the `200` stands, and the resend
//! cooldown the request took is released on any failure. Driven through both entry points,
//! which share the cooldown key.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

use super::*;
use crate::services::auth::DETACHED_TASK_TIMEOUT;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::{EmailError, EmailProvider, InviteData, SessionInfo, UserRepository};

const FLOOR: Duration = Duration::from_millis(300);
const REGISTERED: &str = "registered@example.com";

/// The entry point a case drives; both take and release one cooldown.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Initiate,
    Resend,
}

const ENTRIES: [Entry; 2] = [Entry::Initiate, Entry::Resend];

/// An email provider whose reset sends fail, or never return when `hang` is set, or wait for a
/// permit from `gate` before failing, to drive the delivery-failure branches. `failed` counts the
/// code sends that have failed, so a test knows a late failure has landed.
struct DownMailer {
    hang: bool,
    gate: Option<Arc<Semaphore>>,
    failed: Arc<AtomicUsize>,
}

impl DownMailer {
    fn failing() -> Self {
        Self {
            hang: false,
            gate: None,
            failed: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn hanging() -> Self {
        Self {
            hang: true,
            ..Self::failing()
        }
    }

    /// Every code send waits for a permit of `gate`, then fails.
    fn gated(gate: Arc<Semaphore>) -> Self {
        Self {
            gate: Some(gate),
            ..Self::failing()
        }
    }
}

#[async_trait::async_trait]
impl EmailProvider for DownMailer {
    async fn send_password_reset_token(
        &self,
        _tenant_id: &str,
        _email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        Err(EmailError::Delivery("down".into()))
    }

    async fn send_password_reset_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        if let Some(gate) = &self.gate
            && let Ok(permit) = gate.acquire().await
        {
            permit.forget();
        }
        self.failed.fetch_add(1, Ordering::SeqCst);
        Err(EmailError::Delivery("down".into()))
    }

    async fn send_email_verification_otp(
        &self,
        _tenant_id: &str,
        _email: &str,
        _otp: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_email_change_verification(
        &self,
        _tenant_id: &str,
        _new_email: &str,
        _token: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_enabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_mfa_disabled(
        &self,
        _tenant_id: &str,
        _email: &str,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_new_session_alert(
        &self,
        _tenant_id: &str,
        _email: &str,
        _session: &SessionInfo,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }

    async fn send_invitation(
        &self,
        _tenant_id: &str,
        _email: &str,
        _invite: &InviteData,
        _locale: Option<&str>,
    ) -> Result<(), EmailError> {
        Ok(())
    }
}

/// An engine, the in-memory stores behind it, and one registered account.
struct Rig {
    engine: AuthEngine,
    stores: Arc<InMemoryStores>,
}

/// Build a rig for `method`. `lookup_fails` swaps the account repository for one whose lookup
/// always fails; `mail` is the provider every send goes through.
async fn rig(method: ResetMethod, mail: Arc<dyn EmailProvider>, lookup_fails: bool) -> Option<Rig> {
    let mut cfg = base_config();
    cfg.password_reset.method = method;
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let repo: Arc<dyn UserRepository> = if lookup_fails {
        Arc::new(FailingLookupRepo)
    } else {
        users.clone()
    };
    let engine = AuthEngine::builder()
        .config(cfg)
        .environment(crate::config::Environment::Test)
        .user_repository(repo)
        .redis_stores(stores.clone())
        .email_provider(mail)
        .build()
        .ok()?;
    let seeded = users
        .create(bymax_auth_types::CreateUserData {
            email: REGISTERED.to_owned(),
            name: "R".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    seeded.ok()?;
    Some(Rig { engine, stores })
}

/// Drive one entry point for `email` and return the outcome and how long it took.
async fn request(rig: &Rig, entry: Entry, email: &str) -> (Result<(), AuthError>, Duration) {
    let started = Instant::now();
    let outcome = match entry {
        Entry::Initiate => rig.engine.initiate_reset(forgot(email), &ctx()).await,
        Entry::Resend => {
            let input = ResendResetOtpInput {
                email: email.to_owned(),
                tenant_id: Some("t1".to_owned()),
            };
            rig.engine.resend_reset_otp(input, &ctx()).await
        }
    };
    (outcome, started.elapsed())
}

/// Whether the cooldown for `email` is still held, without releasing it.
fn cooldown_held(rig: &Rig, email: &str) -> bool {
    let identifier = rig.engine.hashed_identifier("t1", email);
    rig.stores
        .resend_cooldown_held(OtpPurpose::PasswordReset, &identifier)
}

/// Wait, bounded, until `count` code sends have failed.
async fn landed(failed: &AtomicUsize, count: usize) -> bool {
    for _ in 0..100 {
        if failed.load(Ordering::SeqCst) >= count {
            // Give the detached task the moment it needs to finish what follows the failure.
            tokio::time::sleep(Duration::from_millis(100)).await;
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn a_failing_cooldown_gate_answers_500_after_the_floor() {
    for entry in ENTRIES {
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(DownMailer::failing()), false).await else {
            return;
        };
        rig.stores.fail_next_resend_gates(1);

        let (outcome, took) = request(&rig, entry, REGISTERED).await;

        assert!(
            matches!(outcome, Err(AuthError::Internal(_))),
            "{entry:?}: {outcome:?}"
        );
        assert!(took >= FLOOR, "{entry:?}: {took:?}");
        assert!(
            !cooldown_held(&rig, REGISTERED),
            "{entry:?}: nothing was taken"
        );
    }
}

#[tokio::test]
async fn a_failing_account_lookup_answers_500_after_the_floor_and_releases_the_cooldown() {
    for entry in ENTRIES {
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(DownMailer::failing()), true).await else {
            return;
        };

        let (outcome, took) = request(&rig, entry, REGISTERED).await;

        assert!(
            matches!(outcome, Err(AuthError::Internal(_))),
            "{entry:?}: {outcome:?}"
        );
        assert!(took >= FLOOR, "{entry:?}: {took:?}");
        assert!(
            !cooldown_held(&rig, REGISTERED),
            "{entry:?}: the retry must not be refused"
        );
    }
}

#[tokio::test]
async fn a_code_that_could_not_be_stored_keeps_the_200_logs_it_and_releases_the_cooldown() {
    for entry in ENTRIES {
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(DownMailer::failing()), false).await else {
            return;
        };
        rig.stores.fail_next_otp_puts(1);

        let (events, guard) = crate::log_capture::capture_events();
        let (outcome, took) = request(&rig, entry, REGISTERED).await;
        drop(guard);

        assert!(outcome.is_ok(), "{entry:?}: {outcome:?}");
        assert!(took >= FLOOR, "{entry:?}: {took:?}");
        let reported = events
            .iter()
            .into_iter()
            .filter(|event| event.rendered.contains("the proof could not be issued"))
            .count();
        assert_eq!(reported, 1, "{entry:?}: one line for one failure");
        assert!(
            !events.contains(REGISTERED),
            "{entry:?}: the address was logged"
        );
        assert!(
            !cooldown_held(&rig, REGISTERED),
            "{entry:?}: the retry must not be refused"
        );
    }
}

#[tokio::test]
async fn a_code_that_could_not_be_sent_keeps_the_200_and_the_cooldown() {
    for entry in ENTRIES {
        let mailer = DownMailer::failing();
        let failed = mailer.failed.clone();
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(mailer), false).await else { return };

        let (outcome, took) = request(&rig, entry, REGISTERED).await;

        assert!(outcome.is_ok(), "{entry:?}: {outcome:?}");
        assert!(took >= FLOOR, "{entry:?}: {took:?}");
        // The send runs detached and fails after the response; a failure the request did not
        // observe never touches the cooldown.
        assert!(landed(&failed, 1).await, "{entry:?}: the send never failed");
        assert!(
            cooldown_held(&rig, REGISTERED),
            "{entry:?}: a late failure released it"
        );
    }
}

#[tokio::test]
async fn a_late_send_failure_never_deletes_the_cooldown_of_a_later_request() {
    for entry in ENTRIES {
        let gate = Arc::new(Semaphore::new(0));
        let mailer = DownMailer::gated(gate.clone());
        let failed = mailer.failed.clone();
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(mailer), false).await else { return };

        // Request A takes the cooldown and its send waits; the window then ends and request B
        // takes a fresh cooldown; only then do both sends fail.
        let (first, _) = request(&rig, entry, REGISTERED).await;
        assert!(first.is_ok(), "{entry:?}: {first:?}");
        let identifier = rig.engine.hashed_identifier("t1", REGISTERED);
        assert!(
            rig.stores
                .expire_resend_cooldown(OtpPurpose::PasswordReset, &identifier)
        );
        let (second, _) = request(&rig, entry, REGISTERED).await;
        assert!(second.is_ok(), "{entry:?}: {second:?}");
        assert!(
            cooldown_held(&rig, REGISTERED),
            "{entry:?}: B holds the cooldown"
        );

        gate.add_permits(2);
        assert!(
            landed(&failed, 2).await,
            "{entry:?}: both sends should have failed"
        );
        assert!(
            cooldown_held(&rig, REGISTERED),
            "{entry:?}: A's late failure deleted B's"
        );
    }
}

#[tokio::test]
async fn a_reset_link_that_could_not_be_sent_keeps_the_200_and_releases_the_cooldown() {
    let Some(rig) = rig(ResetMethod::Token, Arc::new(DownMailer::failing()), false).await else {
        return;
    };

    let (outcome, took) = request(&rig, Entry::Initiate, REGISTERED).await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(took >= FLOOR, "{took:?}");
    assert!(
        !cooldown_held(&rig, REGISTERED),
        "the retry must not be refused"
    );
}

#[tokio::test]
async fn a_request_that_fails_nothing_keeps_its_cooldown_and_a_hit_waits_the_floor() {
    for entry in ENTRIES {
        let healthy = Arc::new(crate::services::auth::test_support::CapturingEmails::default());
        let Some(rig) = rig(ResetMethod::Otp, healthy, false).await else { return };

        let (first, _) = request(&rig, entry, REGISTERED).await;
        let (absent, _) = request(&rig, entry, "absent@example.com").await;
        let (hit, took) = request(&rig, entry, REGISTERED).await;

        assert!(first.is_ok() && absent.is_ok() && hit.is_ok(), "{entry:?}");
        assert!(
            cooldown_held(&rig, REGISTERED),
            "{entry:?}: a delivered code leaves it in place"
        );
        assert!(
            cooldown_held(&rig, "absent@example.com"),
            "{entry:?}: so does an unknown address"
        );
        assert!(
            took >= FLOOR,
            "{entry:?}: a cooldown hit waits the floor too: {took:?}"
        );
    }
}

#[tokio::test]
async fn a_cooldown_that_cannot_be_released_is_logged_and_the_original_error_stands() {
    for entry in ENTRIES {
        let Some(rig) = rig(ResetMethod::Otp, Arc::new(DownMailer::failing()), true).await else {
            return;
        };
        rig.stores.fail_next_resend_releases(1);

        let (events, guard) = crate::log_capture::capture_events();
        let (outcome, _) = request(&rig, entry, REGISTERED).await;
        drop(guard);

        assert!(
            matches!(outcome, Err(AuthError::Internal(_))),
            "{entry:?}: {outcome:?}"
        );
        let reported = events
            .iter()
            .into_iter()
            .filter(|event| {
                event
                    .rendered
                    .contains("the resend cooldown could not be released")
            })
            .count();
        assert_eq!(reported, 1, "{entry:?}");
        assert!(
            cooldown_held(&rig, REGISTERED),
            "{entry:?}: it runs out by itself"
        );
    }
}

#[tokio::test]
async fn a_send_that_never_returns_leaves_the_cooldown_when_the_ceiling_abandons_it() {
    let Some(rig) = rig(ResetMethod::Otp, Arc::new(DownMailer::hanging()), false).await else {
        return;
    };

    let (outcome, took) = request(&rig, Entry::Initiate, REGISTERED).await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(took >= FLOOR, "{took:?}");
    assert!(cooldown_held(&rig, REGISTERED), "the send is still running");
    // The detached-task ceiling abandons the send after DETACHED_TASK_TIMEOUT; the request has
    // long returned, so the cooldown is not its to release.
    tokio::time::sleep(DETACHED_TASK_TIMEOUT + Duration::from_millis(700)).await;
    assert!(cooldown_held(&rig, REGISTERED), "the ceiling released it");
}

#[tokio::test]
async fn a_reset_link_send_that_never_returns_is_bounded_and_releases_the_cooldown() {
    let Some(rig) = rig(ResetMethod::Token, Arc::new(DownMailer::hanging()), false).await else {
        return;
    };

    let (outcome, took) = request(&rig, Entry::Initiate, REGISTERED).await;

    // The link is sent inside the request, so the ceiling bounds how long the response waits:
    // the release has to land well inside the cooldown window or it could delete a later
    // request's cooldown.
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(took >= FLOOR && took < Duration::from_secs(30), "{took:?}");
    assert!(
        !cooldown_held(&rig, REGISTERED),
        "released before the response"
    );
}
