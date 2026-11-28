//! Releasing the per-account MFA transition lock never changes what a transition answers
//! (layer: service, tests).
//!
//! Once the record has been written the transition happened, and a store that cannot answer the
//! release must not turn that into an error. The lock expires on its own, which is the whole cost.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bymax_auth_types::{AuthError, MfaContext};

use super::MfaService;
use super::tests::{TENANT, seed_user, service_over};
use crate::testing::InMemoryUserRepository;
use crate::traits::MfaStore;

/// An MFA store whose lock behaves like the real one while it can answer: a held lock refuses a
/// second taker, and a release that fails leaves the lock held. Every other method is inert.
#[derive(Default)]
struct LockStore {
    /// Whether the release answers with a store failure.
    release_fails: bool,
    /// The token of the lock currently held, if any.
    held: Mutex<Option<String>>,
    /// Every `(lock id, token)` a release was asked for.
    releases: Mutex<Vec<(String, String)>>,
    /// Every `(lock id, token)` a lock was taken with.
    takes: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl MfaStore for LockStore {
    async fn acquire_mfa_lock(&self, id: &str, token: &str, _ttl: u64) -> Result<bool, AuthError> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.is_some() {
            return Ok(false);
        }
        *held = Some(token.to_owned());
        self.takes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((id.to_owned(), token.to_owned()));
        Ok(true)
    }
    async fn release_mfa_lock(&self, id: &str, token: &str) -> Result<(), AuthError> {
        self.releases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((id.to_owned(), token.to_owned()));
        if self.release_fails {
            return Err(AuthError::ServiceUnavailable("connection lost".into()));
        }
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(())
    }
    async fn claim_recovery_code(&self, _id: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn put_setup_nx(&self, _k: &str, _v: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn get_setup(&self, _k: &str) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    async fn take_setup(&self, _k: &str) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    async fn put_temp(&self, _j: &str, _u: &str, _ttl: u64) -> Result<(), AuthError> {
        Ok(())
    }
    async fn get_temp(&self, _j: &str) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    async fn del_temp(&self, _j: &str) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn mark_totp_used(&self, _r: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
    async fn challenge_consume(&self, _r: &str, _j: &str, _ttl: u64) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// A service over `store` and the id of a seeded dashboard user.
async fn rig(store: Arc<LockStore>) -> Option<(MfaService, String)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let uid = seed_user(&users, "lock@example.com").await?;
    Some((service_over(store, users), uid))
}

/// What a transition writes: MFA on or off, the stored secret and the recovery codes, or `None`
/// to abandon.
type Change = Option<(bool, Option<String>, Option<Vec<String>>)>;

/// The change a transition writes: MFA on, with a stored secret and one recovery code.
fn write(_view: &super::MfaUserView) -> Change {
    Some((
        true,
        Some("secret".to_owned()),
        Some(vec!["code".to_owned()]),
    ))
}

async fn transition(
    service: &MfaService,
    uid: &str,
    mutate: fn(&super::MfaUserView) -> Change,
) -> Result<bool, AuthError> {
    service
        .transition_mfa_record(uid, MfaContext::Dashboard, Some(TENANT), mutate)
        .await
}

#[tokio::test]
async fn a_transition_that_wrote_answers_true_when_the_release_fails() {
    let store = Arc::new(LockStore {
        release_fails: true,
        ..LockStore::default()
    });
    let Some((service, uid)) = rig(store.clone()).await else { return };
    let answered = transition(&service, &uid, write).await;
    assert!(matches!(answered, Ok(true)), "got {answered:?}");
    let stored = service
        .fetch_user_mfa(&uid, MfaContext::Dashboard, Some(TENANT))
        .await;
    assert!(
        matches!(stored, Ok(ref view) if view.mfa_enabled),
        "the write must have landed"
    );
}

#[tokio::test]
async fn an_abandoned_transition_answers_false_when_the_release_fails() {
    let store = Arc::new(LockStore {
        release_fails: true,
        ..LockStore::default()
    });
    let Some((service, uid)) = rig(store).await else { return };
    let answered = transition(&service, &uid, |_| None).await;
    assert!(matches!(answered, Ok(false)), "got {answered:?}");
}

#[tokio::test]
async fn the_transitions_own_error_is_not_replaced_by_a_failed_release() {
    let store = Arc::new(LockStore {
        release_fails: true,
        ..LockStore::default()
    });
    let Some((service, _)) = rig(store).await else { return };
    let answered = transition(&service, "no-such-user", write).await;
    assert!(
        matches!(answered, Err(AuthError::MfaNotEnabled)),
        "got {answered:?}"
    );
}

#[tokio::test]
async fn a_lock_whose_release_failed_still_refuses_a_second_transition() {
    // The cost of swallowing the failure, bounded by the lock's TTL: the lock is still held, so
    // two transitions cannot run at once.
    let store = Arc::new(LockStore {
        release_fails: true,
        ..LockStore::default()
    });
    let Some((service, uid)) = rig(store).await else { return };
    assert!(matches!(transition(&service, &uid, write).await, Ok(true)));
    let second = transition(&service, &uid, write).await;
    assert!(
        matches!(second, Err(AuthError::MfaStateConflict)),
        "got {second:?}"
    );
}

#[tokio::test]
async fn an_ordinary_release_uses_the_nonce_of_the_call_and_frees_the_lock() {
    let store = Arc::new(LockStore::default());
    let Some((service, uid)) = rig(store.clone()).await else { return };
    assert!(matches!(transition(&service, &uid, write).await, Ok(true)));
    let takes = store
        .takes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let releases = store
        .releases
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(takes.len(), 1);
    assert_eq!(takes, releases, "the lock released is the lock taken");
    assert!(
        matches!(transition(&service, &uid, write).await, Ok(true)),
        "the lock was freed"
    );
}
