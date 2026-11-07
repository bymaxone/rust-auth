//! Which session a password change spares when the caller's own session moves underneath it.
//!
//! The race is made deterministic by a breach checker that acts at the one point inside the
//! change that sits after the live-session check and before the password is written: the new
//! password is screened there. No timing is involved.

use std::sync::{Arc, Mutex};

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::{AuthError, CreateUserData, LoginResult};

use super::LoginInput;
use super::test_support::{CapturingEmails, base_config, ctx, hash_password};
use crate::engine::AuthEngine;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::{
    PasswordBreachChecker, SessionKind, SessionRotation, SessionStore, UserRepository,
};

/// What happens to the caller's session while the new password is screened.
enum Move {
    /// A refresh of the caller's own session: `old` rotates into `new`.
    Rotate { old: String, new: String },
    /// The caller's session is revoked.
    Revoke { hash: String },
}

/// A breach checker that approves everything and applies its planned [`Move`] on first use.
struct MovesTheSession {
    stores: Arc<InMemoryStores>,
    subject: String,
    plan: Mutex<Option<Move>>,
}

#[async_trait::async_trait]
impl PasswordBreachChecker for MovesTheSession {
    async fn is_breached(&self, _password: &str) -> bool {
        let planned = self.plan.lock().ok().and_then(|mut plan| plan.take());
        match planned {
            Some(Move::Rotate { old, new }) => {
                let record = self.stores.find_session(SessionKind::Dashboard, &old).await;
                let Ok(Some(record)) = record else { return false };
                let rotation = SessionRotation {
                    old_hash: old,
                    new_hash: new,
                    new_raw: String::new(),
                    new_record: record,
                    subject_hash: self.subject.clone(),
                    refresh_ttl: 3600,
                    grace_ttl: 30,
                };
                let _ = self.stores.rotate(SessionKind::Dashboard, &rotation).await;
            }
            Some(Move::Revoke { hash }) => {
                let _ = self
                    .stores
                    .revoke_session(SessionKind::Dashboard, &self.subject, &hash)
                    .await;
            }
            None => {}
        }
        false
    }
}

/// An engine over in-memory collaborators, one verified account, and two logged-in devices.
struct Fixture {
    engine: AuthEngine,
    users: Arc<InMemoryUserRepository>,
    stores: Arc<InMemoryStores>,
    checker: Arc<MovesTheSession>,
    user_id: String,
    mine: String,
    other: String,
}

fn hash_of(raw: &str) -> String {
    RawRefreshToken::from_raw(raw.to_owned()).redis_hash()
}

async fn login(engine: &AuthEngine) -> Option<String> {
    let input = LoginInput {
        email: "keeper@example.com".to_owned(),
        password: "oldsecret77".to_owned(),
        tenant_id: Some("t1".to_owned()),
    };
    let Ok(LoginResult::Success(auth)) = engine.login(input, &ctx()).await else {
        return None;
    };
    Some(auth.refresh_token)
}

async fn fixture() -> Option<Fixture> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let probe = AuthEngine::builder()
        .config(base_config())
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .email_provider(Arc::new(CapturingEmails::default()))
        .redis_stores(stores.clone())
        .build()
        .ok()?;
    let created = users
        .create(CreateUserData {
            email: "keeper@example.com".to_owned(),
            name: "Keeper".to_owned(),
            password_hash: Some(hash_password("oldsecret77")),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await
        .ok()?;
    let subject = probe.session_subject(SessionKind::Dashboard, Some("t1"), &created.id);
    let checker = Arc::new(MovesTheSession {
        stores: stores.clone(),
        subject,
        plan: Mutex::new(None),
    });
    let engine = AuthEngine::builder()
        .config(base_config())
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .email_provider(Arc::new(CapturingEmails::default()))
        .redis_stores(stores.clone())
        .breach_checker(checker.clone())
        .build()
        .ok()?;
    let mine = login(&engine).await?;
    let other = login(&engine).await?;
    Some(Fixture {
        engine,
        users,
        stores,
        checker,
        user_id: created.id,
        mine,
        other,
    })
}

impl Fixture {
    fn plan(&self, planned: Move) {
        if let Ok(mut plan) = self.checker.plan.lock() {
            *plan = Some(planned);
        }
    }

    async fn change(&self, presented: Option<&str>) -> Result<(), AuthError> {
        self.engine
            .change_password(
                "t1",
                &self.user_id,
                "oldsecret77",
                "glidingwalnut42",
                presented,
            )
            .await
    }

    async fn is_live(&self, session_hash: &str) -> bool {
        matches!(
            self.stores
                .find_session(SessionKind::Dashboard, session_hash)
                .await,
            Ok(Some(_))
        )
    }

    async fn stored_password(&self) -> Option<String> {
        let user = self.users.find_by_id(&self.user_id, Some("t1")).await;
        user.ok().flatten().and_then(|user| user.password_hash)
    }
}

#[tokio::test]
async fn a_session_that_rotates_while_the_password_is_screened_is_the_one_kept() {
    let Some(f) = fixture().await else { return };
    let successor = "b".repeat(64);
    f.plan(Move::Rotate {
        old: hash_of(&f.mine),
        new: hash_of(&successor),
    });
    assert!(f.change(Some(&f.mine)).await.is_ok());
    // The caller's device is the one that refreshed, so it survives; the other device ends.
    assert!(
        f.is_live(&hash_of(&successor)).await,
        "the successor was ended"
    );
    assert!(
        !f.is_live(&hash_of(&f.other)).await,
        "the other device survived"
    );
}

#[tokio::test]
async fn a_session_that_cannot_be_resolved_after_the_write_ends_every_session() {
    let Some(f) = fixture().await else { return };
    let before = f.stored_password().await;
    f.plan(Move::Revoke {
        hash: hash_of(&f.mine),
    });
    let outcome = f.change(Some(&f.mine)).await;
    assert!(
        outcome.is_ok(),
        "the password is written; the sweep fails closed: {outcome:?}"
    );
    assert_ne!(f.stored_password().await, before);
    assert!(!f.is_live(&hash_of(&f.mine)).await);
    assert!(!f.is_live(&hash_of(&f.other)).await);
}

#[tokio::test]
async fn a_token_naming_no_live_session_changes_nothing() {
    let Some(f) = fixture().await else { return };
    let before = f.stored_password().await;
    for presented in ["f".repeat(64), "not-a-token".to_owned()] {
        let outcome = f.change(Some(&presented)).await;
        assert!(
            matches!(outcome, Err(AuthError::SessionNotFound)),
            "{outcome:?}"
        );
    }
    assert_eq!(f.stored_password().await, before);
    assert!(f.is_live(&hash_of(&f.mine)).await);
    assert!(f.is_live(&hash_of(&f.other)).await);
}
