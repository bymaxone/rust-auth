//! A dashboard session whose stored record names no tenant is refused at refresh before anything
//! is rotated.

use std::sync::Arc;

use bymax_auth_jwt::RawRefreshToken;
use bymax_auth_types::CreateUserData;

use super::test_support::{CapturingEmails, base_config, hash_password};
use crate::engine::AuthEngine;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::{SessionKind, SessionRecord, SessionRotation, SessionStore, UserRepository};
use time::OffsetDateTime;

/// An engine over in-memory collaborators and one active account.
async fn fixture() -> Option<(AuthEngine, Arc<InMemoryStores>, String)> {
    let users = Arc::new(InMemoryUserRepository::new());
    let stores = Arc::new(InMemoryStores::new());
    let engine = AuthEngine::builder()
        .config(base_config())
        .environment(crate::config::Environment::Test)
        .user_repository(users.clone())
        .email_provider(Arc::new(CapturingEmails::default()))
        .redis_stores(stores.clone())
        .build()
        .ok()?;
    let user = users
        .create(CreateUserData {
            email: "nt@example.com".to_owned(),
            name: "N".to_owned(),
            password_hash: Some(hash_password("oldsecret77")),
            role: Some("USER".to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await
        .ok()?;
    Some((engine, stores, user.id))
}

fn record(user_id: &str, tenant: Option<String>) -> SessionRecord {
    SessionRecord {
        user_id: user_id.to_owned(),
        tenant_id: tenant,
        role: "USER".to_owned(),
        device: "d".to_owned(),
        ip: "1.1.1.1".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        mfa_enabled: false,
        mfa_verified: false,
        family_id: "fam".to_owned(),
        family_created_at: Some(OffsetDateTime::now_utc()),
    }
}

#[tokio::test]
async fn a_session_record_with_no_tenant_is_refused_before_it_rotates() {
    let Some((engine, stores, user_id)) = fixture().await else {
        return;
    };
    for tenant in [None, Some(String::new())] {
        let raw = if tenant.is_none() {
            "c".repeat(64)
        } else {
            "d".repeat(64)
        };
        let hash = RawRefreshToken::from_raw(raw.clone()).redis_hash();
        let subject = engine.session_subject(SessionKind::Dashboard, tenant.as_deref(), &user_id);
        let created = stores
            .create_session(
                SessionKind::Dashboard,
                &subject,
                &hash,
                &record(&user_id, tenant.clone()),
                3600,
            )
            .await;
        assert!(created.is_ok());
        let outcome = engine.refresh(&raw, "1.2.3.4", "ua").await;
        assert!(
            outcome.is_err(),
            "a tenant-less session must not rotate: {tenant:?}"
        );
        // Refused before anything was rotated: the presented token still names the session it
        // named, and no session exists that nobody holds a token for.
        let alive = stores.find_session(SessionKind::Dashboard, &hash).await;
        assert!(
            matches!(alive, Ok(Some(_))),
            "{tenant:?}: the token was consumed"
        );
        let listed = stores.list_sessions(SessionKind::Dashboard, &subject).await;
        assert_eq!(
            listed.map(|v| v.len()).ok(),
            Some(1),
            "{tenant:?}: a session was left behind"
        );
    }
}

/// Store a session for `user_id` under `raw` that has since rotated into a successor whose record
/// names no tenant, so presenting `raw` takes the grace path with a tenant-less recovered record.
async fn rotated_into_a_tenantless_successor(
    engine: &AuthEngine,
    stores: &InMemoryStores,
    user_id: &str,
    raw: &str,
) {
    let old = RawRefreshToken::from_raw(raw.to_owned()).redis_hash();
    let subject = engine.session_subject(SessionKind::Dashboard, Some("t1"), user_id);
    let created = stores
        .create_session(
            SessionKind::Dashboard,
            &subject,
            &old,
            &record(user_id, Some("t1".to_owned())),
            3600,
        )
        .await;
    assert!(created.is_ok());
    let rotation = SessionRotation {
        old_hash: old,
        new_hash: "b".repeat(64),
        new_raw: String::new(),
        new_record: record(user_id, None),
        subject_hash: subject,
        refresh_ttl: 3600,
        grace_ttl: 30,
    };
    let rotated = stores.rotate(SessionKind::Dashboard, &rotation).await;
    assert!(rotated.is_ok());
}

/// Give the tenant-less subject one session of its own (a legacy record). That is what lets a
/// recovery write into that index at all: without it the store refuses the write for a different
/// reason and the grace test would pass whatever the refresh does.
async fn seed_a_legacy_tenantless_session(
    engine: &AuthEngine,
    stores: &InMemoryStores,
    user_id: &str,
) -> String {
    let tenantless = engine.session_subject(SessionKind::Dashboard, None, user_id);
    let legacy = stores
        .create_session(
            SessionKind::Dashboard,
            &tenantless,
            &"e".repeat(64),
            &record(user_id, None),
            3600,
        )
        .await;
    assert!(legacy.is_ok());
    tenantless
}

#[tokio::test]
async fn a_recovered_session_with_no_tenant_is_refused_and_writes_nothing() {
    let Some((engine, stores, user_id)) = fixture().await else {
        return;
    };
    let raw = "a".repeat(64);
    rotated_into_a_tenantless_successor(&engine, &stores, &user_id, &raw).await;
    let tenantless = seed_a_legacy_tenantless_session(&engine, &stores, &user_id).await;

    let outcome = engine.refresh(&raw, "1.2.3.4", "ua").await;
    assert!(outcome.is_err(), "a tenant-less recovery must be refused");
    // Only the legacy session is there: the recovery wrote nothing. (A second attempt would be
    // a reuse of a spent pointer, which revokes the lineage by design and says nothing here.)
    let written = stores
        .list_sessions(SessionKind::Dashboard, &tenantless)
        .await;
    assert_eq!(
        written.map(|v| v.len()).ok(),
        Some(1),
        "a session was written"
    );
}
