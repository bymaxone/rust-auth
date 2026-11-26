//! The atomic publish, withdraw and release scenarios of a tenant invitation, shared by every
//! [`InvitationStore`] implementation (layer: test support).

use time::OffsetDateTime;

use crate::traits::{InvitationStore, InvitationWithdrawal, StoredInvitation};

const TENANT: &str = "invitation-scenarios";
const ELSEWHERE: &str = "elsewhere";
const INVITEE: &str = "invitee";
/// The token a scenario consumes, published under its `sha256`.
const SPENT_TOKEN: &str = "scenario-token";
const FIRST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECOND: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const THIRD: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// What the index of the invitee names in `tenant`.
async fn named<S: InvitationStore + ?Sized>(store: &S, tenant: &str) -> Option<String> {
    let read = store.read_invitation_index(tenant, INVITEE).await;
    assert!(read.is_ok(), "read failed: {read:?}");
    read.ok().flatten()
}

/// The record stored under `hash`.
async fn record<S: InvitationStore + ?Sized>(store: &S, hash: &str) -> Option<String> {
    let read = store.read_invitation_record(hash).await;
    assert!(read.is_ok(), "read failed: {read:?}");
    read.ok().flatten()
}

/// Publishes `hash` in `tenant` over `superseded`.
async fn publish<S: InvitationStore + ?Sized>(
    store: &S,
    tenant: &str,
    hash: &str,
    superseded: Option<&str>,
) -> bool {
    let invitation = StoredInvitation {
        email: "invitee@example.com".to_owned(),
        role: "MEMBER".to_owned(),
        tenant_id: tenant.to_owned(),
        inviter_user_id: "owner".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
    };
    let published = store
        .publish_invitation(tenant, INVITEE, hash, &invitation, 600, superseded)
        .await;
    assert!(published.is_ok(), "publish failed: {published:?}");
    published.unwrap_or(false)
}

/// Withdraws `hash` from `tenant`, judged as `judged`.
async fn withdraw<S: InvitationStore + ?Sized>(
    store: &S,
    tenant: &str,
    hash: &str,
    judged: Option<&str>,
) -> Option<InvitationWithdrawal> {
    let outcome = store
        .withdraw_invitation(tenant, INVITEE, hash, judged)
        .await;
    assert!(outcome.is_ok(), "withdraw failed: {outcome:?}");
    outcome.ok()
}

/// A publication writes only over the index entry the caller judged.
async fn publication_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    assert!(!publish(store, TENANT, FIRST, Some(SECOND)).await);
    assert_eq!(record(store, FIRST).await, None, "a lost publish wrote");
    assert!(publish(store, TENANT, FIRST, None).await);
    assert_eq!(named(store, TENANT).await.as_deref(), Some(FIRST));
    assert!(record(store, FIRST).await.is_some());

    assert!(!publish(store, TENANT, SECOND, None).await, "occupied");
    assert!(!publish(store, TENANT, SECOND, Some(THIRD)).await);
    assert!(!publish(store, ELSEWHERE, SECOND, Some(FIRST)).await);
    assert_eq!(record(store, SECOND).await, None);
    assert_eq!(named(store, TENANT).await.as_deref(), Some(FIRST));
    assert!(record(store, FIRST).await.is_some());

    assert!(publish(store, TENANT, SECOND, Some(FIRST)).await);
    assert_eq!(named(store, TENANT).await.as_deref(), Some(SECOND));
    assert_eq!(record(store, FIRST).await, None, "superseded record");
}

/// A withdrawal deletes only while the index and the record are what the caller read.
async fn withdrawal_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    let stored = record(store, SECOND).await;
    assert!(stored.is_some(), "no record to withdraw");
    let judged = stored.as_deref();
    let changed = Some(InvitationWithdrawal::Changed);
    assert_eq!(withdraw(store, TENANT, FIRST, judged).await, changed);
    assert_eq!(withdraw(store, TENANT, SECOND, Some("{}")).await, changed);
    assert_eq!(withdraw(store, TENANT, SECOND, None).await, changed);
    assert_eq!(withdraw(store, ELSEWHERE, SECOND, judged).await, changed);
    assert_eq!(named(store, TENANT).await.as_deref(), Some(SECOND));
    assert!(record(store, SECOND).await.is_some());

    assert_eq!(
        withdraw(store, TENANT, SECOND, judged).await,
        Some(InvitationWithdrawal::Removed)
    );
    assert_eq!(named(store, TENANT).await, None);
    assert_eq!(record(store, SECOND).await, None);
    assert_eq!(withdraw(store, TENANT, SECOND, None).await, changed);
}

/// A record that was consumed leaves an index a withdrawal drops, and a release drops too.
async fn consumed_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    let spent = crate::services::to_hex(&bymax_auth_crypto::mac::sha256(SPENT_TOKEN.as_bytes()));
    assert!(publish(store, TENANT, &spent, None).await);
    let judged = record(store, &spent).await;
    assert!(matches!(
        store.consume_invitation(SPENT_TOKEN).await,
        Ok(Some(_))
    ));
    assert_eq!(
        withdraw(store, TENANT, &spent, judged.as_deref()).await,
        Some(InvitationWithdrawal::Changed),
        "the judged record is gone"
    );
    assert_eq!(
        withdraw(store, TENANT, &spent, None).await,
        Some(InvitationWithdrawal::Absent)
    );
    assert_eq!(named(store, TENANT).await, None);
}

/// Runs `release_invitation_index` in `tenant`.
async fn release<S: InvitationStore + ?Sized>(store: &S, tenant: &str, expected: &str) -> bool {
    let released = store
        .release_invitation_index(tenant, INVITEE, expected)
        .await;
    assert!(released.is_ok(), "release failed: {released:?}");
    released.unwrap_or(false)
}

/// A release drops the entry only while it holds the named hash.
async fn release_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    assert!(publish(store, TENANT, THIRD, None).await);
    assert!(!release(store, TENANT, SECOND).await, "another hash");
    assert!(!release(store, TENANT, "").await, "empty hash");
    assert!(!release(store, ELSEWHERE, THIRD).await, "another tenant");
    assert_eq!(named(store, TENANT).await.as_deref(), Some(THIRD));
    assert!(release(store, TENANT, THIRD).await, "the held hash");
    assert_eq!(named(store, TENANT).await, None);
    assert!(!release(store, TENANT, THIRD).await, "an absent entry");
    assert!(
        !release(store, TENANT, "").await,
        "empty hash, absent entry"
    );
}

/// Checks that a store publishes, withdraws and releases only over what the caller names.
///
/// # Panics
///
/// When the store breaks one of the rules or fails a call.
pub async fn run_invitation_index_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    publication_scenarios(store).await;
    withdrawal_scenarios(store).await;
    consumed_scenarios(store).await;
    release_scenarios(store).await;
}
