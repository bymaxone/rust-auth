//! The compare-and-delete scenarios of the invitee index, shared by every
//! [`InvitationStore`] implementation (layer: test support).

use crate::traits::InvitationStore;

const TENANT: &str = "release-scenarios";
const HELD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// What the index of `invitee` names in `tenant`.
async fn named<S: InvitationStore + ?Sized>(
    store: &S,
    tenant: &str,
    invitee: &str,
) -> Option<String> {
    let read = store.read_invitation_index(tenant, invitee).await;
    assert!(read.is_ok(), "read failed: {read:?}");
    read.ok().flatten()
}

/// Runs `release_invitation_index` for `invitee` in `tenant`.
async fn release<S: InvitationStore + ?Sized>(
    store: &S,
    tenant: &str,
    invitee: &str,
    expected: &str,
) -> bool {
    let released = store
        .release_invitation_index(tenant, invitee, expected)
        .await;
    assert!(released.is_ok(), "release failed: {released:?}");
    released.unwrap_or(false)
}

/// Checks that a store releases an invitee index only while it holds what the caller names.
///
/// # Panics
///
/// When the store breaks one of the rules or fails a call.
pub async fn run_invitation_index_scenarios<S: InvitationStore + ?Sized>(store: &S) {
    let put = store
        .put_invitation_index(TENANT, "invitee", HELD, 600)
        .await;
    assert!(put.is_ok(), "put failed: {put:?}");

    assert!(
        !release(store, TENANT, "invitee", OTHER).await,
        "another hash"
    );
    assert!(!release(store, TENANT, "invitee", "").await, "empty hash");
    assert!(
        !release(store, "elsewhere", "invitee", HELD).await,
        "another tenant"
    );
    assert_eq!(named(store, TENANT, "invitee").await.as_deref(), Some(HELD));

    assert!(
        release(store, TENANT, "invitee", HELD).await,
        "the held hash"
    );
    assert_eq!(named(store, TENANT, "invitee").await, None);

    assert!(
        !release(store, TENANT, "invitee", HELD).await,
        "an absent entry"
    );
    assert!(
        !release(store, TENANT, "invitee", "").await,
        "empty hash, absent entry"
    );
}
