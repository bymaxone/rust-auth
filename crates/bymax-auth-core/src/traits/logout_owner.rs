//! The owner a failed logout attempt records for the retry that completes it.
//!
//! Layer: a data type of the session-store contract; the store methods that carry it live in
//! `store.rs`.

use serde::{Deserialize, Serialize};

/// Whom a logout belonged to, as the failure path of a logout records it for the retry that
/// completes it.
///
/// A hint, never a credential and never a session: it authenticates nothing, and the owner it
/// names was read from the library's own session record, not from a token's claims. `tenant_id`
/// is omitted from the stored form when the session record carried none, and is always absent on
/// the platform plane. `family_id` is omitted when the record named no family a token could
/// carry. JSON is camelCase for byte-parity with nest-auth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutOwner {
    /// The account whose session the logout was ending.
    pub user_id: String,
    /// The account's tenant, when its session record carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// The session's refresh family id, when its record named a conforming one: a retried logout
    /// ends the access tokens of that session with it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::traits::session_id_or_absent"
    )]
    pub family_id: Option<String>,
}
