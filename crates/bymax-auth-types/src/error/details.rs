//! The structured payloads an error carries under `error.details` (layer: wire types).
//!
//! [`FieldError`] is the array element of a validation or host refusal, and [`BlockingWorkspace`]
//! the element of `details.workspaces` of the account-removal refusal
//! (`workspaceAccountRemoval.rules.blocking`).

use serde::{Deserialize, Serialize};

/// A single field-level validation failure, surfaced under `error.details` for the
/// adapter-originated [`AuthErrorCode::Validation`](super::AuthErrorCode::Validation) code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-error.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct FieldError {
    /// The offending request field (dotted path for nested fields).
    pub field: String,
    /// Human-readable reason the field was rejected.
    pub message: String,
}

/// A workspace that blocks the removal of an account's memberships: serialized as
/// `{ id, name, status }`, or as `{ id }` alone when only the repository's ids are known because
/// it found the workspace during the write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockingWorkspace {
    /// The workspace id.
    pub id: String,
    /// The workspace name, when it was read before the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The workspace status (`active` or `suspended`), when it was read before the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}
