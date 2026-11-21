//! The stored record of a workspace invitation (layer: domain).
//!
//! The record is shared with `@bymax-one/nest-auth` through `workspaceInvitations.record` in the
//! shared wire contract: both libraries read and write one keyspace, so a value one side writes
//! and the other reads as absent is a refused invitation. A value under the key is a record only
//! when every field has the right type and the kind's fields are exactly the contract's; any
//! other combination is read as absent and answered as an invalid token.

use serde_json::{Map, Value};

use crate::workspace::bounds::normalize_workspace_name;

/// The prefix of an invitation record key (`winv:{sha256(token)}`), which is also how the index
/// and the pending set name a record.
pub const RECORD_KEY_PREFIX: &str = "winv:";

/// The record key of the invitation whose token hashes to `token_hash` (`sha256(token)` in
/// lower-case hex).
#[must_use]
pub fn record_key(token_hash: &str) -> String {
    format!("{RECORD_KEY_PREFIX}{token_hash}")
}

/// The fields both kinds of invitation carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationBase {
    /// The invited address, trimmed and lower-cased.
    pub email: String,
    /// The workspace role the invitation grants.
    pub role: String,
    /// The tenant the workspace lives in.
    pub tenant_id: String,
    /// The workspace the invitee joins, or the id a bootstrap workspace will be created with.
    pub workspace_id: String,
    /// When the current token was issued, as an ISO-8601 instant. A resend resets it.
    pub created_at: String,
    /// `0` on the first invitation, one more on each resend or second invitation of the address.
    pub resend_count: u64,
}

/// A stored invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationRecord {
    /// Issued by a member of a workspace that exists.
    Member {
        /// The common fields.
        base: InvitationBase,
        /// The member who issued the current token.
        inviter_user_id: String,
    },
    /// Issued by the platform for the invitee to own a workspace that does not exist until they
    /// accept. It has no inviter, and its role is the owner role.
    Bootstrap {
        /// The common fields.
        base: InvitationBase,
        /// The name the workspace is created with, in the form the create route stores it.
        workspace_name: String,
    },
}

impl InvitationRecord {
    /// The fields both kinds carry.
    #[must_use]
    pub fn base(&self) -> &InvitationBase {
        match self {
            Self::Member { base, .. } | Self::Bootstrap { base, .. } => base,
        }
    }

    /// The record's `kind` as it is stored: `member` or `bootstrap`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Member { .. } => "member",
            Self::Bootstrap { .. } => "bootstrap",
        }
    }

    /// The JSON the record is stored as.
    #[must_use]
    pub fn to_json(&self) -> String {
        let base = self.base();
        let mut fields = Map::new();
        fields.insert("kind".to_owned(), self.kind().into());
        fields.insert("email".to_owned(), base.email.clone().into());
        fields.insert("role".to_owned(), base.role.clone().into());
        fields.insert("tenantId".to_owned(), base.tenant_id.clone().into());
        fields.insert("workspaceId".to_owned(), base.workspace_id.clone().into());
        fields.insert("createdAt".to_owned(), base.created_at.clone().into());
        fields.insert("resendCount".to_owned(), base.resend_count.into());
        match self {
            Self::Member {
                inviter_user_id, ..
            } => fields.insert("inviterUserId".to_owned(), inviter_user_id.clone().into()),
            Self::Bootstrap { workspace_name, .. } => {
                fields.insert("workspaceName".to_owned(), workspace_name.clone().into())
            }
        };
        Value::Object(fields).to_string()
    }

    /// The record `raw` stores, or `None` when it is not one: not JSON, not an object, a field
    /// missing or of the wrong type, a kind other than `member` or `bootstrap`, a `member` that
    /// carries a workspace name or lacks an inviter, a `bootstrap` that carries an inviter or whose
    /// name is not in the stored form, or a resend count that is not a non-negative integer.
    /// Fields the contract does not list are ignored.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(raw).ok()?;
        let fields = value.as_object()?;
        let text = |name: &str| fields.get(name).and_then(Value::as_str).map(str::to_owned);
        let base = InvitationBase {
            email: text("email")?,
            role: text("role")?,
            tenant_id: text("tenantId")?,
            workspace_id: text("workspaceId")?,
            created_at: text("createdAt")?,
            resend_count: fields.get("resendCount").and_then(Value::as_u64)?,
        };
        match fields.get("kind").and_then(Value::as_str)? {
            "member" if !fields.contains_key("workspaceName") => Some(Self::Member {
                base,
                inviter_user_id: text("inviterUserId")?,
            }),
            "bootstrap" if !fields.contains_key("inviterUserId") => {
                let workspace_name = text("workspaceName")?;
                normalize_workspace_name(&workspace_name)
                    .is_ok_and(|stored| stored == workspace_name)
                    .then_some(Self::Bootstrap {
                        base,
                        workspace_name,
                    })
            }
            _ => None,
        }
    }
}
