//! The subjects and Redis key identifiers of the workspace keyspaces (layer: domain).
//!
//! A repository id is unique only inside its tenant, so every key derived from a workspace, a
//! membership or an inviter is derived from a **subject** that carries the tenant, and the subject
//! is hashed with the identifier key: `hmac_sha256(identifierKey, subject)` in lower-case hex.
//! The tenant and the workspace are length-prefixed in UTF-8 bytes, which is what keeps the pair
//! injective when either contains a `:`; the last component carries no prefix because nothing can
//! follow it. The length counts bytes, never UTF-16 units, so a non-ASCII identifier derives the
//! same key here and in `@bymax-one/nest-auth`.
//!
//! A tenant, a workspace or a user id that is empty or only whitespace is refused before any key is
//! derived: no key is ever built from a blank part.
//!
//! The identifiers returned by the `*_id` functions are the `{id}` segment that
//! `NamespacedRedis::key` places after the namespace and the prefix.

use bymax_auth_crypto::mac::{hmac_sha256, sha256};

use crate::services::to_hex;
use crate::workspace::bounds::is_blank;

/// A key part that cannot be used to derive a key because it is empty or only whitespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{part} must not be blank")]
pub struct BlankPart {
    /// The name of the refused part: `tenantId`, `workspaceId` or `userId`.
    pub part: &'static str,
}

/// `Ok(value)` unless it is blank.
fn named<'a>(part: &'static str, value: &'a str) -> Result<&'a str, BlankPart> {
    if is_blank(value) {
        Err(BlankPart { part })
    } else {
        Ok(value)
    }
}

/// `{byteLength}:{value}`, counting UTF-8 bytes.
fn length_prefixed(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// The subject of a workspace: `wsp:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}`.
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the workspace is blank.
pub fn workspace_subject(tenant_id: &str, workspace_id: &str) -> Result<String, BlankPart> {
    let tenant = length_prefixed(named("tenantId", tenant_id)?);
    let workspace = length_prefixed(named("workspaceId", workspace_id)?);
    Ok(format!("wsp:{tenant}:{workspace}"))
}

/// The subject of one membership:
/// `wms:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}:{userId}`.
///
/// # Errors
///
/// [`BlankPart`] when the tenant, the workspace or the user is blank.
pub fn membership_subject(
    tenant_id: &str,
    workspace_id: &str,
    user_id: &str,
) -> Result<String, BlankPart> {
    let tenant = length_prefixed(named("tenantId", tenant_id)?);
    let workspace = length_prefixed(named("workspaceId", workspace_id)?);
    let user = named("userId", user_id)?;
    Ok(format!("wms:{tenant}:{workspace}:{user}"))
}

/// The preimage of the invitee index of a workspace invitation:
/// `wie:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}:{email}`.
///
/// The address is taken as given: the caller passes it trimmed and lower-cased.
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the workspace is blank.
pub fn invitation_email_subject(
    tenant_id: &str,
    workspace_id: &str,
    email: &str,
) -> Result<String, BlankPart> {
    let tenant = length_prefixed(named("tenantId", tenant_id)?);
    let workspace = length_prefixed(named("workspaceId", workspace_id)?);
    Ok(format!("wie:{tenant}:{workspace}:{email}"))
}

/// The preimage of an inviter's hourly counter: `wir:{len(tenant)}:{tenant}:{userId}`.
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the user is blank.
pub fn inviter_rate_subject(tenant_id: &str, user_id: &str) -> Result<String, BlankPart> {
    let tenant = length_prefixed(named("tenantId", tenant_id)?);
    let user = named("userId", user_id)?;
    Ok(format!("wir:{tenant}:{user}"))
}

/// `hmac_sha256(identifier_key, subject)` in lower-case hex: the key suffix every subject maps to.
#[must_use]
pub fn subject_hash(identifier_key: &[u8; 64], subject: &str) -> String {
    to_hex(&hmac_sha256(identifier_key, subject.as_bytes()))
}

/// The `{id}` of a workspace's version counter (`wsv`).
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the workspace is blank.
pub fn workspace_version_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    workspace_id: &str,
) -> Result<String, BlankPart> {
    Ok(subject_hash(
        identifier_key,
        &workspace_subject(tenant_id, workspace_id)?,
    ))
}

/// The `{id}` of a membership's version counter (`wmv`).
///
/// # Errors
///
/// [`BlankPart`] when the tenant, the workspace or the user is blank.
pub fn membership_version_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    workspace_id: &str,
    user_id: &str,
) -> Result<String, BlankPart> {
    Ok(subject_hash(
        identifier_key,
        &membership_subject(tenant_id, workspace_id, user_id)?,
    ))
}

/// The `{id}` of a cached membership entry (`wm`):
/// `{hmac(membershipSubject)}:{workspaceVersion}:{membershipVersion}`.
///
/// The versions are the ones read **before** the repository, so an entry written after a
/// concurrent change lands under a key nobody reads.
///
/// # Errors
///
/// [`BlankPart`] when the tenant, the workspace or the user is blank.
pub fn membership_cache_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    workspace_id: &str,
    user_id: &str,
    versions: (u64, u64),
) -> Result<String, BlankPart> {
    let base = membership_version_id(identifier_key, tenant_id, workspace_id, user_id)?;
    Ok(format!("{base}:{}:{}", versions.0, versions.1))
}

/// The `{id}` of a workspace invitation record (`winv`): `sha256(token)` in lower-case hex.
#[must_use]
pub fn invitation_record_id(token: &str) -> String {
    to_hex(&sha256(token.as_bytes()))
}

/// The `{id}` of the invitee index of a workspace invitation (`winvidx`).
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the workspace is blank.
pub fn invitation_index_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    workspace_id: &str,
    email: &str,
) -> Result<String, BlankPart> {
    Ok(subject_hash(
        identifier_key,
        &invitation_email_subject(tenant_id, workspace_id, email)?,
    ))
}

/// The `{id}` of a workspace's set of live invitation records (`winvset`).
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the workspace is blank.
pub fn invitation_set_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    workspace_id: &str,
) -> Result<String, BlankPart> {
    workspace_version_id(identifier_key, tenant_id, workspace_id)
}

/// The `{id}` of an inviter's hourly counter (`winvrl`).
///
/// # Errors
///
/// [`BlankPart`] when the tenant or the user is blank.
pub fn inviter_rate_id(
    identifier_key: &[u8; 64],
    tenant_id: &str,
    user_id: &str,
) -> Result<String, BlankPart> {
    Ok(subject_hash(
        identifier_key,
        &inviter_rate_subject(tenant_id, user_id)?,
    ))
}
