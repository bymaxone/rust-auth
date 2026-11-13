//! Which parts of `conformance/wire-contract.json` some test in this workspace reads, and which
//! none does yet.
//!
//! Every comparison elsewhere asserts one section against one table. This file asserts the
//! other direction for the whole file: the sections the contract names are exactly the ones
//! listed here, so a section the contract gains is neither silently ignored nor assumed read.
//!
//! A section listed as read must appear, by name, in a source file other than this one; one
//! listed as pending must appear in none. The slice that builds a pending section therefore has
//! to move its entry, and a section left pending while a test already reads it fails.
//!
//! What a name match proves is that something refers to the section, not that the reference
//! compares anything. It is a floor that catches a section nobody opened, not a substitute for
//! the comparison tests themselves.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The contract, parsed. An unreadable or unparseable file yields `Null`, which empties every
/// set below and fails the comparisons rather than passing them over nothing.
fn contract() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

/// Every `.rs` file under `crates/`, except this one.
fn sources() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "target") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files
        .iter()
        .filter(|path| !path.ends_with("tests/contract_inventory.rs"))
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

/// Whether any source mentions `needle` as a quoted string.
fn referenced(needle: &str, sources: &[String]) -> bool {
    let quoted = format!("\"{needle}\"");
    sources.iter().any(|text| text.contains(&quoted))
}

/// Whether any source opens `needle` as a key of the contract: indexing (`["name"]`) or a lookup
/// (`("name")`, `("name",`). A name that merely occurs in another list does not count, which is
/// what keeps a pending list elsewhere (a limit named like a section) from reading as a read.
fn opened(needle: &str, sources: &[String]) -> bool {
    [
        format!("[\"{needle}\"]"),
        format!("(\"{needle}\")"),
        format!("(\"{needle}\","),
    ]
    .iter()
    .any(|form| sources.iter().any(|text| text.contains(form)))
}

/// Compare the keys of one contract object with the lists, then check each name against the
/// sources. `lists` is `(read, exempt, pending)`: `exempt` names are covered without a reference
/// by name (the reason is stated where they are listed), and `pending` carries the slice that
/// builds each.
fn inventory(label: &str, object: &Value, lists: (&[&str], &[&str], &[(&str, &str)])) {
    let (read, exempt, pending) = lists;
    let named: BTreeSet<String> = object
        .as_object()
        .map(|map| {
            map.keys()
                .filter(|key| !key.starts_with('$'))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    assert!(!named.is_empty(), "{label} did not load");
    let mut listed: BTreeSet<String> = read
        .iter()
        .chain(exempt)
        .map(|name| (*name).to_owned())
        .collect();
    let pending_names: BTreeSet<String> =
        pending.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert!(
        listed.is_disjoint(&pending_names),
        "{label}: a name is listed as both read and pending"
    );
    listed.extend(pending_names);
    assert_eq!(listed, named, "{label}: the contract and this list differ");
    let files = sources();
    for name in read {
        assert!(
            referenced(name, &files),
            "{label}.{name} is listed as read but nothing refers to it"
        );
    }
    for (name, slice) in pending {
        assert!(
            !opened(name, &files),
            "{label}.{name} is read already; remove it from the pending list (slice {slice})"
        );
    }
}

#[test]
fn every_section_of_the_contract_is_read_or_pending() {
    let root = contract();
    inventory(
        "contract",
        &root,
        (
            &[
                "accessTokenClaims",
                "apiKeys",
                "credentialFormats",
                "errorCatalog",
                "errorEnvelope",
                "familyIndexMembers",
                "graceRecoveryWrite",
                "hmacKeyDerivation",
                "identifierPreimages",
                "mfaTransitionLock",
                "passwordHashFormat",
                "passwordResetOrder",
                "rateLimits",
                "recordEncodings",
                "recoveryCodeClaim",
                "redisKeyPrefixes",
                "refreshTokenInput",
                "requestEncoding",
                "requestFieldBounds",
                "responseBodies",
                "rotationSemantics",
                "sessionIndexMembers",
                "transportErrors",
                "userStatusCache",
                "userSubjectDerivedKeys",
                "userSubjectPreimages",
                "workspaceAccountRemoval",
                "workspaceInvitations",
                "workspaceMembershipCache",
                "workspaceOwnerRole",
                "workspaceRealtime",
                "workspaceScopedName",
            ],
            // `version` is covered by the byte pin of the whole file.
            &["version"],
            &[],
        ),
    );
}

#[test]
fn every_identifier_preimage_is_read_or_pending() {
    let root = contract();
    inventory(
        "identifierPreimages",
        &root["identifierPreimages"],
        (
            &[
                "dashboard",
                "platform",
                "otpRecord",
                "inviteeIndex",
                "workspaceInvitationEmail",
                "workspaceInviterRate",
            ],
            &[],
            &[],
        ),
    );
}

#[test]
fn every_request_field_bound_is_read_or_pending() {
    let root = contract();
    inventory(
        "requestFieldBounds",
        &root["requestFieldBounds"],
        (
            &[
                "email",
                "newPassword",
                "provenPassword",
                "tenantId",
                "displayName",
                "invitationDisplayName",
                "singleUseToken",
                "resetOtp",
                "verificationOtp",
                "totpCode",
                "role",
                "memberUserId",
                "workspaceName",
                "opaqueToken",
                "pageLimit",
                "pathParameters",
            ],
            &[],
            &[],
        ),
    );
}

#[test]
fn every_page_limit_bound_is_read_or_pending() {
    let root = contract();
    inventory(
        "requestFieldBounds.pageLimit",
        &root["requestFieldBounds"]["pageLimit"],
        (&["min", "max", "default", "cursor"], &[], &[]),
    );
}

#[test]
fn every_record_encoding_is_read_or_pending() {
    let root = contract();
    inventory(
        "recordEncodings",
        &root["recordEncodings"],
        (
            &[
                "refreshSession",
                "sessionDetail",
                "invitation",
                "invitationIndex",
                "wsTicket",
                "logoutPending",
                "passwordResetContext",
                "oauthState",
                "emailChangeContext",
            ],
            &[],
            &[],
        ),
    );
}

#[test]
fn every_membership_cache_statement_is_read_or_pending() {
    let root = contract();
    inventory(
        "workspaceMembershipCache",
        &root["workspaceMembershipCache"],
        (
            &[
                "workspaceSubject",
                "membershipSubject",
                "keys",
                "hmacKey",
                "absentVersion",
                "entryValue",
                "ttl",
                "versionRetentionSeconds",
                "versionRetentionWhy",
                "bump",
                "vectors",
                "entryRead",
                "blankParts",
                "fullKeyVectors",
                "scenarios",
                "entryRefreshesCounters",
            ],
            // `entryRule` is prose whose cases are steps of `scenarios` (an inactive workspace is
            // not cached, a seeded suspended entry reads as a miss) and of the resolver's tests.
            &["entryRule"],
            &[("workspaceWideEvents", "13.5b")],
        ),
    );
}

#[test]
fn every_workspace_realtime_statement_is_read_or_pending() {
    let root = contract();
    let section = &root["workspaceRealtime"];
    inventory(
        "workspaceRealtime",
        section,
        (&["rules"], &[], &[("accessDeniedVectors", "13.9")]),
    );
    inventory(
        "workspaceRealtime.rules",
        &section["rules"],
        (
            &["accessDecision", "workspaceIdField"],
            // The rule points at the `workspaceScopedName` section, which is read in full.
            &["workspaceScopedName"],
            &[
                ("verifierWorkspace", "13.9"),
                ("socketMessage", "13.9"),
                ("jobAuthorization", "13.9"),
                ("accessDeniedEvents", "13.9"),
            ],
        ),
    );
}
