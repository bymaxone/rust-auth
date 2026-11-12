//! The membership-cache names, entry and lifetime against the shared contract (layer: domain,
//! tests).
//!
//! The templates, the vectors and the limits are read from `workspaceMembershipCache` in
//! `conformance/wire-contract.json` and derived here; none is typed into this file. The table the
//! contract lists (`keys`) is compared as a set in both directions.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::keys::{BlankPart, membership_cache_id, membership_subject, workspace_subject};
use super::limits::{MEMBERSHIP_CACHE_TTL_MAX_SECONDS, VERSION_RETENTION_SECONDS};
use super::membership_cache::{
    MembershipCacheIds, MembershipCacheTtl, MembershipVersions, VersionCounter, entry_role,
    entry_value,
};
use super::tests::{contract, hmac_key, prefix, vectors};
use crate::traits::TOKEN_EPOCH_RETENTION_SECS;
use crate::workspace::domain::MembershipRef;

/// The `workspaceMembershipCache` section.
fn section() -> Value {
    contract()["workspaceMembershipCache"].clone()
}

/// A text field of a vector.
fn text<'a>(vector: &'a Map<String, Value>, field: &str) -> &'a str {
    vector
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The member a vector names.
fn member(vector: &Map<String, Value>) -> MembershipRef<'_> {
    MembershipRef {
        tenant_id: text(vector, "tenantId"),
        workspace_id: text(vector, "workspaceId"),
        user_id: text(vector, "userId"),
    }
}

/// A subject template rendered over a member's parts.
fn render_subject(template: &Value, member: MembershipRef<'_>) -> String {
    template
        .as_str()
        .unwrap_or_default()
        .replace(
            "{utf8ByteLength(tenantId)}",
            &member.tenant_id.len().to_string(),
        )
        .replace("{tenantId}", member.tenant_id)
        .replace(
            "{utf8ByteLength(workspaceId)}",
            &member.workspace_id.len().to_string(),
        )
        .replace("{workspaceId}", member.workspace_id)
        .replace("{userId}", member.user_id)
}

#[test]
fn the_subject_templates_are_the_derivations() {
    let cache = section();
    for vector in vectors(&cache["vectors"]) {
        let member = member(&vector);
        let workspace = workspace_subject(member.tenant_id, member.workspace_id);
        assert_eq!(
            workspace.as_deref().ok(),
            Some(render_subject(&cache["workspaceSubject"], member).as_str())
        );
        let membership = membership_subject(member.tenant_id, member.workspace_id, member.user_id);
        assert_eq!(
            membership.as_deref().ok(),
            Some(render_subject(&cache["membershipSubject"], member).as_str())
        );
    }
}

#[test]
fn the_cache_identifiers_are_the_vectors_digests() {
    let key = hmac_key();
    // The vectors are derived with the pinned key the section names.
    let named = section()["hmacKey"].as_str().unwrap_or_default().to_owned();
    assert!(named.contains("hmacKeyDerivation") && named.contains("derivedKeyHex"));
    for vector in vectors(&section()["vectors"]) {
        let ids = MembershipCacheIds::derive(&key, member(&vector));
        let ids = ids.unwrap_or_else(|_| MembershipCacheIds {
            workspace: String::new(),
            membership: String::new(),
        });
        assert_eq!(ids.workspace, text(&vector, "workspaceDigestHex"));
        assert_eq!(ids.membership, text(&vector, "membershipDigestHex"));
        assert_eq!(ids.counter(VersionCounter::Workspace), ids.workspace);
        assert_eq!(ids.counter(VersionCounter::Membership), ids.membership);
    }
}

/// The key a `keys` template names for `ids` under `versions`, built from the identifiers.
fn derived_key(name: &str, ids: &MembershipCacheIds, versions: MembershipVersions) -> String {
    let id = match name {
        "workspaceVersion" => ids.workspace.clone(),
        "membershipVersion" => ids.membership.clone(),
        "membershipCache" => ids.entry(versions),
        _ => String::new(),
    };
    format!("{{namespace}}:{}:{id}", prefix(name))
}

/// A `keys` template rendered over the identifiers and versions.
fn render_key(template: &str, ids: &MembershipCacheIds, versions: MembershipVersions) -> String {
    template
        .replace("{hmac_sha256(hmacKey, workspaceSubject)}", &ids.workspace)
        .replace("{hmac_sha256(hmacKey, membershipSubject)}", &ids.membership)
        .replace("{workspaceVersion}", &versions.workspace.to_string())
        .replace("{membershipVersion}", &versions.membership.to_string())
}

#[test]
fn every_key_template_is_a_derived_key_and_none_is_missing() {
    let cache = section();
    let templates = cache["keys"].as_object().cloned().unwrap_or_default();
    let named: BTreeSet<&str> = templates.keys().map(String::as_str).collect();
    let derived = BTreeSet::from(["workspaceVersion", "membershipVersion", "membershipCache"]);
    assert_eq!(named, derived);
    for vector in vectors(&cache["fullKeyVectors"]) {
        let ids = MembershipCacheIds::derive(&hmac_key(), member(&vector));
        let ids = ids.unwrap_or_else(|_| MembershipCacheIds {
            workspace: String::new(),
            membership: String::new(),
        });
        let versions = MembershipVersions {
            workspace: text(&vector, "workspaceVersion")
                .parse()
                .unwrap_or(u64::MAX),
            membership: text(&vector, "membershipVersion")
                .parse()
                .unwrap_or(u64::MAX),
        };
        for (name, template) in &templates {
            let rendered = render_key(template.as_str().unwrap_or_default(), &ids, versions);
            assert_eq!(rendered, derived_key(name, &ids, versions), "{name}");
            assert_eq!(rendered, text(&vector, &format!("{name}Key")), "{name}");
        }
        let entry = membership_cache_id(
            &hmac_key(),
            member(&vector).tenant_id,
            member(&vector).workspace_id,
            member(&vector).user_id,
            (versions.workspace, versions.membership),
        );
        assert_eq!(entry.ok(), Some(ids.entry(versions)));
    }
}

#[test]
fn an_absent_counter_reads_as_the_text_the_contract_names() {
    let rule = section()["absentVersion"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let quoted = rule.split('\'').nth(1).unwrap_or_default().to_owned();
    let absent = MembershipVersions::default();
    assert_eq!(absent.workspace.to_string(), quoted);
    assert_eq!(absent.to_string(), format!("{quoted}:{quoted}"));
}

#[test]
fn the_entry_written_is_the_contracts_value_for_every_scenario_role() {
    let cache = section();
    let template = cache["entryValue"].as_str().unwrap_or_default().to_owned();
    let mut roles: BTreeSet<String> = BTreeSet::new();
    for sequence in [
        &cache["scenarios"]["steps"],
        &cache["scenarios"]["counterLoss"]["steps"],
    ] {
        for step in sequence.as_array().into_iter().flatten() {
            let role = step["repository"]["role"].as_str().unwrap_or_default();
            roles.insert(role.to_owned());
        }
    }
    assert!(roles.len() > 1, "the scenario roles did not load");
    for role in roles {
        assert_eq!(entry_value(&role), template.replace("<role>", &role));
        assert_eq!(
            entry_role(&entry_value(&role)).as_deref(),
            Some(role.as_str())
        );
    }
    // A role the template cannot hold verbatim is escaped as JSON escapes it, and reads back.
    for role in ["a\"b", "back\\slash", "\u{e9}t\u{e9}", "line\nbreak", ""] {
        assert_eq!(entry_role(&entry_value(role)).as_deref(), Some(role));
    }
}

#[test]
fn an_entry_is_read_by_parsing_and_anything_but_an_active_role_is_a_miss() {
    let cache = section();
    assert!(
        cache["entryRead"]
            .as_str()
            .is_some_and(|rule| rule.contains("PARSING"))
    );
    assert_eq!(
        entry_role("{ \"status\" : \"active\",\n \"role\": \"editor\", \"extra\": 1 }").as_deref(),
        Some("editor")
    );
    let seeded = cache["scenarios"]["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|step| step["entry"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(!seeded.is_empty(), "the seeded entries did not load");
    let misses = [
        "",
        "not json",
        "{",
        "null",
        "[]",
        "\"active\"",
        "{\"role\":\"x\"}",
        "{\"status\":\"active\"}",
        "{\"role\":1,\"status\":\"active\"}",
        "{\"role\":null,\"status\":\"active\"}",
        "{\"role\":\"x\",\"status\":\"ACTIVE\"}",
        "{\"role\":\"x\",\"status\":true}",
        "{\"role\":\"x\",\"status\":\"suspended\"}",
    ];
    for raw in seeded.iter().map(String::as_str).chain(misses) {
        assert_eq!(entry_role(raw), None, "{raw:?}");
    }
}

#[test]
fn a_blank_part_derives_no_cache_identifier() {
    let rule = section()["blankParts"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for blank in ["", " ", "\t\n", "\u{feff}", "\u{a0}\u{2003}"] {
        let cases = [
            (
                "tenantId",
                MembershipRef {
                    tenant_id: blank,
                    workspace_id: "w",
                    user_id: "u",
                },
            ),
            (
                "workspaceId",
                MembershipRef {
                    tenant_id: "t",
                    workspace_id: blank,
                    user_id: "u",
                },
            ),
            (
                "userId",
                MembershipRef {
                    tenant_id: "t",
                    workspace_id: "w",
                    user_id: blank,
                },
            ),
        ];
        for (part, member) in cases {
            assert!(rule.contains(part), "the rule does not name {part}");
            assert_eq!(
                MembershipCacheIds::derive(&hmac_key(), member),
                Err(BlankPart { part })
            );
        }
    }
}

#[test]
fn the_ttl_option_is_the_contracts() {
    let ttl = &section()["ttl"];
    let named: BTreeSet<&str> = ttl
        .as_object()
        .map(|map| map.keys().map(String::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        named,
        BTreeSet::from(["option", "default", "max", "zero", "appliesTo"])
    );
    assert_eq!(
        Some(MembershipCacheTtl::default().seconds()),
        ttl["default"].as_u64()
    );
    let max = ttl["max"].as_u64().unwrap_or_default();
    assert_eq!(max, MEMBERSHIP_CACHE_TTL_MAX_SECONDS);
    assert_eq!(
        MembershipCacheTtl::new(max).map(MembershipCacheTtl::seconds),
        Ok(max)
    );
    let refused = MembershipCacheTtl::new(max + 1)
        .err()
        .map(|error| error.to_string());
    let option = ttl["option"].as_str().unwrap_or("unread").to_owned();
    let got = format!("(got {})", max + 1);
    assert!(refused.is_some_and(|message| message.starts_with(&option) && message.ends_with(&got)));
    // Zero disables the cache, and the lifetime is the entry's only.
    assert!(
        ttl["zero"]
            .as_str()
            .is_some_and(|rule| rule.contains("disables"))
    );
    assert_eq!(MembershipCacheTtl::new(0), Ok(MembershipCacheTtl::DISABLED));
    assert_eq!(MembershipCacheTtl::DISABLED.entry_ttl(), None);
    assert_eq!(
        MembershipCacheTtl::default().entry_ttl().map(|t| t.get()),
        ttl["default"].as_u64()
    );
    assert!(
        ttl["appliesTo"]
            .as_str()
            .is_some_and(|rule| rule.contains("entry"))
    );
}

#[test]
fn the_counter_retention_is_the_token_epoch_retention() {
    let cache = section();
    let why = cache["versionRetentionWhy"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(why.contains("TOKEN_EPOCH_RETENTION_SECONDS"));
    assert_eq!(VERSION_RETENTION_SECONDS, TOKEN_EPOCH_RETENTION_SECS);
    assert_eq!(
        cache["versionRetentionSeconds"].as_u64(),
        Some(TOKEN_EPOCH_RETENTION_SECS)
    );
}
