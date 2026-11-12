//! The workspace derivations and bounds against the shared contract (layer: domain, tests).
//!
//! Every vector is read from `conformance/wire-contract.json` and derived here; none is typed into
//! this file. Each vector's fields are taken out of a copy of the object one by one and the copy
//! must end up empty, so a field a later contract adds fails until it is derived.

use serde_json::{Map, Value};

use super::bounds::{
    CURSOR_MAX_CHARS, IDENTIFIER_MAX_CHARS, PAGE_LIMIT_DEFAULT, PAGE_LIMIT_MAX, check_cursor,
    check_identifier, is_blank, normalize_workspace_name, parse_page_limit,
};
use super::keys::{
    BlankPart, invitation_email_subject, invitation_index_id, invitation_record_id,
    invitation_set_id, inviter_rate_id, inviter_rate_subject, membership_cache_id,
    membership_subject, membership_version_id, subject_hash, workspace_subject,
    workspace_version_id,
};
use super::limits::{
    INVITATION_MAX_RESENDS, INVITATION_RESEND_COOLDOWN_SECONDS, INVITATIONS_PER_INVITER_PER_WINDOW,
    INVITER_WINDOW_SECONDS, MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS, MEMBERSHIP_CACHE_TTL_MAX_SECONDS,
    VERSION_RETENTION_SECONDS,
};
use super::scoped_name::{ScopedNameError, workspace_scoped_name};

/// A file of the shared artefacts, parsed; `Null` when it cannot be read, which fails every
/// assertion below instead of passing them over nothing.
fn shared(file: &str) -> Value {
    let path = format!("{}/../../conformance/{file}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or(Value::Null)
}

fn contract() -> Value {
    shared("wire-contract.json")
}

/// The identifier-HMAC key the vectors use: the hex text of `hmacKeyDerivation`'s derived key.
fn hmac_key() -> [u8; 64] {
    let root = contract();
    let hex = root["hmacKeyDerivation"]["vectors"][0]["derivedKeyHex"]
        .as_str()
        .unwrap_or_default();
    let mut key = [0_u8; 64];
    assert_eq!(hex.len(), 64, "the pinned derived key did not load");
    key.copy_from_slice(hex.as_bytes());
    key
}

/// The prefix the contract names for a key family.
fn prefix(name: &str) -> String {
    contract()["redisKeyPrefixes"][name]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The vectors of a section as objects, and a failure when there are none.
fn vectors(section: &Value) -> Vec<Map<String, Value>> {
    let list: Vec<Map<String, Value>> = section
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_object().cloned())
        .collect();
    assert!(!list.is_empty(), "a vector section did not load");
    list
}

/// Removes `field` from `vector` and returns it as text.
fn take(vector: &mut Map<String, Value>, field: &str) -> String {
    let value = vector.remove(field);
    assert!(value.is_some(), "the vector has no field {field}");
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// A `{namespace}`-relative key: the contract writes the namespace as a placeholder.
fn key(prefix_name: &str, id: &str) -> String {
    format!("{{namespace}}:{}:{id}", prefix(prefix_name))
}

#[test]
fn the_membership_vectors_are_derived_from_their_inputs() {
    let hmac = hmac_key();
    let root = contract();
    for mut vector in vectors(&root["workspaceMembershipCache"]["vectors"]) {
        let (tenant, workspace, user) = (
            take(&mut vector, "tenantId"),
            take(&mut vector, "workspaceId"),
            take(&mut vector, "userId"),
        );
        let subject = workspace_subject(&tenant, &workspace).unwrap_or_default();
        assert_eq!(subject, take(&mut vector, "workspaceSubject"));
        assert_eq!(
            subject_hash(&hmac, &subject),
            take(&mut vector, "workspaceDigestHex")
        );
        let member = membership_subject(&tenant, &workspace, &user).unwrap_or_default();
        assert_eq!(member, take(&mut vector, "membershipSubject"));
        assert_eq!(
            subject_hash(&hmac, &member),
            take(&mut vector, "membershipDigestHex")
        );
        assert!(vector.is_empty(), "underived fields: {vector:?}");
    }
}

#[test]
fn the_membership_keys_are_derived_from_their_inputs() {
    let hmac = hmac_key();
    let root = contract();
    for mut vector in vectors(&root["workspaceMembershipCache"]["fullKeyVectors"]) {
        let (tenant, workspace, user) = (
            take(&mut vector, "tenantId"),
            take(&mut vector, "workspaceId"),
            take(&mut vector, "userId"),
        );
        let versions: (u64, u64) = (
            take(&mut vector, "workspaceVersion")
                .parse()
                .unwrap_or(u64::MAX),
            take(&mut vector, "membershipVersion")
                .parse()
                .unwrap_or(u64::MAX),
        );
        let workspace_version =
            workspace_version_id(&hmac, &tenant, &workspace).unwrap_or_default();
        assert_eq!(
            key("workspaceVersion", &workspace_version),
            take(&mut vector, "workspaceVersionKey")
        );
        let membership_version =
            membership_version_id(&hmac, &tenant, &workspace, &user).unwrap_or_default();
        assert_eq!(
            key("membershipVersion", &membership_version),
            take(&mut vector, "membershipVersionKey")
        );
        let cache = membership_cache_id(&hmac, &tenant, &workspace, &user, versions);
        assert_eq!(
            key("membershipCache", &cache.unwrap_or_default()),
            take(&mut vector, "membershipCacheKey")
        );
        assert!(vector.is_empty(), "underived fields: {vector:?}");
    }
}

#[test]
fn the_invitation_keys_are_derived_from_their_inputs() {
    let hmac = hmac_key();
    let root = contract();
    for mut vector in vectors(&root["workspaceInvitations"]["fullKeyVectors"]) {
        let (tenant, workspace, email) = (
            take(&mut vector, "tenantId"),
            take(&mut vector, "workspaceId"),
            take(&mut vector, "email"),
        );
        let index_subject = invitation_email_subject(&tenant, &workspace, &email);
        assert_eq!(
            index_subject.unwrap_or_default(),
            take(&mut vector, "indexSubject")
        );
        let index = invitation_index_id(&hmac, &tenant, &workspace, &email);
        assert_eq!(
            key("workspaceInvitationIndex", &index.unwrap_or_default()),
            take(&mut vector, "indexKey")
        );
        assert_eq!(
            workspace_subject(&tenant, &workspace).unwrap_or_default(),
            take(&mut vector, "setSubject")
        );
        let set = invitation_set_id(&hmac, &tenant, &workspace);
        assert_eq!(
            key("workspaceInvitationSet", &set.unwrap_or_default()),
            take(&mut vector, "setKey")
        );
        let record = invitation_record_id(&take(&mut vector, "token"));
        assert_eq!(
            key("workspaceInvitation", &record),
            take(&mut vector, "recordKey")
        );
        assert!(vector.is_empty(), "underived fields: {vector:?}");
    }
}

#[test]
fn the_inviter_rate_keys_are_derived_from_their_inputs() {
    let hmac = hmac_key();
    let root = contract();
    for mut vector in vectors(&root["workspaceInvitations"]["inviterRateVectors"]) {
        let (tenant, user) = (take(&mut vector, "tenantId"), take(&mut vector, "userId"));
        assert_eq!(
            inviter_rate_subject(&tenant, &user).unwrap_or_default(),
            take(&mut vector, "subject")
        );
        let id = inviter_rate_id(&hmac, &tenant, &user).unwrap_or_default();
        assert_eq!(
            key("workspaceInvitationInviterRate", &id),
            take(&mut vector, "key")
        );
        assert!(vector.is_empty(), "underived fields: {vector:?}");
    }
}

#[test]
fn the_identifier_preimages_are_the_contracts() {
    // The templates are written in the contract; deriving a subject from known parts and
    // rendering the template by hand over the same parts must agree.
    let root = contract();
    let templates = &root["identifierPreimages"];
    let render = |name: &str, tenant: &str, workspace: &str, rest: &str| -> String {
        templates[name]
            .as_str()
            .unwrap_or_default()
            .replace("{utf8ByteLength(tenantId)}", &tenant.len().to_string())
            .replace("{tenantId}", tenant)
            .replace(
                "{utf8ByteLength(workspaceId)}",
                &workspace.len().to_string(),
            )
            .replace("{workspaceId}", workspace)
            .replace("{email}", rest)
            .replace("{userId}", rest)
    };
    let (tenant, workspace, rest) = ("acme:prod", "w\u{e9}:1", "x@y.z");
    assert_eq!(
        invitation_email_subject(tenant, workspace, rest).unwrap_or_default(),
        render("workspaceInvitationEmail", tenant, workspace, rest)
    );
    assert_eq!(
        inviter_rate_subject(tenant, rest).unwrap_or_default(),
        render("workspaceInviterRate", tenant, "", rest)
    );
}

#[test]
fn two_free_parts_never_share_a_subject() {
    // The tenant and the workspace may both hold `:`; the length prefix keeps the boundary.
    let split_early = workspace_subject("a:b", "c");
    let split_late = workspace_subject("a", "b:c");
    assert!(split_early.is_ok() && split_late.is_ok());
    assert_ne!(split_early, split_late);
    assert_ne!(
        membership_subject("a:b", "c", "d"),
        membership_subject("a", "b:c", "d")
    );
    assert_ne!(
        invitation_email_subject("a:b", "c", "x"),
        invitation_email_subject("a", "b:c", "x")
    );
    // The length counts bytes: "é" is two, so a two-byte tenant is not a one-character one.
    assert_eq!(
        workspace_subject("\u{e9}", "w").unwrap_or_default(),
        "wsp:2:\u{e9}:1:w"
    );
}

#[test]
fn a_blank_part_derives_no_key() {
    for blank in ["", " ", "\t\n", "\u{feff}", "\u{a0}\u{2003}"] {
        let refused = Err(BlankPart { part: "tenantId" });
        assert_eq!(workspace_subject(blank, "w"), refused);
        assert_eq!(
            workspace_subject("t", blank),
            Err(BlankPart {
                part: "workspaceId"
            })
        );
        assert_eq!(
            membership_subject("t", "w", blank),
            Err(BlankPart { part: "userId" })
        );
        assert_eq!(inviter_rate_subject(blank, "u"), refused);
        assert_eq!(
            inviter_rate_subject("t", blank),
            Err(BlankPart { part: "userId" })
        );
        assert_eq!(invitation_email_subject(blank, "w", "e"), refused);
    }
    assert_eq!(
        BlankPart { part: "userId" }.to_string(),
        "userId must not be blank"
    );
    // JavaScript's `trim` knows U+FEFF and not U+0085; `char::is_whitespace` knows the opposite.
    assert!(is_blank("\u{feff}"));
    assert!(!is_blank("\u{85}"));
    assert!(!is_blank(" a "));
}

#[test]
fn the_scoped_names_are_the_contracts() {
    let root = contract();
    for mut vector in vectors(&root["workspaceScopedName"]["vectors"]) {
        let case = take(&mut vector, "case");
        let args: Vec<String> = vector
            .remove("args")
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();
        let mut owned = args;
        let mut refused_by_type = false;
        if let Some(units) = vector.remove("unpairedSurrogateCodeUnits") {
            let units: Vec<u16> = serde_json::from_value(units).unwrap_or_default();
            // An unpaired surrogate has no UTF-8 form, so a `&str` cannot carry one.
            match String::from_utf16(&units) {
                Ok(part) => owned.push(part),
                Err(_) => refused_by_type = true,
            }
        }
        let parts: Vec<&str> = owned.iter().skip(2).map(String::as_str).collect();
        let built = workspace_scoped_name(&owned[0], &owned[1], &parts);
        let (name, refused) = (vector.remove("name"), vector.remove("refused"));
        assert!(
            name.is_some() != refused.is_some(),
            "{case}: a vector needs exactly one of name and refused"
        );
        if let Some(name) = name {
            assert_eq!(built.as_deref().ok(), name.as_str(), "{case}");
            assert!(!refused_by_type, "{case}");
        }
        if let Some(reason) = refused {
            let reason = reason.as_str().unwrap_or_default();
            let expected = match reason {
                "control character" => Some(ScopedNameError::ControlCharacter),
                "empty tenant" => Some(ScopedNameError::EmptyTenant),
                "empty workspace" => Some(ScopedNameError::EmptyWorkspace),
                _ => None,
            };
            let known = expected.is_some() || reason == "unpaired surrogate";
            assert!(known, "{case}: an unknown refusal {reason}");
            match expected {
                Some(error) => assert_eq!(built, Err(error), "{case}"),
                None => assert!(refused_by_type, "{case}"),
            }
        }
        assert!(vector.is_empty(), "{case}: underived fields {vector:?}");
    }
}

#[test]
fn the_limits_are_the_contracts() {
    let root = contract();
    let cache = &root["workspaceMembershipCache"];
    assert_eq!(
        cache["versionRetentionSeconds"].as_u64(),
        Some(VERSION_RETENTION_SECONDS)
    );
    assert_eq!(
        cache["ttl"]["default"].as_u64(),
        Some(MEMBERSHIP_CACHE_TTL_DEFAULT_SECONDS)
    );
    assert_eq!(
        cache["ttl"]["max"].as_u64(),
        Some(MEMBERSHIP_CACHE_TTL_MAX_SECONDS)
    );
    let rules = &root["workspaceInvitations"]["rules"];
    assert_eq!(
        rules["resendCooldownSeconds"].as_u64(),
        Some(INVITATION_RESEND_COOLDOWN_SECONDS)
    );
    assert_eq!(
        rules["maxResends"].as_u64(),
        Some(u64::from(INVITATION_MAX_RESENDS))
    );
    assert_eq!(
        rules["invitationsPerInviterPerHour"].as_u64(),
        Some(u64::from(INVITATIONS_PER_INVITER_PER_WINDOW))
    );
    // The limit is per hour.
    assert_eq!(INVITER_WINDOW_SECONDS, 60 * 60);
}

#[test]
fn the_bounds_are_the_contracts() {
    let root = contract();
    let bounds = &root["requestFieldBounds"];
    let read = |entry: &Value, key: &str| entry[key].as_u64().unwrap_or(u64::MAX);
    assert_eq!(read(&bounds["workspaceName"], "min"), 1);
    assert_eq!(
        read(&bounds["workspaceName"], "max"),
        super::bounds::WORKSPACE_NAME_MAX_CHARS as u64
    );
    assert_eq!(
        read(&bounds["memberUserId"], "max"),
        IDENTIFIER_MAX_CHARS as u64
    );
    assert_eq!(read(&bounds["memberUserId"], "min"), 1);
    let checked = ["workspaceId", "userId"];
    let named: std::collections::BTreeSet<&str> = bounds["pathParameters"]
        .as_object()
        .map(|map| {
            map.keys()
                .filter(|key| !key.starts_with('$'))
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(named, checked.into_iter().collect());
    for field in checked {
        assert_eq!(
            read(&bounds["pathParameters"][field], "max"),
            IDENTIFIER_MAX_CHARS as u64
        );
        assert_eq!(read(&bounds["pathParameters"][field], "min"), 1);
    }
    assert_eq!(read(&bounds["pageLimit"], "min"), 1);
    assert_eq!(read(&bounds["pageLimit"], "max"), u64::from(PAGE_LIMIT_MAX));
    assert_eq!(
        read(&bounds["pageLimit"], "default"),
        u64::from(PAGE_LIMIT_DEFAULT)
    );
    // The cursor bound and the `limit` pattern are written in the request schemas.
    let page =
        &shared("openapi-request-schemas.json")["schemas"]["WorkspacePageQueryDto"]["properties"];
    assert_eq!(
        page["cursor"]["maxLength"].as_u64(),
        Some(CURSOR_MAX_CHARS as u64)
    );
    assert_eq!(page["cursor"]["minLength"].as_u64(), Some(1));
    assert_eq!(
        page["limit"]["pattern"].as_str(),
        Some("^(?:[1-9][0-9]?|100)$")
    );
}

#[test]
fn a_page_limit_is_a_plain_whole_number_from_one_to_a_hundred() {
    assert_eq!(parse_page_limit(None), Ok(PAGE_LIMIT_DEFAULT));
    for accepted in 1..=100_u32 {
        let text = accepted.to_string();
        assert_eq!(
            parse_page_limit(Some(&text)).map(u32::from),
            Ok(accepted),
            "{text}"
        );
    }
    let mut refused: Vec<String> = (101..=1000).map(|n: u32| n.to_string()).collect();
    refused.extend(
        [
            "",
            "0",
            "00",
            "05",
            "005",
            "+5",
            "-5",
            " 5",
            "5 ",
            "5.0",
            "5e1",
            "0x10",
            "1_0",
            "\u{663}",
            "256",
            "300",
            "99999999999",
        ]
        .map(str::to_owned),
    );
    for text in refused {
        assert_eq!(
            parse_page_limit(Some(&text)),
            Err(super::bounds::OutOfBounds { field: "limit" }),
            "{text:?}"
        );
    }
}

#[test]
fn a_cursor_is_one_to_512_characters_without_controls() {
    assert!(check_cursor("a").is_ok());
    assert!(check_cursor(&"\u{e9}".repeat(CURSOR_MAX_CHARS)).is_ok());
    for refused in [
        String::new(),
        "x".repeat(CURSOR_MAX_CHARS + 1),
        "a\u{0}b".to_owned(),
        "a\u{7f}".to_owned(),
        "\u{85}".to_owned(),
    ] {
        assert_eq!(
            check_cursor(&refused),
            Err(super::bounds::OutOfBounds { field: "cursor" })
        );
    }
}

#[test]
fn an_identifier_is_one_to_128_characters_not_blank_and_without_controls() {
    assert!(check_identifier("userId", "u%1+x").is_ok());
    assert!(check_identifier("userId", &"\u{e9}".repeat(IDENTIFIER_MAX_CHARS)).is_ok());
    for refused in [
        String::new(),
        " ".to_owned(),
        "\u{feff}".to_owned(),
        "x".repeat(IDENTIFIER_MAX_CHARS + 1),
        "a\tb".to_owned(),
        "a\u{9f}".to_owned(),
    ] {
        assert_eq!(
            check_identifier("workspaceId", &refused),
            Err(super::bounds::OutOfBounds {
                field: "workspaceId"
            })
        );
    }
}

#[test]
fn a_workspace_name_is_bounded_as_submitted_and_stored_trimmed() {
    assert_eq!(normalize_workspace_name("  Acme  ").as_deref(), Ok("Acme"));
    assert_eq!(
        normalize_workspace_name("\u{feff}Acme\u{3000}").as_deref(),
        Ok("Acme")
    );
    // The bound counts characters as submitted: 120 fit, 121 do not, padding included.
    assert!(normalize_workspace_name(&"a".repeat(120)).is_ok());
    assert!(normalize_workspace_name(&"\u{e9}".repeat(120)).is_ok());
    let padded = format!("{} ", "a".repeat(120));
    assert!(normalize_workspace_name(&padded).is_err());
    for refused in [
        "", "   ", "\u{feff}", "a\u{0}b", "\tAcme", "Acme\n", "a\u{85}",
    ] {
        assert_eq!(
            normalize_workspace_name(refused),
            Err(super::bounds::OutOfBounds { field: "name" }),
            "{refused:?}"
        );
    }
    assert_eq!(
        super::bounds::OutOfBounds { field: "name" }.to_string(),
        "name is out of bounds"
    );
}

#[test]
fn a_scoped_name_error_says_what_was_refused() {
    assert_eq!(
        ScopedNameError::ControlCharacter.to_string(),
        "a piece contains a control character"
    );
    assert_eq!(
        ScopedNameError::EmptyTenant.to_string(),
        "the tenant is empty"
    );
    assert_eq!(
        ScopedNameError::EmptyWorkspace.to_string(),
        "the workspace is empty"
    );
}
