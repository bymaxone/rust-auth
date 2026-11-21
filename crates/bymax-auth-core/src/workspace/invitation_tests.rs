//! The stored invitation record: the shape the shared contract pins, the round trip, and every
//! value that is not a record.

use serde_json::Value;

use super::invitation::{InvitationBase, InvitationRecord, RECORD_KEY_PREFIX, record_key};

fn contract_record() -> Value {
    let raw = include_str!("../../../../conformance/wire-contract.json");
    serde_json::from_str::<Value>(raw)
        .map(|root| root["workspaceInvitations"]["record"].clone())
        .unwrap_or(Value::Null)
}

fn base() -> InvitationBase {
    InvitationBase {
        email: "invitee@example.com".to_owned(),
        role: "member".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        workspace_id: "ws-1".to_owned(),
        created_at: "2026-11-20T10:00:00.000Z".to_owned(),
        resend_count: 2,
    }
}

fn member() -> InvitationRecord {
    InvitationRecord::Member {
        base: base(),
        inviter_user_id: "user-1".to_owned(),
    }
}

fn bootstrap() -> InvitationRecord {
    InvitationRecord::Bootstrap {
        base: base(),
        workspace_name: "Acme Inc".to_owned(),
    }
}

fn keys_of(record: &InvitationRecord) -> Vec<String> {
    let value: Value = serde_json::from_str(&record.to_json()).unwrap_or(Value::Null);
    let mut keys: Vec<String> = value
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn names(value: &Value) -> Vec<String> {
    let mut names: Vec<String> = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn each_kind_stores_exactly_the_fields_the_contract_names() {
    let contract = contract_record();
    let common = names(&contract["fields"]);
    assert!(!common.is_empty(), "the contract lists no record fields");
    for (record, kind) in [(member(), "member"), (bootstrap(), "bootstrap")] {
        let mut expected = common.clone();
        expected.extend(names(&contract["kinds"][kind]["adds"]));
        expected.sort();
        assert_eq!(keys_of(&record), expected, "{kind}");
        for forbidden in names(&contract["kinds"][kind]["forbids"]) {
            assert!(
                !keys_of(&record).contains(&forbidden),
                "{kind}: {forbidden}"
            );
        }
        assert_eq!(record.kind(), kind);
    }
}

#[test]
fn a_record_survives_a_round_trip_and_the_key_names_it_by_its_token_hash() {
    for record in [member(), bootstrap()] {
        assert_eq!(InvitationRecord::parse(&record.to_json()), Some(record));
    }
    assert_eq!(RECORD_KEY_PREFIX, "winv:");
    assert_eq!(record_key("abc"), "winv:abc");
}

#[test]
fn a_value_that_is_not_a_record_reads_as_absent() {
    let member_json = member().to_json();
    let bootstrap_json = bootstrap().to_json();
    let with = |json: &str, edit: &dyn Fn(&mut serde_json::Map<String, Value>)| -> String {
        let mut value: Value = serde_json::from_str(json).unwrap_or(Value::Null);
        if let Some(fields) = value.as_object_mut() {
            edit(fields);
        }
        value.to_string()
    };
    let cases: Vec<(&str, String)> = vec![
        ("not json", "winv".to_owned()),
        ("not an object", "[1]".to_owned()),
        ("null", "null".to_owned()),
        (
            "no kind",
            with(&member_json, &|f| {
                f.remove("kind");
            }),
        ),
        (
            "another kind",
            with(&member_json, &|f| {
                f.insert("kind".to_owned(), "owner".into());
            }),
        ),
        (
            "a numeric kind",
            with(&member_json, &|f| {
                f.insert("kind".to_owned(), 1.into());
            }),
        ),
        (
            "a member with no inviter",
            with(&member_json, &|f| {
                f.remove("inviterUserId");
            }),
        ),
        (
            "a member with a non-string inviter",
            with(&member_json, &|f| {
                f.insert("inviterUserId".to_owned(), 7.into());
            }),
        ),
        (
            "a member carrying a workspace name",
            with(&member_json, &|f| {
                f.insert("workspaceName".to_owned(), "Acme".into());
            }),
        ),
        (
            "a member with a null workspace name",
            with(&member_json, &|f| {
                f.insert("workspaceName".to_owned(), Value::Null);
            }),
        ),
        (
            "a bootstrap carrying an inviter",
            with(&bootstrap_json, &|f| {
                f.insert("inviterUserId".to_owned(), "user-1".into());
            }),
        ),
        (
            "a bootstrap with no name",
            with(&bootstrap_json, &|f| {
                f.remove("workspaceName");
            }),
        ),
        (
            "a bootstrap with an untrimmed name",
            with(&bootstrap_json, &|f| {
                f.insert("workspaceName".to_owned(), " Acme".into());
            }),
        ),
        (
            "a bootstrap with an empty name",
            with(&bootstrap_json, &|f| {
                f.insert("workspaceName".to_owned(), "".into());
            }),
        ),
        (
            "a missing email",
            with(&member_json, &|f| {
                f.remove("email");
            }),
        ),
        (
            "a non-string role",
            with(&member_json, &|f| {
                f.insert("role".to_owned(), 1.into());
            }),
        ),
        (
            "a missing tenant",
            with(&member_json, &|f| {
                f.remove("tenantId");
            }),
        ),
        (
            "a missing workspace",
            with(&member_json, &|f| {
                f.remove("workspaceId");
            }),
        ),
        (
            "a missing createdAt",
            with(&member_json, &|f| {
                f.remove("createdAt");
            }),
        ),
        (
            "a string resend count",
            with(&member_json, &|f| {
                f.insert("resendCount".to_owned(), "2".into());
            }),
        ),
        (
            "a negative resend count",
            with(&member_json, &|f| {
                f.insert("resendCount".to_owned(), (-1).into());
            }),
        ),
        (
            "a fractional resend count",
            with(&member_json, &|f| {
                f.insert("resendCount".to_owned(), 1.5.into());
            }),
        ),
    ];
    for (why, raw) in cases {
        assert_eq!(InvitationRecord::parse(&raw), None, "{why}: {raw}");
    }
}

#[test]
fn a_field_the_contract_does_not_list_is_ignored() {
    let mut value: Value = serde_json::from_str(&member().to_json()).unwrap_or(Value::Null);
    if let Some(fields) = value.as_object_mut() {
        fields.insert("futureField".to_owned(), true.into());
    }
    assert_eq!(InvitationRecord::parse(&value.to_string()), Some(member()));
}
