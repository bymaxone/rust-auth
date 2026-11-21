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
    let kinds: Vec<String> = contract["kinds"]
        .as_object()
        .map(|kinds| kinds.keys().cloned().collect())
        .unwrap_or_default();
    let mut tested = vec!["bootstrap".to_owned(), "member".to_owned()];
    tested.sort();
    let mut named = kinds;
    named.sort();
    assert_eq!(
        named, tested,
        "the contract's kinds and the tested kinds differ"
    );
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

/// One change to a stored record.
enum Edit {
    Drop(&'static str),
    Set(&'static str, Value),
}

fn edited(json: &str, edit: &Edit) -> String {
    let mut value: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    if let Some(fields) = value.as_object_mut() {
        match edit {
            Edit::Drop(name) => {
                fields.remove(*name);
            }
            Edit::Set(name, to) => {
                fields.insert((*name).to_owned(), to.clone());
            }
        }
    }
    value.to_string()
}

/// Requires every edit of `json` to read as absent.
fn all_read_as_absent(json: &str, cases: Vec<(&str, Edit)>) {
    for (why, edit) in cases {
        let raw = edited(json, &edit);
        assert_eq!(InvitationRecord::parse(&raw), None, "{why}: {raw}");
    }
}

#[test]
fn text_that_is_not_an_object_reads_as_absent() {
    for raw in ["winv", "[1]", "null", ""] {
        assert_eq!(InvitationRecord::parse(raw), None, "{raw}");
    }
}

#[test]
fn a_kind_that_is_missing_or_unknown_reads_as_absent() {
    all_read_as_absent(
        &member().to_json(),
        vec![
            ("no kind", Edit::Drop("kind")),
            ("another kind", Edit::Set("kind", "owner".into())),
            ("a numeric kind", Edit::Set("kind", 1.into())),
        ],
    );
}

#[test]
fn a_member_that_breaks_its_shape_reads_as_absent() {
    all_read_as_absent(
        &member().to_json(),
        vec![
            ("no inviter", Edit::Drop("inviterUserId")),
            ("a non-string inviter", Edit::Set("inviterUserId", 7.into())),
            (
                "a workspace name",
                Edit::Set("workspaceName", "Acme".into()),
            ),
            (
                "a null workspace name",
                Edit::Set("workspaceName", Value::Null),
            ),
        ],
    );
}

#[test]
fn a_bootstrap_that_breaks_its_shape_reads_as_absent() {
    all_read_as_absent(
        &bootstrap().to_json(),
        vec![
            ("an inviter", Edit::Set("inviterUserId", "user-1".into())),
            ("no name", Edit::Drop("workspaceName")),
            (
                "an untrimmed name",
                Edit::Set("workspaceName", " Acme".into()),
            ),
            ("an empty name", Edit::Set("workspaceName", "".into())),
        ],
    );
}

#[test]
fn a_record_missing_or_mistyping_a_common_field_reads_as_absent() {
    all_read_as_absent(
        &member().to_json(),
        vec![
            ("a missing email", Edit::Drop("email")),
            ("a non-string role", Edit::Set("role", 1.into())),
            ("a missing tenant", Edit::Drop("tenantId")),
            ("a missing workspace", Edit::Drop("workspaceId")),
            ("a missing createdAt", Edit::Drop("createdAt")),
            (
                "a string resend count",
                Edit::Set("resendCount", "2".into()),
            ),
            (
                "a negative resend count",
                Edit::Set("resendCount", (-1).into()),
            ),
            (
                "a fractional resend count",
                Edit::Set("resendCount", 1.5.into()),
            ),
        ],
    );
}

#[test]
fn a_field_the_contract_does_not_list_is_ignored() {
    let mut value: Value = serde_json::from_str(&member().to_json()).unwrap_or(Value::Null);
    if let Some(fields) = value.as_object_mut() {
        fields.insert("futureField".to_owned(), true.into());
    }
    assert_eq!(InvitationRecord::parse(&value.to_string()), Some(member()));
}
