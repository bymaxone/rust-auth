//! The owner-role name rule against `workspaceOwnerRole` of the shared contract (layer: domain,
//! tests).
//!
//! Every vector is read from `conformance/wire-contract.json`; none is typed here. A refusal that
//! needs ill-formed UTF-16 is not run through the checker, because a `&str` cannot hold it: the
//! test proves instead that the string the contract describes is not valid text, so the refusal
//! holds by the type.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::bounds::{OWNER_ROLE_MAX_CHARS, is_valid_owner_role};
use super::tests::contract;
use crate::config::{WorkspaceRolesConfig, WorkspacesConfig};
use crate::error::ConfigError;

/// One `refuses` entry of the section.
struct Refusal {
    case: String,
    value: String,
    unpaired: Option<Vec<u16>>,
}

/// The section, or an empty map when it did not load (which fails the first assertion using it).
fn section() -> Map<String, Value> {
    contract()["workspaceOwnerRole"]
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// The strings listed under `accepts`.
fn accepts() -> Vec<String> {
    let list = section().remove("accepts").unwrap_or_default();
    let items = list.as_array().cloned().unwrap_or_default();
    let strings: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect();
    assert_eq!(strings.len(), items.len(), "accepts holds a non-string");
    strings
}

/// The code units of an `unpairedSurrogateCodeUnits` list.
fn code_units(units: &Value) -> Vec<u16> {
    let list = units.as_array().cloned().unwrap_or_default();
    let parsed: Vec<u16> = list
        .iter()
        .filter_map(|unit| unit.as_u64().and_then(|n| u16::try_from(n).ok()))
        .collect();
    assert_eq!(
        parsed.len(),
        list.len(),
        "a code unit is not a 16-bit integer"
    );
    parsed
}

/// One `refuses` entry taken apart field by field; a field it gains later fails here until it is
/// understood.
fn refusal(item: &Value) -> Refusal {
    let mut entry = item.as_object().cloned().unwrap_or_default();
    let text = |value: Option<Value>| value.and_then(|v| v.as_str().map(str::to_owned));
    let case = text(entry.remove("case"));
    let value = text(entry.remove("value"));
    let unpaired = entry
        .remove("unpairedSurrogateCodeUnits")
        .map(|units| code_units(&units));
    assert!(
        entry.is_empty(),
        "an unknown key in a refuses entry: {entry:?}"
    );
    assert!(
        case.is_some() && value.is_some(),
        "an entry lacks case or value"
    );
    Refusal {
        case: case.unwrap_or_default(),
        value: value.unwrap_or_default(),
        unpaired,
    }
}

/// The entries listed under `refuses`.
fn refusals() -> Vec<Refusal> {
    let list = section().remove("refuses").unwrap_or_default();
    let items = list.as_array().cloned().unwrap_or_default();
    assert!(!items.is_empty(), "refuses did not load");
    items.iter().map(refusal).collect()
}

/// An enabled group whose hierarchy is the single role `owner`.
fn group_with_owner(owner: &str) -> WorkspacesConfig {
    WorkspacesConfig {
        enabled: true,
        roles: WorkspaceRolesConfig {
            hierarchy: BTreeMap::from([(owner.to_owned(), Vec::new())]),
            owner_role: owner.to_owned(),
        },
        ..WorkspacesConfig::default()
    }
}

/// Runs one refusal and returns its case name; panics through `assert!` when it holds nowhere.
fn exercise(entry: &Refusal) -> String {
    if let Some(units) = &entry.unpaired {
        let mut utf16: Vec<u16> = entry.value.encode_utf16().collect();
        utf16.extend(units);
        assert!(
            String::from_utf16(&utf16).is_err(),
            "{}: the contract's string is well-formed, so a `&str` could hold it",
            entry.case
        );
        return entry.case.clone();
    }
    assert!(!is_valid_owner_role(&entry.value), "{}", entry.case);
    let refused = group_with_owner(&entry.value).resolve();
    assert!(
        matches!(&refused, Err(ConfigError::WorkspaceOwnerRole { value }) if *value == entry.value),
        "{}: not refused as a malformed owner role",
        entry.case
    );
    let text = refused
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        text.contains("workspaces.roles.ownerRole"),
        "{}",
        entry.case
    );
    entry.case.clone()
}

#[test]
fn the_section_has_exactly_the_keys_this_rule_knows_and_the_bound_is_its_maximum() {
    let keys: BTreeSet<String> = section().keys().cloned().collect();
    let known: BTreeSet<String> = ["$comment", "maxLength", "accepts", "refuses"]
        .map(str::to_owned)
        .into();
    assert_eq!(keys, known);
    assert_eq!(
        section()["maxLength"].as_u64(),
        Some(OWNER_ROLE_MAX_CHARS as u64)
    );
}

#[test]
fn every_accepted_name_is_a_valid_owner_role_and_starts_the_engine_config() {
    let names = accepts();
    assert!(!names.is_empty(), "accepts did not load");
    for name in names {
        assert!(is_valid_owner_role(&name), "{name:?}");
        assert!(
            matches!(group_with_owner(&name).resolve(), Ok(Some(_))),
            "{name:?} was refused at startup"
        );
    }
}

#[test]
fn every_refused_name_is_refused_at_startup_naming_the_option_and_the_value() {
    let entries = refusals();
    let mut exercised = BTreeSet::new();
    for entry in &entries {
        let case = exercise(entry);
        assert!(exercised.insert(case.clone()), "{case} is listed twice");
    }
    let named: BTreeSet<String> = entries.into_iter().map(|entry| entry.case).collect();
    assert_eq!(exercised, named);
}

#[test]
fn only_the_owner_role_is_constrained() {
    let odd = "\u{1f600}".repeat(OWNER_ROLE_MAX_CHARS + 1);
    let mut config = group_with_owner("owner");
    config.roles.hierarchy =
        BTreeMap::from([("owner".to_owned(), vec![odd.clone()]), (odd, Vec::new())]);
    assert!(matches!(config.resolve(), Ok(Some(_))));
}
