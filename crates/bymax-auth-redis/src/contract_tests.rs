//! What the shared wire contract pins for the recovery-code claim's value and for the grace
//! recovery write, read from the contract and compared with the code that implements them: the
//! marker value this crate writes and the script that performs the write. The lock and claim
//! TTLs, nonce width and key derivations are pinned beside the engine that chooses them.

use std::collections::BTreeSet;

use bymax_auth_types::AuthError;
use serde_json::Value;

#[cfg(feature = "mfa")]
use crate::keys::Prefix;
#[cfg(feature = "mfa")]
use crate::stores::mfa::SINGLE_USE_MARKER_VALUE;

const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");
const RECOVER_GRACE: &str = include_str!("lua/recover_grace.lua");

/// The `KEYS[n]` slots of `recover_grace.lua`, named as the contract names what they hold.
const SLOT_NAMES: [(usize, &str); 4] = [
    (1, "refreshSession"),
    (2, "sessionIndex"),
    (3, "sessionDetail"),
    (4, "familyIndex"),
];

fn section(name: &str) -> Value {
    serde_json::from_str::<Value>(CONTRACT).map_or(Value::Null, |root| root[name].clone())
}

fn slot_name(slot: usize) -> &'static str {
    SLOT_NAMES
        .iter()
        .find(|(candidate, _)| *candidate == slot)
        .map_or("", |(_, name)| name)
}

/// Every `redis.call('CMD', KEYS[n]` of the script's code (comment lines skipped), in order.
fn script_calls() -> Vec<(String, usize)> {
    let code: String = RECOVER_GRACE
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    code.split("redis.call('")
        .skip(1)
        .filter_map(|call| {
            let (command, rest) = call.split_once("', KEYS[")?;
            let slot = rest.split_once(']')?.0.parse().ok()?;
            Some((command.to_owned(), slot))
        })
        .collect()
}

/// The distinct slots touched by `commands`, in first-use order, as contract names.
fn names_for(commands: &[&str]) -> Vec<String> {
    let mut seen = Vec::new();
    for (command, slot) in script_calls() {
        let name = slot_name(slot).to_owned();
        if commands.contains(&command.as_str()) && !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

#[cfg(feature = "mfa")]
#[test]
fn the_recovery_claim_marker_value_is_the_contracts() {
    let value = section("recoveryCodeClaim")["value"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // "'1' — presence is the whole meaning"
    assert!(
        value.starts_with(&format!("'{SINGLE_USE_MARKER_VALUE}'")),
        "{value}"
    );
    assert_eq!(Prefix::Rcu.as_str(), "rcu");
}

#[test]
fn the_grace_write_section_carries_exactly_the_fields_this_file_pins() {
    let fields: BTreeSet<String> = section("graceRecoveryWrite")
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    let expected = ["$comment", "gate", "refusedError", "writes"];
    assert_eq!(fields, expected.iter().map(|f| (*f).to_owned()).collect());
}

#[test]
fn the_script_writes_what_the_contract_lists_and_only_after_its_gate() {
    let contract = section("graceRecoveryWrite");
    let listed: Vec<String> = contract["writes"]
        .as_array()
        .map(|writes| {
            writes
                .iter()
                .filter_map(|w| w.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names_for(&["SET", "SADD"]), listed);

    let calls = script_calls();
    let last_gate = calls.iter().rposition(|(command, _)| command == "EXISTS");
    let first_write = calls
        .iter()
        .position(|(command, _)| command == "SET" || command == "SADD");
    assert!(
        last_gate < first_write,
        "a write precedes a gate: {calls:?}"
    );
}

#[test]
fn the_script_gates_on_the_witnesses_the_contract_names() {
    let gate = section("graceRecoveryWrite")["gate"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let named: Vec<String> = gate
        .split("EXISTS {")
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_owned()))
        .collect();
    assert_eq!(names_for(&["EXISTS"]), named);
    // The family witness is conditional on the record naming a family, in the contract and in
    // the script alike.
    assert!(gate.ends_with("when the record names a family"), "{gate}");
    assert!(RECOVER_GRACE.contains("if ARGV[4] ~= '' and redis.call('EXISTS', KEYS[4]) == 0"));
}

#[test]
fn a_refused_grace_write_surfaces_as_the_contracts_error() {
    let wire = serde_json::to_value(AuthError::RefreshTokenInvalid.code()).unwrap_or_default();
    assert_eq!(
        wire.as_str(),
        section("graceRecoveryWrite")["refusedError"].as_str()
    );
}
