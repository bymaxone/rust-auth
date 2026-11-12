//! What `workspaceMembershipCache` pins for the bump and the fill, read from the shared contract and
//! compared with the two Lua scripts that implement them (layer: store adapter, tests).
//!
//! The behaviour itself runs against a real Redis in `tests/membership_cache_e2e.rs`; this file
//! holds the script text to the order of commands the contract names, and to the rule that every
//! key a script touches arrives in `KEYS`.

use serde_json::Value;

const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");
const BUMP: &str = include_str!("lua/membership_cache_bump.lua");
const FILL: &str = include_str!("lua/membership_cache_fill.lua");

/// A text statement of the `workspaceMembershipCache` section.
fn statement(name: &str) -> String {
    serde_json::from_str::<Value>(CONTRACT)
        .ok()
        .and_then(|root| {
            root["workspaceMembershipCache"][name]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// The script's code, comment lines dropped.
fn code(script: &str) -> String {
    script
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every `redis.call('CMD', <first argument>` of the script's code, in order.
fn calls(script: &str) -> Vec<(String, String)> {
    code(script)
        .split("redis.call('")
        .skip(1)
        .filter_map(|call| {
            let (command, rest) = call.split_once("', ")?;
            let argument = rest.split([',', ')']).next()?.trim().to_owned();
            Some((command.to_owned(), argument))
        })
        .collect()
}

/// `(command, KEYS[n])` pairs, for comparing with a list.
fn on(command: &str, slot: usize) -> (String, String) {
    (command.to_owned(), format!("KEYS[{slot}]"))
}

#[test]
fn a_bump_is_incr_then_expire_of_its_one_key() {
    let rule = statement("bump");
    let (incr, expire) = (rule.find("INCR"), rule.find("EXPIRE"));
    assert!(
        incr.is_some() && expire.is_some() && incr < expire,
        "{rule}"
    );
    assert!(rule.contains("every bump"));
    assert_eq!(calls(BUMP), [on("INCR", 1), on("EXPIRE", 1)]);
    // The expiry is unconditional: no branch stands between the two commands.
    assert!(!code(BUMP).contains("if "));
}

#[test]
fn a_fill_compares_both_counters_then_refreshes_those_that_exist_then_writes() {
    let rule = statement("entryRefreshesCounters");
    assert!(rule.contains("absent counts as 0") && rule.contains("extends every existing counter"));
    let expected = [
        on("GET", 1),
        on("GET", 2),
        on("EXISTS", 1),
        on("EXPIRE", 1),
        on("EXISTS", 2),
        on("EXPIRE", 2),
        on("SET", 3),
    ];
    assert_eq!(calls(FILL), expected);
    let code = code(FILL);
    // An absent counter compares as the text an absent counter reads as.
    let absent = statement("absentVersion");
    let zero = absent.split('\'').nth(1).unwrap_or("unread");
    assert_eq!(code.matches(&format!("or '{zero}'")).count(), 2);
    // The comparison returns before anything is written.
    let compared = code.find("return 'moved'");
    let first_write = code.find("redis.call('EXPIRE'");
    assert!(compared.is_some() && compared < first_write);
}

#[test]
fn every_key_a_cache_script_touches_is_declared() {
    for script in [BUMP, FILL] {
        let touched = calls(script);
        assert!(!touched.is_empty());
        for (command, argument) in touched {
            assert!(argument.starts_with("KEYS["), "{command} on {argument}");
        }
        assert!(
            !code(script).contains(".."),
            "a key is built inside the script"
        );
    }
}
