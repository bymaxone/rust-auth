//! Which store failures answer `503 auth.service_unavailable`, read from the shared contract's
//! `serviceUnavailable.outage` lists and compared with the classification in `error.rs`. Each list
//! is checked in both directions, so a prefix added to the contract fails here until the code
//! classifies it, and one removed fails until the removal is understood.

use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind as IoKind};

use bymax_auth_types::AuthError;
use deadpool_redis::{PoolError, TimeoutType};
use redis::make_extension_error;
use serde_json::Value;

use crate::error::{OUTAGE_REPLY_PREFIXES, RedisStoreError};

const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");

/// A string list under `serviceUnavailable.outage.<name>`.
fn outage_list(name: &str) -> BTreeSet<String> {
    let root: Value = serde_json::from_str(CONTRACT).unwrap_or(Value::Null);
    root["serviceUnavailable"]["outage"][name]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A server error reply with the given prefix, as the store reports it.
fn reply(prefix: &str) -> AuthError {
    let error = make_extension_error(prefix.to_owned(), Some("detail".to_owned()));
    RedisStoreError::Command(error).into()
}

fn is_unavailable(error: &AuthError) -> bool {
    matches!(error, AuthError::ServiceUnavailable(_))
}

#[test]
fn the_outage_reply_prefixes_are_the_contracts_and_answer_503() {
    let contract = outage_list("replyPrefixes");
    let code: BTreeSet<String> = OUTAGE_REPLY_PREFIXES
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    assert!(!contract.is_empty(), "the contract lists no reply prefixes");
    assert_eq!(
        code, contract,
        "the classified prefixes drifted from the contract"
    );
    for prefix in &contract {
        assert!(is_unavailable(&reply(prefix)), "{prefix} must answer 503");
    }
}

#[test]
fn a_reply_about_the_command_or_an_unclassified_one_stays_internal() {
    let mut refused = outage_list("notAnOutageReplyPrefixes");
    assert!(
        !refused.is_empty(),
        "the contract lists no refused prefixes"
    );
    // The contract names these two as unclassified today, answering 500.
    refused.insert("BUSY".to_owned());
    refused.insert("MISCONF".to_owned());
    for prefix in &refused {
        assert!(
            matches!(reply(prefix), AuthError::Internal(_)),
            "{prefix} must answer 500"
        );
    }
}

/// The `io::ErrorKind` each contract network code surfaces as through the Redis client.
fn io_kind(code: &str) -> Option<IoKind> {
    match code {
        "ECONNREFUSED" => Some(IoKind::ConnectionRefused),
        "ECONNRESET" => Some(IoKind::ConnectionReset),
        "ETIMEDOUT" => Some(IoKind::TimedOut),
        "EPIPE" => Some(IoKind::BrokenPipe),
        "EHOSTUNREACH" | "ENETUNREACH" | "ENOTFOUND" | "EAI_AGAIN" => Some(IoKind::Other),
        _ => None,
    }
}

#[test]
fn every_network_error_of_the_contract_is_an_outage() {
    let codes = outage_list("networkErrorCodes");
    assert!(
        !codes.is_empty(),
        "the contract lists no network error codes"
    );
    for code in &codes {
        let kind = io_kind(code);
        assert!(
            kind.is_some(),
            "{code} has no io mapping: add one with its test"
        );
        let io = IoError::new(kind.unwrap_or(IoKind::Other), code.as_str());
        let error: AuthError = RedisStoreError::Command(io.into()).into();
        assert!(is_unavailable(&error), "{code} must answer 503");
    }
}

#[test]
fn a_pool_that_cannot_hand_out_a_connection_in_time_or_is_closed_is_an_outage() {
    for pool in [PoolError::Timeout(TimeoutType::Wait), PoolError::Closed] {
        assert!(is_unavailable(&RedisStoreError::Pool(pool).into()));
    }
    let backend = PoolError::Backend(IoError::from(IoKind::ConnectionRefused).into());
    assert!(is_unavailable(&RedisStoreError::Pool(backend).into()));
}

#[test]
fn a_defect_is_never_reported_as_an_outage() {
    let malformed = serde_json::from_str::<Value>("{").err();
    let decode = malformed.map(RedisStoreError::Decode);
    assert!(decode.is_some(), "the fixture must fail to parse");
    for case in decode
        .into_iter()
        .chain([RedisStoreError::Pool(PoolError::NoRuntimeSpecified)])
    {
        assert!(matches!(AuthError::from(case), AuthError::Internal(_)));
    }
}
