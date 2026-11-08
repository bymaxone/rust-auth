//! What the shared wire contract pins for the MFA transition lock and the recovery-code claim,
//! read from the contract rather than restated, so a TTL, a nonce width or a key derivation
//! that drifts from nest-auth's turns this side red instead of splitting a shared keyspace.
//! The `grace_recovery_write` section is pinned next to the script that implements it.

use std::collections::BTreeSet;

use bymax_auth_types::MfaContext;
use serde_json::Value;

use super::tests::build;
use super::{
    MFA_TRANSITION_LOCK_TOKEN_BYTES, MFA_TRANSITION_LOCK_TTL_SECONDS,
    RECOVERY_CODE_CLAIM_TTL_SECONDS,
};
use crate::services::{to_hex, user_subject};

const CONTRACT: &str = include_str!("../../../../../conformance/wire-contract.json");

fn section(name: &str) -> Value {
    serde_json::from_str::<Value>(CONTRACT).map_or(Value::Null, |root| root[name].clone())
}

fn text(section: &Value, field: &str) -> String {
    section[field].as_str().unwrap_or_default().to_owned()
}

fn fields(section: &Value) -> BTreeSet<String> {
    section
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_lock_and_claim_sections_carry_exactly_the_fields_this_file_pins() {
    // A field added to either section fails here until someone decides what pins it.
    let expected = names(&["$comment", "key", "ttlSeconds", "value"]);
    assert_eq!(fields(&section("mfaTransitionLock")), expected);
    assert_eq!(fields(&section("recoveryCodeClaim")), expected);
}

#[test]
fn both_ttls_are_the_contracts() {
    assert_eq!(
        section("mfaTransitionLock")["ttlSeconds"].as_u64(),
        Some(MFA_TRANSITION_LOCK_TTL_SECONDS)
    );
    assert_eq!(
        section("recoveryCodeClaim")["ttlSeconds"].as_u64(),
        Some(RECOVERY_CODE_CLAIM_TTL_SECONDS)
    );
}

#[test]
fn the_lock_value_is_a_per_call_nonce_of_the_width_the_contract_names() {
    let value = text(&section("mfaTransitionLock"), "value");
    // "a per-call nonce (16 CSPRNG bytes, hex) — the release compares against it"
    let width = value
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(" CSPRNG bytes"))
        .and_then(|(bytes, _)| bytes.parse::<usize>().ok());
    assert_eq!(width, Some(MFA_TRANSITION_LOCK_TOKEN_BYTES));
    assert!(value.contains("CSPRNG bytes, hex)"), "{value}");

    let first = bymax_auth_crypto::token::generate_secure_token(MFA_TRANSITION_LOCK_TOKEN_BYTES);
    let second = bymax_auth_crypto::token::generate_secure_token(MFA_TRANSITION_LOCK_TOKEN_BYTES);
    assert_eq!(first.len(), 2 * MFA_TRANSITION_LOCK_TOKEN_BYTES);
    assert!(
        first
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_ne!(first, second, "a nonce must differ per call");
}

#[test]
fn the_lock_and_claim_keys_are_derived_as_the_contract_spells_them() -> Result<(), String> {
    let lock_key = text(&section("mfaTransitionLock"), "key");
    let claim_key = text(&section("recoveryCodeClaim"), "key");
    assert_eq!(lock_key, "mfalock:{hmac_sha256(hmacKey, userSubject)}");
    assert_eq!(
        claim_key,
        "rcu:{hmac_sha256(hmacKey, '{userSubject}:{code}')}"
    );

    let h = build(true, false).ok_or("harness")?;
    let mfa = h.engine.mfa().ok_or("mfa service")?;
    for (ctx, tenant) in [
        (MfaContext::Dashboard, Some("t1")),
        (MfaContext::Dashboard, Some("a:b")),
        (MfaContext::Platform, None),
    ] {
        let subject = user_subject(ctx, tenant, "u1");
        let mac = |input: &str| {
            to_hex(&bymax_auth_crypto::mac::hmac_sha256(
                mfa.identifier_key.as_ref(),
                input.as_bytes(),
            ))
        };
        assert_eq!(mfa.mfa_lock_id(ctx, tenant, "u1"), mac(&subject));
        assert_eq!(
            mfa.replay_id(ctx, tenant, "u1", "ABCD-1234"),
            mac(&format!("{subject}:ABCD-1234"))
        );
    }
    Ok(())
}
