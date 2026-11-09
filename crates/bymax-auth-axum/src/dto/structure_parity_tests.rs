//! Whether a request body or query is accepted by the DTO's own validation, against the
//! `acceptedByPipe` of each probe in `conformance/openapi-declared-structures.json`.
//!
//! The artefact says, for each probe, whether validation (the "pipe") lets the request through to
//! the handler, so a refusal can be attributed to the layer that makes it. The answer rust's DTOs
//! give is read by deserializing and validating the probe, as they are in the router. A probe on
//! which they disagree is a finding; the ones this crate has not closed are listed in
//! `KNOWN_DIVERGENCES` with the reason, and the test requires each to still diverge, so a fix
//! that does not remove its entry fails.

use serde_json::{Map, Value};

use super::openapi_parity_tests::{DTOS, artefact};

const DECLARED: &str = include_str!("../../../../conformance/openapi-declared-structures.json");

/// Probes whose acceptance differs from the artefact's: (entry, probe index, reason).
const KNOWN_DIVERGENCES: [(&str, usize, &str); 0] = [];

fn declared() -> Value {
    serde_json::from_str(DECLARED).unwrap_or(Value::Null)
}

/// The bound the request-schemas artefact declares for the callback's `code`.
fn code_bound() -> usize {
    artefact()["schemas"]["OAuthCallbackQueryDto"]["properties"]["code"]["maxLength"]
        .as_u64()
        .and_then(|max| usize::try_from(max).ok())
        .unwrap_or(0)
}

/// `value` with the placeholder for an oversized `code` expanded.
fn expanded(value: &Value) -> Value {
    match value.as_str() {
        Some("OVERSIZED_CODE_2049") => Value::String("x".repeat(code_bound() + 1)),
        _ => value.clone(),
    }
}

/// The probes to check, as (entry, index, DTO name, body, acceptedByPipe).
fn probes() -> Vec<(String, usize, String, Value, bool)> {
    let root = declared();
    let mut found = Vec::new();
    for (key, entry) in root["operationSemantics"].as_object().into_iter().flatten() {
        for (index, probe) in entry["probes"].as_array().into_iter().flatten().enumerate() {
            let dto = probe["dto"].as_str().or_else(|| entry["dto"].as_str());
            let body = if probe["body"].is_null() {
                &probe["query"]
            } else {
                &probe["body"]
            };
            let expanded: Map<String, Value> = body
                .as_object()
                .into_iter()
                .flatten()
                .map(|(name, value)| (name.clone(), expanded(value)))
                .collect();
            if let (Some(dto), Some(accepted)) = (dto, probe["acceptedByPipe"].as_bool()) {
                found.push((
                    key.clone(),
                    index,
                    dto.to_owned(),
                    Value::Object(expanded),
                    accepted,
                ));
            }
        }
    }
    found
}

#[test]
fn every_probe_is_accepted_or_refused_by_the_dto_as_the_artefact_says() {
    let mut disagreements = Vec::new();
    let mut checked = 0;
    for (entry, index, dto, body, accepted) in probes() {
        let Some((_, accepts)) = DTOS.iter().find(|(name, _)| *name == dto) else {
            disagreements.push(format!("{entry}[{index}]: {dto} is not in the DTO table"));
            continue;
        };
        checked += 1;
        let diverges = accepts(&body) != accepted;
        let tracked = KNOWN_DIVERGENCES
            .iter()
            .any(|(key, at, _)| *key == entry && *at == index);
        match (diverges, tracked) {
            (true, false) => disagreements.push(format!("{entry}[{index}]: the DTO disagrees")),
            (false, true) => {
                disagreements.push(format!("{entry}[{index}]: tracked, but it agrees now"))
            }
            _ => {}
        }
    }
    assert!(checked >= 13, "only {checked} probes were checked");
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}
