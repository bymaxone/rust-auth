//! Parity of the request DTOs with `conformance/openapi-request-descriptions.json`: the sentences
//! `nest-auth` publishes about what the server does to a value that a schema cannot say.
//!
//! Every entry carries a probe, an input and the value the server reads from it. Each probe is run
//! through the real `serde` path of the DTO the entry names, and then through its validation, so
//! the sentence ("trimmed and lowercased before validation") is checked as behaviour and not read
//! off an attribute. The set of entries is compared with the properties this crate transforms in
//! both directions: an entry without a property fails, and so does a transformed property without
//! an entry.
//!
//! Known limit, shared with the artefact: a future transform that is the identity on the probe
//! input escapes the probe, and a transform written without a `serde` attribute escapes the
//! inventory.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::pending::PENDING_SCHEMAS;

use super::openapi_parity_tests::{DTOS, Findings, artefact, base_body, props_of};
use super::{
    ChangeEmailDto, CreateInvitationDto, ForgotPasswordDto, LoginDto, PlatformLoginDto,
    RegisterDto, ResendOtpDto, ResendVerificationDto, ResetPasswordDto, RevokeInvitationDto,
    VerifyEmailDto, VerifyOtpDto,
};

const DESCRIPTIONS: &str =
    include_str!("../../../../conformance/openapi-request-descriptions.json");

/// The source of the DTOs, read for the inventory of transformed properties.
const DTO_SOURCE: &str = include_str!("../dto.rs");

/// The text of the one transform this crate applies to a request value.
const NORMALIZER: &str = "text_rules::normalized_email";

/// The value a body deserializes to at one property, or `None` when the body is refused.
type Reads = fn(&Value) -> Option<String>;

/// A row of [`DESCRIBED`]: the DTO, its property as the wire names it, the Rust field that
/// carries it, and how to read that field back.
type Row = (&'static str, &'static str, &'static str, Reads);

fn read<T: DeserializeOwned>(body: &Value, get: fn(T) -> String) -> Option<String> {
    serde_json::from_value::<T>(body.clone()).ok().map(get)
}

macro_rules! row {
    ($dto:ident, $wire:literal, $field:ident) => {
        (stringify!($dto), $wire, stringify!($field), |body| {
            read(body, |dto: $dto| dto.$field)
        })
    };
}

/// Every property the server transforms, with the DTO that carries it.
const DESCRIBED: [Row; 12] = [
    row!(ChangeEmailDto, "newEmail", new_email),
    row!(CreateInvitationDto, "email", email),
    row!(ForgotPasswordDto, "email", email),
    row!(LoginDto, "email", email),
    row!(PlatformLoginDto, "email", email),
    row!(RegisterDto, "email", email),
    row!(ResendOtpDto, "email", email),
    row!(ResendVerificationDto, "email", email),
    row!(ResetPasswordDto, "email", email),
    row!(RevokeInvitationDto, "email", email),
    row!(VerifyEmailDto, "email", email),
    row!(VerifyOtpDto, "email", email),
];

fn descriptions() -> Value {
    serde_json::from_str::<Value>(DESCRIPTIONS)
        .map_or(Value::Null, |root| root["descriptions"].clone())
}

/// The (DTO, property) pairs the artefact describes.
fn described_pairs() -> BTreeSet<(String, String)> {
    let root = descriptions();
    root.as_object()
        .into_iter()
        .flatten()
        .flat_map(|(dto, props)| {
            props
                .as_object()
                .into_iter()
                .flatten()
                .map(|(prop, _)| (dto.clone(), prop.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn every_entry_of_the_artefact_has_a_property_here_and_the_reverse() {
    let rows: BTreeSet<(String, String)> = DESCRIBED
        .iter()
        .map(|(dto, wire, ..)| ((*dto).to_owned(), (*wire).to_owned()))
        .collect();
    assert_eq!(rows.len(), DESCRIBED.len(), "a row is listed twice");
    let built: BTreeSet<(String, String)> = described_pairs()
        .into_iter()
        .filter(|(dto, _)| !PENDING_SCHEMAS.contains(&dto.as_str()))
        .collect();
    assert_eq!(rows, built);
}

/// Each `(DTO, Rust field)` the source marks with the normaliser, found by reading `dto.rs`: the
/// field is the one declared after the attribute.
fn transformed_in_source() -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    let mut dto = "";
    let mut marked = false;
    for line in DTO_SOURCE.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("pub struct ") {
            dto = name.split([' ', '{']).next().unwrap_or_default();
        }
        if line.contains("deserialize_with") {
            assert!(
                line.contains(NORMALIZER),
                "an unrecognised transform: {line}"
            );
            marked = true;
        } else if marked && let Some(field) = line.strip_prefix("pub ") {
            found.insert((
                dto.to_owned(),
                field.split(':').next().unwrap_or_default().to_owned(),
            ));
            marked = false;
        }
    }
    found
}

#[test]
fn every_transformed_property_in_the_source_has_a_row_and_the_reverse() {
    let rows: BTreeSet<(String, String)> = DESCRIBED
        .iter()
        .map(|(dto, _, field, _)| ((*dto).to_owned(), (*field).to_owned()))
        .collect();
    assert_eq!(rows, transformed_in_source());
}

#[test]
fn every_probe_reads_as_the_sentence_says_through_the_real_deserialisation() {
    let root = artefact();
    let described = descriptions();
    let mut failures = Vec::new();
    for (dto, wire, _, reads) in DESCRIBED {
        let probe = &described[dto][wire]["probe"];
        let (input, expected) = (probe["input"].as_str(), probe["expected"].as_str());
        let Some((input, expected)) = input.zip(expected) else {
            failures.push(format!(
                "{dto}.{wire}: the probe has no string input and expected"
            ));
            continue;
        };
        let Some((_, accepts)) = DTOS.iter().find(|(name, _)| *name == dto) else {
            failures.push(format!("{dto}: not in the DTO table"));
            continue;
        };
        let mut findings = Findings::new();
        let mut body = base_body(*accepts, &props_of(&root, dto), dto, &mut findings);
        body.insert(wire.to_owned(), Value::String(input.to_owned()));
        let body = Value::Object(body);
        if reads(&body).as_deref() != Some(expected) {
            failures.push(format!(
                "{dto}.{wire}: {input:?} did not read as {expected:?}"
            ));
        }
        // The sentence says the value is normalised before it is validated: the padded input is
        // not a valid address until it is, so a body that validates proves the order.
        if !accepts(&body) {
            failures.push(format!(
                "{dto}.{wire}: the normalised probe body is refused"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
