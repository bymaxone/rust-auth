//! Parity of the request DTOs with `conformance/openapi-request-schemas.json`, the OpenAPI 3.0
//! request-body schemas nest-auth generates from its own validators and holds as shared data.
//!
//! The schemas are read from the file, never restated here, and every DTO is exercised through
//! its real `serde` + `garde` path: a bound is checked by sending a value one either side of it,
//! not by reading an attribute. A difference is not fixed here and not skipped: it is a finding,
//! and `KNOWN_DIVERGENCES` is the list of findings someone has looked at. A new difference fails
//! the test until it is listed, and a listed one that stops reproducing fails it until it is
//! removed, so the list cannot go stale in either direction.
//!
//! The artefact's identity is pinned below. As with the wire contract, the pin catches an
//! unaccompanied byte change in this repository; it cannot see nest-auth move.

use std::collections::{BTreeMap, BTreeSet};

use bymax_auth_crypto::mac::sha256;
use garde::Validate;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::{
    AcceptInvitationDto, ChangeEmailDto, ChangePasswordDto, ConfirmEmailChangeDto,
    CreateInvitationDto, ForgotPasswordDto, LoginDto, MfaChallengeDto, MfaDisableDto,
    MfaRegenerateRecoveryCodesDto, MfaSetupDto, MfaVerifyDto, OAuthCallbackQuery,
    OAuthInitiateQuery, PlatformLoginDto, RegisterDto, ResendOtpDto, ResendVerificationDto,
    ResetPasswordDto, RevokeInvitationDto, VerifyEmailDto, VerifyOtpDto,
};

const ARTEFACT: &str = include_str!("../../../../conformance/openapi-request-schemas.json");

/// The SHA-256 of the artefact, lower-case hex. Source: nest-auth `v1.4.22`, commit
/// `b3e64f1c6dd1a2cf0f4ad874b6fe6470e3325ea1`, path `conformance/openapi-request-schemas.json`.
const ARTEFACT_SHA256: &str = "2c2b7549f6aa6b2b76e55b38e9eece1e5fa66a562130d488a2a493d4d5ca1b7c";

/// A DTO's verdict on a body: accepted when it deserializes and validates.
type Accepts = fn(&Value) -> bool;

fn accepts<T: DeserializeOwned + Validate<Context = ()>>(body: &Value) -> bool {
    serde_json::from_value::<T>(body.clone()).is_ok_and(|dto| dto.validate().is_ok())
}

/// Every schema in the artefact and the DTO that answers it. The names differ for the two OAuth
/// query types only.
const DTOS: [(&str, Accepts); 22] = [
    ("AcceptInvitationDto", accepts::<AcceptInvitationDto>),
    ("ChangeEmailDto", accepts::<ChangeEmailDto>),
    ("ChangePasswordDto", accepts::<ChangePasswordDto>),
    ("ConfirmEmailChangeDto", accepts::<ConfirmEmailChangeDto>),
    ("CreateInvitationDto", accepts::<CreateInvitationDto>),
    ("ForgotPasswordDto", accepts::<ForgotPasswordDto>),
    ("LoginDto", accepts::<LoginDto>),
    ("MfaChallengeDto", accepts::<MfaChallengeDto>),
    ("MfaDisableDto", accepts::<MfaDisableDto>),
    (
        "MfaRegenerateRecoveryCodesDto",
        accepts::<MfaRegenerateRecoveryCodesDto>,
    ),
    ("MfaSetupDto", accepts::<MfaSetupDto>),
    ("MfaVerifyDto", accepts::<MfaVerifyDto>),
    ("OAuthCallbackQueryDto", accepts::<OAuthCallbackQuery>),
    ("OAuthInitiateQueryDto", accepts::<OAuthInitiateQuery>),
    ("PlatformLoginDto", accepts::<PlatformLoginDto>),
    ("RegisterDto", accepts::<RegisterDto>),
    ("ResendOtpDto", accepts::<ResendOtpDto>),
    ("ResendVerificationDto", accepts::<ResendVerificationDto>),
    ("ResetPasswordDto", accepts::<ResetPasswordDto>),
    ("RevokeInvitationDto", accepts::<RevokeInvitationDto>),
    ("VerifyEmailDto", accepts::<VerifyEmailDto>),
    ("VerifyOtpDto", accepts::<VerifyOtpDto>),
];

/// Samples for each `pattern` in the artefact, with the verdict of an ECMA-262 engine
/// (`new RegExp(pattern).test(sample)` under node) recorded beside each. The set of patterns here
/// is compared with the artefact in both directions, so a new pattern fails until it has samples.
const PATTERN_SAMPLES: [(&str, &[(&str, bool)]); 4] = [
    (
        r"^[^\u0000-\u001F\u007F-\u009F]+$",
        &[
            ("a", true),
            (" ", true),
            ("\u{a0}", true),
            ("\u{e9}", true),
            ("\u{1f600}", true),
            ("a\u{2028}b", true),
            ("\u{0}", false),
            ("\u{1f}", false),
            ("\u{7f}", false),
            ("\u{80}", false),
            ("\u{9f}", false),
            ("a\nb", false),
            ("\u{1f}a", false),
        ],
    ),
    (
        r"\S",
        &[
            ("a", true),
            (" a ", true),
            ("\u{a0}x", true),
            ("\u{85}", true),
            ("\u{180e}", true),
            ("\u{200b}", true),
            (" ", false),
            ("\t", false),
            ("\u{a0}", false),
            ("\u{2003}", false),
            ("\u{2028}", false),
            ("\u{3000}", false),
            ("\u{feff}", false),
        ],
    ),
    (
        r"^\d{6}$",
        &[
            ("123456", true),
            ("000000", true),
            ("12345", false),
            ("1234567", false),
            ("12345a", false),
            ("123456\n", false),
            (" 123456", false),
            ("\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}", false),
            ("\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}", false),
        ],
    ),
    (
        r"^(\d{6}|[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})$",
        &[
            ("123456", true),
            ("ABCD-0123-4567-89AB-CDEF-0123", true),
            ("abcd-0123-4567-89ab-cdef-0123", true),
            ("ABCD-0123-4567-89AB-CDEF", false),
            ("ABCD-0123-4567-89AB-CDEF-012", false),
            ("ABCD-0123-4567-89AB-CDEF-01234", false),
            ("ABCD0123456789ABCDEF0123", false),
            ("GBCD-0123-4567-89AB-CDEF-0123", false),
            ("ABCD-0123-4567-89AB-CDEF-0123\n", false),
            ("12345a", false),
            ("\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}", false),
        ],
    ),
];

/// A property of a request schema, with only the keywords the artefact uses.
struct Prop {
    name: String,
    required: bool,
    min: Option<usize>,
    max: Option<usize>,
    pattern: Option<String>,
    email: bool,
}

fn artefact() -> Value {
    serde_json::from_str(ARTEFACT).unwrap_or(Value::Null)
}

fn schema_names(root: &Value) -> BTreeSet<String> {
    root["schemas"]
        .as_object()
        .map(|schemas| schemas.keys().cloned().collect())
        .unwrap_or_default()
}

fn props_of(root: &Value, schema: &str) -> Vec<Prop> {
    let body = &root["schemas"][schema];
    let required: BTreeSet<&str> = body["required"]
        .as_array()
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let bound = |prop: &Value, key: &str| prop[key].as_u64().and_then(|n| usize::try_from(n).ok());
    body["properties"]
        .as_object()
        .map(|props| {
            props
                .iter()
                .map(|(name, prop)| Prop {
                    name: name.clone(),
                    required: required.contains(name.as_str()),
                    min: bound(prop, "minLength"),
                    max: bound(prop, "maxLength"),
                    pattern: prop["pattern"].as_str().map(str::to_owned),
                    email: prop["format"] == "email",
                })
                .collect()
        })
        .unwrap_or_default()
}

/// An address of exactly `len` characters: a local part of at most 64 and labels of at most 63.
fn email_of_len(len: usize) -> String {
    let local_len = if len <= 76 { len - 12 } else { 64 };
    let mut domain_len = len - local_len - 1;
    let mut labels: Vec<String> = Vec::new();
    while domain_len > 63 + 1 + 3 {
        labels.push("b".repeat(63));
        domain_len -= 64;
    }
    labels.push("b".repeat(domain_len - 4));
    labels.push("com".to_owned());
    format!("{}@{}", "a".repeat(local_len), labels.join("."))
}

/// A string of `len` characters made of `fill`.
fn filled(fill: char, len: usize) -> String {
    std::iter::repeat_n(fill, len).collect()
}

/// A body with `value` as `prop`, over `base`.
fn with(base: &Map<String, Value>, prop: &str, value: &str) -> Value {
    let mut body = base.clone();
    body.insert(prop.to_owned(), Value::String(value.to_owned()));
    Value::Object(body)
}

/// The fills tried, in order, to build a value of a given length for a property.
const FILLS: [char; 3] = ['a', '1', 'A'];

/// What one DTO's run found, keyed by category, each with the fields it concerns.
type Findings = BTreeMap<&'static str, BTreeSet<String>>;

/// Records `detail` under `category` when `failed`. Every probe calls it, so a probe that passes
/// costs a call and not a branch of its own.
fn note_if(
    findings: &mut Findings,
    failed: bool,
    (category, dto, detail): (&'static str, &str, &str),
) {
    if failed {
        findings
            .entry(category)
            .or_default()
            .insert(format!("{dto}.{detail}"));
    }
}

/// The first fill for which the DTO takes a `len`-long value of `prop` over `base`, noting a
/// field that needs more than plain letters.
fn working_fill(
    check: Accepts,
    base: &Map<String, Value>,
    (prop, len, dto): (&Prop, usize, &str),
    findings: &mut Findings,
) -> char {
    let found = FILLS
        .iter()
        .copied()
        .find(|fill| check(&with(base, &prop.name, &filled(*fill, len))));
    let category = "stricter than the schema: letters refused";
    note_if(
        findings,
        found.is_some_and(|fill| fill != FILLS[0]),
        (category, dto, &prop.name),
    );
    found.unwrap_or(FILLS[0])
}

/// A valid value for a required `prop`: the first accepted pattern sample, an address, or a
/// filled string inside its bounds.
fn base_value(prop: &Prop) -> String {
    if let Some(pattern) = &prop.pattern {
        let samples = PATTERN_SAMPLES.iter().find(|(known, _)| known == pattern);
        return samples
            .and_then(|(_, list)| list.first())
            .map(|(sample, _)| (*sample).to_owned())
            .unwrap_or_default();
    }
    if prop.email {
        return "user@example.com".to_owned();
    }
    let len = 8.clamp(prop.min.unwrap_or(1), prop.max.unwrap_or(usize::MAX));
    filled('a', len)
}

/// Whether a pattern is one a plain letter satisfies, so a length can be probed with letters.
fn letters_satisfy(pattern: Option<&String>) -> bool {
    pattern.is_none_or(|pattern| {
        PATTERN_SAMPLES
            .iter()
            .any(|(known, samples)| known == pattern && samples.first().is_some_and(|s| s.0 == "a"))
    })
}

/// The base body for a DTO: its required properties, each with a valid value.
fn base_body(
    check: Accepts,
    props: &[Prop],
    dto: &str,
    findings: &mut Findings,
) -> Map<String, Value> {
    let mut base = Map::new();
    for prop in props.iter().filter(|prop| prop.required) {
        base.insert(prop.name.clone(), Value::String(base_value(prop)));
    }
    let refused = !check(&Value::Object(base.clone()));
    note_if(
        findings,
        refused,
        ("required-only body refused", dto, "body"),
    );
    base
}

/// One length probe: a value of `len` characters must be taken or refused as `expected`.
fn probe_len(
    (check, base): (Accepts, &Map<String, Value>),
    prop: &Prop,
    (len, expected, fill): (usize, bool, char),
) -> bool {
    let value = if prop.email {
        email_of_len(len)
    } else {
        filled(fill, len)
    };
    check(&with(base, &prop.name, &value)) == expected
}

/// The bounds of a free-text property: `minLength` and `maxLength`, one either side.
fn check_lengths(
    ctx: (Accepts, &Map<String, Value>),
    prop: &Prop,
    dto: &str,
    findings: &mut Findings,
) {
    if !prop.email && !letters_satisfy(prop.pattern.as_ref()) {
        return;
    }
    let anchor = prop.max.or(prop.min).unwrap_or(1);
    let fill = if prop.email {
        'a'
    } else {
        working_fill(ctx.0, ctx.1, (prop, anchor, dto), findings)
    };
    let name = prop.name.as_str();
    for min in prop
        .min
        .iter()
        .copied()
        .filter(|min| *min >= 1 && !prop.email)
    {
        let at = probe_len(ctx, prop, (min, true, fill));
        let below = probe_len(ctx, prop, (min - 1, false, fill));
        let category = "minLength: the minimum is refused";
        note_if(findings, !at, (category, dto, name));
        let category = "minLength: one below the minimum is accepted";
        note_if(findings, !below, (category, dto, name));
    }
    for max in prop.max.iter().copied() {
        let at = probe_len(ctx, prop, (max, true, fill));
        let above = probe_len(ctx, prop, (max + 1, false, fill));
        let category = "maxLength: the maximum is refused";
        note_if(findings, !at, (category, dto, name));
        let category = "maxLength: one above the maximum is accepted";
        note_if(findings, !above, (category, dto, name));
    }
}

/// A maximum is a count of characters, so `max` two-byte characters must fit.
fn check_multibyte(
    (check, base): (Accepts, &Map<String, Value>),
    prop: &Prop,
    dto: &str,
    findings: &mut Findings,
) {
    if prop.email || !letters_satisfy(prop.pattern.as_ref()) {
        return;
    }
    for max in prop.max.iter().copied() {
        let letters = filled('a', max.max(prop.min.unwrap_or(1)));
        let letters_work = check(&with(base, &prop.name, &letters));
        let accented_refused = !check(&with(base, &prop.name, &filled('\u{e9}', max)));
        let category = "maxLength: counted in bytes, not characters";
        note_if(
            findings,
            letters_work && accented_refused,
            (category, dto, &prop.name),
        );
    }
}

/// Every sample of the property's pattern, against the verdict an ECMA engine gave it and the
/// property's own length bounds.
fn check_pattern(
    (check, base): (Accepts, &Map<String, Value>),
    prop: &Prop,
    dto: &str,
    findings: &mut Findings,
) {
    let samples = PATTERN_SAMPLES
        .iter()
        .filter(|(known, _)| Some(*known) == prop.pattern.as_deref())
        .flat_map(|(_, list)| list.iter());
    for (sample, matches) in samples {
        let chars = sample.chars().count();
        let in_bounds =
            prop.min.is_none_or(|min| chars >= min) && prop.max.is_none_or(|max| chars <= max);
        let differs = check(&with(base, &prop.name, sample)) != (*matches && in_bounds);
        let detail = format!("{} {:?} (ECMA: {})", prop.name, sample, matches);
        let category = "pattern: the verdict differs from an ECMA engine's";
        note_if(findings, differs, (category, dto, &detail));
    }
}

/// Everything one DTO is checked for.
fn check_dto(root: &Value, dto: &str, check: Accepts, findings: &mut Findings) {
    let props = props_of(root, dto);
    let base = base_body(check, &props, dto, findings);
    for prop in &props {
        let mut without = base.clone();
        without.remove(&prop.name);
        let accepted_without = prop.required && check(&Value::Object(without));
        let category = "required: a body without it is accepted";
        note_if(findings, accepted_without, (category, dto, &prop.name));
        check_lengths((check, &base), prop, dto, findings);
        check_multibyte((check, &base), prop, dto, findings);
        check_pattern((check, &base), prop, dto, findings);
    }
}

/// The differences between the DTOs and the artefact that have been looked at: the category,
/// the fields it concerns, and why it is not fixed here.
const KNOWN_DIVERGENCES: &[(&str, &[&str], &str)] = &[
    (
        "maxLength: counted in bytes, not characters",
        &[
            "AcceptInvitationDto.name",
            "AcceptInvitationDto.password",
            "AcceptInvitationDto.token",
            "ChangeEmailDto.currentPassword",
            "ChangePasswordDto.currentPassword",
            "ChangePasswordDto.newPassword",
            "ChangePasswordDto.refreshToken",
            "ConfirmEmailChangeDto.token",
            "CreateInvitationDto.role",
            "CreateInvitationDto.tenantName",
            "ForgotPasswordDto.tenantId",
            "LoginDto.password",
            "LoginDto.tenantId",
            "MfaChallengeDto.mfaTempToken",
            "MfaSetupDto.password",
            "OAuthCallbackQueryDto.authuser",
            "OAuthCallbackQueryDto.code",
            "OAuthCallbackQueryDto.error",
            "OAuthCallbackQueryDto.hd",
            "OAuthCallbackQueryDto.iss",
            "OAuthCallbackQueryDto.prompt",
            "OAuthCallbackQueryDto.scope",
            "OAuthCallbackQueryDto.state",
            "OAuthInitiateQueryDto.tenantId",
            "PlatformLoginDto.password",
            "RegisterDto.name",
            "RegisterDto.password",
            "RegisterDto.tenantId",
            "ResendOtpDto.tenantId",
            "ResendVerificationDto.tenantId",
            "ResetPasswordDto.newPassword",
            "ResetPasswordDto.otp",
            "ResetPasswordDto.tenantId",
            "ResetPasswordDto.token",
            "ResetPasswordDto.verifiedToken",
            "VerifyEmailDto.otp",
            "VerifyEmailDto.tenantId",
            "VerifyOtpDto.otp",
            "VerifyOtpDto.tenantId",
        ],
        "garde's `length` on a String counts bytes (garde 0.23 `rules/length/simple.rs`), while \
         nest-auth's class-validator `maxLength` counts characters: `maxLength('\u{e9}' x 128, 128)` \
         is true there and `'\u{1f600}' x 2` fits a maximum of 2. A multibyte value near a maximum is \
         accepted by one backend and refused by the other, for example a 100-character passphrase of \
         three-byte characters against a password maximum of 128. Not changed here: `length(chars)` \
         is a decision for this repository and nest-auth, since the contract does not say which unit \
         the bounds are in.",
    ),
    (
        "maxLength: one above the maximum is accepted",
        &[
            "OAuthCallbackQueryDto.error_description",
            "OAuthCallbackQueryDto.error_uri",
        ],
        "The DTO is `rename_all = \"camelCase\"`, so rust reads `errorDescription` and `errorUri`, \
         while nest-auth's DTO and RFC 6749 section 4.1.2.1 name them `error_description` and \
         `error_uri`. A provider's parameter is therefore dropped by serde (the DTO does not deny \
         unknown fields) and its bound never applies; nothing reads either field. Not changed here: \
         a rename on the two fields, or removing them, is a decision for this repository.",
    ),
];

fn known() -> Findings {
    KNOWN_DIVERGENCES
        .iter()
        .map(|(category, fields, _)| {
            (
                *category,
                fields.iter().map(|field| (*field).to_owned()).collect(),
            )
        })
        .collect()
}

#[test]
fn the_artefact_carries_the_bytes_this_repository_declared() {
    let hex: String = sha256(ARTEFACT.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex, ARTEFACT_SHA256,
        "the shared artefact changed without its pin"
    );
}

#[test]
fn every_schema_has_a_dto_and_the_rust_only_ones_are_named() {
    let in_artefact = schema_names(&artefact());
    let mapped: BTreeSet<String> = DTOS.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(mapped, in_artefact);
    assert!(
        !in_artefact.contains("RefreshDto"),
        "RefreshDto is a Rust-only body"
    );
}

#[test]
fn the_keywords_and_patterns_are_the_ones_this_test_understands() {
    let root = artefact();
    let mut schema_keys = BTreeSet::new();
    let mut prop_keys = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut formats = BTreeSet::new();
    let mut patterns = BTreeSet::new();
    for schema in root["schemas"]
        .as_object()
        .into_iter()
        .flat_map(Map::values)
    {
        schema_keys.extend(schema.as_object().into_iter().flat_map(Map::keys).cloned());
        types.insert(schema["type"].as_str().unwrap_or_default().to_owned());
        for prop in schema["properties"]
            .as_object()
            .into_iter()
            .flat_map(Map::values)
        {
            prop_keys.extend(prop.as_object().into_iter().flat_map(Map::keys).cloned());
            types.insert(prop["type"].as_str().unwrap_or_default().to_owned());
            formats.extend(prop["format"].as_str().map(str::to_owned));
            patterns.extend(prop["pattern"].as_str().map(str::to_owned));
        }
    }
    let set =
        |items: &[&str]| -> BTreeSet<String> { items.iter().map(|s| (*s).to_owned()).collect() };
    assert_eq!(schema_keys, set(&["properties", "required", "type"]));
    assert_eq!(
        prop_keys,
        set(&["format", "maxLength", "minLength", "pattern", "type"])
    );
    assert_eq!(types, set(&["object", "string"]));
    assert_eq!(formats, set(&["email"]));
    assert_eq!(
        patterns,
        PATTERN_SAMPLES
            .iter()
            .map(|(pattern, _)| (*pattern).to_owned())
            .collect()
    );
}

#[test]
fn the_dtos_agree_with_the_artefact_or_the_difference_is_listed() {
    let root = artefact();
    let mut observed = Findings::new();
    for (dto, check) in DTOS {
        check_dto(&root, dto, check, &mut observed);
    }
    assert_eq!(
        observed,
        known(),
        "observed on the left, listed on the right"
    );
    assert!(
        KNOWN_DIVERGENCES
            .iter()
            .all(|(_, _, reason)| !reason.is_empty())
    );
}

#[test]
fn an_address_helper_builds_the_length_it_is_asked_for() {
    for len in [14, 76, 77, 128, 255, 256] {
        let address = email_of_len(len);
        assert_eq!(address.chars().count(), len, "{address}");
        let (local, domain) = address.split_once('@').unwrap_or_default();
        assert!(local.len() <= 64 && domain.split('.').all(|label| label.len() <= 63));
    }
}
