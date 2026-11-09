//! The declared structures and operation semantics, against what the router does.
//!
//! `conformance/openapi-declared-structures.json` states contracts a generated schema cannot: a
//! constraint across the properties of a body, a refusal made by a handler and not by
//! validation, a policy floor that is configuration, and two responses that must be
//! indistinguishable. Every entry carries probes. Each probe is run against the real router under
//! the deployment it names, and what the server answers is compared with what the entry says.
//!
//! The structures are also evaluated here, with the three keywords the artefact uses (`required`,
//! `oneOf`, `anyOf`; presence means present and not `null`), and a probe that says whether a body
//! satisfies its structure is checked against both the evaluator and the server, so the sentence
//! and the behaviour are the pair that gets verified. A structure using a keyword this test does
//! not evaluate is refused, because a claim nothing checks is worse than none.
//!
//! The artefact's keys are compared with the entries handled here in both directions, so a new
//! entry fails the build until it is probed.

use std::collections::{BTreeMap, BTreeSet};

use bymax_auth_axum::openapi::{
    declared_operation_semantics, declared_request_structures, request_schema,
};
use bymax_auth_core::config::ResetMethod;
use serde_json::{Value, json};

use super::*;

/// The tenant the artefact's probes name, which stands for whichever tenant a deployment has.
const PROBE_TENANT: &str = "probe-tenant";

// ---- the evaluator -------------------------------------------------------------------------

fn fail<T>(message: &str) -> Result<T, String> {
    Err(message.to_owned())
}

/// Whether `name` is present in `body`: there, and not `null`.
fn present(body: &Value, name: &str) -> bool {
    body.get(name).is_some_and(|value| !value.is_null())
}

/// How many of `branches` the body satisfies.
fn satisfied_branches(branches: &Value, body: &Value) -> Result<usize, String> {
    let Some(list) = branches.as_array() else {
        return fail("a combinator holds a list of structures");
    };
    let mut count = 0;
    for branch in list {
        count += usize::from(satisfies(branch, body)?);
    }
    Ok(count)
}

/// Whether `body` satisfies `structure`: every keyword it holds must hold. A keyword other than
/// `required`, `oneOf` and `anyOf` is an error.
fn satisfies(structure: &Value, body: &Value) -> Result<bool, String> {
    let Some(keywords) = structure.as_object() else {
        return fail("a structure is an object");
    };
    for (keyword, value) in keywords {
        let holds = match keyword.as_str() {
            "required" => match value.as_array() {
                Some(names) => names
                    .iter()
                    .all(|name| name.as_str().is_some_and(|name| present(body, name))),
                None => return fail("`required` is a list of names"),
            },
            "oneOf" => satisfied_branches(value, body)? == 1,
            "anyOf" => satisfied_branches(value, body)? >= 1,
            other => return Err(format!("the keyword `{other}` is not evaluated")),
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

#[test]
fn the_evaluator_reads_presence_as_present_and_not_null() {
    let structure = json!({ "required": ["a"] });
    assert_eq!(satisfies(&structure, &json!({ "a": 1 })), Ok(true));
    assert_eq!(satisfies(&structure, &json!({ "a": null })), Ok(false));
    assert_eq!(satisfies(&structure, &json!({})), Ok(false));
}

#[test]
fn one_of_needs_exactly_one_branch_and_any_of_at_least_one() {
    let branches = json!([{ "required": ["a"] }, { "required": ["b"] }]);
    let one_of = json!({ "oneOf": branches });
    let any_of = json!({ "anyOf": branches });
    let both = json!({ "a": 1, "b": 2 });
    assert_eq!(satisfies(&one_of, &json!({ "a": 1 })), Ok(true));
    assert_eq!(satisfies(&one_of, &both), Ok(false));
    assert_eq!(satisfies(&one_of, &json!({})), Ok(false));
    assert_eq!(satisfies(&any_of, &both), Ok(true));
    assert_eq!(satisfies(&any_of, &json!({})), Ok(false));
}

#[test]
fn a_keyword_the_evaluator_does_not_know_is_refused_and_never_skipped() {
    for keyword in ["allOf", "not", "properties", "type"] {
        let structure = json!({ keyword: [] });
        assert!(satisfies(&structure, &json!({})).is_err(), "{keyword}");
    }
    assert!(satisfies(&json!({ "oneOf": 1 }), &json!({})).is_err());
    assert!(satisfies(&json!({ "required": "a" }), &json!({})).is_err());
    assert!(satisfies(&json!([]), &json!({})).is_err());
}

// ---- the deployment and the router -----------------------------------------------------------

/// The engine a deployment object describes. A key this test does not know is an error, so a
/// deployment option the artefact starts using fails here and is not ignored.
fn spec_for(deployment: &Value) -> Result<EngineSpec, String> {
    let mut spec = EngineSpec::default();
    for (key, value) in deployment.as_object().into_iter().flatten() {
        match (key.as_str(), value["method"].as_str()) {
            ("passwordReset", Some("token")) => spec.reset_method = ResetMethod::Token,
            ("passwordReset", Some("otp")) => spec.reset_method = ResetMethod::Otp,
            ("emailVerification", _) => {
                spec.verification_required = value["required"].as_bool().unwrap_or(false);
            }
            // The artefact names a Google client; the harness registers its own provider.
            ("oauth", _) => {
                spec.oauth = true;
                spec.allow_oauth = true;
            }
            (other, _) => return Err(format!("the deployment option `{other}` is not modelled")),
        }
    }
    Ok(spec)
}

/// The router for `deployment`, with the rate limits out of the way, and the harness behind it.
fn serve(deployment: &Value) -> Option<(common::Harness, axum::Router)> {
    let spec = spec_for(deployment);
    assert!(spec.is_ok(), "{:?}", spec.as_ref().err());
    let harness = build(spec.ok()?)?;
    let mut config =
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
    let generous = Some(bymax_auth_axum::RateLimit::new(100_000, 60));
    for setter in ALL_LIMIT_SETTERS {
        setter(&mut config.rate_limits, generous);
    }
    let app = router_with(&harness, config);
    Some((harness, app))
}

/// `value` with the probes' tenant replaced by the one the harness has.
fn localised(value: &Value) -> Value {
    match value {
        Value::String(text) if text == PROBE_TENANT => Value::String(TENANT.to_owned()),
        Value::Array(items) => Value::Array(items.iter().map(localised).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), localised(item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

// ---- what a probe expects ----------------------------------------------------------------------

/// The parts of an answer an `expect` can name.
fn describe(response: &Captured) -> (u16, Option<String>, Option<String>) {
    let body = response.json();
    let text = |value: &Value| value.as_str().map(str::to_owned);
    (
        response.status.as_u16(),
        text(&body["error"]["code"]),
        text(&body["error"]["details"][0]["field"]),
    )
}

/// The disagreements between an answer and an `expect` (`code`, `field`, `status`).
fn disagreements(response: &Captured, expect: &Value) -> Vec<String> {
    let (status, code, field) = describe(response);
    let mut found = Vec::new();
    let mut compare = |name: &str, want: Option<String>, got: Option<String>| {
        if want.is_some() && want != got {
            found.push(format!("{name}: wanted {want:?}, got {got:?}"));
        }
    };
    compare("code", expect["code"].as_str().map(str::to_owned), code);
    compare("field", expect["field"].as_str().map(str::to_owned), field);
    compare(
        "status",
        expect["status"].as_u64().map(|n| n.to_string()),
        Some(status.to_string()),
    );
    found
}

/// The path of an entry under the router's prefix.
fn route(entry: &Value) -> String {
    format!("/auth{}", entry["path"].as_str().unwrap_or_default())
}

/// Probes whose answer differs from the artefact's in one aspect: (entry, probe index, the
/// aspect, why). Each must still differ, in that aspect only, so a fix that does not remove its
/// entry fails the build, and a difference that is not listed fails it too.
const KNOWN_DIVERGENCES: [(&str, usize, &str, &str); 0] = [];

/// Records, in `failures`, what is wrong with a probe's disagreements given what is tracked.
fn judge(entry: &str, index: usize, found: &[String], failures: &mut Vec<String>) {
    let tracked = KNOWN_DIVERGENCES
        .iter()
        .find(|(key, at, ..)| *key == entry && *at == index);
    match (found.is_empty(), tracked) {
        (false, None) => failures.extend(found.iter().map(|f| format!("{entry}[{index}]: {f}"))),
        (true, Some((_, _, aspect, _))) => {
            failures.push(format!(
                "{entry}[{index}]: the `{aspect}` divergence is tracked but gone"
            ));
        }
        (false, Some((_, _, aspect, _))) => {
            for detail in found.iter().filter(|detail| !detail.starts_with(aspect)) {
                failures.push(format!(
                    "{entry}[{index}]: {detail} (only `{aspect}` is tracked)"
                ));
            }
        }
        (true, None) => {}
    }
}

async fn post(app: &axum::Router, path: &str, body: &Value) -> Captured {
    Req::post(path).json(localised(body)).send(app).await
}

// ---- the artefact's keys -------------------------------------------------------------------------

/// Every entry this test probes, with its kind.
const HANDLED_SEMANTICS: [(&str, &str); 6] = [
    ("AuthController.resendVerification", "indistinguishable"),
    ("AuthController.verifyEmail", "indistinguishable"),
    (
        "OAuthController.callback#codelessCallback",
        "handlerRefusal",
    ),
    (
        "PasswordResetController.forgotPassword",
        "indistinguishable",
    ),
    ("PasswordResetController.resendOtp", "indistinguishable"),
    (
        "PasswordResetController.resetPassword#passwordFloor",
        "policyFloor",
    ),
];

#[test]
fn the_entries_handled_here_are_exactly_the_artefacts_and_every_structure_is_evaluable() {
    let structures = declared_request_structures();
    let names: BTreeSet<&str> = structures.keys().map(String::as_str).collect();
    assert_eq!(names, BTreeSet::from(["ResetPasswordDto"]));
    for (name, entry) in &structures {
        assert_eq!(
            satisfies(&entry["structure"], &json!({})).map(|_| ()),
            Ok(()),
            "{name}"
        );
    }
    let semantics: BTreeMap<String, String> = declared_operation_semantics()
        .into_iter()
        .map(|(key, entry)| (key, entry["kind"].as_str().unwrap_or_default().to_owned()))
        .collect();
    let handled: BTreeMap<String, String> = HANDLED_SEMANTICS
        .iter()
        .map(|(key, kind)| ((*key).to_owned(), (*kind).to_owned()))
        .collect();
    assert_eq!(semantics, handled);
}

// ---- the request structure -----------------------------------------------------------------------

/// An entry of `requestStructures`, by DTO name.
fn structure_entry(name: &str) -> Value {
    declared_request_structures()
        .remove(name)
        .unwrap_or(Value::Null)
}

/// An entry of `operationSemantics`, by key.
fn semantics_entry(key: &str) -> Value {
    declared_operation_semantics()
        .remove(key)
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn the_reset_structure_agrees_with_its_evaluator_and_with_the_server() {
    let entry = structure_entry("ResetPasswordDto");
    let enforcement = &entry["enforcement"];
    assert_eq!(enforcement["kind"], "http");
    let Some((_h, app)) = serve(&enforcement["deployment"]) else { return };
    let path = route(enforcement);
    let mut failures = Vec::new();
    for (index, probe) in entry["probes"].as_array().into_iter().flatten().enumerate() {
        let verdict = satisfies(&entry["structure"], &probe["body"]);
        let said = probe["satisfies"].as_bool().unwrap_or(false);
        if verdict != Ok(said) {
            failures.push(format!(
                "probe {index}: the evaluator said {verdict:?}, the entry says {said}"
            ));
        }
        let response = post(&app, &path, &probe["body"]).await;
        let mut wanted = vec![probe["expect"].clone()];
        // A body that does not satisfy the structure is refused with the structure's own code.
        if !said {
            wanted.push(json!({ "code": enforcement["rejection"] }));
        }
        for expect in wanted {
            for found in disagreements(&response, &expect) {
                failures.push(format!("probe {index}: {found}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// What the server answers a body under one deployment: its status and its whole payload.
async fn answer_under(deployment: &Value, path: &str, body: &Value) -> Option<(u16, Value)> {
    let (_h, app) = serve(deployment)?;
    let response = post(&app, path, body).await;
    Some((response.status.as_u16(), response.json()))
}

#[tokio::test]
async fn the_narrowing_pairs_are_what_their_role_says() {
    let entry = structure_entry("ResetPasswordDto");
    let path = route(&entry["enforcement"]);
    let mut roles = Vec::new();
    for pair in entry["narrowing"]["pairs"].as_array().into_iter().flatten() {
        let role = pair["role"].as_str().unwrap_or_default().to_owned();
        let mut answers = Vec::new();
        for outcome in pair["outcomes"].as_array().into_iter().flatten() {
            let Some(answer) = answer_under(&outcome["deployment"], &path, &pair["body"]).await
            else {
                return;
            };
            let code = answer.1["error"]["code"].as_str().map(str::to_owned);
            assert_eq!(
                code.as_deref(),
                outcome["expect"]["code"].as_str(),
                "{role}: {outcome}"
            );
            answers.push(answer);
        }
        // `documents`: the deployments answer identically in status and payload. `demonstrates`:
        // they must answer differently. A pair labelled the wrong way round fails here.
        let identical = answers.windows(2).all(|pair| pair[0] == pair[1]);
        assert_eq!(identical, role == "documents", "{role}: {}", pair["note"]);
        roles.push(role);
    }
    assert!(
        roles.iter().any(|role| role == "demonstrates"),
        "no pair demonstrates"
    );
    assert!(
        roles
            .iter()
            .all(|role| role == "documents" || role == "demonstrates")
    );
}

// ---- the operation semantics -----------------------------------------------------------------------

#[tokio::test]
async fn the_policy_floor_and_the_order_of_the_checks_are_what_the_probes_say() {
    let entry = semantics_entry("PasswordResetController.resetPassword#passwordFloor");
    assert_eq!(entry["kind"], "policyFloor");
    let path = route(&entry);
    let mut failures = Vec::new();
    for (index, probe) in entry["probes"].as_array().into_iter().flatten().enumerate() {
        let Some((_h, app)) = serve(&probe["deployment"]) else { return };
        let response = post(&app, &path, &probe["body"]).await;
        let key = "PasswordResetController.resetPassword#passwordFloor";
        judge(
            key,
            index,
            &disagreements(&response, &probe["expect"]),
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `query` as a query string, with a placeholder replaced by a value one character past the
/// bound the request-schemas artefact declares for `code`.
fn query_string(query: &Value) -> String {
    let bound = request_schema("OAuthCallbackQueryDto")
        .and_then(|schema| schema["properties"]["code"]["maxLength"].as_u64())
        .and_then(|max| usize::try_from(max).ok())
        .unwrap_or(0);
    query
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, value)| match value.as_str() {
            Some("OVERSIZED_CODE_2049") => format!("{key}={}", "x".repeat(bound + 1)),
            other => format!("{key}={}", other.unwrap_or_default()),
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[tokio::test]
async fn a_callback_without_a_code_is_the_handlers_refusal_and_not_the_pipes() {
    let entry = semantics_entry("OAuthController.callback#codelessCallback");
    assert_eq!(entry["kind"], "handlerRefusal");
    assert_eq!(entry["method"], "get");
    let Some((_h, app)) = serve(&entry["deployment"]) else { return };
    let mut failures = Vec::new();
    for (index, probe) in entry["probes"].as_array().into_iter().flatten().enumerate() {
        let url = format!("{}?{}", route(&entry), query_string(&probe["query"]));
        let response = Req::get(&url).send(&app).await;
        let key = "OAuthController.callback#codelessCallback";
        judge(
            key,
            index,
            &disagreements(&response, &probe["expect"]),
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The account the entry's registered body names: registered through the route when the
/// deployment verifies emails (so a verification record exists), seeded otherwise.
async fn create_registered_account(h: &common::Harness, app: &axum::Router, entry: &Value) {
    let email = entry["registeredBody"]["email"]
        .as_str()
        .unwrap_or_default();
    if entry["deployment"]["emailVerification"]["required"] == true {
        let registered = post(
            app,
            "/auth/register",
            &json!({ "email": email, "password": "glidingwalnut42", "name": "Reg", "tenantId": PROBE_TENANT }),
        )
        .await;
        assert_eq!(registered.status, StatusCode::CREATED);
    } else {
        seed_user(h, email, "glidingwalnut42", "USER").await;
    }
}

#[tokio::test]
async fn the_responses_the_artefact_calls_indistinguishable_are_identical() {
    for (key, entry) in declared_operation_semantics() {
        if entry["kind"] != "indistinguishable" {
            continue;
        }
        let Some((h, app)) = serve(&entry["deployment"]) else { return };
        create_registered_account(&h, &app, &entry).await;
        let path = route(&entry);
        let registered = post(&app, &path, &entry["registeredBody"]).await;
        let unknown = post(&app, &path, &entry["unknownBody"]).await;
        for response in [&registered, &unknown] {
            assert_eq!(
                disagreements(response, &entry["expect"]),
                Vec::<String>::new(),
                "{key}"
            );
        }
        let shape =
            |response: &Captured| (response.status, response.json(), response.retry_after());
        assert_eq!(shape(&registered), shape(&unknown), "{key}");
    }
}
