//! The request-body routes against `bymax_auth_axum::openapi::request_body_routes`.
//!
//! The table maps each route that takes a JSON body to the schema that describes it. Three things
//! keep it from drifting away from the router:
//!
//! * the **behavioural probe** posts to every row a body that breaks exactly one bound of the
//!   row's own schema, and expects the validation error to name that field. It is the only check
//!   that proves a schema describes *that route's* validation;
//! * the **mounted set** is read from the real router and compared with the table and two named
//!   lists, so a route added without a row or a place on a list fails;
//! * the **source inventory** finds the handlers that extract a JSON body in `src/routes/*.rs` and
//!   compares them with the table, because extractor types are erased in the router.
//!
//! The mounted set and the inventory are completeness checks. They read text that is not an
//! API (the router's `Debug` output of axum 0.8, and Rust source), and both fail loudly when
//! the text stops looking the way they expect.

use std::collections::{BTreeMap, BTreeSet};

use bymax_auth_axum::openapi::{RequestBodyRoute, request_body_routes, request_schema};
use serde_json::{Value, json};

use super::*;

/// The route files, by the name they are listed under.
const ROUTE_SOURCES: [(&str, &str); 9] = [
    ("auth", include_str!("../../src/routes/auth.rs")),
    (
        "email_change",
        include_str!("../../src/routes/email_change.rs"),
    ),
    (
        "invitations",
        include_str!("../../src/routes/invitations.rs"),
    ),
    ("mfa", include_str!("../../src/routes/mfa.rs")),
    ("oauth", include_str!("../../src/routes/oauth.rs")),
    (
        "password_reset",
        include_str!("../../src/routes/password_reset.rs"),
    ),
    ("platform", include_str!("../../src/routes/platform.rs")),
    (
        "platform_mfa",
        include_str!("../../src/routes/platform_mfa.rs"),
    ),
    ("sessions", include_str!("../../src/routes/sessions.rs")),
];

/// The prefix the harness router mounts everything under.
const PREFIX: &str = "/auth";

/// Handlers that read their body as raw bytes, not through `ValidatedJson`, with the schema of
/// the body when there is one and the reason for reading it that way. Matched in both
/// directions against the source.
const BYTES_BODIES: [(&str, Option<&str>, &str); 7] = [
    (
        "/mfa/setup",
        Some("MfaSetupDto"),
        "an empty body is valid, so it is parsed only when present",
    ),
    (
        "/platform/mfa/setup",
        Some("MfaSetupDto"),
        "an empty body is valid, so it is parsed only when present",
    ),
    (
        "/logout",
        None,
        "the refresh token travels in the cookie or the body; no shared schema",
    ),
    (
        "/refresh",
        None,
        "the refresh token travels in the cookie or the body; no shared schema",
    ),
    (
        "/sessions/revoke-all",
        None,
        "the keep-session token travels in the cookie or the body; no shared schema",
    ),
    (
        "/platform/logout",
        None,
        "the refresh token travels in the body; no shared schema",
    ),
    (
        "/platform/refresh",
        None,
        "the refresh token travels in the body; no shared schema",
    ),
];

/// Mounted routes that read no body, so no schema describes them.
const NO_BODY_ROUTES: [(&str, &str); 8] = [
    ("GET", "/me"),
    ("POST", "/ws-ticket"),
    ("GET", "/sessions"),
    ("DELETE", "/sessions/{id}"),
    ("GET", "/oauth/{provider}"),
    ("GET", "/oauth/{provider}/callback"),
    ("GET", "/platform/me"),
    ("DELETE", "/platform/sessions"),
];

/// Rows reachable without a session. Every other row is probed with a session, a platform one
/// for the platform MFA routes and a dashboard one for the rest.
const PUBLIC_ROWS: [&str; 12] = [
    "/register",
    "/login",
    "/verify-email",
    "/resend-verification",
    "/password/forgot-password",
    "/password/reset-password",
    "/password/verify-otp",
    "/password/resend-otp",
    "/mfa/challenge",
    "/platform/login",
    "/platform/mfa/challenge",
    "/invitations/accept",
];

/// The text between the first `from` and the next `to` after it.
fn between<'a>(text: &'a str, from: &str, to: &str) -> &'a str {
    let start = text.find(from).map_or(text.len(), |at| at + from.len());
    let rest = &text[start..];
    rest.find(to).map_or(rest, |end| &rest[..end])
}

/// The (verb, path) of every route the router mounts, joined by route id from its `Debug`
/// output. That output is not an API: when axum changes it, this is the function to update.
fn mounted_routes(app: &axum::Router) -> BTreeSet<(String, String)> {
    let text = format!("{app:?}");
    let methods = between(&text, "routes: {", "node: Node");
    // A path can hold `{provider}`, so the list ends at the brace that closes the node, not the first one.
    let paths = between(&text, "paths: {", " } }");
    let by_id: BTreeMap<&str, &str> = paths
        .split("RouteId(")
        .skip(1)
        .filter_map(|entry| Some((entry.split_once(')')?.0, between(entry, "\"", "\""))))
        .collect();
    let mut mounted = BTreeSet::new();
    for entry in methods.split("RouteId(").skip(1) {
        let id = entry.split_once(')').map_or("", |(id, _)| id);
        for verb in ["get", "post", "delete", "put"] {
            if entry.contains(&format!("{verb}: Route")) {
                let path = by_id.get(id).copied().unwrap_or_default();
                mounted.insert((verb.to_uppercase(), path.to_owned()));
            }
        }
    }
    mounted
}

/// A route registration found in a route file: verb, path below the file's own nest segment,
/// and handler name.
fn registrations(source: &str) -> Vec<(String, String, String)> {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let nest = between(&code, ".nest(", ",")
        .trim()
        .trim_matches('"')
        .to_owned();
    let nest = if code.contains(".nest(") {
        nest
    } else {
        String::new()
    };
    code.split(".route(")
        .skip(1)
        .filter_map(|chunk| {
            let path = between(chunk, "\"", "\"");
            let after = &chunk[chunk.find('"')? + path.len() + 2..];
            let (verb, at) = ["get(", "post(", "delete(", "put("]
                .iter()
                .filter_map(|verb| after.find(verb).map(|at| (*verb, at)))
                .min_by_key(|(_, at)| *at)?;
            let handler = between(&after[at + verb.len()..], "", ")");
            Some((
                verb.trim_end_matches('(').to_uppercase(),
                format!("{nest}{path}"),
                handler.rsplit("::").next().unwrap_or_default().to_owned(),
            ))
        })
        .collect()
}

/// What a handler extracts its body with: `Json(type)` for `ValidatedJson<type>`, `Bytes` for
/// `RequestBytes`, or nothing.
fn body_extractor(source: &str, handler: &str) -> (Option<String>, bool) {
    let signature = source
        .split(&format!("fn {handler}("))
        .nth(1)
        .map_or("", |rest| between(rest, "", "{"));
    let json = signature
        .contains("ValidatedJson<")
        .then(|| between(signature, "ValidatedJson<", ">").to_owned());
    (json, signature.contains("RequestBytes"))
}

/// The schema name nest-auth uses for a Rust request type.
fn schema_name(rust_type: &str) -> String {
    if rust_type.ends_with("Dto") {
        rust_type.to_owned()
    } else {
        format!("{rust_type}Dto")
    }
}

/// A valid request-body value for a schema property, by the keywords the artefact uses.
fn valid_value(property: &Value) -> String {
    let min = property["minLength"]
        .as_u64()
        .map_or(1, |n| usize::try_from(n).unwrap_or(1));
    let max = property["maxLength"]
        .as_u64()
        .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    match property["pattern"].as_str() {
        Some(pattern) if pattern.contains("\\d{6}") => "123456".to_owned(),
        _ if property["format"] == "email" => "user@example.com".to_owned(),
        _ => "a".repeat(8.clamp(min, max)),
    }
}

/// An address of exactly `len` characters that is valid in every other respect: a local part of
/// at most 64 and labels of at most 63, so only its length can be what refuses it.
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

/// A value one character over the property's maximum, valid in every other respect where the
/// keywords allow it.
fn over_maximum(property: &Value) -> String {
    let max = property["maxLength"]
        .as_u64()
        .map_or(0, |n| usize::try_from(n).unwrap_or(0));
    if property["format"] == "email" {
        email_of_len(max + 1)
    } else {
        "1".repeat(max + 1)
    }
}

/// A body with every required property valid and `broken` one character over its maximum.
fn body_breaking(schema: &Value, broken: &str) -> Value {
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut body = serde_json::Map::new();
    for (name, property) in schema["properties"].as_object().into_iter().flatten() {
        if name == broken {
            body.insert(name.clone(), Value::String(over_maximum(property)));
        } else if required.contains(name.as_str()) {
            body.insert(name.clone(), Value::String(valid_value(property)));
        }
    }
    Value::Object(body)
}

/// The properties of the schema that have a maximum: each is broken in turn by the probe.
fn bounded(schema: &Value) -> Vec<String> {
    schema["properties"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, property)| property["maxLength"].is_u64())
        .map(|(name, _)| name.clone())
        .collect()
}

/// A router with every optional group on, and the harness behind it.
fn every_group() -> Option<(common::Harness, axum::Router)> {
    let harness = build(EngineSpec {
        mfa: true,
        platform: true,
        oauth: true,
        allow_oauth: true,
        invitations: true,
        email_change: true,
        sessions: true,
        ..EngineSpec::default()
    })?;
    let mut config =
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
    let generous = Some(bymax_auth_axum::RateLimit::new(10_000, 60));
    for setter in ALL_LIMIT_SETTERS {
        setter(&mut config.rate_limits, generous);
    }
    let app = router_with(&harness, config);
    Some((harness, app))
}

#[tokio::test]
async fn the_mounted_set_is_the_rows_the_named_lists_and_nothing_else() {
    let Some((_, app)) = every_group() else { return };
    let mounted = mounted_routes(&app);
    assert!(
        mounted.contains(&("POST".to_owned(), format!("{PREFIX}/login"))),
        "axum 0.8's Router Debug layout changed and this test cannot read the route table any \
         more: update mounted_routes() in tests/adapter/openapi_routes.rs. Parsed: {mounted:?}"
    );
    let mut expected: BTreeSet<(String, String)> = request_body_routes()
        .iter()
        .map(|route| (route.method.to_owned(), format!("{PREFIX}{}", route.path)))
        .collect();
    expected.extend(
        BYTES_BODIES
            .iter()
            .map(|(path, ..)| ("POST".to_owned(), format!("{PREFIX}{path}"))),
    );
    expected.extend(
        NO_BODY_ROUTES
            .iter()
            .map(|(verb, path)| ((*verb).to_owned(), format!("{PREFIX}{path}"))),
    );
    assert_eq!(
        mounted, expected,
        "mounted on the left, rows and named lists on the right"
    );
}

#[test]
fn the_rows_are_the_handlers_that_extract_a_json_body() {
    let mut json_routes = BTreeSet::new();
    let mut bytes_routes = BTreeSet::new();
    let mut json_extractors = 0;
    for (_, source) in ROUTE_SOURCES {
        json_extractors += source.matches("ValidatedJson<").count();
        for (verb, path, handler) in registrations(source) {
            let (json_type, bytes) = body_extractor(source, &handler);
            if let Some(rust_type) = json_type {
                json_routes.insert((verb.clone(), path.clone(), schema_name(&rust_type)));
            }
            if bytes {
                bytes_routes.insert((verb, path));
            }
        }
    }
    // Every `ValidatedJson<` in the route files belongs to a registered handler, so a shape the
    // scan did not understand (an alias, a wrapper, a handler registered elsewhere) fails here.
    assert_eq!(json_extractors, json_routes.len(), "{json_routes:?}");
    let mut table: BTreeSet<(String, String, String)> = request_body_routes()
        .iter()
        .map(|route| {
            (
                route.method.to_owned(),
                route.path.to_owned(),
                route.schema.to_owned(),
            )
        })
        .collect();
    for (path, schema, _) in BYTES_BODIES {
        if let Some(schema) = schema {
            assert!(
                table.remove(&("POST".to_owned(), path.to_owned(), schema.to_owned())),
                "{path}"
            );
        }
    }
    assert_eq!(json_routes, table);
    let listed: BTreeSet<(String, String)> = BYTES_BODIES
        .iter()
        .map(|(path, ..)| ("POST".to_owned(), (*path).to_owned()))
        .collect();
    assert_eq!(bytes_routes, listed);
    assert!(BYTES_BODIES.iter().all(|(_, _, reason)| !reason.is_empty()));
}

/// The sessions the probe presents: a dashboard cookie value and a platform bearer token.
struct Sessions {
    dashboard: String,
    platform: String,
}

/// Posts to `route` a body one character over the maximum of `broken`, with the session the
/// route needs, and checks the refusal: `400 auth.validation`, naming the field as the wire does.
async fn probe_property(
    app: &axum::Router,
    sessions: &Sessions,
    route: &RequestBodyRoute,
    schema: &Value,
    broken: &str,
) {
    let request = Req::post(&format!("{PREFIX}{}", route.path)).json(body_breaking(schema, broken));
    let request = if PUBLIC_ROWS.contains(&route.path) {
        request
    } else if route.path.starts_with("/platform/mfa/") {
        request.bearer(&sessions.platform)
    } else {
        request.cookie("access_token", &sessions.dashboard)
    };
    let res = request.send(app).await;
    let label = format!("{route:?} with {broken} over its maximum");
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "{label}: {:?}",
        res.json()
    );
    assert_eq!(
        res.json()["error"]["code"],
        json!("auth.validation"),
        "{label}"
    );
    let fields = res.json()["error"]["details"].to_string();
    assert!(
        fields.contains(&format!("\"{broken}\"")),
        "{label}: the error names {fields}"
    );
    // The length bound must be what refused it. A fixed-format code cannot say so: its pattern
    // fixes the length, so the format refusal and the length refusal are one.
    let fixed_format = schema["properties"][broken]["pattern"]
        .as_str()
        .is_some_and(|pattern| pattern.contains("\\d{6}"));
    assert!(
        fixed_format || fields.contains("length is greater than"),
        "{label}: {fields}"
    );
}

#[tokio::test]
async fn every_body_route_refuses_a_body_that_breaks_its_own_schema() {
    let Some((h, app)) = every_group() else { return };
    seed_user(&h, "probe@e.com", "glidingwalnut42", "ADMIN").await;
    seed_admin(&h, "padmin@e.com", "SUPER_ADMIN").await;
    let sessions = Sessions {
        dashboard: login_access_cookie(&app, "probe@e.com", "glidingwalnut42").await,
        platform: platform_access(&platform_login(&app, "padmin@e.com").await),
    };
    assert!(!sessions.dashboard.is_empty() && !sessions.platform.is_empty());

    for route in request_body_routes() {
        let Some(schema) = request_schema(route.schema) else { continue };
        for broken in bounded(&schema) {
            probe_property(&app, &sessions, route, &schema, &broken).await;
        }
    }
}
