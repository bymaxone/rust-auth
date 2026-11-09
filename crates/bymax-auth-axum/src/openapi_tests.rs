//! The OpenAPI schema accessors, against the copy of the artefact held under `conformance/`.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::openapi::{
    REQUEST_SCHEMAS_JSON, openapi_version, request_schema, request_schema_names, request_schemas,
};

/// The shared copy, as it sits in the repository.
const CONFORMANCE_COPY: &str = include_str!("../../../conformance/openapi-request-schemas.json");

fn conformance_schemas() -> Value {
    serde_json::from_str::<Value>(CONFORMANCE_COPY)
        .map_or(Value::Null, |root| root["schemas"].clone())
}

#[test]
fn the_copy_that_ships_with_the_crate_is_the_shared_artefact_byte_for_byte() {
    // The crate cannot `include_str!` a file outside its own directory and still package, so it
    // carries a copy; this is what keeps the copy from becoming a second source.
    assert_eq!(REQUEST_SCHEMAS_JSON, CONFORMANCE_COPY);
}

#[test]
fn every_schema_of_the_artefact_is_served_and_nothing_else() {
    let shared = conformance_schemas();
    let expected: BTreeSet<String> = shared
        .as_object()
        .map(|schemas| schemas.keys().cloned().collect())
        .unwrap_or_default();
    let served: BTreeSet<String> = request_schemas().keys().cloned().collect();
    assert_eq!(served, expected);
    assert!(!expected.is_empty());
    let names: BTreeSet<String> = request_schema_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(names, expected);
}

#[test]
fn a_served_schema_is_the_artefacts_schema() {
    let shared = conformance_schemas();
    for (name, schema) in request_schemas() {
        assert_eq!(schema, shared[name.as_str()], "{name}");
    }
    assert_eq!(
        request_schema("LoginDto").as_ref(),
        Some(&shared["LoginDto"])
    );
}

#[test]
fn an_unknown_schema_name_is_none() {
    assert_eq!(request_schema("NoSuchDto"), None);
    assert_eq!(request_schema(""), None);
}

#[test]
fn the_names_come_back_sorted_and_the_version_is_openapi_3_0() {
    let names = request_schema_names();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    assert_eq!(openapi_version(), "3.0");
}

use std::collections::BTreeMap;

use crate::RouteGroups;
use crate::openapi::{RouteGroup, request_body_routes, request_schemas_for};

/// `groups` with exactly the named groups on.
fn mounting(on: &[RouteGroup]) -> RouteGroups {
    let has = |group| on.contains(&group);
    RouteGroups {
        auth: has(RouteGroup::Auth),
        mfa: has(RouteGroup::Mfa),
        password_reset: has(RouteGroup::PasswordReset),
        sessions: false,
        platform: has(RouteGroup::Platform),
        platform_mfa: has(RouteGroup::PlatformMfa),
        oauth: false,
        invitations: has(RouteGroup::Invitations),
        email_change: has(RouteGroup::EmailChange),
    }
}

const ALL_GROUPS: [RouteGroup; 7] = [
    RouteGroup::Auth,
    RouteGroup::PasswordReset,
    RouteGroup::Mfa,
    RouteGroup::Platform,
    RouteGroup::PlatformMfa,
    RouteGroup::Invitations,
    RouteGroup::EmailChange,
];

/// The schemas nest-auth contributes per controller family (`REQUEST_SCHEMAS_BY_CONTROLLER` in
/// `src/server/openapi/request-schema-mounts.ts`, v1.4.22), for the families rust mounts as
/// groups. Sessions and OAuth take no body schema there.
fn nest_schemas(group: RouteGroup) -> Vec<&'static str> {
    let mut names = match group {
        RouteGroup::Auth => vec![
            "RegisterDto",
            "LoginDto",
            "VerifyEmailDto",
            "ResendVerificationDto",
        ],
        RouteGroup::PasswordReset => vec![
            "ForgotPasswordDto",
            "ResetPasswordDto",
            "ChangePasswordDto",
            "VerifyOtpDto",
            "ResendOtpDto",
        ],
        RouteGroup::Mfa => vec![
            "MfaSetupDto",
            "MfaVerifyDto",
            "MfaChallengeDto",
            "MfaDisableDto",
            "MfaRegenerateRecoveryCodesDto",
        ],
        RouteGroup::Platform => vec!["PlatformLoginDto", "MfaChallengeDto"],
        RouteGroup::PlatformMfa => vec![
            "MfaSetupDto",
            "MfaVerifyDto",
            "MfaDisableDto",
            "MfaRegenerateRecoveryCodesDto",
        ],
        RouteGroup::Invitations => vec![
            "CreateInvitationDto",
            "RevokeInvitationDto",
            "AcceptInvitationDto",
        ],
        RouteGroup::EmailChange => vec!["ChangeEmailDto", "ConfirmEmailChangeDto"],
    };
    names.sort_unstable();
    names
}

#[test]
fn every_route_names_a_schema_the_artefact_has() {
    for route in request_body_routes() {
        assert!(request_schema(route.schema).is_some(), "{route:?}");
        assert_eq!(route.method, "POST", "{route:?}");
        assert!(route.path.starts_with('/'), "{route:?}");
    }
}

#[test]
fn a_group_contributes_the_schemas_nest_auth_contributes_for_it() {
    for group in ALL_GROUPS {
        let served: Vec<String> = request_schemas_for(mounting(&[group]))
            .into_keys()
            .collect();
        assert_eq!(served, nest_schemas(group), "{group:?}");
    }
}

#[test]
fn a_group_left_off_contributes_nothing_and_the_groups_add_up() {
    assert!(request_schemas_for(mounting(&[])).is_empty());
    let all = request_schemas_for(mounting(&ALL_GROUPS));
    let mut expected: BTreeMap<String, Value> = BTreeMap::new();
    for group in ALL_GROUPS {
        expected.extend(request_schemas_for(mounting(&[group])));
    }
    assert_eq!(all, expected);
    // The artefact is complete: every schema is served by a group, except the two OAuth query
    // schemas, which are query strings and not request bodies.
    let mut unserved: Vec<String> = request_schemas()
        .into_keys()
        .filter(|name| !all.contains_key(name))
        .collect();
    unserved.sort_unstable();
    assert_eq!(unserved, ["OAuthCallbackQueryDto", "OAuthInitiateQueryDto"]);
}

#[test]
fn a_schema_is_served_unchanged_through_the_selection() {
    let served = request_schemas_for(mounting(&[RouteGroup::Auth]));
    assert_eq!(served.get("LoginDto"), request_schema("LoginDto").as_ref());
}
