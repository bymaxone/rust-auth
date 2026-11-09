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
        sessions: has(RouteGroup::Sessions),
        platform: has(RouteGroup::Platform),
        platform_mfa: has(RouteGroup::PlatformMfa),
        oauth: has(RouteGroup::OAuth),
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
        RouteGroup::Sessions | RouteGroup::OAuth => Vec::new(),
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

use bymax_auth_core::config::TokenDelivery;
use serde_json::json;

use crate::openapi::{
    ACCESS_BEARER_SCHEME, ACCESS_COOKIE_SCHEME, GuardFamily, PLATFORM_BEARER_SCHEME,
    REFRESH_COOKIE_SCHEME, derive_security_schemes, document_security,
};

const DELIVERIES: [TokenDelivery; 3] = [
    TokenDelivery::Cookie,
    TokenDelivery::Bearer,
    TokenDelivery::Both,
];

/// No group mounted.
fn nothing() -> RouteGroups {
    RouteGroups {
        auth: false,
        mfa: false,
        password_reset: false,
        sessions: false,
        platform: false,
        platform_mfa: false,
        oauth: false,
        invitations: false,
        email_change: false,
    }
}

/// The scheme names defined for `groups` under `delivery`, sorted.
fn defined(delivery: TokenDelivery, groups: RouteGroups) -> Vec<&'static str> {
    derive_security_schemes(delivery, "ca", "cr", groups)
        .into_keys()
        .collect()
}

/// The names expected, sorted the way the map sorts them.
fn sorted(mut names: Vec<&'static str>) -> Vec<&'static str> {
    names.sort_unstable();
    names
}

#[test]
fn the_scheme_names_are_the_closed_vocabulary_nest_auth_uses() {
    // AUTH_SECURITY_SCHEMES in nest-auth v1.4.22 (`src/server/openapi/auth-openapi-fragment.ts`).
    // Renaming one is a break a generated client feels, so they are fixed identifiers.
    assert_eq!(ACCESS_COOKIE_SCHEME, "bymaxAuthAccessCookie");
    assert_eq!(ACCESS_BEARER_SCHEME, "bymaxAuthAccessBearer");
    assert_eq!(REFRESH_COOKIE_SCHEME, "bymaxAuthRefreshCookie");
    assert_eq!(PLATFORM_BEARER_SCHEME, "bymaxPlatformAccessBearer");
}

#[test]
fn a_deployment_defines_only_the_schemes_it_can_satisfy() {
    // (the groups mounted, the schemes under Cookie, under Bearer, under Both)
    let cases: [(&str, RouteGroups, [Vec<&str>; 3]); 11] = [
        ("nothing", nothing(), [vec![], vec![], vec![]]),
        // OAuth's operations are public and name no credential: mounted alone it defines nothing.
        (
            "oauth only",
            RouteGroups {
                oauth: true,
                ..nothing()
            },
            [vec![], vec![], vec![]],
        ),
        (
            "auth",
            RouteGroups {
                auth: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME, REFRESH_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![
                    ACCESS_COOKIE_SCHEME,
                    ACCESS_BEARER_SCHEME,
                    REFRESH_COOKIE_SCHEME,
                ],
            ],
        ),
        (
            "sessions only (reads the refresh cookie)",
            RouteGroups {
                sessions: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME, REFRESH_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![
                    ACCESS_COOKIE_SCHEME,
                    ACCESS_BEARER_SCHEME,
                    REFRESH_COOKIE_SCHEME,
                ],
            ],
        ),
        (
            "password reset only (the change spares the caller's session)",
            RouteGroups {
                password_reset: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME, REFRESH_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![
                    ACCESS_COOKIE_SCHEME,
                    ACCESS_BEARER_SCHEME,
                    REFRESH_COOKIE_SCHEME,
                ],
            ],
        ),
        (
            "mfa reads no refresh cookie",
            RouteGroups {
                mfa: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![ACCESS_COOKIE_SCHEME, ACCESS_BEARER_SCHEME],
            ],
        ),
        (
            "invitations reads no refresh cookie",
            RouteGroups {
                invitations: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![ACCESS_COOKIE_SCHEME, ACCESS_BEARER_SCHEME],
            ],
        ),
        (
            "email change reads no refresh cookie",
            RouteGroups {
                email_change: true,
                ..nothing()
            },
            [
                vec![ACCESS_COOKIE_SCHEME],
                vec![ACCESS_BEARER_SCHEME],
                vec![ACCESS_COOKIE_SCHEME, ACCESS_BEARER_SCHEME],
            ],
        ),
        (
            "platform: bearer in every mode",
            RouteGroups {
                platform: true,
                ..nothing()
            },
            [
                vec![PLATFORM_BEARER_SCHEME],
                vec![PLATFORM_BEARER_SCHEME],
                vec![PLATFORM_BEARER_SCHEME],
            ],
        ),
        (
            "platform MFA alone",
            RouteGroups {
                platform_mfa: true,
                ..nothing()
            },
            [
                vec![PLATFORM_BEARER_SCHEME],
                vec![PLATFORM_BEARER_SCHEME],
                vec![PLATFORM_BEARER_SCHEME],
            ],
        ),
        (
            "auth and platform together",
            RouteGroups {
                auth: true,
                platform: true,
                ..nothing()
            },
            [
                vec![
                    ACCESS_COOKIE_SCHEME,
                    REFRESH_COOKIE_SCHEME,
                    PLATFORM_BEARER_SCHEME,
                ],
                vec![ACCESS_BEARER_SCHEME, PLATFORM_BEARER_SCHEME],
                vec![
                    ACCESS_COOKIE_SCHEME,
                    ACCESS_BEARER_SCHEME,
                    REFRESH_COOKIE_SCHEME,
                    PLATFORM_BEARER_SCHEME,
                ],
            ],
        ),
    ];
    for (label, groups, expected) in cases {
        for (delivery, names) in DELIVERIES.into_iter().zip(expected) {
            assert_eq!(
                defined(delivery, groups),
                sorted(names),
                "{label} under {delivery:?}"
            );
        }
    }
}

#[test]
fn each_scheme_is_the_object_a_document_builder_expects() {
    let groups = RouteGroups {
        auth: true,
        platform: true,
        ..nothing()
    };
    let schemes = derive_security_schemes(TokenDelivery::Both, "my_access", "my_refresh", groups);
    // The cookie names are the deployment's: a document naming `access_token` on a deployment
    // that renamed it describes a different server.
    assert_eq!(schemes[ACCESS_COOKIE_SCHEME]["type"], json!("apiKey"));
    assert_eq!(schemes[ACCESS_COOKIE_SCHEME]["in"], json!("cookie"));
    assert_eq!(schemes[ACCESS_COOKIE_SCHEME]["name"], json!("my_access"));
    assert_eq!(schemes[REFRESH_COOKIE_SCHEME]["type"], json!("apiKey"));
    assert_eq!(schemes[REFRESH_COOKIE_SCHEME]["in"], json!("cookie"));
    assert_eq!(schemes[REFRESH_COOKIE_SCHEME]["name"], json!("my_refresh"));
    for bearer in [ACCESS_BEARER_SCHEME, PLATFORM_BEARER_SCHEME] {
        assert_eq!(schemes[bearer]["type"], json!("http"), "{bearer}");
        assert_eq!(schemes[bearer]["scheme"], json!("bearer"), "{bearer}");
        assert_eq!(schemes[bearer]["bearerFormat"], json!("JWT"), "{bearer}");
    }
    assert!(
        schemes
            .values()
            .all(|scheme| scheme["description"].is_string())
    );
}

#[test]
fn the_document_default_follows_the_delivery_mode() {
    let requirement = |scheme: &str| json!({ scheme: [] });
    assert_eq!(
        document_security(GuardFamily::Dashboard, TokenDelivery::Cookie),
        [requirement(ACCESS_COOKIE_SCHEME)]
    );
    assert_eq!(
        document_security(GuardFamily::Dashboard, TokenDelivery::Bearer),
        [requirement(ACCESS_BEARER_SCHEME)]
    );
    // Two entries, each naming one scheme: OpenAPI reads a list as OR, and one entry holding both
    // would mean AND.
    assert_eq!(
        document_security(GuardFamily::Dashboard, TokenDelivery::Both),
        [
            requirement(ACCESS_COOKIE_SCHEME),
            requirement(ACCESS_BEARER_SCHEME)
        ]
    );
    for delivery in DELIVERIES {
        assert_eq!(
            document_security(GuardFamily::Platform, delivery),
            [requirement(PLATFORM_BEARER_SCHEME)],
            "{delivery:?}"
        );
    }
}

#[test]
fn a_document_default_never_names_a_scheme_the_deployment_does_not_define() {
    for delivery in DELIVERIES {
        let everything = RouteGroups {
            auth: true,
            mfa: true,
            password_reset: true,
            sessions: true,
            platform: true,
            platform_mfa: true,
            oauth: true,
            invitations: true,
            email_change: true,
        };
        let defined_here = defined(delivery, everything);
        for guard in [GuardFamily::Dashboard, GuardFamily::Platform] {
            let default = document_security(guard, delivery);
            assert!(!default.is_empty(), "{guard:?} under {delivery:?}");
            for requirement in default {
                let names: Vec<&str> = requirement
                    .as_object()
                    .into_iter()
                    .flat_map(|entry| entry.keys().map(String::as_str))
                    .collect();
                assert_eq!(names.len(), 1, "{requirement}");
                assert!(
                    defined_here.contains(&names[0]),
                    "{guard:?} {delivery:?} names {names:?}"
                );
            }
        }
    }
}

#[test]
fn a_group_is_mounted_exactly_when_its_own_toggle_is_on() {
    let every = [
        RouteGroup::Auth,
        RouteGroup::PasswordReset,
        RouteGroup::Mfa,
        RouteGroup::Platform,
        RouteGroup::PlatformMfa,
        RouteGroup::Invitations,
        RouteGroup::EmailChange,
        RouteGroup::Sessions,
        RouteGroup::OAuth,
    ];
    for group in every {
        for other in every {
            assert_eq!(
                other.is_mounted(mounting(&[group])),
                other == group,
                "{other:?} with only {group:?} on"
            );
        }
    }
}
