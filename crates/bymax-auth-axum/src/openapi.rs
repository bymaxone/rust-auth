//! The OpenAPI 3.0 request-body schemas of the auth routes (layer: HTTP adapter, feature
//! `openapi`).
//!
//! The schemas are `nest-auth`'s, generated there from its own validators and held here
//! byte-identical in `openapi/openapi-request-schemas.json`, so a client generated from either
//! backend sees the same names and the same bounds. They are plain `serde_json` values: this
//! module builds no document and serves no route. A host places the schemas it wants under
//! `components.schemas` of whatever document it builds.
//!
//! Lengths are counts of characters, the way JSON Schema defines `minLength` and `maxLength`;
//! the DTOs this crate validates with count the same way.
//!
//! The schemas are OpenAPI 3.0 on purpose: a 3.1 fragment merged into a 3.0 document validates
//! as neither. [`openapi_version`] names the version the schemas are written for.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

use crate::RouteGroups;

/// The artefact as shipped: a JSON object with the `openapi` version it is written for and a
/// `schemas` map from DTO name to schema.
pub const REQUEST_SCHEMAS_JSON: &str = include_str!("../openapi/openapi-request-schemas.json");

/// The artefact, parsed once.
fn document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| serde_json::from_str(REQUEST_SCHEMAS_JSON).unwrap_or(Value::Null))
}

/// The OpenAPI version the schemas are written for (`"3.0"`).
#[must_use]
pub fn openapi_version() -> &'static str {
    document()["openapi"].as_str().unwrap_or_default()
}

/// The names of the schemas, in sorted order: the DTO names `nest-auth` uses (`LoginDto`, …).
#[must_use]
pub fn request_schema_names() -> Vec<&'static str> {
    document()["schemas"]
        .as_object()
        .map(|schemas| schemas.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The schema named `name`, or `None` when there is no such schema.
#[must_use]
pub fn request_schema(name: &str) -> Option<Value> {
    document()["schemas"].get(name).cloned()
}

/// Every schema, keyed by name.
#[must_use]
pub fn request_schemas() -> BTreeMap<String, Value> {
    request_schema_names()
        .into_iter()
        .filter_map(|name| request_schema(name).map(|schema| (name.to_owned(), schema)))
        .collect()
}

/// A route group of the auth router: the unit a deployment switches on or off, and the unit a
/// schema is contributed by. One variant per group that takes a request body; the sessions and
/// OAuth groups of [`RouteGroups`] take none and have no variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RouteGroup {
    /// The always-on auth flow group.
    Auth,
    /// The password-reset group.
    PasswordReset,
    /// The dashboard MFA group.
    Mfa,
    /// The platform group.
    Platform,
    /// The platform MFA group.
    PlatformMfa,
    /// The invitations group.
    Invitations,
    /// The address-change group.
    EmailChange,
}

impl RouteGroup {
    /// Whether `groups` mounts this group.
    #[must_use]
    pub fn is_mounted(self, groups: RouteGroups) -> bool {
        match self {
            Self::Auth => groups.auth,
            Self::PasswordReset => groups.password_reset,
            Self::Mfa => groups.mfa,
            Self::Platform => groups.platform,
            Self::PlatformMfa => groups.platform_mfa,
            Self::Invitations => groups.invitations,
            Self::EmailChange => groups.email_change,
        }
    }
}

/// A route that takes a JSON request body, and the schema that describes that body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestBodyRoute {
    /// The group that mounts the route.
    pub group: RouteGroup,
    /// The HTTP method, upper-case.
    pub method: &'static str,
    /// The path below the router's route prefix (`/login` is `POST {prefix}/login`).
    pub path: &'static str,
    /// The name of the schema, as [`request_schema`] knows it.
    pub schema: &'static str,
}

/// One row of [`REQUEST_BODY_ROUTES`]. A macro and not a function: a `const fn` that only builds a
/// `static` runs at compile time, so coverage would count its body as never executed.
macro_rules! row {
    ($group:expr, $path:expr, $schema:expr $(,)?) => {
        RequestBodyRoute {
            group: $group,
            method: "POST",
            path: $path,
            schema: $schema,
        }
    };
}

/// Every route of the auth router that takes a JSON request body, with the schema of that body.
///
/// A route that reads no body, or a body no schema describes (the refresh token, which is read
/// from the cookie or the body and has no shared schema), is not here.
static REQUEST_BODY_ROUTES: [RequestBodyRoute; 25] = [
    row!(RouteGroup::Auth, "/register", "RegisterDto"),
    row!(RouteGroup::Auth, "/login", "LoginDto"),
    row!(RouteGroup::Auth, "/verify-email", "VerifyEmailDto"),
    row!(
        RouteGroup::Auth,
        "/resend-verification",
        "ResendVerificationDto",
    ),
    row!(
        RouteGroup::PasswordReset,
        "/password/forgot-password",
        "ForgotPasswordDto",
    ),
    row!(
        RouteGroup::PasswordReset,
        "/password/reset-password",
        "ResetPasswordDto",
    ),
    row!(
        RouteGroup::PasswordReset,
        "/password/verify-otp",
        "VerifyOtpDto",
    ),
    row!(
        RouteGroup::PasswordReset,
        "/password/resend-otp",
        "ResendOtpDto",
    ),
    row!(
        RouteGroup::PasswordReset,
        "/password/change",
        "ChangePasswordDto",
    ),
    row!(RouteGroup::Mfa, "/mfa/setup", "MfaSetupDto"),
    row!(RouteGroup::Mfa, "/mfa/verify-enable", "MfaVerifyDto"),
    row!(RouteGroup::Mfa, "/mfa/challenge", "MfaChallengeDto"),
    row!(RouteGroup::Mfa, "/mfa/disable", "MfaDisableDto"),
    row!(
        RouteGroup::Mfa,
        "/mfa/recovery-codes",
        "MfaRegenerateRecoveryCodesDto",
    ),
    row!(RouteGroup::Platform, "/platform/login", "PlatformLoginDto"),
    row!(
        RouteGroup::Platform,
        "/platform/mfa/challenge",
        "MfaChallengeDto",
    ),
    row!(
        RouteGroup::PlatformMfa,
        "/platform/mfa/setup",
        "MfaSetupDto",
    ),
    row!(
        RouteGroup::PlatformMfa,
        "/platform/mfa/verify-enable",
        "MfaVerifyDto",
    ),
    row!(
        RouteGroup::PlatformMfa,
        "/platform/mfa/disable",
        "MfaDisableDto",
    ),
    row!(
        RouteGroup::PlatformMfa,
        "/platform/mfa/recovery-codes",
        "MfaRegenerateRecoveryCodesDto",
    ),
    row!(
        RouteGroup::Invitations,
        "/invitations",
        "CreateInvitationDto",
    ),
    row!(
        RouteGroup::Invitations,
        "/invitations/accept",
        "AcceptInvitationDto",
    ),
    row!(
        RouteGroup::Invitations,
        "/invitations/revoke",
        "RevokeInvitationDto",
    ),
    row!(RouteGroup::EmailChange, "/email/change", "ChangeEmailDto"),
    row!(
        RouteGroup::EmailChange,
        "/email/change/confirm",
        "ConfirmEmailChangeDto",
    ),
];

/// The routes that take a JSON request body and the schema of each, so a host can build the
/// `paths` of its document from the same table the schemas are selected by.
#[must_use]
pub fn request_body_routes() -> &'static [RequestBodyRoute] {
    &REQUEST_BODY_ROUTES
}

/// The schemas of the groups `groups` mounts: the ones a deployment can receive, and none that
/// nothing in its router would reference. A group the deployment leaves off contributes nothing.
#[must_use]
pub fn request_schemas_for(groups: RouteGroups) -> BTreeMap<String, Value> {
    REQUEST_BODY_ROUTES
        .iter()
        .filter(|route| route.group.is_mounted(groups))
        .filter_map(|route| {
            request_schema(route.schema).map(|schema| (route.schema.to_owned(), schema))
        })
        .collect()
}
