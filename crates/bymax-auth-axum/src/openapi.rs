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

use bymax_auth_core::AuthEngine;
use bymax_auth_core::config::TokenDelivery;
use serde_json::{Value, json};

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

/// The name of the scheme for the access token delivered as a cookie.
pub const ACCESS_COOKIE_SCHEME: &str = "bymaxAuthAccessCookie";
/// The name of the scheme for the access token delivered in the `Authorization` header.
pub const ACCESS_BEARER_SCHEME: &str = "bymaxAuthAccessBearer";
/// The name of the scheme for the refresh token delivered as a cookie.
pub const REFRESH_COOKIE_SCHEME: &str = "bymaxAuthRefreshCookie";
/// The name of the scheme for the platform administrator's access token, which is always bearer.
pub const PLATFORM_BEARER_SCHEME: &str = "bymaxPlatformAccessBearer";

/// Which of this library's guards protects a host's own routes. The two families take different
/// credentials, and only one of them varies with the delivery mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuardFamily {
    /// The dashboard guard: the access token travels as the delivery mode says.
    Dashboard,
    /// The platform guard: the access token is a bearer token in every delivery mode.
    Platform,
}

/// Whether the delivery mode puts credentials in cookies.
fn delivers_cookie(delivery: TokenDelivery) -> bool {
    matches!(delivery, TokenDelivery::Cookie | TokenDelivery::Both)
}

/// Whether the delivery mode puts credentials in the `Authorization` header and the body.
fn delivers_bearer(delivery: TokenDelivery) -> bool {
    matches!(delivery, TokenDelivery::Bearer | TokenDelivery::Both)
}

/// The schemes a deployment can satisfy, from the facts that decide them.
///
/// A scheme the deployment cannot satisfy is absent, not defined and unreferenced: a document
/// that defines the bearer scheme on a cookie-only deployment tells a client generator to offer a
/// credential the server will not read, and a requirement naming a scheme the document does not
/// define is refused by a document builder.
pub(crate) fn derive_security_schemes(
    delivery: TokenDelivery,
    access_cookie_name: &str,
    refresh_cookie_name: &str,
    groups: RouteGroups,
) -> BTreeMap<&'static str, Value> {
    let mut schemes = BTreeMap::new();
    let dashboard = groups.auth
        || groups.password_reset
        || groups.mfa
        || groups.sessions
        || groups.invitations
        || groups.email_change;
    if dashboard && delivers_cookie(delivery) {
        schemes.insert(
            ACCESS_COOKIE_SCHEME,
            cookie_scheme(
                access_cookie_name,
                "Access token, delivered as an HttpOnly cookie.",
            ),
        );
    }
    if dashboard && delivers_bearer(delivery) {
        schemes.insert(
            ACCESS_BEARER_SCHEME,
            bearer_scheme("Access token, delivered in the Authorization header."),
        );
    }
    // The groups that read the refresh cookie: logout and refresh, the two session handlers that
    // identify the caller's own session by it, and the password change that spares that session.
    let reads_refresh_cookie = groups.auth || groups.sessions || groups.password_reset;
    if reads_refresh_cookie && delivers_cookie(delivery) {
        schemes.insert(
            REFRESH_COOKIE_SCHEME,
            cookie_scheme(
                refresh_cookie_name,
                "Refresh token, delivered as an HttpOnly cookie scoped to the auth prefix.",
            ),
        );
    }
    if groups.platform || groups.platform_mfa {
        schemes.insert(
            PLATFORM_BEARER_SCHEME,
            bearer_scheme(
                "Platform administrator access token, always delivered in the Authorization header regardless of the delivery mode.",
            ),
        );
    }
    schemes
}

/// An `apiKey` scheme for a credential carried in the cookie called `name`.
fn cookie_scheme(name: &str, description: &str) -> Value {
    json!({ "type": "apiKey", "in": "cookie", "name": name, "description": description })
}

/// An `http` bearer scheme for a JWT carried in the `Authorization` header.
fn bearer_scheme(description: &str) -> Value {
    json!({ "type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": description })
}

/// The security schemes this deployment can satisfy, for `components.securitySchemes`.
///
/// Derived from the engine's resolved delivery mode and cookie names, and the route groups
/// `groups` mounts (from [`crate::AuthRouter::groups`]), so the document names the cookies the
/// adapter actually sets and defines only the credentials the server reads. The names are the
/// constants of this module.
#[must_use]
pub fn security_schemes(engine: &AuthEngine, groups: RouteGroups) -> BTreeMap<&'static str, Value> {
    let config = engine.config().config();
    derive_security_schemes(
        config.token_delivery,
        &config.cookies.access_token_name,
        &config.cookies.refresh_token_name,
        groups,
    )
}

/// The document-level `security` default for a host's own routes: which of this library's
/// guards protects them, and how the deployment delivers tokens.
///
/// Derived rather than written as a literal, so a change of delivery mode cannot leave the
/// default naming a scheme the document no longer declares. Under `Both` the result is a
/// two-entry list, which OpenAPI reads as OR (either transport satisfies it); one entry holding
/// both schemes would mean AND. Every entry names one scheme and carries no scopes, because
/// scopes belong to OAuth2 schemes and every scheme here is `apiKey` or `http`.
///
/// It takes the guard and the delivery mode and not the mounted groups, so it names a scheme
/// whether or not [`security_schemes`] defines it: a deployment that mounts no group using the
/// guard's credential has no scheme of this library to name and should not set a default from it.
#[must_use]
pub fn document_security(guard: GuardFamily, delivery: TokenDelivery) -> Vec<Value> {
    let requirement = |scheme: &str| json!({ scheme: [] });
    match guard {
        GuardFamily::Platform => vec![requirement(PLATFORM_BEARER_SCHEME)],
        GuardFamily::Dashboard => [
            (delivers_cookie(delivery), ACCESS_COOKIE_SCHEME),
            (delivers_bearer(delivery), ACCESS_BEARER_SCHEME),
        ]
        .into_iter()
        .filter(|(delivered, _)| *delivered)
        .map(|(_, scheme)| requirement(scheme))
        .collect(),
    }
}
