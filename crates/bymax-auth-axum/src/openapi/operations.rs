//! The credential each operation requires, and how a deployment's delivery mode turns it into an
//! OpenAPI security requirement (layer: HTTP adapter, feature `openapi`).
//!
//! The kind of each operation is `nest-auth`'s, held byte-identical in
//! `openapi/openapi-operation-security.json`. A kind says what the handler needs from the caller;
//! the requirement it becomes depends on the deployment, because a credential delivered as a
//! cookie, a bearer header or a body field is named by a different scheme, or by none.
//!
//! OpenAPI writes OR as separate requirement entries and AND as one entry naming several schemes,
//! and an entry with no scheme (`{}`) means a caller who sends nothing this document can name is
//! still served. The functions here return plain `serde_json` values; they build no document.

use serde_json::{Value, json};

use bymax_auth_core::config::TokenDelivery;

use super::{
    ACCESS_BEARER_SCHEME, ACCESS_COOKIE_SCHEME, PLATFORM_BEARER_SCHEME, REFRESH_COOKIE_SCHEME,
    RouteGroup, delivers_bearer, delivers_cookie,
};

/// What an operation needs from the caller, before the deployment's transport is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OperationKind {
    /// Reachable unauthenticated: `security: []`, so a client attaches no credential.
    None,
    /// The access token is required.
    Access,
    /// The refresh credential is required and there is no access token.
    RefreshRequired,
    /// Both credentials are required: the first authorises, the second names the session.
    AccessAndRefreshRequired,
    /// The access token is required and the refresh credential is read when present.
    AccessWithOptionalRefresh,
    /// The same, on a method that carries no body, so only the cookie can hold the refresh token.
    AccessWithOptionalRefreshCookie,
    /// Both credentials are read and neither is required; each one received does more of the job.
    OptionalAccessAndRefresh,
    /// The platform access token is required.
    Platform,
    /// The platform access token is read and not required; the refresh token travels in the body.
    PlatformLogout,
    /// No header credential; the platform refresh token travels in the body.
    PlatformRefresh,
}

impl OperationKind {
    /// The name the shared artefact gives this kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Access => "access",
            Self::RefreshRequired => "refreshRequired",
            Self::AccessAndRefreshRequired => "accessAndRefreshRequired",
            Self::AccessWithOptionalRefresh => "accessWithOptionalRefresh",
            Self::AccessWithOptionalRefreshCookie => "accessWithOptionalRefreshCookie",
            Self::OptionalAccessAndRefresh => "optionalAccessAndRefresh",
            Self::Platform => "platform",
            Self::PlatformLogout => "platformLogout",
            Self::PlatformRefresh => "platformRefresh",
        }
    }

    /// Every kind, in the order the artefact lists them.
    pub const ALL: [Self; 10] = [
        Self::None,
        Self::Access,
        Self::RefreshRequired,
        Self::AccessAndRefreshRequired,
        Self::AccessWithOptionalRefresh,
        Self::AccessWithOptionalRefreshCookie,
        Self::OptionalAccessAndRefresh,
        Self::Platform,
        Self::PlatformLogout,
        Self::PlatformRefresh,
    ];
}

/// One operation of the auth router and the credential it requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OperationSecurity {
    /// The group that mounts the operation.
    pub group: RouteGroup,
    /// The HTTP method, upper-case.
    pub method: &'static str,
    /// The path below the router's route prefix, with `{name}` for a parameter.
    pub path: &'static str,
    /// The credential the operation requires.
    pub kind: OperationKind,
}

/// One row of [`OPERATION_SECURITY`].
macro_rules! op {
    ($group:expr, $method:expr, $path:expr, $kind:expr $(,)?) => {
        OperationSecurity {
            group: $group,
            method: $method,
            path: $path,
            kind: $kind,
        }
    };
}

use OperationKind as K;
use RouteGroup as G;

/// Every operation the auth router mounts and the credential each requires.
static OPERATION_SECURITY: [OperationSecurity; 38] = [
    op!(G::Auth, "POST", "/register", K::None),
    op!(G::Auth, "POST", "/login", K::None),
    op!(G::Auth, "POST", "/logout", K::OptionalAccessAndRefresh),
    op!(G::Auth, "POST", "/refresh", K::RefreshRequired),
    op!(G::Auth, "GET", "/me", K::Access),
    op!(G::Auth, "POST", "/ws-ticket", K::Access),
    op!(G::Auth, "POST", "/verify-email", K::None),
    op!(G::Auth, "POST", "/resend-verification", K::None),
    op!(
        G::PasswordReset,
        "POST",
        "/password/forgot-password",
        K::None
    ),
    op!(
        G::PasswordReset,
        "POST",
        "/password/reset-password",
        K::None
    ),
    op!(
        G::PasswordReset,
        "POST",
        "/password/change",
        K::AccessWithOptionalRefresh
    ),
    op!(G::PasswordReset, "POST", "/password/verify-otp", K::None),
    op!(G::PasswordReset, "POST", "/password/resend-otp", K::None),
    op!(G::Mfa, "POST", "/mfa/setup", K::Access),
    op!(G::Mfa, "POST", "/mfa/verify-enable", K::Access),
    op!(G::Mfa, "POST", "/mfa/challenge", K::None),
    op!(G::Mfa, "POST", "/mfa/disable", K::Access),
    op!(G::Mfa, "POST", "/mfa/recovery-codes", K::Access),
    op!(
        G::Sessions,
        "GET",
        "/sessions",
        K::AccessWithOptionalRefreshCookie
    ),
    op!(
        G::Sessions,
        "POST",
        "/sessions/revoke-all",
        K::AccessAndRefreshRequired
    ),
    op!(G::Sessions, "DELETE", "/sessions/{id}", K::Access),
    op!(G::Platform, "POST", "/platform/login", K::None),
    op!(G::Platform, "POST", "/platform/mfa/challenge", K::None),
    op!(G::Platform, "GET", "/platform/me", K::Platform),
    op!(G::Platform, "POST", "/platform/logout", K::PlatformLogout),
    op!(G::Platform, "POST", "/platform/refresh", K::PlatformRefresh),
    op!(G::Platform, "DELETE", "/platform/sessions", K::Platform),
    op!(G::PlatformMfa, "POST", "/platform/mfa/setup", K::Platform),
    op!(
        G::PlatformMfa,
        "POST",
        "/platform/mfa/verify-enable",
        K::Platform
    ),
    op!(G::PlatformMfa, "POST", "/platform/mfa/disable", K::Platform),
    op!(
        G::PlatformMfa,
        "POST",
        "/platform/mfa/recovery-codes",
        K::Platform
    ),
    op!(G::Invitations, "POST", "/invitations", K::Access),
    op!(G::Invitations, "POST", "/invitations/revoke", K::Access),
    op!(G::Invitations, "POST", "/invitations/accept", K::None),
    op!(G::EmailChange, "POST", "/email/change", K::Access),
    op!(G::EmailChange, "POST", "/email/change/confirm", K::None),
    op!(G::OAuth, "GET", "/oauth/{provider}", K::None),
    op!(G::OAuth, "GET", "/oauth/{provider}/callback", K::None),
];

/// The operations of the auth router and the credential each requires.
#[must_use]
pub fn operation_security() -> &'static [OperationSecurity] {
    &OPERATION_SECURITY
}

/// The security requirement for one access credential: the cookie, the bearer header or both as
/// alternatives, as the delivery mode allows.
fn access_alternatives(delivery: TokenDelivery) -> Vec<&'static str> {
    let mut schemes = Vec::new();
    if delivers_cookie(delivery) {
        schemes.push(ACCESS_COOKIE_SCHEME);
    }
    if delivers_bearer(delivery) {
        schemes.push(ACCESS_BEARER_SCHEME);
    }
    schemes
}

/// One requirement entry naming `schemes`, all of which must be satisfied together.
fn entry(schemes: &[&str]) -> Value {
    Value::Object(
        schemes
            .iter()
            .map(|scheme| ((*scheme).to_owned(), json!([])))
            .collect(),
    )
}

/// A body that carries a refresh token. `required` says whether a body must be sent;
/// `token_required` says whether `refreshToken` must be in it.
fn refresh_body(required: bool, token_required: bool, description: &str) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": { "refreshToken": { "type": "string", "description": description } }
    });
    if token_required {
        schema["required"] = json!(["refreshToken"]);
    }
    json!({ "required": required, "content": { "application/json": { "schema": schema } } })
}

/// The dashboard refresh-token description.
const REFRESH_DESCRIPTION: &str = "The refresh token, when it is not delivered as a cookie.";

/// What a deployment's document says about one operation's credentials.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationDescription {
    /// The operation's `security`: `[]` for an operation that needs none.
    pub security: Vec<Value>,
    /// The request body that carries a credential, where the credential can arrive in one.
    pub request_body: Option<Value>,
}

/// How `kind` is described under `delivery`.
///
/// The entries of `security` are alternatives. An entry naming several schemes needs all of them.
/// The empty entry states that a caller sending nothing this list can name is still served,
/// which is how a credential arriving in the body is expressed: a requirement list cannot name a
/// body field.
#[must_use]
pub fn describe_operation(kind: OperationKind, delivery: TokenDelivery) -> OperationDescription {
    match kind {
        OperationKind::None => OperationDescription {
            security: vec![],
            request_body: None,
        },
        OperationKind::Access => OperationDescription {
            security: access_alternatives(delivery)
                .iter()
                .map(|s| entry(&[s]))
                .collect(),
            request_body: None,
        },
        OperationKind::RefreshRequired => describe_refresh_required(delivery),
        OperationKind::Platform => OperationDescription {
            security: vec![entry(&[PLATFORM_BEARER_SCHEME])],
            request_body: None,
        },
        OperationKind::PlatformLogout => OperationDescription {
            security: vec![entry(&[PLATFORM_BEARER_SCHEME]), json!({})],
            request_body: Some(platform_refresh_body(false)),
        },
        OperationKind::PlatformRefresh => OperationDescription {
            security: vec![],
            request_body: Some(platform_refresh_body(true)),
        },
        two => describe_two_credentials(two, delivery),
    }
}

/// The platform refresh-token body, which the platform surface never takes from a cookie.
fn platform_refresh_body(required: bool) -> Value {
    refresh_body(required, true, "The platform refresh token.")
}

/// The refresh credential alone, required: the cookie scheme where cookies deliver it, with the
/// empty alternative beside it under `Both`, and a required body where the body is the only
/// channel.
fn describe_refresh_required(delivery: TokenDelivery) -> OperationDescription {
    let cookie = delivers_cookie(delivery);
    let bearer = delivers_bearer(delivery);
    let security = match (cookie, bearer) {
        (true, true) => vec![entry(&[REFRESH_COOKIE_SCHEME]), json!({})],
        (true, false) => vec![entry(&[REFRESH_COOKIE_SCHEME])],
        _ => vec![],
    };
    let request_body = bearer.then(|| refresh_body(!cookie, !cookie, REFRESH_DESCRIPTION));
    OperationDescription {
        security,
        request_body,
    }
}

/// An operation that reads both the access and the refresh credential.
///
/// The list is the product of the two channels: every access form with the refresh cookie beside
/// it, then every access form alone (the refresh token then travelling in the body), then, where
/// the access half is optional too, the refresh cookie alone and finally nothing. The entry
/// naming both comes first because a client generator attaches the credentials of the first
/// requirement it can satisfy.
fn describe_two_credentials(kind: OperationKind, delivery: TokenDelivery) -> OperationDescription {
    let cookie = delivers_cookie(delivery);
    let bearer = delivers_bearer(delivery);
    let access_required = kind != OperationKind::OptionalAccessAndRefresh;
    let refresh_required = kind == OperationKind::AccessAndRefreshRequired;
    let access = access_alternatives(delivery);

    let mut security = Vec::new();
    if cookie {
        security.extend(access.iter().map(|s| entry(&[s, REFRESH_COOKIE_SCHEME])));
    }
    if bearer || !refresh_required {
        security.extend(access.iter().map(|s| entry(&[s])));
    }
    if !access_required && cookie {
        security.push(entry(&[REFRESH_COOKIE_SCHEME]));
    }
    if !access_required && !refresh_required {
        security.push(json!({}));
    }

    // A body is a channel only where the deployment delivers credentials that way and the HTTP
    // method defines what a payload means: OpenAPI 3.0 says a request body on GET or DELETE is
    // ignored by consumers.
    let body_channel = bearer && kind != OperationKind::AccessWithOptionalRefreshCookie;
    let request_body = body_channel.then(|| {
        let required = !cookie && refresh_required;
        refresh_body(required, required, REFRESH_DESCRIPTION)
    });
    OperationDescription {
        security,
        request_body,
    }
}
