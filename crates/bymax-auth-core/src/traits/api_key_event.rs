//! The audit event of a request guarded by a service API key (layer: traits).
//!
//! One event per guarded request, refusals included. It never carries the presented key or its
//! secret: `reason` is for the operator, while the caller is always given the same answer for a
//! bad credential.

/// Whether a guarded request was admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyOutcome {
    /// The key verified and holds every scope the route declares.
    Allowed,
    /// The request was refused.
    Denied,
}

impl ApiKeyOutcome {
    /// The spelling the shared contract's `apiKeys.auditEvent.outcome` uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        }
    }
}

/// Why a service-key request was refused. Absent on an admitted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyDenyReason {
    /// No key was presented.
    Missing,
    /// A value was presented that does not parse as a key.
    Malformed,
    /// The key id names no row.
    Unknown,
    /// The row exists and the secret does not match.
    WrongSecret,
    /// The key was revoked.
    Revoked,
    /// The key is past its expiry.
    Expired,
    /// A valid key that lacks a scope the route declares.
    ScopeInsufficient,
    /// The route is guarded but declares no scopes; refused before any credential work.
    RouteUndeclared,
    /// The key store failed.
    StoreError,
}

impl ApiKeyDenyReason {
    /// The spelling the shared contract's `apiKeys.auditEvent.reason` uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Unknown => "unknown",
            Self::WrongSecret => "wrong_secret",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::ScopeInsufficient => "scope_insufficient",
            Self::RouteUndeclared => "route_undeclared",
            Self::StoreError => "store_error",
        }
    }
}

/// One audited service-key request. See `AuthHooks::on_api_key_request`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiKeyAccessEvent {
    /// Whether the request was admitted.
    pub outcome: ApiKeyOutcome,
    /// Why it was refused; `None` when admitted.
    pub reason: Option<ApiKeyDenyReason>,
    /// The row id of the key, when the presented key named an existing row. Public by design:
    /// it is the half of the key that is not secret.
    pub key_id: Option<String>,
    /// The label of the identified key, when one was identified.
    pub label: Option<String>,
    /// The HTTP method.
    pub method: String,
    /// The route PATTERN (`/videos/{id}`), never the concrete URL, so identifiers a caller put
    /// in the path do not reach the audit log. Empty when no pattern matched.
    pub route: String,
    /// The scopes the route declares; empty when it declares none.
    pub required_scopes: Vec<String>,
    /// The client address as the host's trusted-proxy configuration resolves it.
    pub ip: String,
}
