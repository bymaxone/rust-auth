//! The credential each operation declares, against what the router does with it.
//!
//! `operation_security()` says which credential each operation requires. This presents
//! every operation, in each delivery mode, with each combination of credential and transport a
//! client could send, and requires the router to refuse or admit it the way the kind says: a
//! request that carries no credential the kind requires is refused with 401, and one that carries
//! it is not. Transports the deployment does not deliver by are presented too, because a scheme
//! declared for a transport the server ignores would be wrong in the other direction.

use bymax_auth_axum::openapi::{OperationKind, OperationSecurity, operation_security};
use bymax_auth_core::config::TokenDelivery as DeliveryMode;
use serde_json::json;

use super::*;

const ACCESS_NAME: &str = "sess_access";
const REFRESH_NAME: &str = "sess_refresh";

/// The credentials one request carries, and the transport each travels by.
#[derive(Clone, Copy, Debug)]
struct Presented {
    access_cookie: bool,
    access_bearer: bool,
    refresh_cookie: bool,
    refresh_body: bool,
    platform_bearer: bool,
    platform_refresh_body: bool,
}

/// Nothing presented.
const NOTHING: Presented = Presented {
    access_cookie: false,
    access_bearer: false,
    refresh_cookie: false,
    refresh_body: false,
    platform_bearer: false,
    platform_refresh_body: false,
};

/// Every combination the matrix presents.
const PRESENTATIONS: [(&str, Presented); 9] = [
    ("nothing", NOTHING),
    (
        "access cookie",
        Presented {
            access_cookie: true,
            ..NOTHING
        },
    ),
    (
        "access bearer",
        Presented {
            access_bearer: true,
            ..NOTHING
        },
    ),
    (
        "refresh cookie",
        Presented {
            refresh_cookie: true,
            ..NOTHING
        },
    ),
    (
        "refresh body",
        Presented {
            refresh_body: true,
            ..NOTHING
        },
    ),
    (
        "access and refresh cookies",
        Presented {
            access_cookie: true,
            refresh_cookie: true,
            ..NOTHING
        },
    ),
    (
        "access bearer and refresh body",
        Presented {
            access_bearer: true,
            refresh_body: true,
            ..NOTHING
        },
    ),
    (
        "platform bearer",
        Presented {
            platform_bearer: true,
            ..NOTHING
        },
    ),
    (
        "platform refresh body",
        Presented {
            platform_refresh_body: true,
            ..NOTHING
        },
    ),
];

/// The tokens of one login of each plane, whichever way the deployment returned them.
struct Session {
    access: String,
    refresh: String,
    platform_access: String,
    platform_refresh: String,
}

/// A token from the cookie the login set, or from the body when it came back there.
fn issued(login: &Captured, cookie: &str, field: &str) -> String {
    login
        .cookie_value(cookie)
        .or_else(|| login.json()[field].as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Session {
    async fn issue(app: &axum::Router) -> Self {
        let dashboard = login(app, "who@e.com", "glidingwalnut42").await;
        let platform = platform_login(app, "padmin@e.com").await;
        Self {
            access: issued(&dashboard, ACCESS_NAME, "accessToken"),
            refresh: issued(&dashboard, REFRESH_NAME, "refreshToken"),
            platform_access: platform_access(&platform),
            platform_refresh: platform_refresh(&platform),
        }
    }
}

fn delivers_cookie(delivery: DeliveryMode) -> bool {
    matches!(delivery, DeliveryMode::Cookie | DeliveryMode::Both)
}

fn delivers_bearer(delivery: DeliveryMode) -> bool {
    matches!(delivery, DeliveryMode::Bearer | DeliveryMode::Both)
}

/// Whether the request carries a dashboard access token by a transport the deployment reads.
fn access_read(p: Presented, delivery: DeliveryMode) -> bool {
    (p.access_cookie && delivers_cookie(delivery)) || (p.access_bearer && delivers_bearer(delivery))
}

/// Whether the request carries a dashboard refresh token by a transport the deployment reads.
fn refresh_read(p: Presented, delivery: DeliveryMode) -> bool {
    (p.refresh_cookie && delivers_cookie(delivery)) || (p.refresh_body && delivers_bearer(delivery))
}

/// Whether the credential check admits the request, by the semantics of the kind alone: this is
/// the oracle, written from what each kind means and not from the requirement derived for it.
fn admits(kind: OperationKind, p: Presented, delivery: DeliveryMode) -> bool {
    match kind {
        OperationKind::None
        | OperationKind::OptionalAccessAndRefresh
        | OperationKind::PlatformLogout => true,
        OperationKind::RefreshRequired => refresh_read(p, delivery),
        OperationKind::Platform => p.platform_bearer,
        OperationKind::PlatformRefresh => p.platform_refresh_body,
        _ => access_read(p, delivery),
    }
}

/// The path of an operation with its parameters filled in.
fn concrete(path: &str) -> String {
    let filled = path
        .replace("{id}", "no-such-session")
        .replace("{provider}", "google")
        .replace("{workspaceId}", "no-such-workspace")
        .replace("{userId}", "no-such-member");
    format!("/auth{filled}")
}

/// The request for `op` carrying `p`.
fn request(op: &OperationSecurity, p: Presented, s: &Session) -> Req {
    let path = concrete(op.path);
    let mut req = match op.method {
        "GET" => Req::get(&path),
        "DELETE" => Req::delete(&path),
        "PATCH" => Req::new(http::Method::PATCH, &path),
        _ => Req::post(&path),
    };
    if matches!(op.method, "POST" | "PATCH") {
        let token = if p.refresh_body {
            Some(&s.refresh)
        } else if p.platform_refresh_body {
            Some(&s.platform_refresh)
        } else {
            None
        };
        req = req.json(token.map_or_else(|| json!({}), |t| json!({ "refreshToken": t })));
    }
    if p.access_cookie {
        req = req.cookie(ACCESS_NAME, &s.access);
    }
    if p.refresh_cookie {
        req = req.cookie(REFRESH_NAME, &s.refresh);
    }
    if p.access_bearer {
        req = req.bearer(&s.access);
    }
    if p.platform_bearer {
        req = req.bearer(&s.platform_access);
    }
    req
}

/// Whether presenting credentials to `op` can end or rotate the session that carried them, so
/// the next presentation needs a session of its own.
fn spends_session(op: &OperationSecurity) -> bool {
    !matches!(
        op.kind,
        OperationKind::None
            | OperationKind::Access
            | OperationKind::Platform
            | OperationKind::AccessWithOptionalRefresh
            | OperationKind::AccessWithOptionalRefreshCookie
    ) || op.path == "/platform/sessions"
}

/// What the router does with a request, as far as credentials go.
#[derive(Debug, Eq, PartialEq)]
enum Answer {
    /// The guard refuses to accept the request: a 401 before any handler runs.
    GuardRefuses,
    /// The guard accepts the caller and the handler cannot name the session it must act on.
    NoSession,
    /// Anything else, including a handler's own refusal of a wrong password or a missing target.
    Serves,
}

/// The answer a kind promises for a request carrying `p`. A kind that needs both credentials is
/// refused by the guard without the access token and by the handler without the refresh token.
fn promised(kind: OperationKind, p: Presented, delivery: DeliveryMode) -> Answer {
    if kind == OperationKind::AccessAndRefreshRequired && access_read(p, delivery) {
        return if refresh_read(p, delivery) {
            Answer::Serves
        } else {
            Answer::NoSession
        };
    }
    if admits(kind, p, delivery) {
        Answer::Serves
    } else {
        Answer::GuardRefuses
    }
}

/// The answer a response shows. A session the handler cannot name answers 404 `session_not_found`
/// on the operation that acts on the caller's own session; on an operation that names its target
/// in the path, that same answer is only the target being absent.
fn observed(op: &OperationSecurity, got: &Captured) -> Answer {
    let code = got.json()["error"]["code"].as_str().map(str::to_owned);
    let code = code.as_deref();
    if code == Some("auth.session_not_found") && !op.path.contains('{') {
        return Answer::NoSession;
    }
    if got.status == StatusCode::UNAUTHORIZED
        && code != Some("auth.invalid_credentials")
        && !code.is_some_and(|c| c.contains("session"))
    {
        return Answer::GuardRefuses;
    }
    Answer::Serves
}

/// Presents every combination to one operation and returns the disagreements.
async fn probe_operation(
    app: &axum::Router,
    op: &OperationSecurity,
    delivery: DeliveryMode,
) -> Vec<String> {
    let mut disagreements = Vec::new();
    let shared = Session::issue(app).await;
    for (label, p) in PRESENTATIONS {
        let own;
        let session = if spends_session(op) {
            own = Session::issue(app).await;
            &own
        } else {
            &shared
        };
        let got = request(op, p, session).send(app).await;
        let expected = promised(op.kind, p, delivery);
        if observed(op, &got) != expected {
            disagreements.push(format!(
                "{} {} under {delivery:?} presenting {label}: expected {expected:?}, got {} {}",
                op.method,
                op.path,
                got.status,
                got.json()
            ));
        }
    }
    disagreements
}

#[tokio::test]
async fn every_operation_admits_and_refuses_what_its_kind_says_in_every_delivery_mode() {
    let mut disagreements = Vec::new();
    for delivery in [
        DeliveryMode::Cookie,
        DeliveryMode::Bearer,
        DeliveryMode::Both,
    ] {
        let Some(h) = build(EngineSpec {
            delivery,
            mfa: true,
            platform: true,
            oauth: true,
            allow_oauth: true,
            invitations: true,
            email_change: true,
            sessions: true,
            workspaces: true,
            cookie_names: Some((ACCESS_NAME, REFRESH_NAME)),
            ..EngineSpec::default()
        }) else {
            return;
        };
        let mut config =
            bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
        let generous = Some(bymax_auth_axum::RateLimit::new(100_000, 60));
        for setter in ALL_LIMIT_SETTERS {
            setter(&mut config.rate_limits, generous);
        }
        let app = router_with(&h, config);
        seed_user(&h, "who@e.com", "glidingwalnut42", "USER").await;
        seed_admin(&h, "padmin@e.com", "SUPER_ADMIN").await;
        for op in operation_security() {
            disagreements.extend(probe_operation(&app, op, delivery).await);
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}
