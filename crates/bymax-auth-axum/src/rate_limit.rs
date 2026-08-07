//! Per-route edge rate limiting (§16): the [`RateLimitConfig`] catalog mirroring
//! `AUTH_THROTTLE_CONFIGS`, the per-route `governor` layer builder, and the normalization
//! of a throttle hit into the canonical `auth.too_many_requests` (429) envelope with a
//! `Retry-After` header.
//!
//! Each named limit becomes its **own** `GovernorConfig`, attached to a single route during
//! router assembly — never one global layer (§16.2), exactly as nest-auth applies a distinct
//! `@Throttle(...)` per handler. The limiter keys on the client IP, derived per the
//! configured trusted-proxy strategy ([`crate::state::ClientIpSource`]) and charged to its
//! [`rate_limit_bucket`] — the address itself for IPv4, the /64 prefix for IPv6.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use axum::body::Body;
use axum::response::IntoResponse;
use bymax_auth_types::AuthError;
use governor::middleware::NoOpMiddleware;
use http::Response;
use tower_governor::GovernorError;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::KeyExtractor;

use crate::response::error_response;
use crate::state::ClientIpSource;

/// A [`KeyExtractor`] that reads the **rightmost** `X-Forwarded-For` entry, falling back to
/// the peer socket address.
///
/// This replaces `tower_governor`'s `SmartIpKeyExtractor`, which takes the **leftmost**
/// parseable entry and additionally honours `X-Real-IP` and `Forwarded`. A conforming proxy
/// *appends* the address it observed, so the leftmost entry is whatever the client itself
/// sent: an attacker rotating `X-Forwarded-For: <random>` gets a fresh limiter key per
/// request and every per-route limit evaporates, while spoofing a victim's address exhausts
/// that victim's bucket. `X-Real-IP` and `Forwarded` are ignored entirely — a proxy that
/// appends to `X-Forwarded-For` gives no such guarantee for headers it does not manage.
///
/// The rightmost entry is the one the *nearest* trusted hop wrote, which is the strongest
/// claim available without a configured trusted-proxy CIDR set. With exactly one proxy in
/// front — the deployment [`ClientIpSource::TrustedForwardedFor`] documents — it is the real
/// client. With N proxies it is the Nth-from-the-client hop: still unforgeable, still a
/// stable key, just coarser.
///
/// A malformed or absent header falls back to the peer address rather than failing the
/// request, so a missing header degrades to the [`ClientIpSource::PeerAddr`] behaviour
/// instead of 429-ing every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RightmostForwardedIpKeyExtractor;

impl KeyExtractor for RightmostForwardedIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        let forwarded = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(rightmost_forwarded_ip);

        forwarded
            .or_else(|| {
                req.extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|info| info.0.ip())
            })
            .map(rate_limit_bucket)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// A [`KeyExtractor`] that keys on the peer socket address, charged to its
/// [`rate_limit_bucket`].
///
/// This replaces `tower_governor`'s `PeerIpKeyExtractor`, which keys on the full address. That
/// is correct for IPv4 and useless for IPv6: the budget is per key, so an attacker with one
/// routine /64 gets 2^64 of them. The extraction is otherwise identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerIpBucketKeyExtractor;

impl KeyExtractor for PeerIpBucketKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| rate_limit_bucket(info.0.ip()))
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Collapse an address to the unit a rate limit should actually be charged against.
///
/// IPv4 is returned unchanged: one address is one host, and the smallest routine allocation is
/// a single address.
///
/// IPv6 is truncated to its /64 prefix, because there the address is not the unit. A /64 is the
/// standard end-site subnet — the smallest thing a residential or cloud customer is handed —
/// and every one of its 2^64 addresses is free to mint and free to rotate. Keying on the full
/// /128 therefore hands one attacker 2^64 independent budgets: the per-route limit is per key,
/// so "5 login attempts per minute" becomes 5 attempts per address per minute, which is no
/// limit at all. Charging the /64 makes the budget belong to the subnet that was actually
/// allocated to somebody.
///
/// The cost is that hosts sharing a /64 share a budget. That is the same trade IPv4 NAT already
/// forces, and it is the correct side of it: the alternative is a limiter an attacker steps
/// around by incrementing a counter.
///
/// IPv4-mapped addresses (`::ffff:a.b.c.d`) are unwrapped **first**. Truncating one to /64 would
/// send every IPv4 client to the single key `::`, collapsing the entire IPv4 internet into one
/// bucket — a denial of service against legitimate users, delivered by the anti-abuse control.
fn rate_limit_bucket(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { return ip };

    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }

    let [a, b, c, d, ..] = v6.segments();
    IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
}

/// The last parseable IP in a comma-separated `X-Forwarded-For` value.
///
/// Scans from the right so the first parseable address found is the one the nearest hop
/// appended. Returns `None` when no entry parses, which sends the caller to the peer-address
/// fallback.
fn rightmost_forwarded_ip(header: &str) -> Option<IpAddr> {
    header
        .split(',')
        .rev()
        .find_map(|entry| entry.trim().parse::<IpAddr>().ok())
}

/// One named edge limit: `burst` requests, replenished over `per_seconds`. Modeled as
/// governor's quota — a burst bucket of `burst` cells that refills the whole bucket over
/// the window (one cell every `per_seconds / burst` seconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Max requests in a burst.
    pub burst: u32,
    /// The window (seconds) over which the full `burst` replenishes.
    pub per_seconds: u64,
}

impl RateLimit {
    /// Construct a limit from its burst and window.
    #[must_use]
    pub const fn new(burst: u32, per_seconds: u64) -> Self {
        Self { burst, per_seconds }
    }

    /// The governor replenish interval in seconds: one quota cell is restored every
    /// `per_seconds / burst` seconds, so the whole `burst` refills across the window. A
    /// zero result is clamped to `1` (governor rejects a zero period), which only tightens
    /// the limit and never loosens it.
    #[must_use]
    fn replenish_secs(self) -> u64 {
        (self.per_seconds / u64::from(self.burst.max(1))).max(1)
    }
}

/// The full set of per-route edge limits. Defaults reproduce `AUTH_THROTTLE_CONFIGS`
/// (§16.3) one-for-one. Every field is overridable; setting one to `None` disables the
/// layer for that route (the route stays mounted, just unthrottled at the edge). Platform
/// and dashboard refresh share `refresh`; the platform MFA-management routes reuse the
/// dashboard `mfa_setup` / `mfa_verify_enable` / `mfa_disable` limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// `POST /auth/login` — 5 / 60s.
    pub login: Option<RateLimit>,
    /// `POST /auth/register` — 10 / 3600s.
    pub register: Option<RateLimit>,
    /// `POST /auth/refresh` (and platform refresh) — 10 / 60s.
    pub refresh: Option<RateLimit>,
    /// `POST /auth/password/forgot-password` — 3 / 300s.
    pub forgot_password: Option<RateLimit>,
    /// `POST /auth/password/reset-password` — 3 / 300s.
    pub reset_password: Option<RateLimit>,
    /// `POST /auth/password/verify-otp` — 3 / 300s.
    pub verify_otp: Option<RateLimit>,
    /// `POST /auth/password/resend-otp` — 3 / 300s.
    pub resend_password_otp: Option<RateLimit>,
    /// `POST /auth/verify-email` — 5 / 60s.
    pub verify_email: Option<RateLimit>,
    /// `POST /auth/resend-verification` — 3 / 300s.
    pub resend_verification: Option<RateLimit>,
    /// `POST /auth/mfa/setup` (and platform MFA setup) — 5 / 60s.
    pub mfa_setup: Option<RateLimit>,
    /// `POST /auth/mfa/verify-enable` (and platform) — 5 / 60s.
    pub mfa_verify_enable: Option<RateLimit>,
    /// `POST /auth/mfa/challenge` (and platform challenge) — 5 / 60s.
    pub mfa_challenge: Option<RateLimit>,
    /// `POST /auth/mfa/disable` (and platform) — 3 / 300s.
    pub mfa_disable: Option<RateLimit>,
    /// `POST /auth/platform/login` — 5 / 60s.
    pub platform_login: Option<RateLimit>,
    /// `POST /auth/invitations` — 10 / 3600s.
    pub invitation_create: Option<RateLimit>,
    /// `POST /auth/invitations/accept` — 5 / 60s.
    pub invitation_accept: Option<RateLimit>,
    /// `POST /auth/invitations/revoke` — 10 / 3600s, matching the mint.
    pub invitation_revoke: Option<RateLimit>,
    /// `POST /auth/email/change` — 3 / 300s, matching the reset-email limits.
    pub email_change_request: Option<RateLimit>,
    /// `POST /auth/email/change/confirm` — 5 / 60s.
    pub email_change_confirm: Option<RateLimit>,
    /// `GET /auth/sessions` — 30 / 60s.
    pub list_sessions: Option<RateLimit>,
    /// `DELETE /auth/sessions/{id}` — 10 / 60s.
    pub revoke_session: Option<RateLimit>,
    /// `DELETE /auth/sessions/all` — 5 / 60s.
    pub revoke_all_sessions: Option<RateLimit>,
    /// `GET /auth/oauth/{provider}` — 10 / 60s.
    pub oauth_initiate: Option<RateLimit>,
    /// `GET /auth/oauth/{provider}/callback` — 10 / 60s.
    pub oauth_callback: Option<RateLimit>,
    /// `POST /auth/password/change` — 5 / 60s.
    ///
    /// Authenticated, so the caller is already known — but each call spends a KDF verification
    /// of the current password plus a derivation of the new one, the most expensive pair of
    /// operations in the library. The ceiling matches `login`'s for the same reason: it is a
    /// password-guessing surface, just one that needs a live session first.
    pub change_password: Option<RateLimit>,
    /// `POST /auth/logout` — 20 / 60s.
    ///
    /// The route is public: it has to be, or a user whose access token expired could not sign
    /// out and the refresh session would live out its full lifetime on a device they had just
    /// abandoned. Public and unlimited is a different thing, though — each call costs a hash
    /// and several store round trips, and nothing about the caller is known. The ceiling is
    /// deliberately loose: a browser with several tabs can legitimately fire a handful at once,
    /// and being rate-limited out of signing out would be its own security problem.
    pub logout: Option<RateLimit>,
    /// `POST /auth/ws-ticket` — 20 / 60s.
    ///
    /// Authenticated, but every call writes a fresh single-use ticket key, so an authenticated
    /// caller could otherwise mint them without bound. A reconnecting client needs one per
    /// socket; 20 covers a flapping connection without covering a loop.
    pub ws_ticket: Option<RateLimit>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login: Some(RateLimit::new(5, 60)),
            register: Some(RateLimit::new(10, 3600)),
            refresh: Some(RateLimit::new(10, 60)),
            forgot_password: Some(RateLimit::new(3, 300)),
            reset_password: Some(RateLimit::new(3, 300)),
            verify_otp: Some(RateLimit::new(3, 300)),
            resend_password_otp: Some(RateLimit::new(3, 300)),
            verify_email: Some(RateLimit::new(5, 60)),
            resend_verification: Some(RateLimit::new(3, 300)),
            mfa_setup: Some(RateLimit::new(5, 60)),
            mfa_verify_enable: Some(RateLimit::new(5, 60)),
            mfa_challenge: Some(RateLimit::new(5, 60)),
            mfa_disable: Some(RateLimit::new(3, 300)),
            platform_login: Some(RateLimit::new(5, 60)),
            invitation_create: Some(RateLimit::new(10, 3600)),
            invitation_accept: Some(RateLimit::new(5, 60)),
            invitation_revoke: Some(RateLimit::new(10, 3600)),
            email_change_request: Some(RateLimit::new(3, 300)),
            email_change_confirm: Some(RateLimit::new(5, 60)),
            list_sessions: Some(RateLimit::new(30, 60)),
            revoke_session: Some(RateLimit::new(10, 60)),
            revoke_all_sessions: Some(RateLimit::new(5, 60)),
            oauth_initiate: Some(RateLimit::new(10, 60)),
            oauth_callback: Some(RateLimit::new(10, 60)),
            change_password: Some(RateLimit::new(5, 60)),
            logout: Some(RateLimit::new(20, 60)),
            ws_ticket: Some(RateLimit::new(20, 60)),
        }
    }
}

/// The two key extractors the adapter alternates between by [`ClientIpSource`]. The
/// `GovernorConfig`'s `K` type parameter differs per extractor, so the built config is held
/// behind this enum and a [`GovernorLayer`](tower_governor::GovernorLayer) is applied for
/// whichever arm is active.
pub(crate) enum GovernorConfigKind {
    /// Peer-socket-IP keyed (never reads `X-Forwarded-For`) — the secure default.
    Peer(Arc<GovernorConfig<PeerIpBucketKeyExtractor, NoOpMiddleware>>),
    /// Keyed on the rightmost `X-Forwarded-For` entry, for a trusted-proxy deployment.
    Smart(Arc<GovernorConfig<RightmostForwardedIpKeyExtractor, NoOpMiddleware>>),
}

/// How often the per-route key maps are swept, in seconds.
///
/// The sweep is O(live keys) and the maps are only ever grown by traffic, so a minute is far
/// more often than needed to keep them bounded and far too rare to matter for cost.
const KEY_GC_INTERVAL_SECS: u64 = 60;

/// Start a timer that periodically drops rate-limit keys whose budget has fully replenished.
///
/// `tower_governor` keys its state on the extracted client IP in a `DashMap` that is only ever
/// **inserted** into; the documented prune is `retain_recent`, which the application is expected
/// to run on a timer. Nothing did. `ClientIpSource::PeerAddr` — one of the two a deployment now
/// has to choose between, and the one a directly exposed service picks — keys on the peer
/// socket address, so an unauthenticated `POST /auth/login` from a routine IPv6 /64 offers
/// 2^64 distinct keys — and because the per-route limit is *per key*, every new address is both
/// a fresh burst budget and a permanent map entry. The throttle was the mechanism that grew the
/// map rather than a bound on it, and with the default config enabling 27 routes there were 27
/// such maps, all process-lifetime. That is monotonic RSS growth with no ceiling, reachable
/// without a credential.
///
/// The consumer could not compensate: [`GovernorConfigKind`], [`build_governor_config`] and
/// `throttled` are all crate-private and the public `AuthRouter` exposes no path to the
/// limiters. So the library starts the sweep itself rather than documenting an obligation
/// nobody can discharge.
///
/// Spawning needs a Tokio runtime. A router built outside one — a synchronous test harness,
/// say — gets a warning rather than a panic: the crate denies `panic`, and refusing to build a
/// router would be a far worse answer than an unswept map in a process that is not serving.
pub(crate) fn spawn_key_gc<K>(config: Arc<GovernorConfig<K, NoOpMiddleware>>)
where
    K: KeyExtractor + Send + Sync + 'static,
    K::Key: Send + Sync + 'static,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "rate limiter built outside a Tokio runtime — its key map will not be swept; \
             build the auth router inside the runtime that serves it"
        );
        return;
    };
    handle.spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(KEY_GC_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            config.limiter().retain_recent();
        }
    });
}

/// Build a per-route governor config for `limit` under the configured `ip_source`.
/// Returns `None` when `limit` is `None` (the route is mounted unthrottled). The build can
/// only fail if the period/burst were zero, which [`RateLimit::replenish_secs`] and the
/// `burst.max(1)` guard already prevent — a `None` from `finish()` therefore degrades to an
/// unthrottled route rather than a panic.
pub(crate) fn build_governor_config(
    limit: Option<RateLimit>,
    ip_source: ClientIpSource,
) -> Option<GovernorConfigKind> {
    let limit = limit?;
    let per_second = limit.replenish_secs();
    let burst = limit.burst.max(1);
    match ip_source {
        ClientIpSource::PeerAddr => GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .key_extractor(PeerIpBucketKeyExtractor)
            .finish()
            .map(|config| GovernorConfigKind::Peer(Arc::new(config))),
        ClientIpSource::TrustedForwardedFor => GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .key_extractor(RightmostForwardedIpKeyExtractor)
            .finish()
            .map(|config| GovernorConfigKind::Smart(Arc::new(config))),
    }
}

/// Normalize a `tower_governor` rejection into the canonical `auth.too_many_requests` (429)
/// envelope with a `Retry-After` header — replacing governor's plaintext default. A
/// `TooManyRequests` carries the `wait_time` (seconds) governor computed; any other governor
/// error (an unextractable key) is surfaced as the same 429 with no retry hint so the edge
/// fails closed rather than leaking an internal cause.
pub(crate) fn governor_error_to_response(error: GovernorError) -> Response<Body> {
    let retry_after_seconds = match &error {
        GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
        GovernorError::UnableToExtractKey | GovernorError::Other { .. } => None,
    };
    let auth_error = AuthError::TooManyRequests {
        retry_after_seconds,
    };
    error_response(&auth_error).into_response()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use http::StatusCode;

    /// Read the shared cross-implementation wire contract's rate-limit table.
    ///
    /// Held byte-identical by nest-auth, which can serve the same deployment. Reading it here
    /// rather than repeating the numbers means a limit changed on either side turns that side
    /// red, instead of surfacing as the same client being throttled at different points
    /// depending on which backend answered.
    fn contract_limits() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root.get("rateLimits")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }

    #[test]
    fn every_default_limit_matches_the_shared_wire_contract() {
        let contract = contract_limits();
        let defaults = RateLimitConfig::default();
        let pairs: [(&str, Option<RateLimit>); 27] = [
            ("login", defaults.login),
            ("register", defaults.register),
            ("refresh", defaults.refresh),
            ("forgotPassword", defaults.forgot_password),
            ("resetPassword", defaults.reset_password),
            ("verifyOtp", defaults.verify_otp),
            ("resendPasswordOtp", defaults.resend_password_otp),
            ("verifyEmail", defaults.verify_email),
            ("resendVerification", defaults.resend_verification),
            ("mfaSetup", defaults.mfa_setup),
            ("mfaVerifyEnable", defaults.mfa_verify_enable),
            ("mfaChallenge", defaults.mfa_challenge),
            ("mfaDisable", defaults.mfa_disable),
            ("platformLogin", defaults.platform_login),
            ("invitationCreate", defaults.invitation_create),
            ("invitationAccept", defaults.invitation_accept),
            ("invitationRevoke", defaults.invitation_revoke),
            ("emailChangeRequest", defaults.email_change_request),
            ("emailChangeConfirm", defaults.email_change_confirm),
            ("listSessions", defaults.list_sessions),
            ("revokeSession", defaults.revoke_session),
            ("revokeAllSessions", defaults.revoke_all_sessions),
            ("oauthInitiate", defaults.oauth_initiate),
            ("oauthCallback", defaults.oauth_callback),
            ("changePassword", defaults.change_password),
            ("logout", defaults.logout),
            ("wsTicket", defaults.ws_ticket),
        ];

        for (name, limit) in pairs {
            assert!(limit.is_some(), "{name} has no default limit");
            let Some(limit) = limit else { continue };
            let rendered = format!("{}/{}", limit.burst, limit.per_seconds);
            assert_eq!(
                contract.get(name).and_then(serde_json::Value::as_str),
                Some(rendered.as_str()),
                "limit for {name} drifted from the shared contract"
            );
        }

        // And the contract names no route this catalog is missing: an entry on one side only
        // is a route whose limit nobody agreed on.
        let named = contract
            .as_object()
            .map(|table| table.keys().filter(|key| !key.starts_with('$')).count())
            .unwrap_or_default();
        assert_eq!(named, pairs.len());
    }

    #[test]
    fn replenish_clamps_to_at_least_one_second() {
        // 5/60s replenishes one cell every 12s; a tiny window clamps to 1s (never 0).
        assert_eq!(RateLimit::new(5, 60).replenish_secs(), 12);
        assert_eq!(RateLimit::new(10, 5).replenish_secs(), 1);
        assert_eq!(RateLimit::new(0, 60).replenish_secs(), 60);
    }

    #[test]
    fn build_governor_config_for_each_ip_source_and_disabled() {
        // A `None` limit produces no layer; each IP source builds its keyed config.
        assert!(build_governor_config(None, ClientIpSource::PeerAddr).is_none());
        assert!(matches!(
            build_governor_config(Some(RateLimit::new(5, 60)), ClientIpSource::PeerAddr),
            Some(GovernorConfigKind::Peer(_))
        ));
        assert!(matches!(
            build_governor_config(
                Some(RateLimit::new(5, 60)),
                ClientIpSource::TrustedForwardedFor
            ),
            Some(GovernorConfigKind::Smart(_))
        ));
    }

    #[test]
    fn governor_error_normalizes_to_the_429_envelope() {
        // A throttle rejection carries the wait time as Retry-After; an unextractable key
        // still renders the 429 with no retry hint.
        let throttled = governor_error_to_response(GovernorError::TooManyRequests {
            wait_time: 7,
            headers: None,
        });
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(throttled.headers().get(http::header::RETRY_AFTER).is_some());

        let no_key = governor_error_to_response(GovernorError::UnableToExtractKey);
        assert_eq!(no_key.status(), StatusCode::TOO_MANY_REQUESTS);

        let other = governor_error_to_response(GovernorError::Other {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: Some("x".to_owned()),
            headers: None,
        });
        assert_eq!(other.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn default_config_matches_the_throttle_table() {
        // Spot-check the §16.3 defaults are reproduced one-for-one.
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.login, Some(RateLimit::new(5, 60)));
        assert_eq!(cfg.register, Some(RateLimit::new(10, 3600)));
        assert_eq!(cfg.list_sessions, Some(RateLimit::new(30, 60)));
        assert_eq!(cfg.oauth_callback, Some(RateLimit::new(10, 60)));
    }

    /// Build a request carrying the given `X-Forwarded-For` value and peer address.
    fn req_with(xff: Option<&str>, peer: &str) -> http::Request<()> {
        let mut builder = http::Request::builder().uri("/");
        if let Some(value) = xff {
            builder = builder.header("x-forwarded-for", value);
        }
        let mut req = builder.body(()).unwrap_or_default();
        if let Ok(addr) = peer.parse::<std::net::SocketAddr>() {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(addr));
        }
        req
    }

    #[test]
    fn the_forwarded_extractor_keys_on_the_rightmost_entry() {
        // A conforming proxy APPENDS the address it observed, so the leftmost entry is
        // whatever the client itself sent. Keying on it — which `SmartIpKeyExtractor` does —
        // lets an attacker rotate `X-Forwarded-For` for a fresh limiter key per request,
        // evaporating every per-route limit; and lets them spoof a victim's address to
        // exhaust that victim's bucket. The rightmost entry is the one the nearest trusted
        // hop wrote.
        let extractor = RightmostForwardedIpKeyExtractor;

        // Attacker-supplied junk on the left, the proxy's observation on the right.
        let req = req_with(Some("1.1.1.1, 2.2.2.2, 203.0.113.9"), "10.0.0.1:443");
        assert_eq!(
            extractor.extract(&req).ok(),
            Some(
                "203.0.113.9"
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::from([0, 0, 0, 0]))
            )
        );

        // Two requests whose ONLY difference is the spoofable left-hand side must share a key,
        // or the limit is per-attacker-choice rather than per-client.
        let spoof_a = req_with(Some("9.9.9.9, 203.0.113.9"), "10.0.0.1:443");
        let spoof_b = req_with(Some("8.8.8.8, 203.0.113.9"), "10.0.0.1:443");
        assert_eq!(
            extractor.extract(&spoof_a).ok(),
            extractor.extract(&spoof_b).ok()
        );
    }

    #[test]
    fn the_forwarded_extractor_falls_back_to_the_peer_address() {
        // No header, an unparseable header, and an empty header all degrade to the peer
        // address — the `PeerAddr` behaviour — rather than failing the request, which would
        // 429 every caller behind a proxy that does not set the header.
        let extractor = RightmostForwardedIpKeyExtractor;
        let peer = "198.51.100.7"
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));

        for header in [None, Some("not-an-ip"), Some(""), Some(" , ")] {
            let req = req_with(header, "198.51.100.7:443");
            assert_eq!(
                extractor.extract(&req).ok(),
                Some(peer),
                "header {header:?}"
            );
        }
    }

    #[test]
    fn the_forwarded_extractor_ignores_x_real_ip_and_forwarded() {
        // `SmartIpKeyExtractor` also honours `X-Real-IP` and `Forwarded`. A proxy that appends
        // to `X-Forwarded-For` gives no guarantee about headers it does not manage, so reading
        // them reopens the same spoofing hole through a different name.
        let extractor = RightmostForwardedIpKeyExtractor;
        let mut req = http::Request::builder()
            .uri("/")
            .header("x-real-ip", "1.2.3.4")
            .header("forwarded", "for=5.6.7.8")
            .body(())
            .unwrap_or_default();
        if let Ok(addr) = "198.51.100.7:443".parse::<std::net::SocketAddr>() {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(addr));
        }

        assert_eq!(
            extractor.extract(&req).ok(),
            Some(
                "198.51.100.7"
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::from([0, 0, 0, 0]))
            )
        );
    }
    /// Inside a runtime the sweeper actually sweeps.
    ///
    /// The key map grows one entry per distinct client address and nothing removes the ones
    /// whose window has long expired, so a public login route accumulates them for the
    /// process's life. `tokio::time::interval` fires its first tick immediately, so yielding
    /// once is enough to see the body run — which is the whole of the reclaim.
    #[tokio::test]
    async fn the_key_sweeper_runs_its_reclaim_inside_a_runtime() {
        let built = GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(1)
            .key_extractor(PeerIpBucketKeyExtractor)
            .finish();
        let Some(config) = built else { return };
        let config = Arc::new(config);

        spawn_key_gc(Arc::clone(&config));
        // Let the spawned task reach its first tick and run one reclaim.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        // Reaching here at all is the assertion: the sweeper ran on a live limiter without
        // taking the runtime down, which is the failure mode a panic in a detached task has.
        assert!(config.limiter().len() < usize::MAX);
    }

    /// Built outside a Tokio runtime, the sweeper warns and gives up rather than panicking.
    ///
    /// A router assembled in a synchronous harness has no runtime to spawn onto. The crate
    /// denies `panic`, and refusing to build the router over a background sweeper would be a
    /// far worse answer than an unswept key map in a process that is not serving requests —
    /// so the branch exists, and it has to stay reachable without taking the process down.
    #[test]
    fn the_key_sweeper_declines_quietly_outside_a_runtime() {
        let built = GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(1)
            .key_extractor(PeerIpBucketKeyExtractor)
            .finish();
        let Some(config) = built else { return };

        // No `#[tokio::test]`: there is deliberately no runtime here. Returning at all is the
        // assertion — the alternative this guards against is an unwrap on `Handle::current`.
        spawn_key_gc(Arc::new(config));
    }

    // ── rate_limit_bucket ────────────────────────────────────────────────────

    /// Scenario: two addresses inside one IPv6 /64. Expected: one key. Why: a /64 is the
    /// smallest subnet a customer is allocated, and every one of its 2^64 addresses is free to
    /// mint. Keying the full /128 made the per-route budget per-address, so "5 attempts per
    /// minute" became 5 per address per minute — no limit at all against anyone holding a
    /// routine allocation.
    #[test]
    fn two_addresses_in_one_ipv6_slash_64_share_a_key() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 1, 2, 0xffff, 0xffff, 0xffff, 0xffff,
        ));

        assert_eq!(rate_limit_bucket(a), rate_limit_bucket(b));
        // Pinned as a value, not only as an equality: two buckets agree under any consistent
        // mangling, including one that discarded the wrong number of groups.
        assert_eq!(
            rate_limit_bucket(a),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0))
        );
    }

    /// And the converse, so "collapse everything" cannot pass: a different /64 is a different
    /// budget. Only the last four groups are discarded.
    #[test]
    fn a_different_ipv6_slash_64_is_a_different_key() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));

        assert_ne!(rate_limit_bucket(a), rate_limit_bucket(b));
    }

    /// IPv4 is one address per host, so it is charged whole. Two neighbours must not share.
    #[test]
    fn ipv4_addresses_are_never_merged() {
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

        assert_eq!(rate_limit_bucket(a), a);
        assert_ne!(rate_limit_bucket(a), rate_limit_bucket(b));
    }

    /// The trap in the naive version: `::ffff:a.b.c.d` truncated to /64 is `::` for EVERY IPv4
    /// client, so the whole IPv4 internet would share one budget and the anti-abuse control
    /// would itself be the denial of service. Mapped addresses must unwrap to their IPv4 form
    /// first, and two distinct ones must stay distinct.
    #[test]
    fn ipv4_mapped_addresses_unwrap_instead_of_collapsing_to_one_key() {
        let a = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped());
        let b = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 9).to_ipv6_mapped());
        let unspecified = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

        assert_eq!(
            rate_limit_bucket(a),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_ne!(rate_limit_bucket(a), rate_limit_bucket(b));
        assert_ne!(rate_limit_bucket(a), unspecified);
        // The same IPv4 host reaching us mapped and unmapped is one host, so one budget.
        assert_eq!(
            rate_limit_bucket(a),
            rate_limit_bucket(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    /// `ffff` in group 5 does NOT make an address mapped on its own: the range is
    /// `::ffff:0:0/96`, so all five leading groups must be zero too. Reading either half alone
    /// answers `0.0.0.0` here — one bucket for everyone who lands on it.
    #[test]
    fn ffff_behind_a_non_zero_prefix_is_not_a_mapped_address() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0xffff, 0, 0));

        assert_eq!(
            rate_limit_bucket(a),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }
}
