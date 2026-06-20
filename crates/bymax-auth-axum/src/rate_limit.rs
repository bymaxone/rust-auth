//! Per-route edge rate limiting (§16): the [`RateLimitConfig`] catalog mirroring
//! `AUTH_THROTTLE_CONFIGS`, the per-route `governor` layer builder, and the normalization
//! of a throttle hit into the canonical `auth.too_many_requests` (429) envelope with a
//! `Retry-After` header.
//!
//! Each named limit becomes its **own** `GovernorConfig`, attached to a single route during
//! router assembly — never one global layer (§16.2), exactly as nest-auth applies a distinct
//! `@Throttle(...)` per handler. The limiter keys on the client IP, derived per the
//! configured trusted-proxy strategy ([`crate::state::ClientIpSource`]).

use std::sync::Arc;

use axum::body::Body;
use axum::response::IntoResponse;
use bymax_auth_types::AuthError;
use governor::middleware::NoOpMiddleware;
use http::Response;
use tower_governor::GovernorError;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor};

use crate::response::error_response;
use crate::state::ClientIpSource;

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
            list_sessions: Some(RateLimit::new(30, 60)),
            revoke_session: Some(RateLimit::new(10, 60)),
            revoke_all_sessions: Some(RateLimit::new(5, 60)),
            oauth_initiate: Some(RateLimit::new(10, 60)),
            oauth_callback: Some(RateLimit::new(10, 60)),
        }
    }
}

/// The two key extractors the adapter alternates between by [`ClientIpSource`]. The
/// `GovernorConfig`'s `K` type parameter differs per extractor, so the built config is held
/// behind this enum and a [`GovernorLayer`](tower_governor::GovernorLayer) is applied for
/// whichever arm is active.
pub(crate) enum GovernorConfigKind {
    /// Peer-socket-IP keyed (never reads `X-Forwarded-For`) — the secure default.
    Peer(Arc<GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>>),
    /// `X-Forwarded-For`/`X-Real-IP`/`Forwarded` keyed, for a trusted-proxy deployment.
    Smart(Arc<GovernorConfig<SmartIpKeyExtractor, NoOpMiddleware>>),
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
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .map(|config| GovernorConfigKind::Peer(Arc::new(config))),
        ClientIpSource::TrustedForwardedFor => GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .key_extractor(SmartIpKeyExtractor)
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
    use super::*;
    use http::StatusCode;

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
}
