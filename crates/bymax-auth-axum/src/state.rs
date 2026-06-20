//! The shared adapter state and the router-mounting configuration.
//!
//! [`AuthState`] is the `Clone`able handle every handler and extractor receives via
//! `State<AuthState>` (or `FromRef`): it carries the `Arc<AuthEngine>` and the resolved
//! adapter configuration (token-delivery mode, cookie attributes, body limit, rate-limit
//! defaults, and the trusted-proxy strategy). [`AxumAuthConfig`] is the consumer-facing
//! configuration; [`RouteGroups`] is **derived** from the engine's resolved
//! `ControllerToggles` so the route surface can never disagree with what the engine wired.

use std::sync::Arc;

use axum::extract::FromRef;
use bymax_auth_core::AuthEngine;
use bymax_auth_core::config::{ControllerToggles, SameSite, TokenDelivery};

use crate::rate_limit::RateLimitConfig;

/// The default request-body byte cap applied by the body-limit layer (§8.8). One mebibyte
/// is generous for the JSON DTOs this adapter accepts while bounding an oversized payload
/// before it reaches the buffering JSON extractor.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// How the adapter derives the trusted client IP for the per-route rate limiter (§16.2 /
/// §16.4). The default never trusts a raw `X-Forwarded-For`, so a spoofed header cannot
/// bypass the limit; a deployment behind a known proxy opts into trusting the **last**
/// `X-Forwarded-For` hop (the address the trusted proxy observed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientIpSource {
    /// Use the socket peer address only — never read `X-Forwarded-For`. The safe default.
    #[default]
    PeerAddr,
    /// Trust the last `X-Forwarded-For` entry (set by a trusted reverse proxy), falling
    /// back to the peer address when the header is absent or malformed.
    TrustedForwardedFor,
}

/// Adapter-level configuration. Mirrors the routing/cookie/rate-limit options of the
/// NestJS module — but **which route groups mount is NOT configured here**: it is derived
/// from the engine's resolved `ControllerToggles` (see [`RouteGroups`]).
#[derive(Clone)]
pub struct AxumAuthConfig {
    /// Path prefix applied to every mounted group. Default: `auth`.
    pub route_prefix: String,
    /// Maximum accepted request-body size in bytes. Default: [`DEFAULT_MAX_BODY_BYTES`].
    pub max_body_bytes: usize,
    /// Per-route edge rate-limit configuration; defaults reproduce `AUTH_THROTTLE_CONFIGS`.
    pub rate_limits: RateLimitConfig,
    /// How the client IP is derived for rate-limit keying (trusted-proxy strategy).
    pub client_ip_source: ClientIpSource,
    /// Optional CORS layer, applied outermost in the middleware stack when set. Off by
    /// default — the consumer supplies a configured [`tower_http::cors::CorsLayer`].
    pub cors: Option<tower_http::cors::CorsLayer>,
}

impl Default for AxumAuthConfig {
    fn default() -> Self {
        Self {
            route_prefix: bymax_auth_types::constants::AUTH_ROUTE_PREFIX.to_owned(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            rate_limits: RateLimitConfig::default(),
            client_ip_source: ClientIpSource::default(),
            cors: None,
        }
    }
}

/// Per-group enable flags, **derived** from the engine's resolved `ControllerToggles` at
/// router-build time — never supplied independently by the consumer, so routing can never
/// disagree with what the engine actually wired. The mapping copies each matching toggle;
/// the combined `platform_mfa = platform && mfa`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteGroups {
    /// The always-on auth flow group.
    pub auth: bool,
    /// The MFA group (requires the `mfa` feature + the engine toggle).
    pub mfa: bool,
    /// The password-reset group.
    pub password_reset: bool,
    /// The sessions group.
    pub sessions: bool,
    /// The platform group.
    pub platform: bool,
    /// The combined platform-MFA group (`platform && mfa`).
    pub platform_mfa: bool,
    /// The OAuth group.
    pub oauth: bool,
    /// The invitations group.
    pub invitations: bool,
}

impl RouteGroups {
    /// Derive the route groups from the engine's resolved [`ControllerToggles`]. Each group
    /// copies the matching toggle; `platform_mfa` is the conjunction `platform && mfa`.
    #[must_use]
    pub fn from_toggles(toggles: ControllerToggles) -> Self {
        Self {
            auth: toggles.auth,
            mfa: toggles.mfa,
            password_reset: toggles.password_reset,
            sessions: toggles.sessions,
            platform: toggles.platform,
            platform_mfa: toggles.platform && toggles.mfa,
            oauth: toggles.oauth,
            invitations: toggles.invitations,
        }
    }
}

/// The resolved cookie attributes the delivery layer reads. Derived once at router build
/// from the engine's resolved config so a handler never recomputes them. The names/paths
/// come from the engine's `CookieConfig`; `secure` and `same_site` reflect the resolved
/// security posture; the refresh cookie is always path-scoped and `SameSite=Strict`.
#[derive(Clone)]
pub struct ResolvedCookies {
    /// Access-token cookie name.
    pub access_name: String,
    /// Refresh-token cookie name.
    pub refresh_name: String,
    /// Non-HttpOnly session-signal cookie name.
    pub signal_name: String,
    /// Path the refresh cookie is scoped to.
    pub refresh_path: String,
    /// Path the OAuth-MFA temp cookie is scoped to.
    pub mfa_temp_path: String,
    /// Whether cookies carry the `Secure` attribute.
    pub secure: bool,
    /// The configured `SameSite` for the access/signal cookies.
    pub same_site: SameSite,
    /// `Max-Age` (seconds) of the access cookie, from `jwt.access_cookie_max_age`.
    pub access_max_age_secs: i64,
    /// `Max-Age` (seconds) of the refresh / session-signal cookies, from the refresh lifetime.
    pub refresh_max_age_secs: i64,
}

/// The fully-resolved adapter configuration carried on [`AuthState`]. Built once at router
/// assembly so handlers/extractors read constant-time values rather than re-resolving.
pub struct ResolvedConfig {
    /// The route prefix every group mounts under.
    pub route_prefix: String,
    /// The resolved token-delivery mode (cookie / bearer / both).
    pub delivery: TokenDelivery,
    /// The resolved cookie attributes.
    pub cookies: ResolvedCookies,
    /// How the client IP is derived for rate-limit keying.
    pub client_ip_source: ClientIpSource,
}

/// Shared state handed to every handler/extractor via `State<AuthState>`. Cheaply cloneable
/// (`Arc` inside). Carries the engine and the resolved adapter configuration.
#[derive(Clone)]
pub struct AuthState {
    engine: Arc<AuthEngine>,
    config: Arc<ResolvedConfig>,
}

impl AuthState {
    /// Assemble the state from the engine and the resolved adapter configuration.
    pub(crate) fn new(engine: Arc<AuthEngine>, config: Arc<ResolvedConfig>) -> Self {
        Self { engine, config }
    }

    /// The shared engine handle.
    #[must_use]
    pub fn engine(&self) -> &Arc<AuthEngine> {
        &self.engine
    }

    /// The resolved adapter configuration.
    #[must_use]
    pub fn config(&self) -> &ResolvedConfig {
        &self.config
    }
}

impl FromRef<AuthState> for Arc<AuthEngine> {
    fn from_ref(state: &AuthState) -> Self {
        state.engine.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::scaffold;
    use bymax_auth_core::config::TokenDelivery;

    #[test]
    fn route_groups_derive_from_toggles_with_platform_mfa_conjunction() {
        // `platform_mfa` is the conjunction of platform AND mfa; every other group copies its
        // toggle.
        let toggles = ControllerToggles {
            platform: true,
            mfa: true,
            ..ControllerToggles::default()
        };
        let groups = RouteGroups::from_toggles(toggles);
        assert!(groups.auth && groups.password_reset);
        assert!(groups.platform && groups.mfa && groups.platform_mfa);

        // platform without mfa → no platform_mfa.
        let only_platform = ControllerToggles {
            platform: true,
            ..ControllerToggles::default()
        };
        assert!(!RouteGroups::from_toggles(only_platform).platform_mfa);
    }

    #[test]
    fn defaults_and_client_ip_source() {
        // The config default carries the canonical prefix/body-limit and the safe IP source.
        let config = AxumAuthConfig::default();
        assert_eq!(config.route_prefix, "auth");
        assert_eq!(config.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(config.client_ip_source, ClientIpSource::PeerAddr);
        assert!(config.cors.is_none());
        assert_eq!(ClientIpSource::default(), ClientIpSource::PeerAddr);
    }

    #[test]
    fn auth_state_accessors_and_from_ref() {
        // The state exposes the engine + config, and `FromRef` hands back the engine.
        let Some(s) = scaffold(TokenDelivery::Cookie) else { return };
        assert_eq!(s.state.config().route_prefix, "auth");
        let engine: Arc<AuthEngine> = Arc::<AuthEngine>::from_ref(&s.state);
        assert!(Arc::ptr_eq(&engine, s.state.engine()));
    }
}
