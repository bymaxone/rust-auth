//! The router factory (§8.1): [`auth_router`] / [`AuthRouter`] assembling exactly the route
//! groups the engine's resolved `ControllerToggles` enabled, under the configured prefix,
//! with the per-route rate-limit layers and the ordered middleware stack.
//!
//! The mount set is **derived** from the engine (`RouteGroups::from_toggles`), never
//! supplied independently, so routing can never disagree with what the engine wired. A
//! disabled toggle — or an absent Cargo feature — mounts no routes.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::routing::MethodRouter;
use bymax_auth_core::AuthEngine;
use tower_governor::GovernorLayer;

use crate::middleware::apply_middleware;
use crate::rate_limit::{
    GovernorConfigKind, RateLimit, build_governor_config, governor_error_to_response,
};
use crate::state::{AuthState, AxumAuthConfig, ResolvedConfig, ResolvedCookies, RouteGroups};

/// Build the auth router from a fully-built [`AuthEngine`] and the adapter configuration.
/// Mounts only the groups the engine's resolved toggles enabled, nests them under
/// `route_prefix`, attaches per-route rate-limit layers, and applies the §8.8 middleware
/// stack. The returned router has its `State` already applied, so it composes directly into
/// a consumer app via `app.merge(router)` or `app.nest("/api", router)`.
pub fn auth_router(engine: AuthEngine, config: AxumAuthConfig) -> Router {
    AuthRouter::from_engine(Arc::new(engine), config).into_router()
}

/// The assembled router plus the derived route groups, exposed so a consumer can inspect
/// exactly which groups were mounted. Build it with [`AuthRouter::from_engine`].
pub struct AuthRouter {
    router: Router,
    groups: RouteGroups,
}

impl AuthRouter {
    /// Assemble the router from a shared engine handle and the adapter configuration. Reads
    /// the engine's resolved `ControllerToggles` to derive [`RouteGroups`] and mounts the
    /// matching groups.
    #[must_use]
    pub fn from_engine(engine: Arc<AuthEngine>, config: AxumAuthConfig) -> Self {
        let groups = RouteGroups::from_toggles(engine.config().config().controllers);
        let resolved = resolve_config(&engine, &config);
        let state = AuthState::new(engine, Arc::new(resolved));

        let prefix = format!("/{}", config.route_prefix.trim_matches('/'));
        let mut grouped: Router<AuthState> = Router::new();

        // The always-on groups (still gated by their toggle, which defaults to true).
        if groups.auth {
            grouped = grouped.merge(crate::routes::auth::routes(
                &config,
                state.config().client_ip_source,
            ));
        }
        if groups.password_reset {
            grouped = grouped.merge(crate::routes::password_reset::routes(
                &config,
                state.config().client_ip_source,
            ));
        }

        grouped = mount_optional_groups(grouped, groups, &config, state.config().client_ip_source);

        // Nest the grouped routes under the configured prefix, apply the middleware stack,
        // then bind the shared state so the router is self-contained.
        let nested: Router<AuthState> = Router::new().nest(&prefix, grouped);
        let nested = apply_middleware(nested, config.max_body_bytes, config.cors.clone());
        let router = nested.with_state(state);

        Self { router, groups }
    }

    /// The derived route groups (which controllers were mounted).
    #[must_use]
    pub fn groups(&self) -> RouteGroups {
        self.groups
    }

    /// Consume into the assembled `axum::Router`.
    pub fn into_router(self) -> Router {
        self.router
    }
}

/// Mount the feature- and toggle-gated optional groups. Each arm is doubly gated: a
/// `#[cfg(feature = ...)]` removes the code when the Cargo feature is off, and the runtime
/// toggle removes the routes when the engine did not wire the capability.
#[cfg_attr(
    not(any(
        feature = "mfa",
        feature = "sessions",
        feature = "platform",
        feature = "oauth",
        feature = "invitations"
    )),
    expect(
        unused_variables,
        unused_mut,
        reason = "a bare adapter mounts no optional groups, so the inputs are unused"
    )
)]
fn mount_optional_groups(
    mut router: Router<AuthState>,
    groups: RouteGroups,
    config: &AxumAuthConfig,
    ip_source: crate::state::ClientIpSource,
) -> Router<AuthState> {
    // Each block is doubly gated: a `#[cfg(feature = …)]` removes the code when the Cargo
    // feature is off, and the runtime toggle removes the routes when the engine did not wire
    // the capability. Both gates must pass for a group to contribute routes.
    #[cfg(feature = "mfa")]
    if groups.mfa {
        router = router.merge(crate::routes::mfa::routes(config, ip_source));
    }
    #[cfg(feature = "sessions")]
    if groups.sessions {
        router = router.merge(crate::routes::sessions::routes(config, ip_source));
    }
    #[cfg(feature = "platform")]
    if groups.platform {
        router = router.merge(crate::routes::platform::routes(config, ip_source));
    }
    #[cfg(all(feature = "platform", feature = "mfa"))]
    if groups.platform_mfa {
        router = router.merge(crate::routes::platform_mfa::routes(config, ip_source));
    }
    #[cfg(feature = "oauth")]
    if groups.oauth {
        router = router.merge(crate::routes::oauth::routes(config, ip_source));
    }
    #[cfg(feature = "invitations")]
    if groups.invitations {
        router = router.merge(crate::routes::invitations::routes(config, ip_source));
    }

    router
}

/// Resolve the adapter config from the engine's resolved settings: the delivery mode, the
/// cookie names/paths/attributes, the cookie max-ages, and the client-IP strategy.
fn resolve_config(engine: &AuthEngine, config: &AxumAuthConfig) -> ResolvedConfig {
    let resolved = engine.config();
    let auth_config = resolved.config();
    let cookies = ResolvedCookies {
        access_name: auth_config.cookies.access_token_name.clone(),
        refresh_name: auth_config.cookies.refresh_token_name.clone(),
        signal_name: auth_config.cookies.session_signal_name.clone(),
        refresh_path: auth_config.cookies.refresh_cookie_path.clone(),
        mfa_temp_path: auth_config.cookies.mfa_temp_cookie_path.clone(),
        secure: resolved.secure_cookies(),
        same_site: auth_config.cookies.same_site,
        access_max_age_secs: clamp_secs(auth_config.jwt.access_cookie_max_age.as_secs()),
        refresh_max_age_secs: refresh_max_age_secs(auth_config.jwt.refresh_expires_in_days),
    };
    ResolvedConfig {
        route_prefix: config.route_prefix.clone(),
        delivery: auth_config.token_delivery,
        cookies,
        client_ip_source: config.client_ip_source,
    }
}

/// Clamp a `u64` second count into the `i64` the cookie crate's `Duration` accepts.
fn clamp_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// The refresh / session-signal cookie max-age in seconds, from the refresh lifetime in days.
fn refresh_max_age_secs(days: u32) -> i64 {
    i64::from(days).saturating_mul(86_400)
}

/// Attach a per-route governor rate-limit layer to a single route's [`MethodRouter`],
/// normalizing a throttle hit into the canonical `auth.too_many_requests` envelope. When the
/// limit is `None` (disabled for that route), the route is returned unchanged — still mounted,
/// just unthrottled at the edge.
pub(crate) fn throttled(
    method_router: MethodRouter<AuthState>,
    limit: Option<RateLimit>,
    ip_source: crate::state::ClientIpSource,
) -> MethodRouter<AuthState> {
    match build_governor_config(limit, ip_source) {
        Some(GovernorConfigKind::Peer(config)) => {
            let layer =
                GovernorLayer::<_, _, Body>::new(config).error_handler(governor_error_to_response);
            method_router.route_layer(layer)
        }
        Some(GovernorConfigKind::Smart(config)) => {
            let layer =
                GovernorLayer::<_, _, Body>::new(config).error_handler(governor_error_to_response);
            method_router.route_layer(layer)
        }
        None => method_router,
    }
}
