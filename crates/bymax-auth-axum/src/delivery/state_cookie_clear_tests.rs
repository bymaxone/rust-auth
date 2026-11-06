//! The expiry `Set-Cookie` lines of the two ephemeral cookies (OAuth `state`, MFA-temp). A
//! browser matches a deletion by name, domain and path, but a removal that is weaker than the
//! cookie it removes — no `HttpOnly`, no `Secure`, no `SameSite` — is a cookie a scanner or a
//! strict cookie policy rejects on its own, so each expiry carries the attributes its plant has.
//! Drives the real cookie middleware so the assertions read what a browser would receive.

use axum::Router;
use axum::body::Body;
use axum::response::IntoResponse;
use axum::routing::get;
use bymax_auth_core::config::{SameSite as ConfigSS, TokenDelivery as DeliveryMode};
use http::Request;
use tower::ServiceExt;
use tower_cookies::{CookieManagerLayer, Cookies};

use super::TokenDelivery;
use crate::state::ResolvedConfig;
use crate::test_support::resolved_config_with;

/// Run `clear` once through the cookie middleware, on a request that carries `cookie_header`
/// (the jar emits a removal only for a cookie the request brought), and return the `Set-Cookie`
/// line for `name`.
async fn removal_line(
    cfg: ResolvedConfig,
    cookie_header: &'static str,
    name: &'static str,
    clear: fn(&TokenDelivery, &Cookies),
) -> String {
    let cfg = std::sync::Arc::new(cfg);
    let app = Router::new()
        .route(
            "/",
            get(move |cookies: Cookies| {
                let cfg = cfg.clone();
                async move {
                    clear(&TokenDelivery::new(&cfg), &cookies);
                    "ok".into_response()
                }
            }),
        )
        .layer(CookieManagerLayer::new());
    let request = Request::builder()
        .uri("/")
        .header(http::header::COOKIE, cookie_header)
        .body(Body::empty());
    let Ok(request) = request else {
        return String::new();
    };
    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.starts_with(&format!("{name}=")))
        .map(str::to_owned)
        .unwrap_or_default()
}

fn cfg(same_site: ConfigSS) -> ResolvedConfig {
    resolved_config_with(DeliveryMode::Cookie, same_site)
}

/// A config whose cookies are not `Secure`, as a plain-http development deployment has them.
fn plain_http() -> ResolvedConfig {
    let mut config = cfg(ConfigSS::Lax);
    config.cookies.secure = false;
    config
}

#[cfg(feature = "oauth")]
mod oauth_state {
    use super::*;
    use bymax_auth_types::constants::OAUTH_STATE_COOKIE_NAME as NAME;

    async fn line(cfg: ResolvedConfig) -> String {
        removal_line(cfg, "oauth_state=s1", NAME, |d, c| {
            d.clear_oauth_state_cookie(c);
        })
        .await
    }

    #[tokio::test]
    async fn the_expiry_is_http_only_secure_and_lax_on_the_planted_path() {
        let line = line(cfg(ConfigSS::Lax)).await;
        assert!(line.contains("Max-Age=0"), "{line}");
        assert!(line.contains("Path=/"), "{line}");
        assert!(line.contains("HttpOnly"), "{line}");
        assert!(line.contains("Secure"), "{line}");
        assert!(line.contains("SameSite=Lax"), "{line}");
    }

    #[tokio::test]
    async fn the_expiry_stays_lax_whatever_the_deployment_configures() {
        // The plant is always `Lax` (a `Strict` cookie is withheld on the provider's redirect).
        for configured in [ConfigSS::Strict, ConfigSS::None] {
            let line = line(cfg(configured)).await;
            assert!(line.contains("SameSite=Lax"), "{line}");
        }
    }

    #[tokio::test]
    async fn the_expiry_is_not_secure_when_the_planted_cookie_is_not() {
        let line = line(plain_http()).await;
        assert!(line.contains("Max-Age=0"), "{line}");
        assert!(!line.contains("Secure"), "{line}");
        assert!(line.contains("HttpOnly"), "{line}");
    }
}

#[cfg(feature = "mfa")]
mod mfa_temp {
    use super::*;
    use bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME as NAME;

    async fn line(cfg: ResolvedConfig) -> String {
        removal_line(cfg, "mfa_temp_token=t1", NAME, |d, c| {
            d.clear_mfa_temp_cookie(c);
        })
        .await
    }

    #[tokio::test]
    async fn the_expiry_is_http_only_and_secure() {
        let line = line(cfg(ConfigSS::Lax)).await;
        assert!(line.contains("Max-Age=0"), "{line}");
        assert!(line.contains("HttpOnly"), "{line}");
        assert!(line.contains("Secure"), "{line}");
    }

    #[tokio::test]
    async fn the_expiry_takes_the_configured_same_site() {
        for (configured, expected) in [
            (ConfigSS::Lax, "SameSite=Lax"),
            (ConfigSS::Strict, "SameSite=Strict"),
            (ConfigSS::None, "SameSite=None"),
        ] {
            let line = line(cfg(configured)).await;
            assert!(line.contains(expected), "{expected}: {line}");
        }
    }

    #[tokio::test]
    async fn the_expiry_is_not_secure_when_the_planted_cookie_is_not() {
        let line = line(plain_http()).await;
        assert!(line.contains("Max-Age=0"), "{line}");
        assert!(!line.contains("Secure"), "{line}");
    }

    #[tokio::test]
    async fn the_expiry_names_the_path_the_cookie_was_planted_on() {
        let config = cfg(ConfigSS::Lax);
        let path = format!("Path={}", config.cookies.mfa_temp_path);
        let line = line(config).await;
        assert!(line.contains(&path), "{path}: {line}");
    }
}
