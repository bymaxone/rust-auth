//! What the session cookies carry when the resolver names domains, and which `SameSite` the
//! refresh and MFA-temp cookies take. Drives the real cookie middleware so the assertions read
//! the `Set-Cookie` headers a browser would receive, including the expiries a clear emits.

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use bymax_auth_core::config::{SameSite as ConfigSS, TokenDelivery as DeliveryMode};
use http::Request;
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;

use super::{TokenDelivery, with_extra_cookies};
use crate::state::ResolvedConfig;
use crate::test_support::resolved_config_with;
use axum::response::IntoResponse;

/// What a handler does with the delivery helper.
#[derive(Clone, Copy)]
enum Act {
    Plant,
    Clear,
    #[cfg(feature = "oauth")]
    MfaTemp,
}

/// Run `act` once through the cookie middleware and return every `Set-Cookie` header.
async fn set_cookies(cfg: ResolvedConfig, domains: Vec<String>, act: Act) -> Vec<String> {
    let cfg = std::sync::Arc::new(cfg);
    let app = Router::new()
        .route(
            "/",
            get(move |cookies: tower_cookies::Cookies| {
                let cfg = cfg.clone();
                let domains = domains.clone();
                async move {
                    let delivery = TokenDelivery::with_domains(&cfg, &domains);
                    let extras = match act {
                        Act::Plant => delivery.set_auth_cookies(&cookies, "acc", "ref"),
                        Act::Clear => delivery.clear_session(&cookies),
                        #[cfg(feature = "oauth")]
                        Act::MfaTemp => {
                            delivery.set_mfa_temp_cookie(&cookies, "temp");
                            Vec::new()
                        }
                    };
                    with_extra_cookies("ok".into_response(), extras)
                }
            }),
        )
        .layer(CookieManagerLayer::new());
    // A real logout carries the session cookies; the jar emits a removal only for a cookie the
    // request brought, so the request has to bring them.
    let request = Request::builder()
        .uri("/")
        .header(
            http::header::COOKIE,
            "access_token=a; refresh_token=r; has_session=1",
        )
        .body(Body::empty());
    let Ok(request) = request else { return Vec::new() };
    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
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

fn domains(list: &[&str]) -> Vec<String> {
    list.iter().map(|d| (*d).to_owned()).collect()
}

/// The `Set-Cookie` lines for `name`.
fn named<'a>(headers: &'a [String], name: &str) -> Vec<&'a String> {
    headers
        .iter()
        .filter(|h| h.starts_with(&format!("{name}=")))
        .collect()
}

#[tokio::test]
async fn a_session_is_planted_on_every_domain_the_resolver_names() {
    let headers = set_cookies(
        cfg(ConfigSS::Lax),
        domains(&["example.com", "app.example.com"]),
        Act::Plant,
    )
    .await;
    for name in ["access_token", "refresh_token", "has_session"] {
        let lines = named(&headers, name);
        assert_eq!(lines.len(), 2, "{name} once per domain: {headers:?}");
        assert!(lines.iter().any(|l| l.contains("Domain=example.com")));
        assert!(lines.iter().any(|l| l.contains("Domain=app.example.com")));
    }
}

#[tokio::test]
async fn a_logout_clears_the_session_on_every_domain_the_resolver_names() {
    let headers = set_cookies(
        cfg(ConfigSS::Lax),
        domains(&["example.com", "app.example.com"]),
        Act::Clear,
    )
    .await;
    for name in ["access_token", "refresh_token", "has_session"] {
        let lines = named(&headers, name);
        assert_eq!(lines.len(), 2, "{name} cleared per domain: {headers:?}");
        assert!(lines.iter().all(|l| l.contains("Max-Age=0")));
        assert!(
            lines.iter().all(|l| l.contains("Secure")),
            "{name} expiry mirrors the plant's Secure attribute: {lines:?}"
        );
    }
}

#[tokio::test]
async fn without_a_resolver_the_session_is_host_only() {
    let headers = set_cookies(cfg(ConfigSS::Lax), Vec::new(), Act::Plant).await;
    assert_eq!(named(&headers, "refresh_token").len(), 1);
    assert!(
        headers.iter().all(|h| !h.contains("Domain=")),
        "{headers:?}"
    );
}

#[tokio::test]
async fn the_refresh_cookie_is_strict_unless_the_deployment_is_cross_site() {
    for (configured, expected) in [
        (ConfigSS::Lax, "SameSite=Strict"),
        (ConfigSS::Strict, "SameSite=Strict"),
        (ConfigSS::None, "SameSite=None"),
    ] {
        let headers = set_cookies(cfg(configured), Vec::new(), Act::Plant).await;
        let refresh = named(&headers, "refresh_token");
        assert!(
            refresh.iter().all(|l| l.contains(expected)),
            "{expected}: {refresh:?}"
        );
    }
}

#[cfg(feature = "oauth")]
#[tokio::test]
async fn the_mfa_temp_cookie_takes_the_configured_same_site() {
    for (configured, expected) in [
        (ConfigSS::Lax, "SameSite=Lax"),
        (ConfigSS::Strict, "SameSite=Strict"),
        (ConfigSS::None, "SameSite=None"),
    ] {
        let headers = set_cookies(cfg(configured), Vec::new(), Act::MfaTemp).await;
        let temp = named(&headers, bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME);
        assert!(
            temp.iter().all(|l| l.contains(expected)),
            "{expected}: {temp:?}"
        );
    }
}

#[tokio::test]
async fn the_expiries_are_not_secure_when_the_planted_cookies_are_not() {
    let planted = set_cookies(plain_http(), domains(&["example.com"]), Act::Plant).await;
    let cleared = set_cookies(plain_http(), domains(&["example.com"]), Act::Clear).await;
    for name in ["access_token", "refresh_token", "has_session"] {
        for line in named(&planted, name)
            .into_iter()
            .chain(named(&cleared, name))
        {
            assert!(
                !line.contains("Secure"),
                "{name} on a plain-http config: {line}"
            );
        }
    }
}

#[tokio::test]
async fn the_refresh_expiry_carries_the_same_site_the_refresh_cookie_was_issued_with() {
    // The refresh cookie is `Strict` unless the deployment is cross-site (`None`); its expiry names
    // the same attribute, so a browser that matches the two sees one cookie being replaced.
    for (configured, expected) in [
        (ConfigSS::Lax, "SameSite=Strict"),
        (ConfigSS::Strict, "SameSite=Strict"),
        (ConfigSS::None, "SameSite=None"),
    ] {
        let planted = set_cookies(cfg(configured), domains(&["example.com"]), Act::Plant).await;
        let cleared = set_cookies(cfg(configured), domains(&["example.com"]), Act::Clear).await;
        for line in named(&planted, "refresh_token")
            .into_iter()
            .chain(named(&cleared, "refresh_token"))
        {
            assert!(line.contains(expected), "{expected}: {line}");
        }
    }
}
