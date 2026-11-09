//! The security schemes a deployment declares, against what its server actually does.
//!
//! The schemes are derived from the engine's delivery mode, its cookie names and the groups it
//! mounted. This checks the derivation against the behaviour it describes: the names of the
//! cookies the adapter really sets on a login, and where the tokens really travel, in every
//! delivery mode, with the cookies renamed so a default cannot pass by coincidence.

use bymax_auth_axum::openapi::{
    ACCESS_BEARER_SCHEME, ACCESS_COOKIE_SCHEME, PLATFORM_BEARER_SCHEME, REFRESH_COOKIE_SCHEME,
    security_schemes,
};
use bymax_auth_core::config::TokenDelivery as DeliveryMode;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::*;

const ACCESS_NAME: &str = "sess_access";
const REFRESH_NAME: &str = "sess_refresh";

/// The names of the cookies a response sets.
fn set_cookie_names(response: &Captured) -> Vec<String> {
    response
        .set_cookies
        .iter()
        .filter_map(|cookie| cookie.split_once('=').map(|(name, _)| name.to_owned()))
        .collect()
}

/// The schemes `security_schemes` returned, by name.
type Schemes = BTreeMap<&'static str, Value>;

/// The dashboard schemes against a login: the cookie schemes are declared exactly when the adapter
/// sets those cookies and carry the names it sets, and the bearer scheme exactly when the tokens
/// come back in the body.
fn assert_dashboard_schemes(login: &Captured, schemes: &Schemes, label: &str) {
    let cookies = set_cookie_names(login);
    for (scheme, name) in [
        (ACCESS_COOKIE_SCHEME, ACCESS_NAME),
        (REFRESH_COOKIE_SCHEME, REFRESH_NAME),
    ] {
        assert_eq!(
            cookies.contains(&name.to_owned()),
            schemes.contains_key(scheme),
            "{label}: {scheme} against {cookies:?}"
        );
        if let Some(declared) = schemes.get(scheme) {
            assert_eq!(declared["name"], json!(name), "{label}: {scheme}");
        }
    }
    let in_body = login.json()["accessToken"].is_string();
    assert_eq!(
        in_body,
        schemes.contains_key(ACCESS_BEARER_SCHEME),
        "{label}"
    );
}

/// The platform credential is bearer in every mode: tokens in the body, no cookie, and the
/// scheme declared.
async fn assert_platform_scheme(
    h: &common::Harness,
    app: &axum::Router,
    schemes: &Schemes,
    label: &str,
) {
    seed_admin(h, "padmin@e.com", "SUPER_ADMIN").await;
    let platform = platform_login(app, "padmin@e.com").await;
    assert!(platform.json()["accessToken"].is_string(), "{label}");
    assert!(set_cookie_names(&platform).is_empty(), "{label}");
    assert!(schemes.contains_key(PLATFORM_BEARER_SCHEME), "{label}");
}

#[tokio::test]
async fn the_declared_schemes_match_what_each_delivery_mode_does() {
    for delivery in [
        DeliveryMode::Cookie,
        DeliveryMode::Bearer,
        DeliveryMode::Both,
    ] {
        let Some(h) = build(EngineSpec {
            delivery,
            platform: true,
            sessions: true,
            cookie_names: Some((ACCESS_NAME, REFRESH_NAME)),
            ..EngineSpec::default()
        }) else {
            return;
        };
        let config =
            bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
        let Ok(router) = bymax_auth_axum::AuthRouter::from_engine(h.engine.clone(), config) else {
            return;
        };
        let schemes = security_schemes(&h.engine, router.groups());
        let app = router.into_router();
        let label = format!("{delivery:?}");

        seed_user(&h, "who@e.com", "glidingwalnut42", "USER").await;
        let login = login(&app, "who@e.com", "glidingwalnut42").await;
        assert_dashboard_schemes(&login, &schemes, &label);
        assert_platform_scheme(&h, &app, &schemes, &label).await;
    }
}
