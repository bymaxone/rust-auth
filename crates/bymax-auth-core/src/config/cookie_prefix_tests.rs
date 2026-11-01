//! The cookie-name prefix contract: which names the startup check accepts and which it refuses.

use std::sync::Arc;

use super::cookie_prefix::validate_cookie_prefixes;
use super::{CookieConfig, CookieDomainResolver};
use crate::error::ConfigError;

/// A resolver that names one domain, standing in for any configured `resolve_domains`.
struct OneDomain;

impl CookieDomainResolver for OneDomain {
    fn resolve(&self, _host: &str) -> Vec<String> {
        vec!["example.com".to_owned()]
    }
}

fn unmet(result: Result<(), ConfigError>) -> Option<(&'static str, String)> {
    match result {
        Err(ConfigError::CookiePrefixUnsatisfied {
            option,
            requirement,
            ..
        }) => Some((option, requirement)),
        _ => None,
    }
}

/// The defaults with the three cookie names replaced (an empty string keeps the default).
fn named(access: &str, refresh: &str, signal: &str) -> CookieConfig {
    let defaults = CookieConfig::default();
    let pick = |chosen: &str, default: String| {
        if chosen.is_empty() {
            default
        } else {
            chosen.to_owned()
        }
    };
    CookieConfig {
        access_token_name: pick(access, defaults.access_token_name.clone()),
        refresh_token_name: pick(refresh, defaults.refresh_token_name.clone()),
        session_signal_name: pick(signal, defaults.session_signal_name.clone()),
        ..defaults
    }
}

fn secure_required(option: &'static str) -> Option<(&'static str, String)> {
    Some((option, "secure_cookies = true".to_owned()))
}

#[test]
fn the_default_unprefixed_names_are_accepted_whatever_the_posture() {
    let cookies = CookieConfig::default();
    assert!(validate_cookie_prefixes(&cookies, false).is_ok());
    assert!(validate_cookie_prefixes(&cookies, true).is_ok());
}

#[test]
fn a_secure_prefix_needs_secure_cookies() {
    let cookies = named("__Secure-access_token", "", "");
    assert_eq!(
        unmet(validate_cookie_prefixes(&cookies, false)),
        secure_required("cookies.access_token_name")
    );
    assert!(validate_cookie_prefixes(&cookies, true).is_ok());
}

#[test]
fn a_secure_prefix_does_not_ask_for_the_root_path_or_a_missing_domain() {
    // Only `__Host-` pins the path and the domain: a path-scoped, domain-scoped cookie may still
    // carry `__Secure-`.
    let cookies = CookieConfig {
        resolve_domains: Some(Arc::new(OneDomain)),
        ..named("", "__Secure-refresh_token", "")
    };
    assert!(validate_cookie_prefixes(&cookies, true).is_ok());
}

#[test]
fn a_host_prefix_needs_secure_the_root_path_and_no_domain() {
    let cookies = named("__Host-access_token", "", "");
    assert_eq!(
        unmet(validate_cookie_prefixes(&cookies, false)),
        secure_required("cookies.access_token_name")
    );
    assert!(validate_cookie_prefixes(&cookies, true).is_ok());

    let with_domain = CookieConfig {
        resolve_domains: Some(Arc::new(OneDomain)),
        ..cookies
    };
    assert_eq!(
        unmet(validate_cookie_prefixes(&with_domain, true)),
        Some((
            "cookies.access_token_name",
            "no cookies.resolve_domains".to_owned()
        ))
    );
}

#[test]
fn the_refresh_cookie_is_held_to_its_own_path() {
    // The refresh cookie is path-scoped (default `/auth`), so `__Host-` can only hold when the
    // deployment scopes it to the root.
    let cookies = named("", "__Host-refresh_token", "");
    assert_eq!(
        unmet(validate_cookie_prefixes(&cookies, true)),
        Some((
            "cookies.refresh_token_name",
            "Path=/ (this cookie uses '/auth')".to_owned()
        ))
    );
    let at_root = CookieConfig {
        refresh_cookie_path: "/".to_owned(),
        ..cookies
    };
    assert!(validate_cookie_prefixes(&at_root, true).is_ok());
}

#[test]
fn the_signal_cookie_is_checked_too() {
    let cookies = named("", "", "__Secure-has_session");
    assert_eq!(
        unmet(validate_cookie_prefixes(&cookies, false)),
        secure_required("cookies.session_signal_name")
    );
}

#[test]
fn a_prefix_is_matched_case_sensitively_like_the_browser_does() {
    // A browser treats only the exact-case prefix as one, so a lowercase lookalike is an
    // ordinary name and is not held to the contract.
    let cookies = named("__host-access_token", "", "");
    assert!(validate_cookie_prefixes(&cookies, false).is_ok());
}

#[cfg(any(feature = "scrypt", feature = "argon2"))]
#[test]
fn startup_validation_runs_the_prefix_check_against_the_resolved_secure_cookies() {
    use secrecy::SecretString;

    use crate::config::{AuthConfig, Environment};

    let mut cfg = AuthConfig::default();
    #[cfg(not(feature = "scrypt"))]
    {
        cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
    }
    cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
    cfg.roles.hierarchy = std::collections::HashMap::from([
        ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
        ("MEMBER".to_owned(), Vec::new()),
    ]);
    cfg.cookies = named("__Secure-access_token", "", "");
    // Development leaves `secure_cookies` unset resolving to false: the prefix cannot hold.
    assert!(matches!(
        cfg.validate(Environment::Development),
        Err(ConfigError::CookiePrefixUnsatisfied { .. })
    ));
    // Production resolves it to true.
    assert!(cfg.validate(Environment::Production).is_ok());
}
