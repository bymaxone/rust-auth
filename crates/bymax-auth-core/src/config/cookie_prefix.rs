//! The browser's cookie-name prefix contract, checked at startup (layer: configuration).
//!
//! The `__Secure-` and `__Host-` prefixes are the only browser-enforced defence against cookie
//! tossing: a sibling host under the registrable domain can otherwise set
//! `refresh_token=<theirs>; Domain=.example.com`, and the server cannot tell the two apart because
//! `Set-Cookie` carries `Domain` and `Path` but the `Cookie` header does not. `HttpOnly` and
//! `Secure` do not stop that; the prefix does, by making the injected cookie unsettable.
//!
//! A browser enforces a prefix by silently dropping a `Set-Cookie` whose attributes do not match,
//! so a name that opts in while the attributes do not follow gives no error and no cookie: the
//! symptom is "login does not work", far from the cause. The contract is therefore checked here.
//! The default names stay unprefixed; opting in is the deployment's decision.

use super::CookieConfig;
use crate::error::ConfigError;

/// The prefix that pins a cookie to a secure origin.
const SECURE_PREFIX: &str = "__Secure-";
/// The prefix that additionally pins a cookie to the exact host and the root path.
const HOST_PREFIX: &str = "__Host-";

/// Refuse a cookie name whose prefix the cookie's attributes cannot satisfy.
///
/// `__Secure-` needs the `Secure` attribute. `__Host-` needs `Secure`, `Path=/` and no `Domain`,
/// and a configured `resolve_domains` is the only way a `Domain` is ever written. `secure` is the
/// resolved `secure_cookies` value, not the raw option.
///
/// # Errors
///
/// [`ConfigError::CookiePrefixUnsatisfied`] naming the option, the name and the first
/// requirement it breaks.
pub(super) fn validate_cookie_prefixes(
    cookies: &CookieConfig,
    secure: bool,
) -> Result<(), ConfigError> {
    let named = [
        ("cookies.access_token_name", &cookies.access_token_name, "/"),
        (
            "cookies.refresh_token_name",
            &cookies.refresh_token_name,
            cookies.refresh_cookie_path.as_str(),
        ),
        (
            "cookies.session_signal_name",
            &cookies.session_signal_name,
            "/",
        ),
    ];
    for (option, name, path) in named {
        let unmet = if name.starts_with(HOST_PREFIX) {
            if !secure {
                Some("secure_cookies = true".to_owned())
            } else if path != "/" {
                Some(format!("Path=/ (this cookie uses '{path}')"))
            } else if cookies.resolve_domains.is_some() {
                Some("no cookies.resolve_domains".to_owned())
            } else {
                None
            }
        } else if name.starts_with(SECURE_PREFIX) && !secure {
            Some("secure_cookies = true".to_owned())
        } else {
            None
        };
        if let Some(requirement) = unmet {
            return Err(ConfigError::CookiePrefixUnsatisfied {
                option,
                name: name.clone(),
                requirement,
            });
        }
    }
    Ok(())
}
