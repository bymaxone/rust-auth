//! The [`TokenDelivery`] helper (§8.5 / §14): the single place the adapter writes auth
//! cookies and shapes the auth body.
//!
//! It honors the configured mode — `cookie` (set the secure cookies, body = safe user),
//! `bearer` (no cookies, body = `{ user, accessToken, refreshToken }`), `both` (cookies +
//! tokens in the body) — and the §14 cookie attributes: HttpOnly (except `has_session`),
//! Secure-by-default, the refresh cookie path-scoped and `SameSite=Strict`, the access /
//! signal cookies `SameSite=Lax`. Handlers never hand-roll a `Set-Cookie`; they delegate
//! here. The MFA-temp cookie (planted on the MFA-gated OAuth callback) is also written here.

use axum::Json;
use axum::response::{IntoResponse, Response};
use bymax_auth_core::config::{SameSite as ConfigSameSite, TokenDelivery as DeliveryMode};
use bymax_auth_types::constants::AUTH_HAS_SESSION_COOKIE_VALUE;
use bymax_auth_types::{AuthResult, MfaChallengeResult, RotatedTokens, SafeAuthUser};
use http::StatusCode;
use serde::Serialize;
use serde_json::json;
use tower_cookies::Cookies;
use tower_cookies::cookie::time::Duration;
use tower_cookies::cookie::{Cookie, SameSite};

use crate::state::{ResolvedConfig, ResolvedCookies};

/// Map the engine's `SameSite` to the cookie crate's `SameSite`.
fn map_same_site(value: ConfigSameSite) -> SameSite {
    match value {
        ConfigSameSite::Lax => SameSite::Lax,
        ConfigSameSite::Strict => SameSite::Strict,
        ConfigSameSite::None => SameSite::None,
    }
}

/// The writer that emits cookies into the request's [`Cookies`] jar and shapes the auth
/// body per the resolved delivery mode. Borrows the resolved config so it reads the cookie
/// attributes computed once at router build.
pub(crate) struct TokenDelivery<'a> {
    config: &'a ResolvedConfig,
}

impl<'a> TokenDelivery<'a> {
    /// Construct a delivery helper over the resolved adapter config.
    pub(crate) fn new(config: &'a ResolvedConfig) -> Self {
        Self { config }
    }

    /// The cookie attributes resolved at router build.
    fn cookies(&self) -> &ResolvedCookies {
        &self.config.cookies
    }

    /// Build the access-token cookie (`/`, HttpOnly, Secure-by-default, the configured
    /// `SameSite`, the configured access max-age).
    fn build_access_cookie(&self, value: String) -> Cookie<'static> {
        let c = self.cookies();
        Cookie::build((c.access_name.clone(), value))
            .path("/")
            .http_only(true)
            .secure(c.secure)
            .same_site(map_same_site(c.same_site))
            .max_age(Duration::seconds(c.access_max_age_secs))
            .build()
    }

    /// Build the refresh-token cookie — always path-scoped to the refresh path and always
    /// `SameSite=Strict` (the long-lived credential's blast-radius limiter), HttpOnly,
    /// Secure-by-default, with the refresh lifetime as its max-age.
    fn build_refresh_cookie(&self, value: String) -> Cookie<'static> {
        let c = self.cookies();
        Cookie::build((c.refresh_name.clone(), value))
            .path(c.refresh_path.clone())
            .http_only(true)
            .secure(c.secure)
            .same_site(SameSite::Strict)
            .max_age(Duration::seconds(c.refresh_max_age_secs))
            .build()
    }

    /// Build the non-HttpOnly session-signal cookie (`/`, value `"1"` only — no token, no
    /// PII — so the SPA/edge can decide whether to attempt a silent refresh).
    fn build_signal_cookie(&self) -> Cookie<'static> {
        let c = self.cookies();
        Cookie::build((
            c.signal_name.clone(),
            AUTH_HAS_SESSION_COOKIE_VALUE.to_owned(),
        ))
        .path("/")
        .http_only(false)
        .secure(c.secure)
        .same_site(map_same_site(c.same_site))
        .max_age(Duration::seconds(c.refresh_max_age_secs))
        .build()
    }

    /// Plant the full auth-cookie set (access + path-scoped refresh + the session signal)
    /// into the jar. Used by login/register/refresh/MFA-success/invitation-accept.
    fn set_auth_cookies(&self, cookies: &Cookies, access: &str, refresh: &str) {
        cookies.add(self.build_access_cookie(access.to_owned()));
        cookies.add(self.build_refresh_cookie(refresh.to_owned()));
        cookies.add(self.build_signal_cookie());
    }

    /// Plant the auth cookies for a browser-redirect flow (the OAuth success/MFA redirect),
    /// regardless of the configured delivery mode — a browser navigation can only carry the
    /// session via cookies, so the redirect always sets them.
    #[cfg(feature = "oauth")]
    pub(crate) fn set_auth_cookies_for_browser(&self, cookies: &Cookies, result: &AuthResult) {
        self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
    }

    /// Clear the access, refresh, and session-signal cookies on logout — reusing the exact
    /// `Path` each was set with (a mismatched path leaves a ghost cookie the browser keeps
    /// sending). `Cookies::remove` emits the expiry `Set-Cookie`.
    pub(crate) fn clear_session(&self, cookies: &Cookies) {
        let c = self.cookies();
        cookies.remove(Cookie::build((c.access_name.clone(), "")).path("/").build());
        cookies.remove(
            Cookie::build((c.refresh_name.clone(), ""))
                .path(c.refresh_path.clone())
                .build(),
        );
        cookies.remove(Cookie::build((c.signal_name.clone(), "")).path("/").build());
    }

    /// Plant the ephemeral MFA-temp cookie (§14.1): path-scoped to the MFA challenge path,
    /// HttpOnly, Secure-by-default, `SameSite` aligned with the refresh cookie, Max-Age
    /// pinned to the temp-token's 300 s lifetime so the cookie can never outlive the JWT.
    /// Only the OAuth callback plants this cookie, so it compiles under the `oauth` feature.
    #[cfg(feature = "oauth")]
    pub(crate) fn set_mfa_temp_cookie(&self, cookies: &Cookies, value: &str) {
        use bymax_auth_types::constants::{MFA_TEMP_COOKIE_MAX_AGE_SECONDS, MFA_TEMP_COOKIE_NAME};
        let c = self.cookies();
        let max_age = i64::try_from(MFA_TEMP_COOKIE_MAX_AGE_SECONDS).unwrap_or(i64::MAX);
        cookies.add(
            Cookie::build((MFA_TEMP_COOKIE_NAME.to_owned(), value.to_owned()))
                .path(c.mfa_temp_path.clone())
                .http_only(true)
                .secure(c.secure)
                .same_site(SameSite::Strict)
                .max_age(Duration::seconds(max_age))
                .build(),
        );
    }

    /// Deliver a successful authentication (login/register/invitation-accept). In `cookie`
    /// mode it sets the auth cookies and the body carries only the safe user; in `bearer`
    /// mode no cookies are set and the body carries the tokens; `both` does both. `status`
    /// lets a caller return 200 or 201.
    pub(crate) fn deliver_auth(
        &self,
        cookies: &Cookies,
        result: &AuthResult,
        status: StatusCode,
    ) -> Response {
        match self.config.delivery {
            DeliveryMode::Cookie => {
                self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
                (status, Json(json!({ "user": result.user }))).into_response()
            }
            DeliveryMode::Bearer => (status, Json(bearer_body(result))).into_response(),
            DeliveryMode::Both => {
                self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
                (status, Json(bearer_body(result))).into_response()
            }
        }
    }

    /// Deliver a successful **platform** authentication. The platform result mirrors
    /// `AuthResult` field-for-field, so the body shape and cookie behavior are identical to
    /// [`TokenDelivery::deliver_auth`]; only the safe-user type differs.
    #[cfg(feature = "platform")]
    pub(crate) fn deliver_platform_auth(
        &self,
        cookies: &Cookies,
        result: &bymax_auth_types::PlatformAuthResult,
        status: StatusCode,
    ) -> Response {
        match self.config.delivery {
            DeliveryMode::Cookie => {
                self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
                (status, Json(json!({ "user": result.user }))).into_response()
            }
            DeliveryMode::Bearer => (status, Json(platform_bearer_body(result))).into_response(),
            DeliveryMode::Both => {
                self.set_auth_cookies(cookies, &result.access_token, &result.refresh_token);
                (status, Json(platform_bearer_body(result))).into_response()
            }
        }
    }

    /// Deliver a refresh outcome (rotated token pair). In `cookie` mode the new cookies are
    /// set and the body is empty `{}`; in `bearer` mode the body carries the new pair;
    /// `both` does both.
    pub(crate) fn deliver_refresh(&self, cookies: &Cookies, tokens: &RotatedTokens) -> Response {
        match self.config.delivery {
            DeliveryMode::Cookie => {
                self.set_auth_cookies(cookies, &tokens.access_token, &tokens.refresh_token);
                (StatusCode::OK, Json(json!({}))).into_response()
            }
            DeliveryMode::Bearer => (StatusCode::OK, Json(tokens)).into_response(),
            DeliveryMode::Both => {
                self.set_auth_cookies(cookies, &tokens.access_token, &tokens.refresh_token);
                (StatusCode::OK, Json(tokens)).into_response()
            }
        }
    }

    /// Deliver an MFA challenge body (`{ mfaRequired: true, mfaTempToken }`) — the same in
    /// every delivery mode (no session cookies are set; the temp token is in the body).
    pub(crate) fn deliver_mfa_challenge(&self, challenge: &MfaChallengeResult) -> Response {
        (StatusCode::OK, Json(challenge)).into_response()
    }
}

/// The bearer/both auth body: the safe user plus the token pair, camelCase on the wire.
fn bearer_body(result: &AuthResult) -> impl Serialize + '_ {
    json!({
        "user": &result.user,
        "accessToken": &result.access_token,
        "refreshToken": &result.refresh_token,
    })
}

/// The bearer/both platform auth body: the safe admin plus the token pair, camelCase.
#[cfg(feature = "platform")]
fn platform_bearer_body(result: &bymax_auth_types::PlatformAuthResult) -> impl Serialize + '_ {
    json!({
        "user": &result.user,
        "accessToken": &result.access_token,
        "refreshToken": &result.refresh_token,
    })
}

/// A safe-user body with no tokens (used by `me` and the cookie-mode auth body shape).
pub(crate) fn user_body(user: &SafeAuthUser) -> Json<serde_json::Value> {
    Json(json!({ "user": user }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::resolved_config_with;
    use bymax_auth_core::config::SameSite as ConfigSS;
    #[cfg(feature = "platform")]
    use bymax_auth_types::{AuthPlatformUser, PlatformAuthResult, SafeAuthPlatformUser};
    use bymax_auth_types::{AuthResult, AuthUser, MfaChallengeResult, RotatedTokens};
    use time::OffsetDateTime;

    fn safe_user() -> SafeAuthUser {
        SafeAuthUser::from(AuthUser {
            id: "u1".to_owned(),
            email: "u@e.com".to_owned(),
            name: "U".to_owned(),
            password_hash: None,
            role: "USER".to_owned(),
            status: "ACTIVE".to_owned(),
            tenant_id: "t1".to_owned(),
            email_verified: true,
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        })
    }

    fn auth_result() -> AuthResult {
        AuthResult {
            user: safe_user(),
            access_token: "acc".to_owned(),
            refresh_token: "ref".to_owned(),
        }
    }

    #[cfg(feature = "platform")]
    fn platform_result() -> PlatformAuthResult {
        PlatformAuthResult {
            user: SafeAuthPlatformUser::from(AuthPlatformUser {
                id: "a1".to_owned(),
                email: "a@e.com".to_owned(),
                name: "A".to_owned(),
                password_hash: "ph".to_owned(),
                role: "SUPER_ADMIN".to_owned(),
                status: "ACTIVE".to_owned(),
                mfa_enabled: false,
                mfa_secret: None,
                mfa_recovery_codes: None,
                platform_id: None,
                last_login_at: None,
                updated_at: OffsetDateTime::UNIX_EPOCH,
                created_at: OffsetDateTime::UNIX_EPOCH,
            }),
            access_token: "pacc".to_owned(),
            refresh_token: "pref".to_owned(),
        }
    }

    /// Collect the `Set-Cookie` headers a delivery emitted into the jar, via a fresh response.
    fn cookies_jar() -> Cookies {
        Cookies::default()
    }

    fn has_cookie(jar: &Cookies, name: &str) -> bool {
        jar.get(name)
            .map(|c| !c.value().is_empty())
            .unwrap_or(false)
    }

    #[test]
    fn map_same_site_covers_every_arm() {
        assert_eq!(map_same_site(ConfigSS::Lax), SameSite::Lax);
        assert_eq!(map_same_site(ConfigSS::Strict), SameSite::Strict);
        assert_eq!(map_same_site(ConfigSS::None), SameSite::None);
    }

    #[test]
    fn deliver_auth_in_every_mode_sets_the_right_cookies_and_body() {
        // cookie mode: cookies set, body = user only.
        let cfg = resolved_config_with(DeliveryMode::Cookie, ConfigSS::None);
        let jar = cookies_jar();
        let resp = TokenDelivery::new(&cfg).deliver_auth(&jar, &auth_result(), StatusCode::OK);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(has_cookie(&jar, "access_token") && has_cookie(&jar, "refresh_token"));
        assert!(has_cookie(&jar, "has_session"));

        // bearer mode: no cookies, body has tokens.
        let cfg = resolved_config_with(DeliveryMode::Bearer, ConfigSS::Strict);
        let jar = cookies_jar();
        let _ = TokenDelivery::new(&cfg).deliver_auth(&jar, &auth_result(), StatusCode::CREATED);
        assert!(!has_cookie(&jar, "access_token"));

        // both mode: cookies set and tokens in body.
        let cfg = resolved_config_with(DeliveryMode::Both, ConfigSS::Lax);
        let jar = cookies_jar();
        let _ = TokenDelivery::new(&cfg).deliver_auth(&jar, &auth_result(), StatusCode::OK);
        assert!(has_cookie(&jar, "access_token"));
    }

    #[test]
    fn deliver_refresh_in_every_mode() {
        let tokens = RotatedTokens {
            access_token: "na".to_owned(),
            refresh_token: "nr".to_owned(),
        };
        for mode in [
            DeliveryMode::Cookie,
            DeliveryMode::Bearer,
            DeliveryMode::Both,
        ] {
            let cfg = resolved_config_with(mode, ConfigSS::Lax);
            let jar = cookies_jar();
            let resp = TokenDelivery::new(&cfg).deliver_refresh(&jar, &tokens);
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[cfg(feature = "platform")]
    #[test]
    fn deliver_platform_auth_in_every_mode() {
        for mode in [
            DeliveryMode::Cookie,
            DeliveryMode::Bearer,
            DeliveryMode::Both,
        ] {
            let cfg = resolved_config_with(mode, ConfigSS::Lax);
            let jar = cookies_jar();
            let resp = TokenDelivery::new(&cfg).deliver_platform_auth(
                &jar,
                &platform_result(),
                StatusCode::OK,
            );
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[test]
    fn challenge_clear_signal_and_mfa_temp_and_user_body() {
        let cfg = resolved_config_with(DeliveryMode::Cookie, ConfigSS::Lax);
        let delivery = TokenDelivery::new(&cfg);

        // The MFA-challenge body is the same in every mode.
        let challenge = MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "t".to_owned(),
        };
        assert_eq!(
            delivery.deliver_mfa_challenge(&challenge).status(),
            StatusCode::OK
        );

        // clear_session removes the auth cookies (the jar records the removals).
        let jar = cookies_jar();
        jar.add(Cookie::new("access_token", "x"));
        delivery.clear_session(&jar);

        // The MFA-temp cookie planter and the browser-redirect planter are oauth-gated.
        #[cfg(feature = "oauth")]
        {
            delivery.set_mfa_temp_cookie(&jar, "temp.jwt");
            assert!(
                jar.get(bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME)
                    .is_some()
            );
            let jar2 = cookies_jar();
            delivery.set_auth_cookies_for_browser(&jar2, &auth_result());
            assert!(has_cookie(&jar2, "access_token"));
        }

        // `user_body` shapes the safe user.
        let body = user_body(&safe_user());
        assert_eq!(body.0["user"]["email"], "u@e.com");
    }
}
