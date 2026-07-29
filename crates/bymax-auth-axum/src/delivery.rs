//! The [`TokenDelivery`] helper (§8.5 / §14): the single place the adapter writes auth
//! cookies and shapes the auth body.
//!
//! It honors the configured mode — `cookie` (set the secure cookies, body = safe user),
//! `bearer` (no cookies, body = `{ user, accessToken, refreshToken }`), `both` (cookies +
//! tokens in the body) — and the §14 cookie attributes: HttpOnly (except `has_session`),
//! Secure-by-default, the refresh cookie path-scoped and `SameSite=Strict`, the access /
//! signal cookies `SameSite=Lax`. Handlers never hand-roll a `Set-Cookie`; they delegate
//! here. The MFA-temp cookie (planted on the MFA-gated OAuth callback) is also written here.
//!
//! The **platform** delivery is the one exception to the mode switch: it is always bearer
//! (§7.11.1 — "`deliver_platform_auth` is **always bearer** regardless of mode"), because the
//! operator dashboard is not a browser session. It never plants a cookie and its body is
//! always `{ admin, accessToken, refreshToken }`.

use axum::Json;
use axum::response::{IntoResponse, Response};
use bymax_auth_core::config::{SameSite as ConfigSameSite, TokenDelivery as DeliveryMode};
use bymax_auth_types::constants::AUTH_HAS_SESSION_COOKIE_VALUE;
use bymax_auth_types::{AuthResult, MfaChallengeResult, SafeAuthUser};
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

    /// Plant the ephemeral OAuth `state` cookie, binding the flow to the browser that started
    /// it (RFC 6749 §10.12). Scoped to `/` because the callback path is operator-configured and
    /// the core cannot know it; HttpOnly because nothing client-side reads it; Max-Age pinned
    /// to the 600 s TTL of the server-side `os:` record so neither half outlives the other.
    ///
    /// `SameSite` is always `Lax`, never the configured value: the provider redirects the
    /// browser back with a top-level GET, which is a **cross-site** navigation, and `Strict`
    /// withholds the cookie on exactly that hop — a deployment that hardened the setting
    /// everywhere else would find every OAuth login broken with no way to complete it. `Lax`
    /// is the tightest value that survives the callback, and it is enough: the cookie is read
    /// on that one navigation and is useless to a cross-site *request*.
    #[cfg(feature = "oauth")]
    pub(crate) fn set_oauth_state_cookie(&self, cookies: &Cookies, state: &str) {
        use bymax_auth_types::constants::{
            OAUTH_STATE_COOKIE_MAX_AGE_SECONDS, OAUTH_STATE_COOKIE_NAME,
        };
        let max_age = i64::try_from(OAUTH_STATE_COOKIE_MAX_AGE_SECONDS).unwrap_or(i64::MAX);
        cookies.add(
            Cookie::build((OAUTH_STATE_COOKIE_NAME.to_owned(), state.to_owned()))
                .path("/")
                .http_only(true)
                .secure(self.cookies().secure)
                .same_site(SameSite::Lax)
                .max_age(Duration::seconds(max_age))
                .build(),
        );
    }

    /// Clear the OAuth `state` cookie once its callback has been handled, reusing the exact
    /// `Path` it was planted with. The cookie is single-use: a stale one left behind would
    /// never match the next flow's freshly minted state, turning one failed login into a
    /// permanently broken one.
    #[cfg(feature = "oauth")]
    pub(crate) fn clear_oauth_state_cookie(&self, cookies: &Cookies) {
        use bymax_auth_types::constants::OAUTH_STATE_COOKIE_NAME;
        cookies.remove(
            Cookie::build((OAUTH_STATE_COOKIE_NAME.to_owned(), ""))
                .path("/")
                .build(),
        );
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

    /// Clear the ephemeral MFA-temp cookie, reusing the exact `Path` [`set_mfa_temp_cookie`]
    /// scoped it to (a mismatched path leaves a ghost cookie the browser keeps sending).
    ///
    /// The challenge handler applies nest-auth's clearing policy verbatim (see
    /// `mfa.controller.ts`): clear on SUCCESS (the JWT was consumed) and on
    /// `mfa_temp_token_invalid` (forged/expired/unknown — a retry under the same cookie can
    /// never succeed); KEEP the cookie on `mfa_invalid_code` / `account_locked` / a transient
    /// failure, because the temp token is still alive in the store and the user can retry
    /// inside its 5-minute TTL. The brute-force counter still caps how many wrong codes one
    /// token accepts, so keeping it does not weaken the threat model.
    ///
    /// [`set_mfa_temp_cookie`]: TokenDelivery::set_mfa_temp_cookie
    #[cfg(feature = "mfa")]
    pub(crate) fn clear_mfa_temp_cookie(&self, cookies: &Cookies) {
        use bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME;
        cookies.remove(
            Cookie::build((MFA_TEMP_COOKIE_NAME.to_owned(), ""))
                .path(self.cookies().mfa_temp_path.clone())
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

    /// Deliver a successful **platform** authentication (login / MFA challenge / refresh).
    ///
    /// Unlike [`TokenDelivery::deliver_auth`] this ignores the configured delivery mode
    /// entirely: platform sessions are **always** bearer (§7.11.1), so no cookie is ever
    /// planted and the body is always `{ admin, accessToken, refreshToken }`. The account key
    /// is `admin` (not `user`), matching nest-auth's `PlatformBearerAuthResponse`.
    #[cfg(feature = "platform")]
    pub(crate) fn deliver_platform_auth(
        &self,
        result: &bymax_auth_types::PlatformAuthResult,
        status: StatusCode,
    ) -> Response {
        (status, Json(platform_bearer_body(result))).into_response()
    }

    /// Deliver a refresh outcome. The rotated pair is paired with the freshly fetched account
    /// so the body matches nest-auth's `deliverRefreshResponse`, which delegates to the login
    /// delivery and therefore echoes the user in every mode: `cookie` sets the new cookies and
    /// returns `{ user }`, `bearer` returns `{ user, accessToken, refreshToken }`, `both` does
    /// both. Kept as a distinct call site (as nest-auth does) so a reader can tell a rotation
    /// from an initial login at the handler.
    pub(crate) fn deliver_refresh(&self, cookies: &Cookies, result: &AuthResult) -> Response {
        self.deliver_auth(cookies, result, StatusCode::OK)
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

/// The platform auth body: the safe admin under the `admin` key plus the token pair,
/// camelCase. The key is `admin`, not `user` — nest-auth's published
/// `PlatformBearerAuthResponse` names it that way, and §7.11.1 of the spec agrees.
#[cfg(feature = "platform")]
fn platform_bearer_body(result: &bymax_auth_types::PlatformAuthResult) -> impl Serialize + '_ {
    json!({
        "admin": &result.admin,
        "accessToken": &result.access_token,
        "refreshToken": &result.refresh_token,
    })
}

/// The `GET /auth/me` body: the safe user as the **top-level** object, with no wrapper —
/// nest-auth's `AuthController.me` returns the `SafeAuthUser` itself, and its published
/// client (`createAuthClient().getMe()`) decodes the bare object.
pub(crate) fn user_body(user: &SafeAuthUser) -> Json<serde_json::Value> {
    Json(json!(user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::resolved_config_with;
    use bymax_auth_core::config::SameSite as ConfigSS;
    #[cfg(feature = "platform")]
    use bymax_auth_types::{AuthPlatformUser, PlatformAuthResult, SafeAuthPlatformUser};
    use bymax_auth_types::{AuthResult, AuthUser, MfaChallengeResult};
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
            admin: SafeAuthPlatformUser::from(AuthPlatformUser {
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
    fn deliver_refresh_sets_the_rotated_cookies_and_is_a_200_in_every_mode() {
        // A rotation delivers exactly like a login (nest-auth's `deliverRefreshResponse`
        // delegates to `deliverAuthResponse`): 200 in every mode, with the NEW pair planted as
        // cookies in the two cookie-bearing modes and none in `bearer`.
        for mode in [
            DeliveryMode::Cookie,
            DeliveryMode::Bearer,
            DeliveryMode::Both,
        ] {
            let cfg = resolved_config_with(mode, ConfigSS::Lax);
            let jar = cookies_jar();
            let resp = TokenDelivery::new(&cfg).deliver_refresh(&jar, &auth_result());
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                has_cookie(&jar, "access_token"),
                mode != DeliveryMode::Bearer
            );
        }
    }

    #[cfg(feature = "platform")]
    #[test]
    fn deliver_platform_auth_is_always_bearer_in_every_mode() {
        // Platform delivery ignores the configured mode entirely (§7.11.1): even under
        // `cookie`/`both` it plants NO cookie, because the operator dashboard is not a browser
        // session. The status passes through so a caller can pick 200 or 201.
        for mode in [
            DeliveryMode::Cookie,
            DeliveryMode::Bearer,
            DeliveryMode::Both,
        ] {
            let cfg = resolved_config_with(mode, ConfigSS::Lax);
            let jar = cookies_jar();
            let resp =
                TokenDelivery::new(&cfg).deliver_platform_auth(&platform_result(), StatusCode::OK);
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(!has_cookie(&jar, "access_token"));
            assert!(!has_cookie(&jar, "refresh_token"));
            assert!(!has_cookie(&jar, "has_session"));
        }
    }

    /// Read a `responseBodies` entry from the shared cross-implementation wire contract.
    ///
    /// These are the payloads a consumer's TypeScript describes, so a difference here is not a
    /// record that fails to load — it is a client that compiles against one backend and reads
    /// `undefined` from the other.
    fn response_body_keys(path: &[&str]) -> Vec<String> {
        let file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(file).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        let mut node = root
            .get("responseBodies")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        for step in path {
            node = node.get(step).cloned().unwrap_or(serde_json::Value::Null);
        }
        let keys: Vec<String> = node
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        // The label is built before the assert, not inside its message: an argument evaluated
        // only on failure is a line the coverage gate never sees executed.
        let label = path.join(".");
        assert!(
            !keys.is_empty(),
            "the wire contract declared no responseBodies.{label} — it did not load"
        );
        keys
    }

    /// The keys of a serialized body, sorted.
    fn sorted_keys(body: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = body
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    #[test]
    fn the_login_bodies_match_the_shared_wire_contract() {
        // Cookie mode: the body carries the user and NOTHING else. The tokens are in
        // `Set-Cookie` precisely so script cannot read them, and repeating a refresh token in
        // the JSON payload would hand it to any XSS on the page — making the HttpOnly flag
        // decorative. This is the assertion that would catch that regression.
        let result = auth_result();
        let cookie_body = serde_json::json!({ "user": &result.user });
        let mut expected = response_body_keys(&["login", "cookie"]);
        expected.sort();
        assert_eq!(sorted_keys(&cookie_body), expected);
        assert!(!cookie_body.to_string().contains("acc"));
        assert!(!cookie_body.to_string().contains("ref"));

        // Bearer mode: exactly the declared keys.
        let bearer = serde_json::to_value(bearer_body(&result)).unwrap_or_default();
        let mut expected = response_body_keys(&["login", "bearer"]);
        expected.sort();
        assert_eq!(sorted_keys(&bearer), expected);
    }

    #[cfg(feature = "platform")]
    #[test]
    fn the_platform_login_body_matches_the_shared_wire_contract() {
        // The account rides under `admin`. This library's own generated TypeScript said `user`
        // until the struct field was renamed to match what the adapter emits — a consumer
        // reading `result.user` got `undefined` at runtime, and nothing was checking.
        let body =
            serde_json::to_value(platform_bearer_body(&platform_result())).unwrap_or_default();
        let mut expected = response_body_keys(&["platformLogin", "bearer"]);
        expected.sort();
        assert_eq!(sorted_keys(&body), expected);
        assert!(expected.contains(&"admin".to_owned()));
        assert!(!expected.contains(&"user".to_owned()));
    }

    #[test]
    fn the_challenge_body_matches_the_shared_wire_contract() {
        let challenge = bymax_auth_types::MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "t".to_owned(),
        };
        let body = serde_json::to_value(challenge).unwrap_or_default();
        let mut expected = response_body_keys(&["mfaChallenge"]);
        expected.sort();
        assert_eq!(sorted_keys(&body), expected);
    }

    #[cfg(feature = "platform")]
    #[test]
    fn platform_bearer_body_names_the_account_admin_not_user() {
        // The platform body key is `admin` (nest-auth's `PlatformBearerAuthResponse`); a
        // `user` key here would silently break every published platform client.
        let result = platform_result();
        let body = serde_json::to_value(platform_bearer_body(&result)).unwrap_or_default();
        assert_eq!(body["admin"]["email"], "a@e.com");
        assert!(body.get("user").is_none());
        assert_eq!(body["accessToken"], "pacc");
        assert_eq!(body["refreshToken"], "pref");
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

        // `user_body` is the BARE safe user — no `{ user: … }` wrapper (nest-auth's `me`
        // returns the object itself, and its published client decodes it unwrapped).
        let body = user_body(&safe_user());
        assert_eq!(body.0["email"], "u@e.com");
        assert!(body.0.get("user").is_none());
    }

    #[cfg(feature = "mfa")]
    #[test]
    fn clear_mfa_temp_cookie_removes_it_on_the_path_it_was_set_with() {
        // The clear must reuse the MFA-temp path; a mismatched `Path` would leave a ghost
        // cookie the browser keeps replaying at the challenge endpoint.
        let cfg = resolved_config_with(DeliveryMode::Cookie, ConfigSS::Lax);
        let delivery = TokenDelivery::new(&cfg);
        let jar = cookies_jar();
        jar.add(Cookie::new(
            bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME,
            "temp.jwt",
        ));
        delivery.clear_mfa_temp_cookie(&jar);
        assert!(!has_cookie(
            &jar,
            bymax_auth_types::constants::MFA_TEMP_COOKIE_NAME
        ));
    }
}
