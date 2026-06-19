//! Shared default constants mirrored into the npm `./shared` surface: the auth cookie
//! names and refresh path, the MFA-temp cookie parameters, and the default HTTP route
//! table.
//!
//! These are the single source of truth that the server, the typed client, and the
//! WASM edge proxy all read, so they cannot disagree. The [`routes`] paths are shown
//! with the default [`AUTH_ROUTE_PREFIX`]; if a deployment changes the prefix, the
//! refresh cookie path and the route paths move together (the adapter recomposes them),
//! which is why [`AUTH_REFRESH_COOKIE_PATH`] must track the prefix.

/// Cookie carrying the HS256 access JWT. `HttpOnly`, `SameSite=Lax`, path `/`.
pub const AUTH_ACCESS_COOKIE_NAME: &str = "access_token";

/// Cookie carrying the opaque refresh token. `HttpOnly`, `SameSite=Strict`, path
/// [`AUTH_REFRESH_COOKIE_PATH`].
pub const AUTH_REFRESH_COOKIE_NAME: &str = "refresh_token";

/// Non-`HttpOnly` JS/proxy-readable session hint. Its value is only `"1"` — never a
/// token or PII — so the SPA/edge can decide whether to attempt a silent refresh.
pub const AUTH_HAS_SESSION_COOKIE_NAME: &str = "has_session";

/// Path the refresh cookie is scoped to, shrinking its exposure to the refresh/logout
/// endpoints. MUST track [`AUTH_ROUTE_PREFIX`].
pub const AUTH_REFRESH_COOKIE_PATH: &str = "/auth";

/// Value written to [`AUTH_HAS_SESSION_COOKIE_NAME`] — a bare presence flag.
pub const AUTH_HAS_SESSION_COOKIE_VALUE: &str = "1";

/// Ephemeral cookie that plants the MFA-temp JWT on the MFA-gated OAuth callback path.
pub const MFA_TEMP_COOKIE_NAME: &str = "mfa_temp_token";

/// Max-Age of the MFA-temp cookie, pinned to the MFA-temp JWT's 300 s lifetime so the
/// cookie can never outlive the token.
pub const MFA_TEMP_COOKIE_MAX_AGE_SECONDS: u64 = 300;

/// Default route prefix. Every path in [`routes`] is built under it.
pub const AUTH_ROUTE_PREFIX: &str = "auth";

/// The default HTTP route table, with every path shown under [`AUTH_ROUTE_PREFIX`].
/// Grouped by controller; these are the byte-for-byte nest-auth endpoint paths.
pub mod routes {
    // AuthController — always on
    /// `POST` — register a new local user.
    pub const AUTH_REGISTER: &str = "/auth/register";
    /// `POST` — email + password login.
    pub const AUTH_LOGIN: &str = "/auth/login";
    /// `POST` — revoke the current session.
    pub const AUTH_LOGOUT: &str = "/auth/logout";
    /// `POST` — rotate the token pair from the refresh token.
    pub const AUTH_REFRESH: &str = "/auth/refresh";
    /// `GET` — the current authenticated user.
    pub const AUTH_ME: &str = "/auth/me";
    /// `POST` — verify an email with a code.
    pub const AUTH_VERIFY_EMAIL: &str = "/auth/verify-email";
    /// `POST` — resend the verification challenge.
    pub const AUTH_RESEND_VERIFICATION: &str = "/auth/resend-verification";
    /// `POST` — mint a single-use WebSocket upgrade ticket (`websocket` feature).
    pub const AUTH_WS_TICKET: &str = "/auth/ws-ticket";

    // MfaController — `mfa` feature
    /// `POST` — begin MFA enrolment.
    pub const MFA_SETUP: &str = "/auth/mfa/setup";
    /// `POST` — confirm and enable MFA.
    pub const MFA_VERIFY_ENABLE: &str = "/auth/mfa/verify-enable";
    /// `POST` — the post-login MFA challenge exchange (public).
    pub const MFA_CHALLENGE: &str = "/auth/mfa/challenge";
    /// `POST` — disable MFA (TOTP-gated).
    pub const MFA_DISABLE: &str = "/auth/mfa/disable";
    /// `POST` — regenerate recovery codes (TOTP-gated).
    pub const MFA_RECOVERY_CODES: &str = "/auth/mfa/recovery-codes";

    // PasswordResetController — always on
    /// `POST` — start a password reset (anti-enumeration).
    pub const PASSWORD_FORGOT: &str = "/auth/password/forgot-password";
    /// `POST` — complete a password reset.
    pub const PASSWORD_RESET: &str = "/auth/password/reset-password";
    /// `POST` — verify a reset OTP, returning a short-lived verified token.
    pub const PASSWORD_VERIFY_OTP: &str = "/auth/password/verify-otp";
    /// `POST` — resend a reset OTP (atomic cooldown).
    pub const PASSWORD_RESEND_OTP: &str = "/auth/password/resend-otp";

    // SessionController — `sessions` feature
    /// `GET` — list the caller's sessions.
    pub const SESSIONS_LIST: &str = "/auth/sessions";
    /// `DELETE` — revoke every session.
    pub const SESSIONS_REVOKE_ALL: &str = "/auth/sessions/all";
    /// `DELETE` — revoke one session by its hash (`/auth/sessions/{id}`).
    pub const SESSIONS_REVOKE_ONE: &str = "/auth/sessions/{id}";

    // PlatformAuthController — `platform` feature
    /// `POST` — platform-admin login.
    pub const PLATFORM_LOGIN: &str = "/auth/platform/login";
    /// `POST` — platform-admin MFA challenge exchange (public).
    pub const PLATFORM_MFA_CHALLENGE: &str = "/auth/platform/mfa/challenge";
    /// `GET` — the current platform admin.
    pub const PLATFORM_ME: &str = "/auth/platform/me";
    /// `POST` — revoke the current platform session.
    pub const PLATFORM_LOGOUT: &str = "/auth/platform/logout";
    /// `POST` — rotate the platform token pair.
    pub const PLATFORM_REFRESH: &str = "/auth/platform/refresh";
    /// `DELETE` — revoke every platform session.
    pub const PLATFORM_SESSIONS_REVOKE_ALL: &str = "/auth/platform/sessions";

    // PlatformMfaController — `platform` + `mfa`
    /// `POST` — begin platform-admin MFA enrolment.
    pub const PLATFORM_MFA_SETUP: &str = "/auth/platform/mfa/setup";
    /// `POST` — confirm and enable platform-admin MFA.
    pub const PLATFORM_MFA_VERIFY_ENABLE: &str = "/auth/platform/mfa/verify-enable";
    /// `POST` — disable platform-admin MFA.
    pub const PLATFORM_MFA_DISABLE: &str = "/auth/platform/mfa/disable";
    /// `POST` — regenerate platform-admin recovery codes.
    pub const PLATFORM_MFA_RECOVERY_CODES: &str = "/auth/platform/mfa/recovery-codes";

    // OAuthController — `oauth` feature
    /// `GET` — begin the OAuth authorize redirect (`/auth/oauth/{provider}`).
    pub const OAUTH_INITIATE: &str = "/auth/oauth/{provider}";
    /// `GET` — the OAuth callback (`/auth/oauth/{provider}/callback`).
    pub const OAUTH_CALLBACK: &str = "/auth/oauth/{provider}/callback";

    // InvitationController — `invitations` feature
    /// `POST` — create an invitation.
    pub const INVITATIONS_CREATE: &str = "/auth/invitations";
    /// `POST` — accept an invitation (public).
    pub const INVITATIONS_ACCEPT: &str = "/auth/invitations/accept";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_constants_match_the_nest_auth_defaults() {
        // The cookie names, refresh path, and MFA-temp parameters are the shared
        // contract the server, client, and edge all read; pin them to the spec values.
        assert_eq!(AUTH_ACCESS_COOKIE_NAME, "access_token");
        assert_eq!(AUTH_REFRESH_COOKIE_NAME, "refresh_token");
        assert_eq!(AUTH_HAS_SESSION_COOKIE_NAME, "has_session");
        assert_eq!(AUTH_HAS_SESSION_COOKIE_VALUE, "1");
        assert_eq!(AUTH_REFRESH_COOKIE_PATH, "/auth");
        assert_eq!(MFA_TEMP_COOKIE_NAME, "mfa_temp_token");
        assert_eq!(MFA_TEMP_COOKIE_MAX_AGE_SECONDS, 300);
    }

    #[test]
    fn refresh_cookie_path_tracks_the_route_prefix() {
        // The refresh cookie must be scoped under the route prefix, or the browser
        // would not attach it to the refresh endpoints.
        assert_eq!(AUTH_REFRESH_COOKIE_PATH, format!("/{AUTH_ROUTE_PREFIX}"));
        assert!(routes::AUTH_REFRESH.starts_with(AUTH_REFRESH_COOKIE_PATH));
    }

    #[test]
    fn route_paths_are_prefixed_and_well_formed() {
        // Every published route lives under the prefix — a sanity net against a typo'd
        // path that would silently 404 a whole controller group.
        let all = [
            routes::AUTH_REGISTER,
            routes::AUTH_LOGIN,
            routes::AUTH_LOGOUT,
            routes::AUTH_REFRESH,
            routes::AUTH_ME,
            routes::AUTH_VERIFY_EMAIL,
            routes::AUTH_RESEND_VERIFICATION,
            routes::AUTH_WS_TICKET,
            routes::MFA_SETUP,
            routes::MFA_VERIFY_ENABLE,
            routes::MFA_CHALLENGE,
            routes::MFA_DISABLE,
            routes::MFA_RECOVERY_CODES,
            routes::PASSWORD_FORGOT,
            routes::PASSWORD_RESET,
            routes::PASSWORD_VERIFY_OTP,
            routes::PASSWORD_RESEND_OTP,
            routes::SESSIONS_LIST,
            routes::SESSIONS_REVOKE_ALL,
            routes::SESSIONS_REVOKE_ONE,
            routes::PLATFORM_LOGIN,
            routes::PLATFORM_MFA_CHALLENGE,
            routes::PLATFORM_ME,
            routes::PLATFORM_LOGOUT,
            routes::PLATFORM_REFRESH,
            routes::PLATFORM_SESSIONS_REVOKE_ALL,
            routes::PLATFORM_MFA_SETUP,
            routes::PLATFORM_MFA_VERIFY_ENABLE,
            routes::PLATFORM_MFA_DISABLE,
            routes::PLATFORM_MFA_RECOVERY_CODES,
            routes::OAUTH_INITIATE,
            routes::OAUTH_CALLBACK,
            routes::INVITATIONS_CREATE,
            routes::INVITATIONS_ACCEPT,
        ];
        let prefix = format!("/{AUTH_ROUTE_PREFIX}/");
        for path in all {
            assert!(path.starts_with(&prefix), "route not under prefix: {path}");
        }
        // Spot-check the two parameterized paths use Axum 0.8 brace syntax.
        assert!(routes::SESSIONS_REVOKE_ONE.ends_with("/{id}"));
        assert!(routes::OAUTH_CALLBACK.ends_with("/{provider}/callback"));
    }
}
