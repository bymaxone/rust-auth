//! Authentication result types returned by the engine: [`AuthResult`],
//! [`PlatformAuthResult`], [`MfaChallengeResult`], the [`LoginResult`] /
//! [`PlatformLoginResult`] unions, and [`RotatedTokens`].
//!
//! The opaque refresh token travels as a plain `String` here; the typed
//! `RawRefreshToken` helper that mints and hashes it lives in `bymax-auth-jwt`
//! (it needs the CSPRNG/SHA-256 primitives, which `bymax-auth-types` does not depend
//! on). A login that needs a second factor returns [`MfaChallengeResult`] instead of
//! tokens; the untagged [`LoginResult`] union models the either/or on the wire exactly
//! as nest-auth emits it.

use serde::{Deserialize, Serialize};

use crate::domain::{SafeAuthPlatformUser, SafeAuthUser};

/// Result of a successful dashboard/tenant authentication: the credential-free user
/// plus the freshly issued token pair (the refresh token is delivered in `bearer`/
/// `both` modes; in `cookie` mode the delivery layer sets it as a cookie instead).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct AuthResult {
    /// The authenticated user, with all credential fields removed.
    pub user: SafeAuthUser,
    /// The signed HS256 access JWT.
    pub access_token: String,
    /// The opaque refresh token (never a JWT).
    pub refresh_token: String,
}

/// Result of a successful platform-admin authentication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct PlatformAuthResult {
    /// The authenticated admin, with all credential fields removed.
    pub user: SafeAuthPlatformUser,
    /// The signed HS256 platform access JWT.
    pub access_token: String,
    /// The opaque refresh token (never a JWT).
    pub refresh_token: String,
}

/// Body returned when a login (password or OAuth) needs the second factor. Wire shape:
/// `{ "mfaRequired": true, "mfaTempToken": "<jwt>" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct MfaChallengeResult {
    /// Always `true` — present so a client can branch on it structurally.
    pub mfa_required: bool,
    /// The signed `MfaTempClaims` JWT to submit to the challenge endpoint.
    pub mfa_temp_token: String,
}

/// The outcome of a dashboard login: either a full authentication or an MFA challenge.
/// Serialized untagged so the wire body is exactly `AuthResult` **or**
/// `MfaChallengeResult`, matching nest-auth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(untagged)]
pub enum LoginResult {
    /// Login succeeded outright. The large success payload is boxed so the union stays
    /// small to move around (the challenge arm is tiny); `Box` is transparent to both
    /// serde's untagged representation and the generated TypeScript.
    Success(Box<AuthResult>),
    /// Login needs the second factor.
    MfaChallenge(MfaChallengeResult),
}

/// The outcome of a platform-admin login: a full authentication or an MFA challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(untagged)]
pub enum PlatformLoginResult {
    /// Login succeeded outright (boxed; see [`LoginResult::Success`]).
    Success(Box<PlatformAuthResult>),
    /// Login needs the second factor.
    MfaChallenge(MfaChallengeResult),
}

/// The freshly minted token pair returned by a refresh (rotation). Wire shape:
/// `{ "accessToken": "<jwt>", "refreshToken": "<opaque>" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-result.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct RotatedTokens {
    /// The new signed HS256 access JWT.
    pub access_token: String,
    /// The new opaque refresh token.
    pub refresh_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuthPlatformUser, AuthUser};
    use time::OffsetDateTime;

    fn instant() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn safe_user() -> SafeAuthUser {
        SafeAuthUser::from(AuthUser {
            id: "u_1".to_owned(),
            email: "u@e.com".to_owned(),
            name: "Ada".to_owned(),
            password_hash: None,
            role: "member".to_owned(),
            status: "ACTIVE".to_owned(),
            tenant_id: "t_1".to_owned(),
            email_verified: true,
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: Some(instant()),
            created_at: instant(),
        })
    }

    fn safe_platform_user() -> SafeAuthPlatformUser {
        SafeAuthPlatformUser::from(AuthPlatformUser {
            id: "p_1".to_owned(),
            email: "a@e.com".to_owned(),
            name: "Grace".to_owned(),
            password_hash: "ph".to_owned(),
            role: "admin".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_secret: None,
            mfa_recovery_codes: None,
            platform_id: None,
            last_login_at: None,
            updated_at: instant(),
            created_at: instant(),
        })
    }

    #[test]
    fn auth_result_emits_camel_case_token_fields() {
        // The bearer-mode body carries the user plus `accessToken`/`refreshToken`.
        let result = AuthResult {
            user: safe_user(),
            access_token: "jwt".to_owned(),
            refresh_token: "opaque".to_owned(),
        };
        let json = serde_json::to_value(result).unwrap_or_default();
        assert_eq!(json["accessToken"], "jwt");
        assert_eq!(json["refreshToken"], "opaque");
        assert_eq!(json["user"]["id"], "u_1");
    }

    #[test]
    fn mfa_challenge_result_uses_the_nest_auth_wire_shape() {
        // The challenge body must be exactly `{ mfaRequired, mfaTempToken }`.
        let challenge = MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "temp.jwt".to_owned(),
        };
        let json = serde_json::to_value(challenge).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({ "mfaRequired": true, "mfaTempToken": "temp.jwt" })
        );
    }

    #[test]
    fn login_result_is_untagged_success_or_challenge() {
        // The union serializes with no discriminator wrapper: a success body is an
        // `AuthResult`, a challenge body is an `MfaChallengeResult`.
        let success = LoginResult::Success(Box::new(AuthResult {
            user: safe_user(),
            access_token: "jwt".to_owned(),
            refresh_token: "opaque".to_owned(),
        }));
        let success_json = serde_json::to_value(&success).unwrap_or_default();
        assert!(success_json.get("user").is_some());
        assert!(success_json.get("Success").is_none(), "must be untagged");

        let challenge = LoginResult::MfaChallenge(MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "t".to_owned(),
        });
        let challenge_json = serde_json::to_value(&challenge).unwrap_or_default();
        assert_eq!(challenge_json["mfaRequired"], true);

        // The challenge arm round-trips back to the challenge variant.
        let back = serde_json::from_value::<LoginResult>(challenge_json).ok();
        assert_eq!(back, Some(challenge));
    }

    #[test]
    fn platform_login_result_round_trips_both_arms() {
        // The platform union mirrors the dashboard one over the platform result type.
        let success = PlatformLoginResult::Success(Box::new(PlatformAuthResult {
            user: safe_platform_user(),
            access_token: "jwt".to_owned(),
            refresh_token: "opaque".to_owned(),
        }));
        let json = serde_json::to_value(&success).unwrap_or_default();
        assert_eq!(json["accessToken"], "jwt");

        let challenge = PlatformLoginResult::MfaChallenge(MfaChallengeResult {
            mfa_required: true,
            mfa_temp_token: "t".to_owned(),
        });
        let back = serde_json::from_value::<PlatformLoginResult>(
            serde_json::to_value(&challenge).unwrap_or_default(),
        )
        .ok();
        assert_eq!(back, Some(challenge));
    }

    #[test]
    fn rotated_tokens_emit_camel_case() {
        // The refresh response body is `{ accessToken, refreshToken }`.
        let rotated = RotatedTokens {
            access_token: "new.jwt".to_owned(),
            refresh_token: "new.opaque".to_owned(),
        };
        let json = serde_json::to_value(&rotated).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({ "accessToken": "new.jwt", "refreshToken": "new.opaque" })
        );
        let back = serde_json::from_value::<RotatedTokens>(json).ok();
        assert_eq!(back, Some(rotated));
    }
}
