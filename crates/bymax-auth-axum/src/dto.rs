//! The complete input-DTO catalog (§8.4.1 + the OAuth query DTOs of §11.3).
//!
//! Each struct derives `Deserialize` with `#[serde(deny_unknown_fields)]` (the Rust
//! analogue of `forbidNonWhitelisted` — an unexpected field 400s rather than being
//! silently stripped) and `garde::Validate` with the exact field rules from the nest-auth
//! DTOs. The body DTOs are camelCase on the wire (matching the engine's claim/result
//! shapes); deserialization maps the wire names to the snake_case Rust fields.

use garde::Validate;
use serde::Deserialize;

/// `POST /auth/register` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterDto {
    /// The email being registered.
    #[garde(email)]
    pub email: String,
    /// The plaintext password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub password: String,
    /// The display name (≥ 2 chars).
    #[garde(length(min = 2))]
    pub name: String,
    /// The tenant scope; ignored when a `TenantIdResolver` is configured.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/login` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginDto {
    /// The login email.
    #[garde(email)]
    pub email: String,
    /// The plaintext password (≤ 128 chars).
    #[garde(length(max = 128))]
    pub password: String,
    /// The tenant scope; ignored when a `TenantIdResolver` is configured.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/password/forgot-password` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForgotPasswordDto {
    /// The account email (anti-enumeration; the same response regardless of existence).
    #[garde(email)]
    pub email: String,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/password/reset-password` body. Exactly one of `token` / `otp` /
/// `verified_token` carries the reset proof (validated by the engine, not garde).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResetPasswordDto {
    /// The account email.
    #[garde(email)]
    pub email: String,
    /// The new password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub new_password: String,
    /// `method = "token"`: the emailed reset token.
    #[garde(skip)]
    pub token: Option<String>,
    /// `method = "otp"`: the numeric OTP.
    #[garde(skip)]
    pub otp: Option<String>,
    /// 2-step flow: the verified-token issued by `verify-otp`.
    #[garde(skip)]
    pub verified_token: Option<String>,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/password/verify-otp` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyOtpDto {
    /// The account email.
    #[garde(email)]
    pub email: String,
    /// The numeric OTP (4–8 digits).
    #[garde(length(min = 4, max = 8))]
    pub otp: String,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/password/resend-otp` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResendOtpDto {
    /// The account email (anti-enumeration).
    #[garde(email)]
    pub email: String,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/verify-email` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyEmailDto {
    /// The account email.
    #[garde(email)]
    pub email: String,
    /// The verification OTP (4–8 digits).
    #[garde(length(min = 4, max = 8))]
    pub otp: String,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/resend-verification` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResendVerificationDto {
    /// The account email (anti-enumeration).
    #[garde(email)]
    pub email: String,
    /// The tenant scope.
    #[garde(length(min = 1))]
    pub tenant_id: String,
}

/// `POST /auth/mfa/setup` body: the account password, re-proving who is asking.
///
/// Enabling MFA changes how the account authenticates, so an access token alone is not proof
/// of identity: a token lifted by XSS or from a shared machine could otherwise enrol an
/// authenticator the attacker holds, and the enable would revoke every session and lock the
/// real owner out of an account they still know the password to.
///
/// **Optional in the body, required by the engine whenever the account has a password.** An
/// account provisioned purely through OAuth has none, and refusing those would make MFA
/// unreachable for them. Mirrors nest-auth's `MfaSetupDto`.
#[derive(Debug, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaSetupDto {
    /// The account password. `None` for an OAuth-only account.
    #[garde(length(min = 1, max = 128))]
    pub password: Option<String>,
}

/// `POST /auth/mfa/verify-enable` body: the 6-digit TOTP from the authenticator.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaVerifyDto {
    /// The 6-digit TOTP shown during enrolment.
    #[garde(length(min = 6, max = 6))]
    pub code: String,
}

/// `POST /auth/mfa/challenge` body: the temp token plus the TOTP or recovery code.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaChallengeDto {
    /// The short-lived MFA temp token issued by the password/OAuth step.
    ///
    /// **Optional**, exactly as in nest-auth's `MfaChallengeDto`: the browser-driven OAuth +
    /// MFA flow leaves it out of the body because the callback planted it in the HttpOnly
    /// `mfa_temp_token` cookie, which the challenge handler reads as the fallback. When it IS
    /// present it must be non-empty and ≤ 512 chars — a compact HS256 JWT is ~200 chars, and
    /// the cap keeps an oversized payload away from JWT verification on this public endpoint.
    /// A request carrying neither channel is rejected by the handler as an invalid temp token,
    /// not as a field-validation failure.
    #[garde(inner(length(min = 1, max = 512)))]
    pub mfa_temp_token: Option<String>,
    /// A 6-digit TOTP or a recovery code (≤ 128 prevents hash-bombing).
    #[garde(length(min = 1, max = 128))]
    pub code: String,
}

/// `POST /auth/mfa/disable` body: TOTP only (recovery codes are not accepted, by design).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaDisableDto {
    /// The 6-digit TOTP.
    #[garde(length(min = 6, max = 6))]
    pub code: String,
}

/// `POST /auth/mfa/recovery-codes` body: the strong TOTP re-auth gate.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaRegenerateRecoveryCodesDto {
    /// The 6-digit TOTP.
    #[garde(length(min = 6, max = 6))]
    pub code: String,
}

/// `POST /auth/platform/login` body. The platform domain has no tenant.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformLoginDto {
    /// The admin email.
    #[garde(email)]
    pub email: String,
    /// The plaintext password (≤ 128 chars).
    #[garde(length(max = 128))]
    pub password: String,
}

/// `POST /auth/invitations` body. `tenant_id` is intentionally **absent** — it is derived
/// from the authenticated inviter's claims, never the body (anti cross-tenant injection).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateInvitationDto {
    /// The invitee email.
    #[garde(email)]
    pub email: String,
    /// The invited role (validated against the hierarchy by the engine).
    #[garde(length(min = 1))]
    pub role: String,
    /// Optional human-readable tenant name for the invitation email.
    #[garde(skip)]
    pub tenant_name: Option<String>,
}

/// `POST /auth/invitations/accept` body (public).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptInvitationDto {
    /// The single-use invitation token.
    #[garde(length(min = 1))]
    pub token: String,
    /// The new user's display name (≥ 2 chars).
    #[garde(length(min = 2))]
    pub name: String,
    /// The new user's password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub password: String,
}

/// `POST /auth/refresh` (and platform refresh) body — bearer/both mode only. In cookie mode
/// the refresh token is read from the cookie and this body is optional/empty.
#[derive(Debug, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshDto {
    /// The refresh token, present only in bearer/both mode.
    #[garde(skip)]
    pub refresh_token: Option<String>,
}

/// `GET /auth/oauth/{provider}` query (§11.3.1).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthInitiateQuery {
    /// The tenant the user will join on success; carried in the Redis state and recovered
    /// on callback. Not validated against the DB here (the `on_oauth_login` hook enforces
    /// tenant membership).
    #[garde(length(min = 1, max = 128))]
    pub tenant_id: String,
}

/// `GET /auth/oauth/{provider}/callback` query (§11.3.2). Only `code` and `state` are
/// required; the named optionals below are common provider extras we recognize. Crucially
/// this DTO does **not** use `deny_unknown_fields` (unlike the other query/body DTOs, where
/// it is a deliberate security default): a real provider redirect appends extra query
/// parameters we do not enumerate (Google alone varies its set over time), and rejecting an
/// unknown one would break a legitimate callback. Serde ignores unrecognized fields by
/// default, so any extra parameter is silently dropped while the known fields still validate.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackQuery {
    /// The authorization code returned by the provider.
    ///
    /// Absent on the error callback RFC 6749 §4.1.2.1 defines — the response a provider sends
    /// when the user declines consent, which used to be rejected as a malformed query for the
    /// missing field: a user who simply changed their mind saw a validation envelope instead
    /// of the configured error redirect. The handler refuses a callback carrying neither this
    /// nor `error`.
    #[garde(inner(length(min = 1, max = 2048)))]
    pub code: Option<String>,
    /// The provider's error code (RFC 6749 §4.1.2.1) — `access_denied` when the user clicks
    /// "Cancel" at the consent screen, plus `server_error`, `temporarily_unavailable` and the
    /// rest. Logged and never echoed to the caller: the response stays `auth.oauth_failed`, so
    /// the provider cannot choose what appears in a redirect URL the browser follows.
    #[garde(inner(length(max = 128)))]
    pub error: Option<String>,
    /// Human-readable detail accompanying `error`. Accepted so the query validates; logged
    /// with `error`, never echoed.
    #[garde(inner(length(max = 512)))]
    pub error_description: Option<String>,
    /// URI of a provider page describing `error`. Accepted so the query validates; never
    /// followed and never echoed.
    #[garde(inner(length(max = 512)))]
    pub error_uri: Option<String>,
    /// The CSRF `state` nonce (matched against the stored single-use record).
    #[garde(length(min = 1, max = 128))]
    pub state: String,
    /// RFC 9207 issuer (accepted, unused).
    #[garde(skip)]
    pub iss: Option<String>,
    /// RFC 6749 scope echo (accepted, unused).
    #[garde(skip)]
    pub scope: Option<String>,
    /// Google `authuser` (accepted, unused).
    #[garde(skip)]
    pub authuser: Option<String>,
    /// Google `prompt` (accepted, unused).
    #[garde(skip)]
    pub prompt: Option<String>,
    /// Google `hd` hosted-domain hint (accepted, unused).
    #[garde(skip)]
    pub hd: Option<String>,
}
