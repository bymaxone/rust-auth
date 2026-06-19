//! The error model: the [`AuthErrorCode`] catalog (stable `auth.*` strings + HTTP
//! statuses), the typed [`AuthError`], and the `{ error: { code, message, details } }`
//! wire envelope shared by the server, the typed client, and the WASM edge.
//!
//! # Parity & security
//!
//! Every code string and HTTP status is byte-identical to `@bymax-one/nest-auth`, so
//! existing clients decode `rust-auth` errors unchanged. Three internal-only codes —
//! [`AuthErrorCode::TokenExpired`], [`AuthErrorCode::TokenRevoked`], and the
//! [`AuthErrorCode::TokenMissing`] sentinel — must never reach a client: they exist
//! for internal control flow and logs and are collapsed to
//! [`AuthErrorCode::TokenInvalid`] at the HTTP boundary (via [`AuthErrorCode::to_wire`]),
//! denying an attacker an oracle that distinguishes "expired" from "revoked" from
//! "garbage".

use serde::{Deserialize, Serialize};

/// Stable, serializable error code. Each variant serializes to its exact `auth.*`
/// string literal, byte-identical to nest-auth's `AUTH_ERROR_CODES`, and maps to a
/// fixed HTTP status via [`AuthErrorCode::http_status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "error-codes.ts"))]
pub enum AuthErrorCode {
    // Credentials & account state
    /// Login email not found or password mismatch — deliberately indistinguishable.
    #[serde(rename = "auth.invalid_credentials")]
    InvalidCredentials,
    /// Brute-force counter reached the limit; carries `Retry-After`.
    #[serde(rename = "auth.account_locked")]
    AccountLocked,
    /// Account status is inactive.
    #[serde(rename = "auth.account_inactive")]
    AccountInactive,
    /// Account status is suspended.
    #[serde(rename = "auth.account_suspended")]
    AccountSuspended,
    /// Account status is banned.
    #[serde(rename = "auth.account_banned")]
    AccountBanned,
    /// Account is pending operator approval.
    #[serde(rename = "auth.pending_approval")]
    PendingApproval,

    // Tokens & sessions
    /// **Internal only** — access JWT past `exp`. Remapped to `TokenInvalid` on the wire.
    #[serde(rename = "auth.token_expired")]
    TokenExpired,
    /// **Internal only** — access JTI present in the blacklist. Remapped to `TokenInvalid`.
    #[serde(rename = "auth.token_revoked")]
    TokenRevoked,
    /// The single public token-failure code (malformed/bad-signature/wrong-alg/…).
    #[serde(rename = "auth.token_invalid")]
    TokenInvalid,
    /// Refresh token absent from the store and outside the grace window.
    #[serde(rename = "auth.refresh_token_invalid")]
    RefreshTokenInvalid,
    /// Session backing a refresh token no longer exists.
    #[serde(rename = "auth.session_expired")]
    SessionExpired,
    /// Concurrent-session cap reached (informational).
    #[serde(rename = "auth.session_limit_reached")]
    SessionLimitReached,
    /// Revoke targeted a session not owned by the caller (anti-IDOR).
    #[serde(rename = "auth.session_not_found")]
    SessionNotFound,
    /// **Internal only** — no access token present on a protected route. Remapped to
    /// `TokenInvalid`. Has no nest-auth catalog row; it is a boundary sentinel.
    #[serde(rename = "auth.token_missing")]
    TokenMissing,

    // Registration & email
    /// Register with an email already present in the same tenant.
    #[serde(rename = "auth.email_already_exists")]
    EmailAlreadyExists,
    /// Login when email verification is required and the email is unverified.
    #[serde(rename = "auth.email_not_verified")]
    EmailNotVerified,

    // MFA
    /// Endpoint demands verified MFA but the JWT lacks `mfaVerified: true`.
    #[serde(rename = "auth.mfa_required")]
    MfaRequired,
    /// Submitted TOTP code is wrong.
    #[serde(rename = "auth.mfa_invalid_code")]
    MfaInvalidCode,
    /// `setup()` called while MFA is already enabled.
    #[serde(rename = "auth.mfa_already_enabled")]
    MfaAlreadyEnabled,
    /// `disable()`/challenge when MFA is not enabled.
    #[serde(rename = "auth.mfa_not_enabled")]
    MfaNotEnabled,
    /// `verify_enable()` before a setup record exists.
    #[serde(rename = "auth.mfa_setup_required")]
    MfaSetupRequired,
    /// MFA-temp JWT expired, malformed, or already consumed.
    #[serde(rename = "auth.mfa_temp_token_invalid")]
    MfaTempTokenInvalid,
    /// Submitted recovery code matches no stored hash.
    #[serde(rename = "auth.recovery_code_invalid")]
    RecoveryCodeInvalid,

    // Password
    /// New password fails the minimum policy.
    #[serde(rename = "auth.password_too_weak")]
    PasswordTooWeak,
    /// Reset token absent from the store.
    #[serde(rename = "auth.password_reset_token_invalid")]
    PasswordResetTokenInvalid,
    /// Defined for completeness; the reset flow consumes tokens with `GETDEL`, so this
    /// is unreachable by design (expired and missing both map to the invalid code).
    #[serde(rename = "auth.password_reset_token_expired")]
    PasswordResetTokenExpired,

    // OTP
    /// OTP code mismatch.
    #[serde(rename = "auth.otp_invalid")]
    OtpInvalid,
    /// OTP record absent (TTL elapsed).
    #[serde(rename = "auth.otp_expired")]
    OtpExpired,
    /// Too many failed OTP attempts; record locked/consumed.
    #[serde(rename = "auth.otp_max_attempts")]
    OtpMaxAttempts,

    // Authorization
    /// Caller role does not satisfy the endpoint's required role.
    #[serde(rename = "auth.insufficient_role")]
    InsufficientRole,
    /// Generic access-denied fallback.
    #[serde(rename = "auth.forbidden")]
    Forbidden,

    // Invitations
    /// Invitation token absent from the store — invalid or expired.
    #[serde(rename = "auth.invalid_invitation_token")]
    InvalidInvitationToken,

    // OAuth
    /// Provider rejected the request or the `state` CSRF check failed.
    #[serde(rename = "auth.oauth_failed")]
    OauthFailed,
    /// Provider-returned email does not match the account being linked.
    #[serde(rename = "auth.oauth_email_mismatch")]
    OauthEmailMismatch,

    // Platform
    /// Platform endpoint reached with a dashboard JWT (`token_type` mismatch).
    #[serde(rename = "auth.platform_auth_required")]
    PlatformAuthRequired,

    // Adapter-originated — no nest-auth `auth.*` equivalent
    /// Request body/query failed DTO validation. Per-field messages serialize into
    /// `error.details`. One of two adapter-originated codes (the other is
    /// `TooManyRequests`).
    #[serde(rename = "auth.validation")]
    Validation,
    /// Per-IP edge rate limit exceeded. Synthesized at the HTTP boundary; carries
    /// `Retry-After`. Distinct from the per-account `AccountLocked` lockout.
    #[serde(rename = "auth.too_many_requests")]
    TooManyRequests,

    // Internal
    /// Unexpected internal failure (store down, serialization error, repository error).
    /// The underlying cause is logged, never serialized — only this generic code and a
    /// generic message reach the client, preserving the consistent envelope.
    #[serde(rename = "auth.internal")]
    Internal,
}

impl AuthErrorCode {
    /// The fixed HTTP status for this code, identical to nest-auth's catalog.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidCredentials
            | Self::TokenExpired
            | Self::TokenRevoked
            | Self::TokenInvalid
            | Self::RefreshTokenInvalid
            | Self::SessionExpired
            | Self::TokenMissing
            | Self::MfaInvalidCode
            | Self::MfaTempTokenInvalid
            | Self::RecoveryCodeInvalid
            | Self::OtpInvalid
            | Self::OtpExpired
            | Self::OauthFailed
            | Self::PlatformAuthRequired => 401,
            Self::AccountInactive
            | Self::AccountSuspended
            | Self::AccountBanned
            | Self::PendingApproval
            | Self::EmailNotVerified
            | Self::MfaRequired
            | Self::InsufficientRole
            | Self::Forbidden => 403,
            Self::SessionNotFound => 404,
            Self::EmailAlreadyExists
            | Self::SessionLimitReached
            | Self::MfaAlreadyEnabled
            | Self::OauthEmailMismatch => 409,
            Self::MfaNotEnabled
            | Self::MfaSetupRequired
            | Self::PasswordTooWeak
            | Self::PasswordResetTokenInvalid
            | Self::PasswordResetTokenExpired
            | Self::InvalidInvitationToken
            | Self::Validation => 400,
            Self::AccountLocked | Self::OtpMaxAttempts | Self::TooManyRequests => 429,
            Self::Internal => 500,
        }
    }

    /// The English default client message — the exact strings nest-auth ships in
    /// `AUTH_ERROR_MESSAGES`. End-user-facing defaults, not internal diagnostics;
    /// localization is the host's responsibility, keyed on the stable code.
    #[must_use]
    pub fn client_message(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Invalid email or password",
            Self::AccountLocked => "Account temporarily locked. Please try again in a few minutes.",
            Self::AccountInactive => "Account inactive",
            Self::AccountSuspended => "Account suspended",
            Self::AccountBanned => "Account banned",
            Self::PendingApproval => "Account pending approval",
            Self::TokenExpired => "Token expired",
            Self::TokenRevoked => "Token revoked",
            Self::TokenInvalid => "Invalid token",
            Self::RefreshTokenInvalid => "Invalid or expired refresh token",
            Self::SessionExpired => "Session expired",
            Self::SessionLimitReached => "Session limit reached",
            Self::SessionNotFound => "Session not found",
            Self::TokenMissing => "Token missing",
            Self::EmailAlreadyExists => "Email already registered",
            Self::EmailNotVerified => "Email not verified",
            Self::MfaRequired => "Two-factor authentication required",
            Self::MfaInvalidCode => "Invalid MFA code",
            Self::MfaAlreadyEnabled => "MFA is already enabled",
            Self::MfaNotEnabled => "MFA is not enabled",
            Self::MfaSetupRequired => "MFA setup required",
            Self::MfaTempTokenInvalid => "Invalid or expired temporary MFA token",
            Self::RecoveryCodeInvalid => "Invalid recovery code",
            Self::PasswordTooWeak => "Password too weak",
            Self::PasswordResetTokenInvalid => "Invalid password reset token",
            Self::PasswordResetTokenExpired => "Expired password reset token",
            Self::OtpInvalid => "Invalid OTP code",
            Self::OtpExpired => "Expired OTP code",
            Self::OtpMaxAttempts => "Maximum number of attempts exceeded",
            Self::InsufficientRole => "Insufficient permission",
            Self::Forbidden => "Access denied",
            Self::InvalidInvitationToken => "Invalid or expired invitation token",
            Self::OauthFailed => "OAuth authentication failed",
            Self::OauthEmailMismatch => "OAuth email does not match",
            Self::PlatformAuthRequired => "Platform authentication required",
            Self::Validation => "Validation failed",
            Self::TooManyRequests => "Too many requests. Please slow down and try again shortly.",
            Self::Internal => "Internal server error",
        }
    }

    /// Whether this code is internal-only and MUST be remapped before reaching a
    /// client. True for the three token sentinels (`TokenExpired`, `TokenRevoked`,
    /// `TokenMissing`); see [`AuthErrorCode::to_wire`].
    #[must_use]
    pub fn is_internal_only(self) -> bool {
        matches!(
            self,
            Self::TokenExpired | Self::TokenRevoked | Self::TokenMissing
        )
    }

    /// The code as it is allowed to appear on the wire: the internal-only token
    /// sentinels collapse to [`AuthErrorCode::TokenInvalid`]; every other code maps to
    /// itself.
    #[must_use]
    pub fn to_wire(self) -> Self {
        if self.is_internal_only() {
            Self::TokenInvalid
        } else {
            self
        }
    }
}

/// A single field-level validation failure, surfaced under `error.details` for the
/// adapter-originated [`AuthErrorCode::Validation`] code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-error.types.ts"))]
#[serde(rename_all = "camelCase")]
pub struct FieldError {
    /// The offending request field (dotted path for nested fields).
    pub field: String,
    /// Human-readable reason the field was rejected.
    pub message: String,
}

/// The reduced, client-parsed error shape exported for the typed client: the
/// authoritative `code` plus an advisory/localizable `message`. The full wire body is
/// [`AuthErrorEnvelope`]; this is the projection clients decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "auth-error.types.ts"))]
pub struct AuthErrorResponse {
    /// The stable, authoritative `auth.*` code.
    pub code: AuthErrorCode,
    /// The advisory English (or host-localized) message.
    pub message: String,
}

/// The inner body of the wire envelope: `{ code, message, details }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthErrorBody {
    /// The wire `auth.*` code (already remapped past any internal-only sentinel).
    pub code: AuthErrorCode,
    /// The client-facing message for `code`.
    pub message: String,
    /// Optional structured data (e.g. `{ "retryAfterSeconds": 300 }` or the per-field
    /// validation errors); the field is omitted from the JSON entirely (not `null`)
    /// when the variant carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// The complete on-the-wire error envelope: `{ "error": { code, message, details } }`.
/// Every error — including the generic 500 — uses this shape, frustrating
/// response-fingerprinting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthErrorEnvelope {
    /// The error body.
    pub error: AuthErrorBody,
}

/// Canonical error type raised by every service and guard. Each variant maps to a
/// stable [`AuthErrorCode`] and a fixed HTTP status, and may carry structured details.
///
/// The [`std::fmt::Display`] impl (`#[error(...)]`) is for logs/`tracing` only — it is
/// never the client-facing message, which comes from [`AuthError::client_message`].
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    // Credentials & account state
    /// Missing email or wrong password — deliberately indistinguishable.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Per-account brute-force lockout, with the seconds until retry.
    #[error("account locked")]
    AccountLocked {
        /// Seconds the caller must wait before retrying, if known.
        retry_after_seconds: Option<u64>,
    },
    /// Account status is inactive.
    #[error("account inactive")]
    AccountInactive,
    /// Account status is suspended.
    #[error("account suspended")]
    AccountSuspended,
    /// Account status is banned.
    #[error("account banned")]
    AccountBanned,
    /// Account is pending operator approval.
    #[error("account pending approval")]
    PendingApproval,

    // Tokens & sessions
    /// Internal-only: access JWT past `exp`.
    #[error("token expired")]
    TokenExpired,
    /// Internal-only: access JTI revoked.
    #[error("token revoked")]
    TokenRevoked,
    /// The single public token-failure error.
    #[error("token invalid")]
    TokenInvalid,
    /// Refresh token absent and outside the grace window.
    #[error("refresh token invalid")]
    RefreshTokenInvalid,
    /// Session backing a refresh token no longer exists.
    #[error("session expired")]
    SessionExpired,
    /// Concurrent-session cap reached.
    #[error("session limit reached")]
    SessionLimitReached,
    /// Revoke targeted a session not owned by the caller.
    #[error("session not found")]
    SessionNotFound,
    /// Internal-only: no access token on a protected route.
    #[error("token missing")]
    TokenMissing,

    // Registration & email
    /// Duplicate email within a tenant.
    #[error("email already exists")]
    EmailAlreadyExists,
    /// Email not verified while verification is required.
    #[error("email not verified")]
    EmailNotVerified,

    // MFA
    /// Verified MFA required but absent from the JWT.
    #[error("mfa required")]
    MfaRequired,
    /// Submitted TOTP code is wrong.
    #[error("mfa invalid code")]
    MfaInvalidCode,
    /// `setup()` called while MFA is already enabled.
    #[error("mfa already enabled")]
    MfaAlreadyEnabled,
    /// MFA operation requested while MFA is not enabled.
    #[error("mfa not enabled")]
    MfaNotEnabled,
    /// `verify_enable()` called before a setup record exists.
    #[error("mfa setup required")]
    MfaSetupRequired,
    /// MFA-temp token expired, malformed, or already consumed.
    #[error("mfa temp token invalid")]
    MfaTempTokenInvalid,
    /// Submitted recovery code matches no stored hash.
    #[error("recovery code invalid")]
    RecoveryCodeInvalid,

    // Password
    /// New password fails the minimum policy.
    #[error("password too weak")]
    PasswordTooWeak,
    /// Reset token absent from the store.
    #[error("password reset token invalid")]
    PasswordResetTokenInvalid,
    /// Reset token expired (unreachable by design; see [`AuthErrorCode`]).
    #[error("password reset token expired")]
    PasswordResetTokenExpired,

    // OTP
    /// OTP code mismatch.
    #[error("otp invalid")]
    OtpInvalid,
    /// OTP record absent (TTL elapsed).
    #[error("otp expired")]
    OtpExpired,
    /// Too many failed OTP attempts.
    #[error("otp max attempts")]
    OtpMaxAttempts,

    // Authorization
    /// Caller role does not satisfy the endpoint's required role.
    #[error("insufficient role")]
    InsufficientRole,
    /// Generic access-denied fallback.
    #[error("forbidden")]
    Forbidden,

    // Invitations
    /// Invitation token absent — invalid or expired.
    #[error("invalid invitation token")]
    InvalidInvitationToken,

    // OAuth
    /// Provider rejected the request or `state` failed the CSRF check.
    #[error("oauth failed")]
    OauthFailed,
    /// Provider-returned email does not match the account being linked.
    #[error("oauth email mismatch")]
    OauthEmailMismatch,

    // Platform
    /// Platform endpoint reached with a dashboard token.
    #[error("platform auth required")]
    PlatformAuthRequired,

    // Adapter-originated
    /// Request body/query validation failure; carries the per-field messages.
    #[error("validation failed")]
    Validation {
        /// The field-level failures rendered under `error.details`.
        details: Vec<FieldError>,
    },
    /// Edge per-IP rate-limit rejection, with the seconds until retry.
    #[error("too many requests")]
    TooManyRequests {
        /// Seconds the caller should wait before retrying, if known.
        retry_after_seconds: Option<u64>,
    },

    // Internal
    /// Unexpected internal failure; the cause is logged, never serialized.
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl AuthError {
    /// The stable [`AuthErrorCode`] for this error (before any wire remap).
    #[must_use]
    pub fn code(&self) -> AuthErrorCode {
        match self {
            Self::InvalidCredentials => AuthErrorCode::InvalidCredentials,
            Self::AccountLocked { .. } => AuthErrorCode::AccountLocked,
            Self::AccountInactive => AuthErrorCode::AccountInactive,
            Self::AccountSuspended => AuthErrorCode::AccountSuspended,
            Self::AccountBanned => AuthErrorCode::AccountBanned,
            Self::PendingApproval => AuthErrorCode::PendingApproval,
            Self::TokenExpired => AuthErrorCode::TokenExpired,
            Self::TokenRevoked => AuthErrorCode::TokenRevoked,
            Self::TokenInvalid => AuthErrorCode::TokenInvalid,
            Self::RefreshTokenInvalid => AuthErrorCode::RefreshTokenInvalid,
            Self::SessionExpired => AuthErrorCode::SessionExpired,
            Self::SessionLimitReached => AuthErrorCode::SessionLimitReached,
            Self::SessionNotFound => AuthErrorCode::SessionNotFound,
            Self::TokenMissing => AuthErrorCode::TokenMissing,
            Self::EmailAlreadyExists => AuthErrorCode::EmailAlreadyExists,
            Self::EmailNotVerified => AuthErrorCode::EmailNotVerified,
            Self::MfaRequired => AuthErrorCode::MfaRequired,
            Self::MfaInvalidCode => AuthErrorCode::MfaInvalidCode,
            Self::MfaAlreadyEnabled => AuthErrorCode::MfaAlreadyEnabled,
            Self::MfaNotEnabled => AuthErrorCode::MfaNotEnabled,
            Self::MfaSetupRequired => AuthErrorCode::MfaSetupRequired,
            Self::MfaTempTokenInvalid => AuthErrorCode::MfaTempTokenInvalid,
            Self::RecoveryCodeInvalid => AuthErrorCode::RecoveryCodeInvalid,
            Self::PasswordTooWeak => AuthErrorCode::PasswordTooWeak,
            Self::PasswordResetTokenInvalid => AuthErrorCode::PasswordResetTokenInvalid,
            Self::PasswordResetTokenExpired => AuthErrorCode::PasswordResetTokenExpired,
            Self::OtpInvalid => AuthErrorCode::OtpInvalid,
            Self::OtpExpired => AuthErrorCode::OtpExpired,
            Self::OtpMaxAttempts => AuthErrorCode::OtpMaxAttempts,
            Self::InsufficientRole => AuthErrorCode::InsufficientRole,
            Self::Forbidden => AuthErrorCode::Forbidden,
            Self::InvalidInvitationToken => AuthErrorCode::InvalidInvitationToken,
            Self::OauthFailed => AuthErrorCode::OauthFailed,
            Self::OauthEmailMismatch => AuthErrorCode::OauthEmailMismatch,
            Self::PlatformAuthRequired => AuthErrorCode::PlatformAuthRequired,
            Self::Validation { .. } => AuthErrorCode::Validation,
            Self::TooManyRequests { .. } => AuthErrorCode::TooManyRequests,
            Self::Internal(_) => AuthErrorCode::Internal,
        }
    }

    /// The HTTP status for this error (from its code).
    #[must_use]
    pub fn http_status(&self) -> u16 {
        self.code().http_status()
    }

    /// The English default client message for this error (from its **wire** code, so
    /// an internal-only error reports the public message it collapses to).
    #[must_use]
    pub fn client_message(&self) -> &'static str {
        self.code().to_wire().client_message()
    }

    /// Whether this error's code is internal-only and must be remapped before it
    /// reaches a client.
    #[must_use]
    pub fn is_internal_only(&self) -> bool {
        self.code().is_internal_only()
    }

    /// The structured `details` payload for the wire envelope, or `None` when the
    /// variant carries none. `retry_after_seconds` serializes as `retryAfterSeconds`.
    #[must_use]
    pub fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::AccountLocked {
                retry_after_seconds,
            }
            | Self::TooManyRequests {
                retry_after_seconds,
            } => retry_after_seconds.map(|secs| serde_json::json!({ "retryAfterSeconds": secs })),
            // Infallible in practice: `Vec<FieldError>` serializes only `String` fields,
            // so `to_value` never fails for this type. `.ok()` (not `unwrap`/`expect`,
            // which the workspace lints forbid) yields `None` on the unreachable error,
            // degrading to a detail-less envelope rather than panicking.
            Self::Validation { details } => serde_json::to_value(details).ok(),
            _ => None,
        }
    }

    /// Render the reduced client shape ([`AuthErrorResponse`]) using the **wire** code
    /// and its public message.
    #[must_use]
    pub fn to_response(&self) -> AuthErrorResponse {
        let code = self.code().to_wire();
        AuthErrorResponse {
            code,
            message: code.client_message().to_owned(),
        }
    }

    /// Render the full wire envelope (`{ error: { code, message, details } }`) using
    /// the **wire** code, its public message, and any structured details.
    #[must_use]
    pub fn to_envelope(&self) -> AuthErrorEnvelope {
        let code = self.code().to_wire();
        AuthErrorEnvelope {
            error: AuthErrorBody {
                code,
                message: code.client_message().to_owned(),
                details: self.details(),
            },
        }
    }
}
