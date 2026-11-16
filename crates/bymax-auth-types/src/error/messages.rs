//! The English default client message of every [`AuthErrorCode`] (layer: wire types).
//!
//! Split from `error.rs` so that file stays within the repository's size limit; the strings are
//! the exact ones nest-auth ships, and `errorCatalog` in the shared contract pins them.

use super::AuthErrorCode;

impl AuthErrorCode {
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
            Self::SessionNotFound => "Session not found",
            Self::TokenMissing => "Token missing",
            Self::EmailAlreadyExists => "Email already registered",
            Self::EmailNotVerified => "Email not verified",
            Self::EmailChangeTokenInvalid => "Invalid or expired email change link",
            Self::MfaRequired => "Two-factor authentication required",
            Self::MfaInvalidCode => "Invalid MFA code",
            Self::MfaAlreadyEnabled => "MFA is already enabled",
            Self::MfaNotEnabled => "MFA is not enabled",
            Self::MfaSetupRequired => "MFA setup required",
            Self::MfaTempTokenInvalid => "Invalid or expired temporary MFA token",
            Self::MfaStateConflict => "Another MFA change is in progress. Please try again.",
            Self::PasswordCompromised => {
                "This password has appeared in a data breach. Please choose a different one."
            }
            Self::PasswordResetTokenInvalid => "Invalid password reset token",
            Self::OtpInvalid => "Invalid OTP code",
            Self::OtpExpired => "Expired OTP code",
            Self::OtpMaxAttempts => "Maximum number of attempts exceeded",
            Self::InsufficientRole => "Insufficient permission",
            Self::Forbidden => "Access denied",
            Self::UntrustedOrigin => "Request origin not allowed",
            Self::ReauthenticationRequired => {
                "Please sign in again to change your security settings."
            }
            Self::InvalidInvitationToken => "Invalid or expired invitation token",
            Self::OauthFailed => "OAuth authentication failed",
            Self::OauthEmailMismatch => "OAuth email does not match",
            Self::PlatformAuthRequired => "Platform authentication required",
            Self::ApiKeyInvalid => "Invalid API key",
            Self::ApiKeyScopeInsufficient => "API key lacks the required scope",
            Self::ApiKeyNotFound => "API key not found",
            Self::Validation => "Validation failed",
            Self::TooManyRequests => "Too many requests. Please slow down and try again shortly.",
            Self::WorkspaceRequired => "A workspace is required",
            Self::WorkspaceNotFound => "Workspace not found",
            Self::InsufficientWorkspaceRole => "Insufficient workspace role",
            Self::LastOwner => "A workspace needs at least one owner",
            Self::AlreadyMember => "Already a member of this workspace",
            Self::InvitationEmailMismatch => {
                "This invitation was sent to a different email address"
            }
            Self::RegistrationClosed => "Registration is closed",
            Self::WorkspaceLimitReached => {
                "Workspace limit reached. Workspaces pending deletion count toward the limit."
            }
            Self::WorkspacePendingDeletion => "Workspace is scheduled for deletion",
            Self::Internal => "Internal server error",
            Self::ServiceUnavailable => "Service temporarily unavailable",
        }
    }
}
