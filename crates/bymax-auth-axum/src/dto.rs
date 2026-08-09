//! The complete input-DTO catalog (§8.4.1 + the OAuth query DTOs of §11.3).
//!
//! Each struct derives `Deserialize` with `#[serde(deny_unknown_fields)]` (the Rust
//! analogue of `forbidNonWhitelisted` — an unexpected field 400s rather than being
//! silently stripped) and `garde::Validate` with the exact field rules from the nest-auth
//! DTOs. The body DTOs are camelCase on the wire (matching the engine's claim/result
//! shapes); deserialization maps the wire names to the snake_case Rust fields.

use garde::Validate;
use serde::Deserialize;

/// Refuse a value carrying a control character.
///
/// `tenant_id` is the widest attacker-controlled field on this surface: it arrives in the body
/// of `/login`, `/register`, `/verify-email`, `/password/forgot-password` and
/// `/oauth/{provider}` — all public — and is the caller's own value whenever no
/// `TenantIdResolver` is configured, which is the default. It then reaches a `tracing` event, a
/// Redis key segment and an HMAC preimage.
///
/// A length bound alone does not cover that. nest-auth has always rejected control characters
/// here, and this side accepted them, so the same request was a 400 on one backend and a 200 on
/// the other — the exact divergence `requestFieldBounds` exists to prevent, and one that also
/// let a caller forge a record in a plain-text log pipeline (ASVS 16.4.1).
///
/// `log_safe` is the second lock at the log site, for values that reach one without passing a
/// DTO — a host's `TenantIdResolver` returns whatever it returns.
fn no_control_characters(value: &str, _: &()) -> garde::Result {
    // `is_control` is Unicode category Cc — C0, DEL and C1 — which is exactly the set that can
    // forge a record boundary. Held identical to `log_safe`, the second lock at the log site.
    if value.chars().any(char::is_control) {
        return Err(garde::Error::new("must not contain control characters"));
    }
    Ok(())
}

/// `POST /auth/register` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterDto {
    /// The email being registered.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The plaintext password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub password: String,
    /// The display name (2–128 chars).
    #[garde(length(min = 2, max = 128))]
    pub name: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/login` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginDto {
    /// The login email.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The plaintext password (1–128 chars).
    ///
    /// The floor is 1, not the deployment's policy length: this is a login, and the password
    /// may predate whatever the policy says today — refusing it here would lock someone out
    /// with a validation error rather than an authentication one, while telling an
    /// unauthenticated caller what the policy is before any derivation runs. Rejecting the
    /// empty string still keeps a caller from spending a KDF derivation for free.
    #[garde(length(min = 1, max = 128))]
    pub password: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/password/forgot-password` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForgotPasswordDto {
    /// The account email (anti-enumeration; the same response regardless of existence).
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/password/change` body — the **authenticated** rotation.
///
/// Distinct from [`ResetPasswordDto`], which serves the unauthenticated recovery flow and
/// proves identity with an emailed token or OTP. Here the proof is the current password, which
/// is the one thing a stolen session does not carry.
#[derive(Debug, Default, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePasswordDto {
    /// The account's current password, re-proving who is asking (ASVS v5 §6.2.3).
    ///
    /// The floor is 1, not the policy length: rejecting the empty string keeps a caller from
    /// spending a KDF derivation for free, while enforcing the deployment's real policy here
    /// would leak it as a pre-KDF signal — and this is a *current* password, which may predate
    /// whatever the policy says today.
    #[garde(length(min = 1, max = 128))]
    pub current_password: String,
    /// The new password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub new_password: String,
    /// The caller's refresh token, when it has one to send.
    ///
    /// Optional, and only used to spare the caller's own session from the sweep: with it, the
    /// device that made the change stays signed in; without it, every session goes, this one
    /// included. A change that leaves an unidentified session alive is the failure the control
    /// exists to prevent, so the safe branch is the one that takes them all.
    ///
    /// Bounded, like every other free-text field: the value is hashed before it is looked up,
    /// so an oversized one buys nothing but the bytes it costs to carry and log.
    #[garde(inner(length(min = 1, max = 2048)))]
    pub refresh_token: Option<String>,
}

/// `POST /auth/password/reset-password` body. Exactly one of `token` / `otp` /
/// `verified_token` carries the reset proof (validated by the engine, not garde).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResetPasswordDto {
    /// The account email.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The new password (8–128 chars).
    #[garde(length(min = 8, max = 128))]
    pub new_password: String,
    /// `method = "token"`: the emailed reset token.
    ///
    /// Which of the three proofs is required is the engine's decision — it depends on the
    /// configured method, and answering "wrong proof for this deployment" before that decision
    /// would describe the configuration to an unauthenticated caller. What garde does here is
    /// only the shape: the same bounds nest-auth's DTO carries, so an oversized or absurd value
    /// never reaches the lookup on either backend.
    #[garde(inner(length(min = 1, max = 2048)))]
    pub token: Option<String>,
    /// `method = "otp"`: the numeric OTP (4–8 digits).
    #[garde(inner(length(min = 4, max = 8)))]
    pub otp: Option<String>,
    /// 2-step flow: the verified-token issued by `verify-otp` (64 hex chars).
    #[garde(inner(length(min = 64, max = 64)))]
    pub verified_token: Option<String>,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/password/verify-otp` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyOtpDto {
    /// The account email.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The numeric OTP (4–8 digits).
    #[garde(length(min = 4, max = 8))]
    pub otp: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/password/resend-otp` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResendOtpDto {
    /// The account email (anti-enumeration).
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/verify-email` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyEmailDto {
    /// The account email.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The verification OTP — exactly 6 digits.
    //
    // Six exactly: the verification OTP has a fixed length on both backends, unlike the
    // password-reset OTP whose length is configurable. Accepting 4-8 here let a caller spend
    // the verify path — and one of the five attempts on the record — on a value that could
    // never have been issued.
    #[garde(length(min = 6, max = 6))]
    pub otp: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
}

/// `POST /auth/resend-verification` body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResendVerificationDto {
    /// The account email (anti-enumeration).
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The tenant scope. Optional: a deployment that configures a `TenantIdResolver`
    /// ignores this value, so a client there may omit it. With no resolver configured it is
    /// the only thing that can scope the request, and omitting it is refused rather than
    /// defaulted (`auth.validation`) — see `AuthEngine::resolve_tenant`.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
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
    ///
    /// `inner(...)` is required on an `Option`: without it the rule never runs against the
    /// contained value, so the bound was declared and enforced nothing.
    #[garde(inner(length(min = 1, max = 128)))]
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
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The plaintext password (1–128 chars).
    ///
    /// The floor is 1, not the deployment's policy length: this is a login, and the password
    /// may predate whatever the policy says today — refusing it here would lock someone out
    /// with a validation error rather than an authentication one, while telling an
    /// unauthenticated caller what the policy is before any derivation runs. Rejecting the
    /// empty string still keeps a caller from spending a KDF derivation for free.
    #[garde(length(min = 1, max = 128))]
    pub password: String,
}

/// `POST /auth/invitations` body. `tenant_id` is intentionally **absent** — it is derived
/// from the authenticated inviter's claims, never the body (anti cross-tenant injection).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateInvitationDto {
    /// The invitee email.
    #[garde(email, length(max = 255))]
    pub email: String,
    /// The invited role (validated against the hierarchy by the engine).
    #[garde(length(min = 1, max = 64))]
    pub role: String,
    /// Optional human-readable tenant name for the invitation email.
    #[garde(inner(length(min = 1, max = 128)))]
    pub tenant_name: Option<String>,
}

/// `POST /auth/email/change` body (authenticated).
///
/// The account is never named here — it comes from the caller's own claims. A body that could
/// name a user id would let anyone holding any session move any account's recovery address.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeEmailDto {
    /// The address to move to.
    #[garde(email, length(max = 255))]
    pub new_email: String,
    /// The account's current password, re-proved because the address is the recovery
    /// credential. Bounded at 128 to match the hasher's input limit — an unbounded field is a
    /// cheap way to make someone else pay for a key derivation.
    #[garde(length(min = 1, max = 128))]
    pub current_password: String,
}

/// `POST /auth/email/change/confirm` body (public).
///
/// The token is the whole payload: it already names the account, the target address and the
/// tenant, all fixed when it was minted. Accepting any of those from the body would let the
/// holder of one link redirect it at a different account.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmEmailChangeDto {
    /// The single-use token mailed to the new address — exactly 64 hex characters.
    #[garde(length(min = 64, max = 64))]
    pub token: String,
}

/// `POST /auth/invitations/revoke` body (authenticated).
///
/// The address is the entire payload because it is the only handle the issuing side has: the
/// invitation record is keyed by the hash of a token only the invitee's mailbox ever held.
/// `tenant_id` is absent for the same reason it is absent from [`CreateInvitationDto`] — it
/// comes from the caller's claims, never the body.
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeInvitationDto {
    /// The invited address whose pending invitation is being withdrawn.
    #[garde(email, length(max = 255))]
    pub email: String,
}

/// `POST /auth/invitations/accept` body (public).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptInvitationDto {
    /// The single-use invitation token — exactly 64 hex characters.
    #[garde(length(min = 64, max = 64))]
    pub token: String,
    /// The new user's display name (2–100 chars).
    #[garde(length(min = 2, max = 100))]
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
    ///
    /// Bounded like every other free-text field: the value is hashed before it is looked up,
    /// so an oversized one buys nothing but the bytes it costs to carry and log.
    #[garde(inner(length(min = 1, max = 2048)))]
    pub refresh_token: Option<String>,
}

/// `GET /auth/oauth/{provider}` query (§11.3.1).
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthInitiateQuery {
    /// The tenant the user will join on success — a REQUEST for one, not a decision.
    ///
    /// `oauth_initiate` resolves it through the configured `TenantIdResolver` before anything
    /// is minted, and the RESOLVED value is what goes into the single-use Redis state and is
    /// recovered on callback. This field previously went in verbatim, on the rationale that
    /// "the `on_oauth_login` hook enforces tenant membership" — which did not hold: the hook
    /// is handed the same value through its `HookContext`, so a hook deciding on the profile
    /// alone admitted a caller into any tenant they named, on the one flow that decides which
    /// tenant an account is PROVISIONED into.
    ///
    /// Optional for the same reason the body DTOs' is: a resolver makes it dead weight, and
    /// with no resolver its absence is refused rather than defaulted.
    #[garde(
        inner(length(min = 1, max = 128)),
        inner(custom(no_control_characters))
    )]
    pub tenant_id: Option<String>,
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
    // The five below are accepted and unused, but still bounded — at the same ceilings
    // nest-auth's DTO carries. A field nothing reads is still a field an unauthenticated
    // caller fills, and the callback is a public route: unbounded, they are free bytes to
    // carry, parse and log.
    /// RFC 9207 issuer (accepted, unused).
    #[garde(inner(length(max = 512)))]
    pub iss: Option<String>,
    /// RFC 6749 scope echo (accepted, unused).
    #[garde(inner(length(max = 2048)))]
    pub scope: Option<String>,
    /// Google `authuser` (accepted, unused).
    #[garde(inner(length(max = 16)))]
    pub authuser: Option<String>,
    /// Google `prompt` (accepted, unused).
    #[garde(inner(length(max = 64)))]
    pub prompt: Option<String>,
    /// Google `hd` hosted-domain hint (accepted, unused) — bounded at the DNS name limit.
    #[garde(inner(length(max = 253)))]
    pub hd: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read `requestFieldBounds.{name}` from the shared cross-implementation wire contract.
    ///
    /// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
    /// can serve the same clients. Reading it here rather than repeating its numbers means a
    /// bound that moves on one side turns that side red, instead of surfacing as a request one
    /// backend accepts and the other refuses.
    fn contract_bound(name: &str) -> (Option<usize>, usize) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        let field = root
            .get("requestFieldBounds")
            .and_then(|s| s.get(name))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let read = |key: &str| {
            field
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
        };
        // The max comes back as a plain `usize`, with 0 standing for "the contract names none".
        // An `Option` would need unwrapping at every call, and the unwrap's `None` arm is dead
        // the moment the contract is complete — a branch no run reaches, which is the shape a
        // 100% gate is right to refuse. A zero is asserted instead, in one place.
        (read("min"), read("max").unwrap_or(0))
    }

    /// A well-formed address of exactly `n` characters.
    fn address(n: usize) -> String {
        format!("{}@e.com", "a".repeat(n.saturating_sub(6).max(1)))
    }

    /// Whether the DTO built by `build` from a field of exactly `n` characters validates.
    ///
    /// Takes an already-erased `&dyn Fn` rather than a generic `impl Fn`: a generic is
    /// instantiated once per DTO, and every instantiation is a separate function to the
    /// coverage instrumentation. One erased helper is one function, exercised by every entry
    /// in the table below.
    fn accepts(
        build: &dyn Fn(String) -> Result<(), garde::Report>,
        filler: char,
        n: usize,
    ) -> bool {
        build(std::iter::repeat_n(filler, n).collect::<String>()).is_ok()
    }

    /// Assert a field enforces the contract's bound at both edges.
    fn assert_bounded(
        name: &str,
        filler: char,
        build: &dyn Fn(String) -> Result<(), garde::Report>,
    ) {
        let (min, max) = contract_bound(name);
        // The contract is required to name a ceiling for every field listed here; a missing
        // one is a red test, not a silent skip.
        assert!(max > 0, "the contract names no max for {name}");
        assert!(
            accepts(build, filler, max),
            "{name} refused its own maximum"
        );
        assert!(
            !accepts(build, filler, max + 1),
            "{name} accepted a value past the contract maximum"
        );
        if let Some(min) = min
            && min > 1
        {
            assert!(
                !accepts(build, filler, min - 1),
                "{name} accepted a value below the contract minimum"
            );
        }
    }

    #[test]
    fn every_shared_field_enforces_the_contract_bound() {
        // These decide which requests each backend accepts. An unbounded field on a public
        // route is a free byte sink to carry, parse and log; a bound that differs between the
        // two means the same request is taken by one backend and refused by the other, which
        // for a deployment running both behind one address nobody can explain from the outside.
        assert_bounded("newPassword", 'a', &|password| {
            RegisterDto {
                email: "a@e.com".to_owned(),
                password,
                name: "Ok".to_owned(),
                tenant_id: Some("t1".to_owned()),
            }
            .validate()
        });
        assert_bounded("provenPassword", 'a', &|password| {
            LoginDto {
                email: "a@e.com".to_owned(),
                password,
                tenant_id: Some("t1".to_owned()),
            }
            .validate()
        });
        assert_bounded("tenantId", 'a', &|tenant_id| {
            LoginDto {
                email: "a@e.com".to_owned(),
                password: "hunter2hunter2".to_owned(),
                tenant_id: Some(tenant_id),
            }
            .validate()
        });
        assert_bounded("displayName", 'a', &|name| {
            RegisterDto {
                email: "a@e.com".to_owned(),
                password: "hunter2hunter2".to_owned(),
                name,
                tenant_id: Some("t1".to_owned()),
            }
            .validate()
        });
        assert_bounded("invitationDisplayName", 'a', &|name| {
            AcceptInvitationDto {
                token: "a".repeat(64),
                name,
                password: "hunter2hunter2".to_owned(),
            }
            .validate()
        });
        assert_bounded("singleUseToken", 'a', &|token| {
            AcceptInvitationDto {
                token,
                name: "Ok".to_owned(),
                password: "hunter2hunter2".to_owned(),
            }
            .validate()
        });
        assert_bounded("verificationOtp", '1', &|otp| {
            VerifyEmailDto {
                email: "a@e.com".to_owned(),
                otp,
                tenant_id: Some("t1".to_owned()),
            }
            .validate()
        });
        assert_bounded("resetOtp", '1', &|otp| {
            VerifyOtpDto {
                email: "a@e.com".to_owned(),
                otp,
                tenant_id: Some("t1".to_owned()),
            }
            .validate()
        });
        assert_bounded("totpCode", '1', &|code| MfaVerifyDto { code }.validate());
    }

    #[test]
    fn an_oversized_address_is_refused_at_the_contract_ceiling() {
        // Only the upper edge, and only from above: `garde(email)` already refuses an address
        // near that length on its own grounds (the domain-label limits), so "accepted at
        // exactly 255" is not a property this DTO has. The half that matters is that an
        // oversized value never reaches the lookup.
        let (_, max) = contract_bound("email");
        assert!(max > 0, "the contract names no max for email");
        let over = LoginDto {
            email: address(max + 1),
            password: "hunter2hunter2".to_owned(),
            tenant_id: Some("t1".to_owned()),
        };
        assert!(
            over.validate().is_err(),
            "an oversized address was accepted"
        );
    }

    /// `tenant_id` carrying a control character must be refused at the boundary.
    ///
    /// It is the widest attacker-controlled field on this surface — it arrives in the body of
    /// five public routes and is the caller's own value whenever no `TenantIdResolver` is
    /// configured, which is the default — and it reaches a `tracing` event, a Redis key segment
    /// and an HMAC preimage. A newline in it forges a record on a plain-text subscriber
    /// (ASVS 16.4.1), and a length bound alone does not cover that.
    ///
    /// nest-auth has always rejected these, so this is also a wire divergence: without it the
    /// same request is a 400 on one backend and a 200 on the other, which is precisely what
    /// `requestFieldBounds` exists to prevent.
    #[test]
    fn a_tenant_id_with_a_control_character_is_refused() {
        for bad in [
            "acme\nINFO login: success user_id=victim",
            "acme\r\nforged",
            "acme\u{0}truncated",
            "acme\u{7f}del",
            "acme\u{1b}[31mescape",
            "acme\u{85}c1-next-line",
        ] {
            let dto = LoginDto {
                email: "user@example.com".to_owned(),
                password: "hunter2hunter2".to_owned(),
                tenant_id: Some(bad.to_owned()),
            };
            assert!(
                dto.validate().is_err(),
                "a tenant_id carrying a control character was accepted: {bad:?}"
            );
        }
    }

    /// …and an ordinary tenant id is still accepted, or the check above would be satisfied by a
    /// validator that refuses everything.
    #[test]
    fn an_ordinary_tenant_id_is_accepted() {
        for good in [
            "acme",
            "acme-corp",
            "tenant_42",
            "ACME.Corp",
            "empresa-são-paulo",
        ] {
            let dto = LoginDto {
                email: "user@example.com".to_owned(),
                password: "hunter2hunter2".to_owned(),
                tenant_id: Some(good.to_owned()),
            };
            assert!(
                dto.validate().is_ok(),
                "a legitimate tenant_id was refused: {good:?}"
            );
        }
    }
}
