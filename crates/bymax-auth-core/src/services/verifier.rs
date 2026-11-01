//! Verifying an access token in one call (layer: engine surface for any transport).
//!
//! The HTTP extractors compose the building blocks themselves. A consumer that authenticates
//! outside them (a WebSocket upgrade, an SSE stream, a gRPC interceptor, a background consumer)
//! would otherwise re-assemble the chain by hand and, as a rule, omit one link: the revocation
//! read, the account-status re-check, or the second-factor policy. [`AuthEngine::verify_access`]
//! runs the whole chain in a fixed order and answers with the same codes the HTTP surface does.

#[cfg(feature = "platform")]
use bymax_auth_types::PlatformClaims;
use bymax_auth_types::{AuthError, DashboardClaims};

use crate::context::RequestContext;
use crate::engine::AuthEngine;

/// The authentication plane a token is verified against.
///
/// Always named by the caller and never inferred from the token: inferring it would let a token
/// pick the (cross-tenant) platform path for a connection the caller meant to scope to a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlane {
    /// Tenant-scoped dashboard users.
    Dashboard,
    /// Cross-tenant platform administrators, whose tokens carry no tenant.
    #[cfg(feature = "platform")]
    Platform,
}

/// What [`AuthEngine::verify_access`] checks beyond the signature.
///
/// Both opt-outs default to checking. They exist to be turned off by a caller that has already
/// established the same fact by another route, never to make a reconnect cheaper.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct VerifyAccessOptions<'a> {
    /// The plane the caller expects.
    pub plane: AuthPlane,
    /// Refuse a token whose account has MFA enabled but which was not issued after a successful
    /// challenge. Defaults to `true`.
    pub require_mfa: bool,
    /// Re-resolve the account's lifecycle status instead of trusting the token's snapshot,
    /// refusing a blocked, deleted or (dashboard plane, where the deployment requires it)
    /// unverified account. Defaults to `true`.
    pub check_status: bool,
    /// The request the credential arrived on, so `enforce_tenant_binding` can be applied.
    ///
    /// The binding needs the request the tenant resolver reads, which a token does not carry.
    /// Omit it and the binding is **not** applied to that call; with the flag on, that is logged
    /// once. The platform plane has no tenant and ignores it.
    pub request: Option<&'a RequestContext>,
}

impl<'a> VerifyAccessOptions<'a> {
    /// Options for `plane`, with every check on and no request.
    #[must_use]
    pub const fn new(plane: AuthPlane) -> Self {
        Self {
            plane,
            require_mfa: true,
            check_status: true,
            request: None,
        }
    }

    /// Apply or waive the second-factor policy.
    #[must_use]
    pub const fn require_mfa(mut self, require: bool) -> Self {
        self.require_mfa = require;
        self
    }

    /// Re-resolve, or trust the token's snapshot of, the account status.
    #[must_use]
    pub const fn check_status(mut self, check: bool) -> Self {
        self.check_status = check;
        self
    }

    /// Supply the request the token arrived on so the tenant binding can be applied.
    #[must_use]
    pub const fn request(mut self, request: &'a RequestContext) -> Self {
        self.request = Some(request);
        self
    }
}

/// A verified access token, tagged with the plane it was checked against.
#[derive(Debug, Clone)]
pub enum VerifiedAccessToken {
    /// A dashboard token's claims.
    Dashboard(DashboardClaims),
    /// A platform token's claims.
    #[cfg(feature = "platform")]
    Platform(PlatformClaims),
}

/// The longest `sub` or `tenant_id` accepted from a token.
const MAX_SUBJECT_LEN: usize = 256;

/// Whether `value` is a canonical UUID version 4 (any letter case).
fn is_uuid_v4(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    groups.len() == 5
        && groups
            .iter()
            .zip(lens)
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
        && groups[2].starts_with('4')
        && groups[3]
            .bytes()
            .next()
            .is_some_and(|b| matches!(b.to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b'))
}

/// Whether `value` is a usable subject or tenant id: non-empty and bounded, because both feed
/// keys built further down.
fn is_bounded_id(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= MAX_SUBJECT_LEN
}

/// Whether a verified dashboard token's identifying claims are well formed.
fn dashboard_shape_ok(claims: &DashboardClaims) -> bool {
    is_uuid_v4(&claims.jti) && is_bounded_id(&claims.sub) && is_bounded_id(&claims.tenant_id)
}

/// Collapse every way a token can be refused onto the one opaque answer, keeping the account
/// and store outcomes the caller must be able to tell apart.
fn collapse(error: AuthError) -> AuthError {
    match error {
        AuthError::TokenExpired | AuthError::TokenRevoked => AuthError::TokenInvalid,
        other => other,
    }
}

impl AuthEngine {
    /// Verify an access token end to end and return its claims tagged with the plane.
    ///
    /// The chain, in order: signature (with key rotation and the `iss`/`aud` binding) and
    /// expiry; the token type of the named plane; both revocation channels; claim shape (`jti`
    /// is a UUID v4, `sub` and the tenant are bounded); the tenant binding (dashboard, when a
    /// request is supplied); the account's current status; then the second-factor policy. The
    /// status is judged **before** the second factor, so a blocked or deleted account is told
    /// that rather than asked for a challenge it could not use.
    ///
    /// The dashboard status comes from the shared status cache when one holds it, so a change
    /// reaches it within `user_status_cache_ttl` or at once after
    /// [`AuthEngine::invalidate_account_status`]; the platform plane reads its repository on every
    /// call.
    ///
    /// # Errors
    ///
    /// [`AuthError::TokenInvalid`] when the signature, expiry, claim shape, token type,
    /// revocation state or tenant binding refuses the token (one opaque answer);
    /// [`AuthError::PlatformAuthRequired`] when a dashboard token is presented on the platform
    /// plane; the matching `Account*`/[`AuthError::EmailNotVerified`] code when the account is no
    /// longer usable; [`AuthError::MfaRequired`] when the account is usable, has MFA enabled and
    /// this token predates its challenge; a store [`AuthError`] when a lookup fails.
    pub async fn verify_access(
        &self,
        token: &str,
        options: &VerifyAccessOptions<'_>,
    ) -> Result<VerifiedAccessToken, AuthError> {
        match options.plane {
            AuthPlane::Dashboard => self
                .verify_dashboard_plane(token, options)
                .await
                .map(VerifiedAccessToken::Dashboard),
            #[cfg(feature = "platform")]
            AuthPlane::Platform => self
                .verify_platform_plane(token, options)
                .await
                .map(VerifiedAccessToken::Platform),
        }
    }

    /// The dashboard arm: the full chain plus the tenant claim and the tenant-scoped gate.
    async fn verify_dashboard_plane(
        &self,
        token: &str,
        options: &VerifyAccessOptions<'_>,
    ) -> Result<DashboardClaims, AuthError> {
        let claims = self.verify_access_token(token).await.map_err(collapse)?;
        if !dashboard_shape_ok(&claims) {
            return Err(AuthError::TokenInvalid);
        }
        self.bind_to_request(&claims.tenant_id, options.request)
            .await?;
        if options.check_status {
            self.assert_user_active_and_verified(&claims.sub, &claims.tenant_id)
                .await?;
        }
        if options.require_mfa && claims.mfa_enabled && !claims.mfa_verified {
            return Err(AuthError::MfaRequired);
        }
        Ok(claims)
    }

    /// The platform arm. No tenant exists to bind or scope by: an administrator is cross-tenant.
    #[cfg(feature = "platform")]
    async fn verify_platform_plane(
        &self,
        token: &str,
        options: &VerifyAccessOptions<'_>,
    ) -> Result<PlatformClaims, AuthError> {
        let claims = match self.verify_platform_token(token).await {
            Ok(claims) => claims,
            Err(error) => return Err(self.explain_platform_refusal(token, error).await),
        };
        if !is_uuid_v4(&claims.jti) || !is_bounded_id(&claims.sub) {
            return Err(AuthError::TokenInvalid);
        }
        if options.check_status {
            self.assert_platform_active(&claims.sub).await?;
        }
        if options.require_mfa && claims.mfa_enabled && !claims.mfa_verified {
            return Err(AuthError::MfaRequired);
        }
        Ok(claims)
    }

    /// Why a platform-plane verification failed: a validly signed **dashboard** token answers
    /// `PlatformAuthRequired`, so a caller can tell "the other context's token" from "a malformed
    /// one"; everything else collapses to the opaque answer.
    #[cfg(feature = "platform")]
    async fn explain_platform_refusal(&self, token: &str, error: AuthError) -> AuthError {
        if !matches!(error, AuthError::TokenInvalid) {
            return collapse(error);
        }
        match self.verify_access_token(token).await {
            // A malformed token is malformed on either plane, so shape is judged before the type.
            Ok(claims) if dashboard_shape_ok(&claims) => AuthError::PlatformAuthRequired,
            Err(AuthError::TokenRevoked) => AuthError::PlatformAuthRequired,
            _ => AuthError::TokenInvalid,
        }
    }

    /// Assert the platform administrator `admin_id` exists and is not in a blocked status.
    ///
    /// A deployment with no platform repository mints no platform token, so a token reaching this
    /// check cannot have been issued here: it is refused, never waved through. There is no
    /// email-verification arm, because administrators are provisioned rather than self-registered.
    ///
    /// # Errors
    ///
    /// [`AuthError::TokenInvalid`] when no platform repository is registered or no such
    /// administrator exists; the matching `Account*` code when the status is blocked; a store
    /// [`AuthError`] when the lookup fails.
    #[cfg(feature = "platform")]
    pub async fn assert_platform_active(&self, admin_id: &str) -> Result<(), AuthError> {
        let Some(repository) = self.platform_user_repository() else {
            return Err(AuthError::TokenInvalid);
        };
        let admin = repository
            .find_by_id(admin_id)
            .await
            .map_err(crate::services::auth::map_repository_error)?
            .ok_or(AuthError::TokenInvalid)?;
        crate::status_gate::assert_not_blocked(
            &admin.status,
            &self.config().config().blocked_statuses,
        )
    }

    /// Apply `enforce_tenant_binding` when a request was supplied, and say once when it could not.
    ///
    /// Every resolver failure is [`AuthError::TokenInvalid`] on this surface: the caller has a
    /// credential, not a request it can retry against another host.
    async fn bind_to_request(
        &self,
        tenant_id: &str,
        request: Option<&RequestContext>,
    ) -> Result<(), AuthError> {
        if let Some(request) = request {
            return self
                .assert_tenant_binding(tenant_id, request)
                .await
                .map_err(|_| AuthError::TokenInvalid);
        }
        if self.config().config().enforce_tenant_binding {
            warn_unbound_once(&UNBOUND_WARNED);
        }
        Ok(())
    }
}

/// Whether the "binding not applied" warning has been logged by this process.
static UNBOUND_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Log that a verification ran without the request its tenant binding needs, the first time only.
fn warn_unbound_once(flag: &std::sync::atomic::AtomicBool) {
    if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "verify_access: enforce_tenant_binding is on but no request was supplied, so the \
             tenant binding is not applied to this call"
        );
    }
}

#[cfg(test)]
mod tests {
    mod dashboard_tests;
    #[cfg(feature = "platform")]
    mod platform_tests;
    mod shape_tests;
}
