//! The lifecycle-hook extension point. [`AuthHooks`] is a single object-safe trait whose
//! methods all carry default no-op bodies, so a consumer overrides only the events it
//! cares about. The engine holds the implementation as `Arc<dyn AuthHooks>`.
//!
//! # Blocking vs. fire-and-forget
//!
//! Only three hooks can change an outcome: [`AuthHooks::before_register`] (returns a
//! [`BeforeRegisterResult`] that may reject or override field defaults),
//! [`AuthHooks::before_login`] (blocks by returning `Err`), and
//! [`AuthHooks::on_oauth_login`] (returns an [`OAuthLoginResult`] selecting create / link
//! / reject). Every other hook is **fire-and-forget** under the engine's invocation
//! contract: it is run detached and time-bounded, with any error, timeout, or panic
//! swallowed and logged via `tracing`, so a slow or failing notification can never stall —
//! or roll back — the user-facing operation. (The flows that invoke hooks honor this
//! contract; the trait itself only defines the surface.)
//!
//! Every hook receives a [`SafeAuthUser`] (never the credential-bearing `AuthUser`) plus a
//! [`HookContext`], so secret fields can never leak into analytics, audit, or CRM code.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bymax_auth_types::SafeAuthUser;

use crate::context::RequestContext;
use crate::traits::email::SessionInfo;
use crate::traits::oauth::OAuthProfile;

/// The minimal, sanitized request context passed to every hook.
#[derive(Clone, Debug)]
pub struct HookContext {
    /// Internal user id, present once the user is identified.
    pub user_id: Option<String>,
    /// User email, present once identified.
    pub email: Option<String>,
    /// Tenant id, present in multi-tenant flows.
    pub tenant_id: Option<String>,
    /// Originating IP. Comes from a trusted-proxy configuration — never raw
    /// `X-Forwarded-For`, or brute-force protection and alerting can be spoofed.
    pub ip: String,
    /// Raw `User-Agent` value.
    pub user_agent: String,
    /// Headers pre-sanitized by the engine (sensitive entries removed, keys lowercased). A
    /// `BTreeMap` preserves the deterministic ordering of [`RequestContext`], so a hook can
    /// derive a reproducible audit key or signature from it. Safe to log or persist.
    pub sanitized_headers: BTreeMap<String, String>,
}

impl HookContext {
    /// Build a hook context from a [`RequestContext`] plus the identity fields known at
    /// the call site. The sanitized headers are copied across from the request context.
    #[must_use]
    pub fn from_request(
        ctx: &RequestContext,
        user_id: Option<String>,
        email: Option<String>,
        tenant_id: Option<String>,
    ) -> Self {
        Self {
            user_id,
            email,
            tenant_id,
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
            sanitized_headers: ctx
                .sanitized_headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

/// The registration payload visible to [`AuthHooks::before_register`].
#[derive(Clone, Debug)]
pub struct RegisterAttempt {
    /// The email being registered.
    pub email: String,
    /// The display name.
    pub name: String,
    /// The tenant scope.
    pub tenant_id: String,
}

/// Field overrides applied to a new user before persistence. Only `Some` fields change
/// the defaults; `None` leaves the default in place.
#[derive(Clone, Debug, Default)]
pub struct RegisterOverrides {
    /// Override the default role.
    pub role: Option<String>,
    /// Override the default status.
    pub status: Option<String>,
    /// Override the default `email_verified` flag.
    pub email_verified: Option<bool>,
}

/// The outcome of [`AuthHooks::before_register`].
#[derive(Clone, Debug)]
pub enum BeforeRegisterResult {
    /// Proceed, applying the (possibly empty) field overrides.
    Allow(RegisterOverrides),
    /// Abort. `reason` may be surfaced to the client, so it must not leak sensitive
    /// detail.
    Reject {
        /// An optional client-safe reason.
        reason: Option<String>,
    },
}

/// The outcome of [`AuthHooks::on_oauth_login`].
#[derive(Clone, Debug)]
pub enum OAuthLoginResult {
    /// Provision a new account from the OAuth profile.
    Create,
    /// Link the OAuth identity to the existing account.
    Link,
    /// Deny the login. `reason` may be surfaced to the client.
    Reject {
        /// An optional client-safe reason.
        reason: Option<String>,
    },
}

/// A hook failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HookError {
    /// The hook deliberately blocks the operation (blocking/decision hooks only).
    #[error("hook rejected the operation: {0}")]
    Rejected(String),
    /// An unexpected failure inside the hook implementation.
    #[error("hook failed")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The lifecycle-hook contract. Every method has a default body, so a consumer implements
/// only the relevant subset. Held on the engine as `Arc<dyn AuthHooks>`.
///
/// # Errors
///
/// The blocking/decision hooks ([`AuthHooks::before_register`],
/// [`AuthHooks::before_login`], [`AuthHooks::on_oauth_login`]) propagate [`HookError`] to
/// abort the operation. The fire-and-forget hooks also return `Result` for ergonomics,
/// but the engine logs and drops any error — it never reaches the client.
#[async_trait]
pub trait AuthHooks: Send + Sync {
    // ---- Blocking / decision hooks ---------------------------------------

    /// Called BEFORE a new user is persisted — the only hook that can reject or modify
    /// registration. Returns `Reject { reason }` to deny, or `Allow` with optional
    /// role/status/`email_verified` overrides.
    async fn before_register(
        &self,
        data: &RegisterAttempt,
        ctx: &HookContext,
    ) -> Result<BeforeRegisterResult, HookError> {
        let _ = (data, ctx);
        Ok(BeforeRegisterResult::Allow(RegisterOverrides::default()))
    }

    /// Called BEFORE credentials are validated on login. To block, return `Err`; returning
    /// `Ok(())` lets login proceed.
    async fn before_login(
        &self,
        email: &str,
        tenant_id: &str,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (email, tenant_id, ctx);
        Ok(())
    }

    /// Called when an OAuth profile has arrived. Decides account resolution: `Create` a
    /// new user, `Link` to `existing_user`, or `Reject`.
    ///
    /// The default is a **secure deny**: OAuth sign-in stays disabled until the deployer
    /// implements this hook (the mandatory create/link/tenant-membership decision).
    async fn on_oauth_login(
        &self,
        profile: &OAuthProfile,
        existing_user: Option<&SafeAuthUser>,
        ctx: &HookContext,
    ) -> Result<OAuthLoginResult, HookError> {
        let _ = (profile, existing_user, ctx);
        Ok(OAuthLoginResult::Reject {
            reason: Some("OAuth login not configured".into()),
        })
    }

    // ---- Fire-and-forget notifications (errors logged, never propagated) ----

    /// Called after a new user is persisted.
    async fn after_register(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after a successful login.
    async fn after_login(&self, user: &SafeAuthUser, ctx: &HookContext) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after a logout.
    async fn after_logout(&self, user_id: &str, ctx: &HookContext) -> Result<(), HookError> {
        let _ = (user_id, ctx);
        Ok(())
    }

    /// Called after an email is verified.
    async fn after_email_verified(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after a password reset completes.
    async fn after_password_reset(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after MFA is enabled.
    async fn after_mfa_enabled(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after MFA is disabled.
    async fn after_mfa_disabled(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after recovery codes are regenerated. The plaintext codes are NOT passed
    /// here — they go only to the requesting client.
    async fn after_mfa_recovery_codes_regenerated(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called after an invitation is accepted.
    async fn after_invitation_accepted(
        &self,
        user: &SafeAuthUser,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, ctx);
        Ok(())
    }

    /// Called when a login originates from a new device/location.
    async fn on_new_session(
        &self,
        user: &SafeAuthUser,
        session: &SessionInfo,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user, session, ctx);
        Ok(())
    }

    /// Called when the session manager evicts a session to make room for a new one (FIFO).
    /// `evicted_session_hash` is the stored hash, never the raw token.
    async fn on_session_evicted(
        &self,
        user_id: &str,
        evicted_session_hash: &str,
        ctx: &HookContext,
    ) -> Result<(), HookError> {
        let _ = (user_id, evicted_session_hash, ctx);
        Ok(())
    }
}

/// The default hooks installed when the consumer supplies none. Every method uses the
/// trait default: the `before_*` hooks are permissive, `on_oauth_login` is a secure
/// **deny** (OAuth stays disabled until the deployer implements it), and all
/// notifications are pure no-ops.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpAuthHooks;

#[async_trait]
impl AuthHooks for NoOpAuthHooks {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use time::OffsetDateTime;

    fn ctx() -> HookContext {
        HookContext {
            user_id: Some("u1".into()),
            email: Some("e@x.io".into()),
            tenant_id: Some("t1".into()),
            ip: "203.0.113.4".into(),
            user_agent: "agent/1.0".into(),
            sanitized_headers: BTreeMap::new(),
        }
    }

    fn safe_user() -> SafeAuthUser {
        SafeAuthUser {
            id: "u1".into(),
            email: "e@x.io".into(),
            name: "E".into(),
            role: "MEMBER".into(),
            status: "ACTIVE".into(),
            tenant_id: "t1".into(),
            email_verified: true,
            mfa_enabled: false,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn profile() -> OAuthProfile {
        OAuthProfile {
            provider: "google".into(),
            provider_id: "google-1".into(),
            email: "e@x.io".into(),
            name: Some("E".into()),
            avatar: None,
        }
    }

    fn session() -> SessionInfo {
        SessionInfo {
            device: "Chrome".into(),
            ip: "203.0.113.4".into(),
            session_hash: "deadbeef".into(),
        }
    }

    #[tokio::test]
    async fn noop_decision_defaults_are_permissive_except_oauth_deny() {
        // The two `before_*` defaults allow; `on_oauth_login` defaults to a secure deny so
        // OAuth sign-in cannot silently create or link accounts.
        let hooks: Arc<dyn AuthHooks> = Arc::new(NoOpAuthHooks);
        let attempt = RegisterAttempt {
            email: "e@x.io".into(),
            name: "E".into(),
            tenant_id: "t1".into(),
        };
        assert!(matches!(
            hooks.before_register(&attempt, &ctx()).await,
            Ok(BeforeRegisterResult::Allow(_))
        ));
        assert!(hooks.before_login("e@x.io", "t1", &ctx()).await.is_ok());
        let user = safe_user();
        assert!(matches!(
            hooks.on_oauth_login(&profile(), Some(&user), &ctx()).await,
            Ok(OAuthLoginResult::Reject { .. })
        ));
    }

    #[tokio::test]
    async fn noop_fire_and_forget_defaults_all_succeed() {
        // Every notification hook must be a no-op success on the default impl; this covers
        // all eleven default bodies.
        let hooks = NoOpAuthHooks;
        let user = safe_user();
        let c = ctx();
        assert!(hooks.after_register(&user, &c).await.is_ok());
        assert!(hooks.after_login(&user, &c).await.is_ok());
        assert!(hooks.after_logout("u1", &c).await.is_ok());
        assert!(hooks.after_email_verified(&user, &c).await.is_ok());
        assert!(hooks.after_password_reset(&user, &c).await.is_ok());
        assert!(hooks.after_mfa_enabled(&user, &c).await.is_ok());
        assert!(hooks.after_mfa_disabled(&user, &c).await.is_ok());
        assert!(
            hooks
                .after_mfa_recovery_codes_regenerated(&user, &c)
                .await
                .is_ok()
        );
        assert!(hooks.after_invitation_accepted(&user, &c).await.is_ok());
        assert!(hooks.on_new_session(&user, &session(), &c).await.is_ok());
        assert!(hooks.on_session_evicted("u1", "hash", &c).await.is_ok());
    }

    #[test]
    fn hook_context_from_request_copies_headers_and_identity() {
        // The bridge carries the sanitized headers across and stamps the identity fields
        // the call site supplies.
        let mut headers = BTreeMap::new();
        headers.insert("x-trace".to_string(), "abc".to_string());
        let req = RequestContext::new("203.0.113.4", "agent/1.0", headers);
        let hctx = HookContext::from_request(
            &req,
            Some("u1".into()),
            Some("e@x.io".into()),
            Some("t1".into()),
        );
        assert_eq!(hctx.user_id.as_deref(), Some("u1"));
        assert_eq!(hctx.email.as_deref(), Some("e@x.io"));
        assert_eq!(hctx.tenant_id.as_deref(), Some("t1"));
        assert_eq!(hctx.ip, "203.0.113.4");
        assert_eq!(hctx.user_agent, "agent/1.0");
        assert_eq!(
            hctx.sanitized_headers.get("x-trace").map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn hook_error_and_result_constructors_are_usable() {
        // The decision result and error types are part of the public surface; exercise
        // their construction and Display.
        let overrides = RegisterOverrides {
            role: Some("MEMBER".into()),
            status: Some("ACTIVE".into()),
            email_verified: Some(true),
        };
        assert!(matches!(
            BeforeRegisterResult::Allow(overrides),
            BeforeRegisterResult::Allow(_)
        ));
        assert!(matches!(
            BeforeRegisterResult::Reject {
                reason: Some("no seats".into())
            },
            BeforeRegisterResult::Reject { .. }
        ));
        assert!(matches!(OAuthLoginResult::Create, OAuthLoginResult::Create));
        assert!(matches!(OAuthLoginResult::Link, OAuthLoginResult::Link));
        assert_eq!(
            HookError::Rejected("blocked".into()).to_string(),
            "hook rejected the operation: blocked"
        );
        let internal = HookError::Internal("boom".into());
        assert_eq!(internal.to_string(), "hook failed");
    }
}
