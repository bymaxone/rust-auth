//! What an MFA event is reported to the consumer's hooks as (layer: engine service).
//!
//! Hooks receive a credential-free [`SafeAuthUser`] and a [`HookContext`]. A platform
//! administrator is not a tenant user, so the projection and the context are built here once,
//! with the plane stated explicitly rather than left for the consumer to infer from an empty
//! tenant.

use std::collections::BTreeMap;

use bymax_auth_types::{AuthPlatformUser, SafeAuthUser};

use crate::services::mfa::MfaService;
use crate::traits::{HookContext, HookPlane};

impl MfaService {
    /// Build the sanitized hook context for an MFA operation from the identity already proven by
    /// the access token or temp token, plus the request IP and user agent.
    pub(super) fn hook_context(
        &self,
        plane: HookPlane,
        user_id: &str,
        email: &str,
        ip: &str,
        user_agent: &str,
    ) -> HookContext {
        HookContext {
            plane,
            user_id: Some(user_id.to_owned()),
            email: Some(email.to_owned()),
            tenant_id: None,
            ip: ip.to_owned(),
            user_agent: user_agent.to_owned(),
            sanitized_headers: BTreeMap::new(),
        }
    }
}

/// A platform administrator in the shape hooks receive.
///
/// The user type demands a tenant, and an administrator has none, so `tenant_id` is the empty
/// string; the plane on the accompanying [`HookContext`] is what tells a consumer which kind of
/// account this is. `email_verified` is `true`: administrators are provisioned rather than
/// self-registered, so there is no verification step they could still owe.
pub(super) fn platform_hook_user(admin: &AuthPlatformUser) -> SafeAuthUser {
    SafeAuthUser {
        id: admin.id.clone(),
        email: admin.email.clone(),
        name: admin.name.clone(),
        role: admin.role.clone(),
        status: admin.status.clone(),
        tenant_id: String::new(),
        email_verified: true,
        mfa_enabled: admin.mfa_enabled,
        oauth_provider: None,
        oauth_provider_id: None,
        last_login_at: admin.last_login_at,
        created_at: admin.created_at,
    }
}

/// The account as the transition left it, for the `after_mfa_*` hooks.
///
/// These hooks fire after the second factor was written, but the view they are built from was
/// read before the write, so its flag still holds the previous state. Only the flag is taken from
/// the transition; the rest is the credential-free projection unchanged, and the stored record is
/// not touched (this works on a copy).
pub(super) fn after_transition(user: &SafeAuthUser, mfa_enabled: bool) -> SafeAuthUser {
    SafeAuthUser {
        mfa_enabled,
        ..user.clone()
    }
}
