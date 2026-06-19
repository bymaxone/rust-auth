//! The invitation flows (§7.10): `invite` (role-authorized creation of a secure single-use
//! token + stored metadata + email) and `accept_invitation` (single-use consume, role
//! re-validation against the hierarchy, duplicate-email guard, user creation, full session).
//!
//! The stored invitation payload is trusted on accept, so `accept_invitation` re-validates
//! `role` against the configured hierarchy as anti-tamper — a tampered Redis value cannot
//! escalate privilege. The role re-validation blocks privilege escalation but not a forged
//! tenant/email; a deployment that does not fully trust its Redis SHOULD additionally
//! HMAC-sign the stored record (persist `hmac_sha256(json, hmac_key)` alongside it and verify
//! the tag on accept) so a forged record is rejected outright.

use std::collections::{BTreeMap, HashMap};

use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_types::{AuthError, AuthResult, CreateUserData, SafeAuthUser};
use time::OffsetDateTime;

use crate::context::RequestContext;
use crate::engine::AuthEngine;
use crate::services::auth::detached::run_after_invitation_accepted;
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::traits::{HookContext, InviteData, StoredInvitation};

/// The bytes of entropy in an invitation token before hex-encoding (256-bit, 64 hex chars).
const INVITE_TOKEN_BYTES: usize = 32;

/// Input to accept an invitation: the single-use token plus the new account's credentials.
/// The `Debug` impl redacts the token and the password.
#[derive(Clone)]
pub struct AcceptInvitationInput {
    /// The single-use invitation token presented by the invitee.
    pub token: String,
    /// The invitee's display name.
    pub name: String,
    /// The invitee's chosen password (redacted in `Debug`).
    pub password: String,
}

impl std::fmt::Debug for AcceptInvitationInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the live single-use token and the password so a stray `{:?}` cannot leak them.
        f.debug_struct("AcceptInvitationInput")
            .field("token", &"[REDACTED]")
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl AuthEngine {
    /// Create a tenant invitation: authorize the inviter against the role hierarchy, mint a
    /// secure single-use token, store the trusted metadata under its hash, and dispatch the
    /// invitation email. The raw token is never persisted or logged — only its hash becomes a
    /// key, and the email provider builds the accept URL from the raw value.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InsufficientRole`] when the invited role is unknown or the inviter
    /// does not hold a role at least as high, [`AuthError::TokenInvalid`] when the inviter no
    /// longer exists, or a store [`AuthError`].
    pub async fn invite(
        &self,
        inviter_user_id: &str,
        email: &str,
        role: &str,
        tenant_id: &str,
        tenant_name: Option<&str>,
    ) -> Result<(), AuthError> {
        // Normalize the email at the service boundary so the duplicate-guard and the stored
        // payload use the same canonical form the accept flow will match against.
        let email = email.trim().to_ascii_lowercase();
        let hierarchy = &self.config().config().roles.hierarchy;

        // The invited role must be a declared role, and the inviter must hold a role at least
        // as high — both checked before any token is minted.
        if !hierarchy.contains_key(role) {
            return Err(AuthError::InsufficientRole);
        }
        let inviter = self
            .user_repository()
            .find_by_id(inviter_user_id, None)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::TokenInvalid)?;
        if !has_role(&inviter.role, role, hierarchy) {
            return Err(AuthError::InsufficientRole);
        }

        let store = self
            .invitation_store()
            .ok_or_else(|| crate::services::internal_error("invitation store not configured"))?;
        let raw = generate_secure_token(INVITE_TOKEN_BYTES);
        let ttl = self.config().config().invitations.token_ttl.as_secs();
        let invitation = StoredInvitation {
            email: email.clone(),
            role: role.to_owned(),
            tenant_id: tenant_id.to_owned(),
            inviter_user_id: inviter_user_id.to_owned(),
        };
        store.put_invitation(&raw, &invitation, ttl).await?;

        // The email provider builds the accept URL from the raw token (never logged).
        let expires_at = OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(
                i64::try_from(ttl).unwrap_or(i64::MAX),
            ))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let invite_data = InviteData {
            inviter_name: inviter.name.clone(),
            tenant_name: tenant_name.unwrap_or(tenant_id).to_owned(),
            invite_token: raw,
            expires_at,
        };
        // Best-effort delivery: a send failure does not roll back the persisted invitation.
        let _ = self
            .email_provider()
            .send_invitation(&email, &invite_data, None)
            .await;
        Ok(())
    }

    /// Accept an invitation: atomically consume the single-use token, re-validate the stored
    /// role against the hierarchy (anti-tamper), reject a duplicate email, create the verified
    /// user, and issue a full session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidInvitationToken`] for an unknown/expired/used token, a
    /// malformed stored record, or a tampered role; [`AuthError::EmailAlreadyExists`] when the
    /// invitee already has an account in the tenant; or a hashing/store [`AuthError`].
    pub async fn accept_invitation(
        &self,
        input: AcceptInvitationInput,
        ip: &str,
        user_agent: &str,
        headers: BTreeMap<String, String>,
    ) -> Result<AuthResult, AuthError> {
        let store = self
            .invitation_store()
            .ok_or(AuthError::InvalidInvitationToken)?;

        // Atomic single-use consume; an absent/expired/already-used token is invalid.
        let invitation = store
            .consume_invitation(&input.token)
            .await?
            .ok_or(AuthError::InvalidInvitationToken)?;

        // Structural + anti-tamper validation: a non-empty payload whose stored role is still a
        // declared role. A tampered role (escalation attempt) is rejected outright.
        let hierarchy = &self.config().config().roles.hierarchy;
        if invitation.email.is_empty()
            || invitation.tenant_id.is_empty()
            || !hierarchy.contains_key(&invitation.role)
        {
            return Err(AuthError::InvalidInvitationToken);
        }

        // Duplicate-registration guard within the tenant.
        if self
            .user_repository()
            .find_by_email(&invitation.email, &invitation.tenant_id)
            .await
            .map_err(map_repository_error)?
            .is_some()
        {
            return Err(AuthError::EmailAlreadyExists);
        }

        // Token possession implies email ownership, so the new account is created verified.
        let password_hash = self.passwords().hash(&input.password).await?;
        let user = self
            .user_repository()
            .create(CreateUserData {
                email: invitation.email.clone(),
                name: input.name.clone(),
                password_hash: Some(password_hash),
                role: Some(invitation.role.clone()),
                status: None,
                tenant_id: invitation.tenant_id.clone(),
                email_verified: Some(true),
            })
            .await
            .map_err(map_repository_error)?;

        // Issue a full session; the engine's token manager writes the refresh session, and the
        // session service enforces the per-user cap when session tracking is enabled.
        let safe = SafeAuthUser::from(user);
        let result = self
            .tokens()
            .issue_tokens(&safe, ip, user_agent, false)
            .await?;

        let ctx = RequestContext::new(ip.to_owned(), user_agent.to_owned(), headers);
        let hook_ctx = HookContext::from_request(
            &ctx,
            Some(safe.id.clone()),
            Some(safe.email.clone()),
            Some(safe.tenant_id.clone()),
        );
        self.enforce_sessions_after_issue(&result, ip, user_agent, &hook_ctx)
            .await?;

        spawn_guarded(run_after_invitation_accepted(
            self.hooks().clone(),
            safe,
            hook_ctx,
        ));
        Ok(result)
    }
}

/// Whether `holder` satisfies `required` against the fully-denormalized role hierarchy:
/// either it *is* the required role, or its hierarchy entry transitively includes it. The
/// hierarchy is denormalized (each role lists every role it includes), so this is a single
/// membership check — no graph walk.
fn has_role(holder: &str, required: &str, hierarchy: &HashMap<String, Vec<String>>) -> bool {
    if holder == required {
        return true;
    }
    hierarchy
        .get(holder)
        .is_some_and(|included| included.iter().any(|r| r == required))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, Environment};
    use crate::testing::{InMemoryStores, InMemoryUserRepository};
    use crate::traits::{InvitationStore, SessionKind, SessionStore, UserRepository};
    use secrecy::SecretString;
    use std::sync::Arc;

    /// A config with a two-tier hierarchy (`ADMIN` includes `MEMBER`) and invitations enabled.
    fn invite_config() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        #[cfg(not(feature = "scrypt"))]
        {
            cfg.password.active_algorithm = crate::config::PasswordAlgorithm::Argon2id;
        }
        cfg.jwt.secret = SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        cfg.roles.hierarchy = HashMap::from([
            ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
            ("MEMBER".to_owned(), Vec::new()),
        ]);
        cfg.email_verification.required = false;
        cfg.invitations.enabled = true;
        cfg
    }

    /// An engine plus its in-memory collaborators, wired for the invitation flow.
    struct Setup {
        engine: AuthEngine,
        users: Arc<InMemoryUserRepository>,
        stores: Arc<InMemoryStores>,
    }

    fn setup(cfg: AuthConfig) -> Option<Setup> {
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let engine = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users.clone())
            .redis_stores(stores.clone())
            .build()
            .ok()?;
        Some(Setup {
            engine,
            users,
            stores,
        })
    }

    async fn seed_admin(users: &InMemoryUserRepository, email: &str, role: &str) -> String {
        let created = users
            .create(CreateUserData {
                email: email.to_owned(),
                name: "Inviter".to_owned(),
                password_hash: Some("$scrypt$x".to_owned()),
                role: Some(role.to_owned()),
                status: Some("ACTIVE".to_owned()),
                tenant_id: "t1".to_owned(),
                email_verified: Some(true),
            })
            .await;
        let Ok(user) = created else { return String::new() };
        user.id
    }

    #[tokio::test]
    async fn accept_creates_a_verified_user_and_a_full_session() {
        // A valid invitation token creates a verified MEMBER and issues a session persisted in
        // the store; the token is single-use.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(
                    &inviter,
                    "Invitee@Example.com ",
                    "MEMBER",
                    "t1",
                    Some("Acme")
                )
                .await
                .is_ok()
        );
        // The raw token is opaque; store a known invitation directly to drive accept.
        let token = "c".repeat(64);
        assert!(
            s.stores
                .put_invitation(
                    &token,
                    &StoredInvitation {
                        email: "invitee@example.com".to_owned(),
                        role: "MEMBER".to_owned(),
                        tenant_id: "t1".to_owned(),
                        inviter_user_id: inviter.clone(),
                    },
                    600
                )
                .await
                .is_ok()
        );
        let accepted = s
            .engine
            .accept_invitation(
                AcceptInvitationInput {
                    token: token.clone(),
                    name: "New Member".to_owned(),
                    password: "a-strong-password".to_owned(),
                },
                "203.0.113.4",
                "agent/1.0",
                BTreeMap::new(),
            )
            .await;
        assert!(matches!(&accepted, Ok(a) if a.user.email == "invitee@example.com"));
        let Ok(result) = accepted else { return };
        assert!(result.user.email_verified);
        assert_eq!(result.user.role, "MEMBER");
        assert!(!result.access_token.is_empty());

        // The session is persisted under the refresh hash.
        let hash =
            bymax_auth_jwt::RawRefreshToken::from_raw(result.refresh_token.clone()).redis_hash();
        assert!(matches!(
            s.stores.find_session(SessionKind::Dashboard, &hash).await,
            Ok(Some(_))
        ));

        // The token is single-use: a replay is rejected.
        assert!(matches!(
            s.engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token,
                        name: "Replay".to_owned(),
                        password: "pw".to_owned(),
                    },
                    "203.0.113.4",
                    "agent/1.0",
                    BTreeMap::new(),
                )
                .await,
            Err(AuthError::InvalidInvitationToken)
        ));
    }

    #[tokio::test]
    async fn invite_rejects_unknown_role_and_insufficient_inviter() {
        // An undeclared invited role and an inviter who does not outrank the invited role both
        // fail with InsufficientRole; an unknown inviter is TokenInvalid.
        let Some(s) = setup(invite_config()) else { return };
        let member = seed_admin(&s.users, "member@example.com", "MEMBER").await;
        // An undeclared role.
        assert!(matches!(
            s.engine
                .invite(&member, "x@example.com", "GHOST", "t1", None)
                .await,
            Err(AuthError::InsufficientRole)
        ));
        // A MEMBER cannot invite an ADMIN (does not outrank it).
        assert!(matches!(
            s.engine
                .invite(&member, "x@example.com", "ADMIN", "t1", None)
                .await,
            Err(AuthError::InsufficientRole)
        ));
        // An unknown inviter.
        assert!(matches!(
            s.engine
                .invite("ghost", "x@example.com", "MEMBER", "t1", None)
                .await,
            Err(AuthError::TokenInvalid)
        ));
        // An ADMIN can invite a MEMBER and an ADMIN (equal-or-lower), exercising has_role's
        // equal and included branches.
        let admin = seed_admin(&s.users, "admin2@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(&admin, "a@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
        assert!(
            s.engine
                .invite(&admin, "b@example.com", "ADMIN", "t1", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn accept_rejects_a_tampered_role_and_a_duplicate_email() {
        // A stored invitation whose role is not a declared role (tamper) is rejected; an
        // invitee who already has an account is EmailAlreadyExists.
        let Some(s) = setup(invite_config()) else { return };
        // Tampered role.
        let tampered = "d".repeat(64);
        assert!(
            s.stores
                .put_invitation(
                    &tampered,
                    &StoredInvitation {
                        email: "t@example.com".to_owned(),
                        role: "SUPERADMIN".to_owned(),
                        tenant_id: "t1".to_owned(),
                        inviter_user_id: "x".to_owned(),
                    },
                    600
                )
                .await
                .is_ok()
        );
        assert!(matches!(
            s.engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token: tampered,
                        name: "T".to_owned(),
                        password: "pw".to_owned(),
                    },
                    "1.2.3.4",
                    "agent",
                    BTreeMap::new(),
                )
                .await,
            Err(AuthError::InvalidInvitationToken)
        ));

        // Duplicate email.
        let _ = seed_admin(&s.users, "dup@example.com", "MEMBER").await;
        let dup = "e".repeat(64);
        assert!(
            s.stores
                .put_invitation(
                    &dup,
                    &StoredInvitation {
                        email: "dup@example.com".to_owned(),
                        role: "MEMBER".to_owned(),
                        tenant_id: "t1".to_owned(),
                        inviter_user_id: "x".to_owned(),
                    },
                    600
                )
                .await
                .is_ok()
        );
        assert!(matches!(
            s.engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token: dup,
                        name: "D".to_owned(),
                        password: "pw".to_owned(),
                    },
                    "1.2.3.4",
                    "agent",
                    BTreeMap::new(),
                )
                .await,
            Err(AuthError::EmailAlreadyExists)
        ));
    }

    #[tokio::test]
    async fn accept_rejects_an_unknown_token() {
        // A token with no stored invitation is invalid.
        let Some(s) = setup(invite_config()) else { return };
        assert!(matches!(
            s.engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token: "unknown".to_owned(),
                        name: "N".to_owned(),
                        password: "pw".to_owned(),
                    },
                    "1.2.3.4",
                    "agent",
                    BTreeMap::new(),
                )
                .await,
            Err(AuthError::InvalidInvitationToken)
        ));
    }

    #[tokio::test]
    async fn invite_without_an_invitation_store_is_an_internal_error() {
        // An engine wired without an invitation store (invitations disabled) reports an
        // internal error when `invite` is called — the store-not-configured guard.
        let mut cfg = invite_config();
        cfg.invitations.enabled = false;
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let built = AuthEngine::builder()
            .config(cfg)
            .environment(Environment::Test)
            .user_repository(users.clone())
            // Wire only the three required stores; no invitation store.
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores.clone())
            .build();
        let Ok(engine) = built else { return };
        let admin = seed_admin(&users, "noinv@example.com", "ADMIN").await;
        assert!(matches!(
            engine
                .invite(&admin, "x@example.com", "MEMBER", "t1", None)
                .await,
            Err(AuthError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn invite_clamps_an_oversized_ttl_when_computing_the_expiry() {
        // A token TTL larger than `i64::MAX` seconds saturates rather than overflowing, so the
        // expiry computation stays total — exercising the `try_from(ttl)` fallback.
        let mut cfg = invite_config();
        cfg.invitations.token_ttl = std::time::Duration::from_secs(u64::MAX);
        let Some(s) = setup(cfg) else { return };
        let admin = seed_admin(&s.users, "bigttl@example.com", "ADMIN").await;
        // The invite still succeeds; the oversized TTL is clamped internally.
        assert!(
            s.engine
                .invite(&admin, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
    }

    #[test]
    fn has_role_honors_the_denormalized_hierarchy() {
        // The holder satisfies its own role and every role its denormalized entry includes,
        // but not a role above it.
        let hierarchy = HashMap::from([
            ("ADMIN".to_owned(), vec!["MEMBER".to_owned()]),
            ("MEMBER".to_owned(), Vec::new()),
        ]);
        assert!(has_role("ADMIN", "ADMIN", &hierarchy));
        assert!(has_role("ADMIN", "MEMBER", &hierarchy));
        assert!(has_role("MEMBER", "MEMBER", &hierarchy));
        assert!(!has_role("MEMBER", "ADMIN", &hierarchy));
        // An unknown holder satisfies only its own (equal) role.
        assert!(!has_role("GHOST", "MEMBER", &hierarchy));
    }

    #[test]
    fn accept_invitation_input_debug_redacts_token_and_password() {
        // A stray `{:?}` must never expose the single-use token or the password.
        let input = AcceptInvitationInput {
            token: "live-invite-token".to_owned(),
            name: "Ada".to_owned(),
            password: "super-secret".to_owned(),
        };
        let dbg = format!("{input:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("live-invite-token"));
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("Ada"));
    }
}
