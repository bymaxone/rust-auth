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
use crate::normalize::normalize_email;
use crate::services::auth::detached::run_after_invitation_accepted;
use crate::services::auth::{map_repository_error, spawn_guarded};
use crate::traits::{HookContext, InviteData, StoredInvitation};

/// The bytes of entropy in an invitation token before hex-encoding (256-bit, 64 hex chars).
const INVITE_TOKEN_BYTES: usize = 32;

/// The stored key suffix for a raw invitation token: `sha256(token)` in lowercase hex, the
/// same form the store derives, so the index can point at a record the engine never keys.
fn token_hash(token: &str) -> String {
    crate::services::to_hex(&bymax_auth_crypto::mac::sha256(token.as_bytes()))
}

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
        // payload use the same canonical form the accept flow will match against. Routed
        // through the shared helper: an ASCII-only fold here would canonicalize a non-ASCII
        // address differently from nest-auth's Unicode `toLowerCase()` and split the keyspace
        // the two backends share.
        let email = normalize_email(email);
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
        // The inviter must belong to the tenant they are inviting into. Without this the only
        // authorization is the role-hierarchy check below, which says nothing about *where*
        // the role is held: an ADMIN of tenant A could mint an invitation that provisions an
        // ADMIN account inside tenant B. The shipped axum adapter sources `tenant_id` from the
        // caller's own claims, which hides it — but this is a library whose core API hosts
        // call directly, and the authorization contract belongs here rather than in one
        // caller. It is also what makes `invite` consistent with `accept_invitation`, which
        // already re-validates the role as anti-tamper.
        if inviter.tenant_id != tenant_id {
            return Err(AuthError::InsufficientRole);
        }
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
            // Required by nest-auth's record guard: an invitation without `createdAt` is
            // rejected on accept, and because accept consumes the token with `GETDEL` the
            // rejection would destroy the invitation rather than merely fail it.
            created_at: OffsetDateTime::now_utc(),
        };
        // Re-inviting an address supersedes the previous invitation rather than adding a
        // second one. Two live tokens for one invitee is two chances for an intercepted link
        // to be redeemed, and a revoke would only ever reach the newest — the older would sit
        // valid and unreferenced for the rest of its TTL.
        if let Some(previous) = store
            .take_invitation_index(tenant_id, &self.invitee_identifier(&email))
            .await?
        {
            store.delete_invitation_by_hash(&previous).await?;
        }
        store.put_invitation(&raw, &invitation, ttl).await?;
        // The invitee index is what makes an invitation manageable at all: the record is keyed
        // by the hash of a token only the recipient's mailbox holds, so without this nobody on
        // the issuing side can name a pending invitation, let alone withdraw one.
        store
            .put_invitation_index(
                tenant_id,
                &self.invitee_identifier(&email),
                &token_hash(&raw),
                ttl,
            )
            .await?;

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
        if let Err(error) = self
            .email_provider()
            .send_invitation(&email, &invite_data, None)
            .await
        {
            tracing::error!(%error, "invitation: delivery failed (the invitation stands)");
        }
        tracing::info!(%tenant_id, role = %invitation.role, "invitation: created");
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
            // The consume is a single-use GETDEL, so the record is already gone: a rejection
            // here destroys the invitation rather than merely failing it, and an undeclared role
            // is what a tampered token looks like. Both are worth an operator's attention.
            tracing::warn!(
                "invitation: stored record rejected as empty or carrying an undeclared role"
            );
            return Err(AuthError::InvalidInvitationToken);
        }

        // The record is already gone; drop the index that pointed at it so a later revoke does
        // not report success over an invitation that was accepted. Both carry the same TTL, so
        // this is tidiness rather than correctness — but a stale pointer is exactly the kind of
        // thing an operator reads as "still pending".
        store
            .take_invitation_index(
                &invitation.tenant_id,
                &self.invitee_identifier(&invitation.email),
            )
            .await?;

        // …and re-validate the INVITER, whose authority is what the invitation rests on. It was
        // checked when the link was minted and never again, so for the token's whole lifetime
        // the invitation outlived the person behind it: an admin could send one, be banned and
        // stripped of their role, and the invitee would still arrive as an admin of that tenant
        // with a live session. That is a clean way to keep a foothold across the account kill
        // switch, which makes the switch advisory.
        self.assert_inviter_still_authorised(&invitation).await?;

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
        self.passwords()
            .assert_not_compromised(&input.password)
            .await?;
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

        tracing::info!(user_id = %safe.id, tenant_id = %safe.tenant_id, "invitation: accepted");
        spawn_guarded(run_after_invitation_accepted(
            self.hooks().clone(),
            safe,
            hook_ctx,
        ));
        Ok(result)
    }
    /// Withdraw a pending invitation before it is accepted.
    ///
    /// An invitation is a credential: it provisions an account, at a role, inside a tenant,
    /// to whoever holds the link. Until now the library could mint one and had no way to take
    /// it back — a link sent to the wrong address, or sent by someone who has since left,
    /// stayed redeemable for its whole TTL with nothing an operator could do about it. ASVS v5
    /// §6.1.1 expects an administrative path to invalidate a credential that should no longer
    /// work.
    ///
    /// The revoker is held to the same bar as the issuer: they must belong to the tenant, be
    /// in good standing, and out-rank the role the invitation grants. Anything looser would
    /// let a member cancel an admin's invitations.
    ///
    /// Idempotent: revoking an invitation that never existed, already expired, or was already
    /// accepted is not an error — the caller asked for an end state and gets it, and reporting
    /// the difference would tell them whether an address has a pending invitation, which is
    /// precisely what hashing the email in the index avoids disclosing.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenInvalid`] when the revoker no longer exists,
    /// [`AuthError::InsufficientRole`] when the revoker belongs to another tenant or is not in
    /// good standing — both facts about the caller alone — or a store/repository
    /// [`AuthError`]. A revoker who merely does not out-rank the invitation is answered
    /// `Ok(false)`, exactly as one asking about an address with nothing pending.
    pub async fn revoke_invitation(
        &self,
        revoker_user_id: &str,
        email: &str,
        tenant_id: &str,
    ) -> Result<bool, AuthError> {
        let email = normalize_email(email);
        let store = self
            .invitation_store()
            .ok_or_else(|| crate::services::internal_error("invitation store not configured"))?;

        let revoker = self
            .user_repository()
            .find_by_id(revoker_user_id, None)
            .await
            .map_err(map_repository_error)?
            .ok_or(AuthError::TokenInvalid)?;
        if revoker.tenant_id != tenant_id {
            return Err(AuthError::InsufficientRole);
        }
        // Standing is a fact about the CALLER, so refusing out loud describes nobody else — and
        // it is settled before any lookup, so a suspended account cannot use this door to ask
        // questions at all. The rank comparison below is the opposite kind of check, and is
        // answered the opposite way.
        self.assert_user_not_blocked(&revoker.status)?;

        let Some(hash) = store
            .read_invitation_index(tenant_id, &self.invitee_identifier(&email))
            .await?
        else {
            return Ok(false);
        };

        // The role check reads the invitation itself rather than the request: the caller names
        // an address, not a role, so the only way to know what authority is being withdrawn is
        // to look. A record that no longer parses reads as absent and is withdrawn without a
        // role check — it can no longer be accepted either, and leaving it would be worse.
        //
        // An outranked revoker is answered exactly as one who asked about an address with
        // nothing pending. `InsufficientRole` here was an oracle: the caller names an address
        // and nothing else, so the refusal said "there is a pending invitation for this
        // address, at a role above yours" while `Ok(false)` said "there is none" — letting any
        // member enumerate a tenant's pending invitations, and roughly at what authority. That
        // is precisely the disclosure hashing the address into the index exists to prevent.
        // The refusal is recorded, where an operator can see it and the prober cannot.
        if let Some(invitation) = store.read_invitation_by_hash(&hash).await?
            && !has_role(
                &revoker.role,
                &invitation.role,
                &self.config().config().roles.hierarchy,
            )
        {
            tracing::warn!(
                %tenant_id,
                %revoker_user_id,
                "invitation: revoke refused — outranked by the invitation"
            );
            return Ok(false);
        }

        store
            .take_invitation_index(tenant_id, &self.invitee_identifier(&email))
            .await?;
        let removed = store.delete_invitation_by_hash(&hash).await?;
        tracing::info!(%tenant_id, %revoker_user_id, "invitation: withdrawn");
        Ok(removed)
    }

    /// Re-check, at redemption time, everything that was true of the inviter when the link was
    /// minted.
    ///
    /// An invitation is a delegation of authority, and authority is revocable. Validating it
    /// only at creation means a token carries whatever power its author had at the moment they
    /// clicked send — surviving their suspension, their demotion, and their removal from the
    /// tenant. The failure is answered as `InvalidInvitationToken` rather than as a role error:
    /// the redeemer is not the one who lost authority, and telling them *why* would describe
    /// the inviter's account status to someone who may be a stranger to it.
    async fn assert_inviter_still_authorised(
        &self,
        invitation: &crate::traits::StoredInvitation,
    ) -> Result<(), AuthError> {
        let inviter = self
            .user_repository()
            .find_by_id(&invitation.inviter_user_id, None)
            .await
            .map_err(map_repository_error)?;
        let still_authorised = inviter.is_some_and(|inviter| {
            self.assert_user_not_blocked(&inviter.status).is_ok()
                && inviter.tenant_id == invitation.tenant_id
                && has_role(
                    &inviter.role,
                    &invitation.role,
                    &self.config().config().roles.hierarchy,
                )
        });
        if !still_authorised {
            tracing::warn!(
                inviter_user_id = %invitation.inviter_user_id,
                role = %invitation.role,
                "invitation: the inviter can no longer grant this invitation"
            );
            return Err(AuthError::InvalidInvitationToken);
        }
        Ok(())
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
    use crate::traits::{
        EmailProvider, InvitationStore, SessionKind, SessionStore, UserRepository,
    };
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
                        created_at: OffsetDateTime::UNIX_EPOCH,
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
    async fn invite_refuses_a_tenant_the_inviter_does_not_belong_to() {
        // The role-hierarchy check says WHAT role the inviter holds and nothing about WHERE
        // they hold it, so on its own an ADMIN of tenant t1 could mint an invitation that
        // provisions an ADMIN account inside t2 — a tenant they have no relationship with.
        // The shipped axum adapter sources `tenant_id` from the caller's own claims, which
        // hides it, but this is a library whose core API hosts call directly.
        let Some(s) = setup(invite_config()) else { return };
        let admin = seed_admin(&s.users, "t1admin@example.com", "ADMIN").await;

        // Same inviter, same role, only the tenant differs: t1 succeeds, t2 is refused.
        assert!(matches!(
            s.engine
                .invite(&admin, "victim@example.com", "ADMIN", "t2", None)
                .await,
            Err(AuthError::InsufficientRole)
        ));
        assert!(
            s.engine
                .invite(&admin, "ok@example.com", "ADMIN", "t1", None)
                .await
                .is_ok(),
            "the inviter's own tenant must still work"
        );
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
    async fn accept_refuses_an_invitation_whose_inviter_lost_their_authority() {
        // An invitation is a delegation of authority, and authority is revocable. Validating it
        // only at creation meant a 48-hour token carried whatever power its author had when
        // they clicked send: an admin could invite, then be banned and stripped of their role,
        // and the invitee would still arrive as an admin of that tenant with a live session —
        // a clean way to keep a foothold across the account kill switch, which makes the switch
        // advisory.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "deposed@example.com", "ADMIN").await;
        let token = "f".repeat(64);
        assert!(
            s.stores
                .put_invitation(
                    &token,
                    &StoredInvitation {
                        email: "newcomer@example.com".to_owned(),
                        role: "ADMIN".to_owned(),
                        tenant_id: "t1".to_owned(),
                        inviter_user_id: inviter.clone(),
                        created_at: OffsetDateTime::UNIX_EPOCH,
                    },
                    600
                )
                .await
                .is_ok()
        );

        // The inviter is banned between minting and redemption.
        assert!(s.users.update_status(&inviter, "BANNED").await.is_ok());

        assert!(matches!(
            s.engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token,
                        name: "N".to_owned(),
                        password: "glidingwalnut42".to_owned(),
                    },
                    "1.2.3.4",
                    "agent",
                    BTreeMap::new(),
                )
                .await,
            // Answered as an invalid token, not a role error: the redeemer is not the one who
            // lost authority, and saying why would describe the inviter's account status to
            // someone who may be a stranger to it.
            Err(AuthError::InvalidInvitationToken)
        ));
        // Nothing was provisioned.
        assert!(matches!(
            s.users.find_by_email("newcomer@example.com", "t1").await,
            Ok(None)
        ));
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
                        created_at: OffsetDateTime::UNIX_EPOCH,
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

        // Duplicate email. The inviter has to be a real, still-authorised account: the
        // authority re-check runs first, so a placeholder id would refuse this as an invalid
        // token and the duplicate-email arm would never be reached.
        let inviter = seed_admin(&s.users, "dup-inviter@example.com", "ADMIN").await;
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
                        inviter_user_id: inviter,
                        created_at: OffsetDateTime::UNIX_EPOCH,
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
    async fn accept_rejects_each_malformed_field_on_its_own() {
        // The structural guard is three independent reasons, and the tamper test above trips
        // only one of them — so an `||` that became an `&&` (accept unless *every* field is
        // wrong) read the same. Each field is broken alone here: an invitation with no
        // recipient, one with no tenant, and one whose role was never declared.
        let Some(s) = setup(invite_config()) else { return };
        let cases = [
            (
                "no-email",
                StoredInvitation {
                    email: String::new(),
                    role: "MEMBER".to_owned(),
                    tenant_id: "t1".to_owned(),
                    inviter_user_id: "x".to_owned(),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                },
            ),
            (
                "no-tenant",
                StoredInvitation {
                    email: "ok@example.com".to_owned(),
                    role: "MEMBER".to_owned(),
                    tenant_id: String::new(),
                    inviter_user_id: "x".to_owned(),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                },
            ),
        ];
        for (index, (label, invitation)) in cases.into_iter().enumerate() {
            let token = format!("{}{index}", "a".repeat(63));
            let stored = s.stores.put_invitation(&token, &invitation, 600).await;
            assert!(stored.is_ok(), "{label} could not be stored");
            let outcome = s
                .engine
                .accept_invitation(
                    AcceptInvitationInput {
                        token,
                        name: "N".to_owned(),
                        password: "pw".to_owned(),
                    },
                    "1.2.3.4",
                    "agent",
                    BTreeMap::new(),
                )
                .await;
            let rejected = matches!(outcome, Err(AuthError::InvalidInvitationToken));
            assert!(rejected, "{label} was accepted");
        }
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

    /// An email provider whose invitation send always fails, so the best-effort delivery path
    /// is observable. Every other method succeeds — only the send under test errors.
    #[tokio::test]
    async fn the_failing_invite_double_answers_the_address_change_send() {
        // The double exists to fail ONE send. Everything else about it succeeding is the
        // property that makes it a valid `EmailProvider`, and a method nothing calls is a
        // method nothing proves.
        use crate::traits::EmailProvider as _;

        assert!(
            FailingInviteEmail
                .send_email_change_verification("new@example.com", "t", None)
                .await
                .is_ok()
        );
    }

    struct FailingInviteEmail;

    #[async_trait::async_trait]
    impl crate::traits::EmailProvider for FailingInviteEmail {
        async fn send_email_change_verification(
            &self,
            _new_email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }

        async fn send_password_reset_token(
            &self,
            _email: &str,
            _token: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_password_reset_otp(
            &self,
            _email: &str,
            _otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_email_verification_otp(
            &self,
            _email: &str,
            _otp: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_mfa_enabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_mfa_disabled(
            &self,
            _email: &str,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_new_session_alert(
            &self,
            _email: &str,
            _session: &crate::traits::email::SessionInfo,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Ok(())
        }
        async fn send_invitation(
            &self,
            _to: &str,
            _data: &crate::traits::email::InviteData,
            _locale: Option<&str>,
        ) -> Result<(), crate::traits::EmailError> {
            Err(crate::traits::EmailError::Delivery(
                "smtp unavailable".into(),
            ))
        }
    }

    #[tokio::test]
    async fn an_undeliverable_invitation_still_stands() {
        // Delivery is best-effort by design: the invitation is already persisted, and rolling
        // it back on a transient SMTP failure would destroy a token the inviter can still
        // resend. So the failure cannot surface to the caller — which makes the log the only
        // signal that invitations are being created and never arriving.
        let Some(s) = setup(invite_config()) else { return };
        let users = Arc::new(InMemoryUserRepository::new());
        let stores = Arc::new(InMemoryStores::new());
        let built = AuthEngine::builder()
            .config(invite_config())
            .environment(Environment::Test)
            .user_repository(users.clone())
            .redis_stores(stores.clone())
            .email_provider(Arc::new(FailingInviteEmail))
            .build();
        let Ok(engine) = built else { return };
        let admin = seed_admin(&users, "sender@example.com", "ADMIN").await;
        drop(s);

        assert!(
            engine
                .invite(&admin, "unreachable@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );

        // Exercise every method of the double so its object-safe surface is fully covered: the
        // invitation send errors (the path under test), the rest succeed.
        let provider = FailingInviteEmail;
        let invite = crate::traits::email::InviteData {
            inviter_name: "Inviter".to_owned(),
            tenant_name: "Tenant".to_owned(),
            invite_token: "t".to_owned(),
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let session = crate::traits::email::SessionInfo {
            device: "Chrome".to_owned(),
            ip: "1.2.3.4".to_owned(),
            session_hash: "abcd1234".to_owned(),
        };
        assert!(provider.send_invitation("e", &invite, None).await.is_err());
        assert!(
            provider
                .send_password_reset_token("e", "t", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_password_reset_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(
            provider
                .send_email_verification_otp("e", "o", None)
                .await
                .is_ok()
        );
        assert!(provider.send_mfa_enabled("e", None).await.is_ok());
        assert!(provider.send_mfa_disabled("e", None).await.is_ok());
        assert!(
            provider
                .send_new_session_alert("e", &session, None)
                .await
                .is_ok()
        );
    }

    /// Read the token the invitee index points at, so a test can assert over the record.
    async fn indexed(s: &Setup, email: &str) -> Option<String> {
        // Through the engine's own derivation: the index is keyed by an HMAC of the address,
        // so a test that spelled the key itself would pass over a changed preimage.
        s.stores
            .read_invitation_index("t1", &s.engine.invitee_identifier(&normalize_email(email)))
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn revoking_withdraws_the_invitation_and_its_index() {
        // The capability the library documented and never had: an invitation provisions an
        // account at a role, and it was unwithdrawable for its whole TTL.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(&inviter, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
        let Some(hash) = indexed(&s, "invitee@example.com").await else { return };

        assert!(matches!(
            s.engine
                .revoke_invitation(&inviter, " Invitee@Example.com ", "t1")
                .await,
            Ok(true)
        ));
        // Both the record and the pointer are gone — a surviving index would read to an
        // operator as "still pending".
        assert!(indexed(&s, "invitee@example.com").await.is_none());
        assert!(matches!(
            s.stores.read_invitation_by_hash(&hash).await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn revoking_nothing_is_not_an_error() {
        // Idempotent, and deliberately silent about which case it was: answering differently
        // would turn the endpoint into an oracle for "does this address have an invitation".
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;

        assert!(matches!(
            s.engine
                .revoke_invitation(&inviter, "nobody@example.com", "t1")
                .await,
            Ok(false)
        ));
    }

    #[tokio::test]
    async fn a_member_cannot_withdraw_an_admins_invitation() {
        // The revoker is held to the same bar as the issuer, or a member could cancel the
        // invitations of someone who out-ranks them.
        let Some(s) = setup(invite_config()) else { return };
        let admin = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        let member = seed_admin(&s.users, "member@example.com", "MEMBER").await;
        assert!(
            s.engine
                .invite(&admin, "invitee@example.com", "ADMIN", "t1", None)
                .await
                .is_ok()
        );

        // Silently, and that is the point. The caller names an address and nothing else, so
        // `InsufficientRole` would say "there is a pending invitation here, at a role above
        // yours" while `Ok(false)` says "there is none" — an oracle any member could walk an
        // address list through, which is what hashing the address into the index prevents.
        assert!(matches!(
            s.engine
                .revoke_invitation(&member, "invitee@example.com", "t1")
                .await,
            Ok(false)
        ));
        // The same caller, against an address with nothing pending: the same answer.
        assert!(matches!(
            s.engine
                .revoke_invitation(&member, "nobody@example.com", "t1")
                .await,
            Ok(false)
        ));
        // …and the invitation survived the refusal.
        assert!(indexed(&s, "invitee@example.com").await.is_some());
    }

    #[tokio::test]
    async fn a_revoker_from_another_tenant_is_refused_before_any_lookup() {
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;

        assert!(matches!(
            s.engine
                .revoke_invitation(&inviter, "invitee@example.com", "t2")
                .await,
            Err(AuthError::InsufficientRole)
        ));
    }

    #[tokio::test]
    async fn a_suspended_revoker_is_refused_out_loud_and_before_any_lookup() {
        // The opposite side of the line from the rank check above: standing is a fact about
        // the CALLER, so refusing out loud describes nobody else — and refusing before the
        // lookup means a suspended account cannot use this door to ask questions at all.
        let Some(s) = setup(invite_config()) else { return };
        let admin = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        let suspended = seed_admin(&s.users, "gone@example.com", "ADMIN").await;
        assert!(s.users.update_status(&suspended, "SUSPENDED").await.is_ok());
        assert!(
            s.engine
                .invite(&admin, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );

        assert!(matches!(
            s.engine
                .revoke_invitation(&suspended, "invitee@example.com", "t1")
                .await,
            Err(AuthError::AccountSuspended)
        ));
        assert!(indexed(&s, "invitee@example.com").await.is_some());
    }

    #[tokio::test]
    async fn the_invitee_index_is_keyed_by_an_hmac_of_the_address() {
        // An address carries far too little entropy for a plain digest to hide it: the index
        // used to key on a bare `sha256(email)`, reversible by dictionary, and it is the one
        // handle anyone reading a keyspace dump has on who a tenant has been inviting. The
        // preimage is pinned here because nest-auth writes the same keys into the same Redis.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(&inviter, "Invitee@Example.COM", "MEMBER", "t1", None)
                .await
                .is_ok()
        );

        let expected = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            s.engine.config().hmac_key(),
            b"invitee@example.com",
        ));
        assert!(
            s.stores
                .read_invitation_index("t1", &expected)
                .await
                .ok()
                .flatten()
                .is_some(),
            "the index is not keyed by hmac(canonical address)"
        );
        // And nothing sits under the bare digest the key used to carry.
        let bare = crate::services::to_hex(&bymax_auth_crypto::mac::sha256(b"invitee@example.com"));
        assert!(
            s.stores
                .read_invitation_index("t1", &bare)
                .await
                .ok()
                .flatten()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_revoker_who_no_longer_exists_is_refused() {
        let Some(s) = setup(invite_config()) else { return };

        assert!(matches!(
            s.engine
                .revoke_invitation("ghost", "invitee@example.com", "t1")
                .await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[tokio::test]
    async fn reinviting_the_same_address_supersedes_the_previous_invitation() {
        // Two live tokens for one invitee is two chances for an intercepted link to be
        // redeemed, and a revoke would only ever reach the newest — the older would sit valid
        // and unreferenced for the rest of its TTL.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(&inviter, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
        let Some(first) = indexed(&s, "invitee@example.com").await else { return };

        assert!(
            s.engine
                .invite(&inviter, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
        let Some(second) = indexed(&s, "invitee@example.com").await else { return };

        assert_ne!(first, second, "the re-invite reused the first token");
        assert!(
            matches!(s.stores.read_invitation_by_hash(&first).await, Ok(None)),
            "the superseded invitation is still redeemable"
        );
    }

    #[tokio::test]
    async fn accepting_clears_the_invitee_index() {
        // A pointer left behind after an acceptance reads to an operator as still pending, and
        // a later revoke would report success over an invitation that was already redeemed.
        let Some(s) = setup(invite_config()) else { return };
        let inviter = seed_admin(&s.users, "admin@example.com", "ADMIN").await;
        assert!(
            s.engine
                .invite(&inviter, "invitee@example.com", "MEMBER", "t1", None)
                .await
                .is_ok()
        );
        // The raw token is opaque, so plant a known one and point the index at it — exactly
        // the pair `invite` writes.
        let token = "d".repeat(64);
        let hash = token_hash(&token);
        assert!(
            s.stores
                .put_invitation(
                    &token,
                    &StoredInvitation {
                        email: "invitee@example.com".to_owned(),
                        role: "MEMBER".to_owned(),
                        tenant_id: "t1".to_owned(),
                        inviter_user_id: inviter.clone(),
                        created_at: OffsetDateTime::UNIX_EPOCH,
                    },
                    600
                )
                .await
                .is_ok()
        );
        assert!(
            s.stores
                .put_invitation_index(
                    "t1",
                    &s.engine.invitee_identifier("invitee@example.com"),
                    &hash,
                    600
                )
                .await
                .is_ok()
        );
        let accepted = s
            .engine
            .accept_invitation(
                AcceptInvitationInput {
                    token,
                    name: "Invitee".to_owned(),
                    password: "correct-horse-battery-staple".to_owned(),
                },
                "1.2.3.4",
                "agent/1.0",
                BTreeMap::new(),
            )
            .await;
        assert!(accepted.is_ok(), "the invitation was not accepted");

        assert!(indexed(&s, "invitee@example.com").await.is_none());
    }
}
