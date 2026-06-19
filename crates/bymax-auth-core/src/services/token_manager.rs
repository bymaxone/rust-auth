//! The engine's token manager: HS256 access-JWT issuance, opaque-refresh issuance, atomic
//! rotation with a grace window, the access-token revocation blacklist (keyed by `jti`),
//! and the short-lived MFA temp token.
//!
//! Access tokens are short HS256 JWTs carrying a fresh UUID-v4 `jti` (the `rv:` blacklist
//! key, §24 invariant 2). Refresh tokens are **opaque** CSPRNG values — never JWTs — and
//! only their `sha256` is ever written to the store (§24 invariant 1); the rotation grace
//! pointer holds the new [`SessionRecord`] JSON, never a raw token (§12.4).

use std::sync::Arc;
use std::time::Duration;

use bymax_auth_jwt::keys::{HsKey, VerifyOptions};
use bymax_auth_jwt::{RawRefreshToken, sign, verify};
use bymax_auth_types::{
    AuthError, AuthResult, DashboardClaims, DashboardType, MfaContext, MfaTempClaims, MfaTempType,
    RotatedTokens, SafeAuthUser,
};

use crate::services::{internal_error, new_uuid_v4, now_offset, now_unix};
use crate::traits::{RotateOutcome, SessionKind, SessionRecord, SessionRotation, SessionStore};

/// MFA temp-token lifetime, in seconds (§7.3 constant `MFA_TEMP_TOKEN_TTL_SECONDS`).
const MFA_TEMP_TOKEN_TTL_SECONDS: i64 = 300;

/// Issues and rotates the dashboard token pair over the [`SessionStore`] seam. Platform
/// issuance (`SafeAuthPlatformUser`/`PlatformClaims`) is a separate identity surface and
/// is wired with the platform domain.
pub struct TokenManagerService {
    key: HsKey,
    session_store: Arc<dyn SessionStore>,
    access_ttl: Duration,
    refresh_ttl_secs: u64,
    grace_ttl_secs: u64,
}

impl TokenManagerService {
    /// Assemble the token manager from the signing key, the session store, and the
    /// resolved token lifetimes.
    pub(crate) fn new(
        key: HsKey,
        session_store: Arc<dyn SessionStore>,
        access_ttl: Duration,
        refresh_expires_in_days: u32,
        grace_window: Duration,
    ) -> Self {
        Self {
            key,
            session_store,
            access_ttl,
            refresh_ttl_secs: u64::from(refresh_expires_in_days) * 86_400,
            grace_ttl_secs: grace_window.as_secs(),
        }
    }

    /// Sign a dashboard access JWT (HS256). The claims already carry a fresh `jti`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable for
    /// the crate's claim types).
    pub fn issue_access(&self, claims: &DashboardClaims) -> Result<String, AuthError> {
        sign(claims, &self.key).map_err(signing_failed)
    }

    /// Issue a fresh access JWT plus an opaque refresh token for `user`, persisting the
    /// refresh session under `sha256(refresh)`. `mfa_verified` flags whether this session
    /// has cleared the second factor (always `false` at first issuance; set `true` only
    /// after an MFA challenge succeeds).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if signing fails or the store rejects the session write.
    pub async fn issue_tokens(
        &self,
        user: &SafeAuthUser,
        ip: &str,
        user_agent: &str,
        mfa_verified: bool,
    ) -> Result<AuthResult, AuthError> {
        let refresh = RawRefreshToken::generate();
        let now = now_unix();
        let claims = DashboardClaims {
            sub: user.id.clone(),
            jti: new_uuid_v4(),
            tenant_id: user.tenant_id.clone(),
            role: user.role.clone(),
            token_type: DashboardType::Dashboard,
            status: user.status.clone(),
            mfa_enabled: user.mfa_enabled,
            mfa_verified,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
        };
        let access_token = self.issue_access(&claims)?;

        let record = SessionRecord {
            user_id: user.id.clone(),
            tenant_id: Some(user.tenant_id.clone()),
            role: user.role.clone(),
            device: device_label(user_agent),
            ip: ip.to_owned(),
            created_at: now_offset(),
        };
        self.session_store
            .create_session(
                SessionKind::Dashboard,
                &refresh.redis_hash(),
                &record,
                self.refresh_ttl_secs,
            )
            .await?;

        Ok(AuthResult {
            user: user.clone(),
            access_token,
            refresh_token: refresh.expose_secret().to_owned(),
        })
    }

    /// Atomically rotate a presented refresh token into a fresh pair, honoring the grace
    /// window. On the primary path the old token is consumed and the new session is stored
    /// by the rotation; on the grace path a concurrent retry mints a brand-new session for
    /// the recovered identity (single-shot — no new grace pointer is planted).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RefreshTokenInvalid`] when the token is neither live nor inside
    /// the grace window, or a store/signing [`AuthError`] on failure.
    pub async fn reissue_tokens(
        &self,
        raw_refresh: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<RotatedTokens, AuthError> {
        let old = RawRefreshToken::from_raw(raw_refresh.to_owned());
        let old_hash = old.redis_hash();
        let new = RawRefreshToken::generate();

        // The new record's identity comes from the live old record when present. When the
        // old token is already gone we still attempt rotation to detect a grace hit; the
        // seed identity there is a placeholder that the rotation never stores (it can only
        // return Grace/Invalid for an absent live token).
        let live = self
            .session_store
            .find_session(SessionKind::Dashboard, &old_hash)
            .await?;
        let seed = live.unwrap_or_else(|| placeholder_record(ip, user_agent));
        let new_record = identity_record(&seed, ip, user_agent);

        let rotation = SessionRotation {
            old_hash,
            new_hash: new.redis_hash(),
            new_raw: new.expose_secret().to_owned(),
            new_record: new_record.clone(),
            refresh_ttl: self.refresh_ttl_secs,
            grace_ttl: self.grace_ttl_secs,
        };

        match self
            .session_store
            .rotate(SessionKind::Dashboard, &rotation)
            .await?
        {
            RotateOutcome::Rotated(_old) => {
                let access_token = self.issue_access(&self.rotated_claims(&new_record))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: new.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Grace(recovered) => {
                // Lost the rotation race: mint a fresh session for the recovered identity
                // rather than re-planting a grace pointer.
                let fresh = RawRefreshToken::generate();
                let fresh_record = identity_record(&recovered, ip, user_agent);
                self.session_store
                    .create_session(
                        SessionKind::Dashboard,
                        &fresh.redis_hash(),
                        &fresh_record,
                        self.refresh_ttl_secs,
                    )
                    .await?;
                let access_token = self.issue_access(&self.rotated_claims(&fresh_record))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: fresh.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Invalid => Err(AuthError::RefreshTokenInvalid),
        }
    }

    /// Verify a dashboard access JWT (signature + algorithm + temporal) and reject it if
    /// its `jti` is blacklisted.
    ///
    /// # Errors
    ///
    /// Returns the internal-only [`AuthError::TokenExpired`]/[`AuthError::TokenRevoked`] or
    /// the public [`AuthError::TokenInvalid`]; all collapse to `token_invalid` at the HTTP
    /// boundary so no oracle is exposed.
    pub async fn verify_access(&self, token: &str) -> Result<DashboardClaims, AuthError> {
        let claims = verify::<DashboardClaims>(token, &self.key, &VerifyOptions::default())
            .map_err(map_jwt_error)?;
        if self.session_store.is_blacklisted(&claims.jti).await? {
            return Err(AuthError::TokenRevoked);
        }
        Ok(claims)
    }

    /// Blacklist an access token by its `jti` for its remaining lifetime (logout).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] on a store failure.
    pub async fn revoke_access(&self, jti: &str, remaining_ttl_secs: u64) -> Result<(), AuthError> {
        self.session_store
            .blacklist_access(jti, remaining_ttl_secs)
            .await
    }

    /// Issue a short-lived MFA temp token bridging the password step and the second factor.
    /// The TOTP verification is performed by the MFA challenge flow; this only mints the
    /// signed challenge JWT.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable).
    pub fn issue_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<String, AuthError> {
        let now = now_unix();
        let claims = MfaTempClaims {
            sub: user_id.to_owned(),
            jti: new_uuid_v4(),
            token_type: MfaTempType::MfaChallenge,
            context,
            iat: now,
            exp: now.saturating_add(MFA_TEMP_TOKEN_TTL_SECONDS),
        };
        sign(&claims, &self.key).map_err(signing_failed)
    }

    /// Verify an MFA temp token (signature + expiry). Does **not** consume it — the
    /// single-use store consumption is part of the MFA challenge flow.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] for any malformed, mis-signed, or expired
    /// token.
    pub fn verify_mfa_temp_token(&self, token: &str) -> Result<MfaTempClaims, AuthError> {
        verify::<MfaTempClaims>(token, &self.key, &VerifyOptions::default())
            .map_err(|_| AuthError::MfaTempTokenInvalid)
    }

    /// Build the access claims for a rotated/recovered session. Rotation always drops
    /// `mfa_verified` (the user re-acquires it only via the MFA challenge) and issues an
    /// empty `status` — status guards consult the repository/status cache, not the rotated
    /// JWT, because the stored session record carries no live status.
    fn rotated_claims(&self, record: &SessionRecord) -> DashboardClaims {
        let now = now_unix();
        DashboardClaims {
            sub: record.user_id.clone(),
            jti: new_uuid_v4(),
            tenant_id: record.tenant_id.clone().unwrap_or_default(),
            role: record.role.clone(),
            token_type: DashboardType::Dashboard,
            status: String::new(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
        }
    }
}

/// Map a JWT signing failure to the opaque internal error. Signing the crate's concrete
/// claim types cannot fail in practice (they always serialize), so this is a defensive
/// mapping that never surfaces the failing step.
fn signing_failed(_error: bymax_auth_jwt::JwtError) -> AuthError {
    internal_error("token signing failed")
}

/// Map a JWT verification failure onto the engine error catalog: an expired token uses the
/// internal-only `token_expired`, everything else collapses to the public `token_invalid`.
fn map_jwt_error(error: bymax_auth_jwt::JwtError) -> AuthError {
    match error {
        bymax_auth_jwt::JwtError::Expired => AuthError::TokenExpired,
        _ => AuthError::TokenInvalid,
    }
}

/// Build a fresh refresh-session record for a rotation, carrying the seed identity and
/// stamping the current device/IP/time.
fn identity_record(seed: &SessionRecord, ip: &str, user_agent: &str) -> SessionRecord {
    SessionRecord {
        user_id: seed.user_id.clone(),
        tenant_id: seed.tenant_id.clone(),
        role: seed.role.clone(),
        device: device_label(user_agent),
        ip: ip.to_owned(),
        created_at: now_offset(),
    }
}

/// A placeholder identity used only when the live old token is absent; the rotation never
/// stores it (an absent live token can only yield Grace or Invalid), so its empty identity
/// is never observed.
fn placeholder_record(ip: &str, user_agent: &str) -> SessionRecord {
    SessionRecord {
        user_id: String::new(),
        tenant_id: None,
        role: String::new(),
        device: device_label(user_agent),
        ip: ip.to_owned(),
        created_at: now_offset(),
    }
}

/// The human-readable device label stored on a session record. Full user-agent parsing is
/// the session service's concern; here the raw value is carried verbatim.
fn device_label(user_agent: &str) -> String {
    user_agent.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::InMemoryStores;
    use time::OffsetDateTime;

    fn key() -> HsKey {
        HsKey::from_bytes(b"a-test-hs256-secret-key-0123456789")
    }

    fn service(store: Arc<InMemoryStores>) -> TokenManagerService {
        TokenManagerService::new(
            key(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
        )
    }

    fn user() -> SafeAuthUser {
        SafeAuthUser {
            id: "u1".to_owned(),
            email: "u@example.com".to_owned(),
            name: "U".to_owned(),
            role: "MEMBER".to_owned(),
            status: "ACTIVE".to_owned(),
            tenant_id: "t1".to_owned(),
            email_verified: true,
            mfa_enabled: false,
            oauth_provider: None,
            oauth_provider_id: None,
            last_login_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn issue_then_verify_round_trips_with_a_fresh_unique_jti() {
        // Issuance mints an access JWT verifiable through the manager and an opaque refresh
        // persisted in the store; two issuances carry distinct UUID-v4 jtis (§24 inv. 2).
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let first = svc
            .issue_tokens(&user(), "203.0.113.4", "agent/1.0", false)
            .await;
        assert!(first.is_ok());
        let Ok(first) = first else { return };
        let claims = svc.verify_access(&first.access_token).await;
        assert!(matches!(&claims, Ok(c) if c.sub == "u1" && c.jti.len() == 36));
        let Ok(claims) = claims else { return };
        assert_eq!(claims.tenant_id, "t1");
        // The opaque refresh is not a JWT (no dot-delimited three segments).
        assert_ne!(first.refresh_token.matches('.').count(), 2);
        // The refresh session was persisted under its hash.
        let hash = RawRefreshToken::from_raw(first.refresh_token.clone()).redis_hash();
        assert!(matches!(
            store.find_session(SessionKind::Dashboard, &hash).await,
            Ok(Some(_))
        ));

        let second = svc
            .issue_tokens(&user(), "203.0.113.4", "agent/1.0", false)
            .await;
        let Ok(second) = second else { return };
        let Ok(second_claims) = svc.verify_access(&second.access_token).await else { return };
        assert_ne!(
            claims.jti, second_claims.jti,
            "jti must be unique per issuance"
        );
    }

    #[tokio::test]
    async fn rotation_produces_a_new_pair_and_grace_absorbs_a_concurrent_retry() {
        // The first rotation consumes the old token; a second rotation of the same old
        // token succeeds via the grace window (no logout), and an unknown token is invalid.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };

        let rotated = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        assert!(rotated.is_ok());
        let Ok(rotated) = rotated else { return };
        assert_ne!(rotated.refresh_token, issued.refresh_token);
        // The rotated access token verifies and carries no live status (status guards
        // consult the repo, not the rotated JWT).
        assert!(matches!(
            svc.verify_access(&rotated.access_token).await,
            Ok(c) if c.status.is_empty()
        ));

        // Replaying the original token lands in the grace window and still succeeds.
        let grace = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        assert!(grace.is_ok());

        // An unknown refresh token is rejected.
        let unknown = svc
            .reissue_tokens("never-issued", "10.0.0.1", "agent/1.0")
            .await;
        assert!(matches!(unknown, Err(AuthError::RefreshTokenInvalid)));
    }

    #[tokio::test]
    async fn blacklist_rejects_a_revoked_access_token() {
        // After revoking the access jti, verify_access reports the internal-only
        // token_revoked (which collapses to token_invalid at the boundary).
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let issued = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };
        let Ok(claims) = svc.verify_access(&issued.access_token).await else { return };
        assert!(svc.revoke_access(&claims.jti, 900).await.is_ok());
        assert!(matches!(
            svc.verify_access(&issued.access_token).await,
            Err(AuthError::TokenRevoked)
        ));
    }

    #[tokio::test]
    async fn verify_access_maps_malformed_and_expired_tokens() {
        // A garbage token is token_invalid; an expired token is the internal-only
        // token_expired (both collapse to token_invalid downstream).
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        assert!(matches!(
            svc.verify_access("not.a.jwt").await,
            Err(AuthError::TokenInvalid)
        ));
        // Craft an already-expired token by signing claims with exp in the past.
        let now = now_unix();
        let expired = DashboardClaims {
            sub: "u1".to_owned(),
            jti: new_uuid_v4(),
            tenant_id: "t1".to_owned(),
            role: "MEMBER".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            mfa_verified: false,
            iat: now - 1_000,
            exp: now - 500,
        };
        let Ok(token) = svc.issue_access(&expired) else { return };
        assert!(matches!(
            svc.verify_access(&token).await,
            Err(AuthError::TokenExpired)
        ));
    }

    #[test]
    fn signing_failed_collapses_to_the_internal_error() {
        // The defensive signing-error mapping (unreachable for the concrete claim types)
        // collapses any JWT failure to the opaque internal error.
        assert!(matches!(
            signing_failed(bymax_auth_jwt::JwtError::Decode),
            AuthError::Internal(_)
        ));
    }

    #[test]
    fn mfa_temp_token_round_trips_and_rejects_garbage() {
        // The short MFA temp token signs and verifies back to its claims; a malformed token
        // is rejected as mfa_temp_token_invalid (the TOTP step is the MFA challenge's job).
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let Ok(token) = svc.issue_mfa_temp_token("u1", MfaContext::Dashboard) else { return };
        let verified = svc.verify_mfa_temp_token(&token);
        assert!(matches!(&verified, Ok(c) if c.sub == "u1" && c.context == MfaContext::Dashboard));
        assert!(matches!(
            svc.verify_mfa_temp_token("garbage"),
            Err(AuthError::MfaTempTokenInvalid)
        ));
    }
}
