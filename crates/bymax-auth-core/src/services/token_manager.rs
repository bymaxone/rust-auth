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
#[cfg(feature = "platform")]
use bymax_auth_types::{PlatformAuthResult, PlatformClaims, PlatformType, SafeAuthPlatformUser};

use crate::services::session::normalize_session_metadata;
use crate::services::{internal_error, is_refresh_token_shape, new_uuid_v4, now_offset, now_unix};
use crate::traits::{RotateOutcome, SessionKind, SessionRecord, SessionRotation, SessionStore};

/// MFA temp-token lifetime, in seconds (§7.3 constant `MFA_TEMP_TOKEN_TTL_SECONDS`).
const MFA_TEMP_TOKEN_TTL_SECONDS: i64 = 300;

/// The verified payload of an MFA temp token, returned by
/// [`TokenManagerService::verify_mfa_temp_token`]. The split verify/consume design means this
/// is produced **without** consuming the token, so a mistyped code stays retryable (§7.3.5).
#[cfg(feature = "mfa")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfaTempVerified {
    /// The challenged user id (the token `sub`, cross-checked against the `mfa:` marker).
    pub user_id: String,
    /// The identity domain the challenge targets (selects the repository downstream).
    pub context: MfaContext,
    /// The token id, used to consume the `mfa:` marker after the code is confirmed valid.
    pub jti: String,
}

/// The collaborators the MFA temp-token methods need beyond JWT signing: the single-use
/// `mfa:` marker store and the brute-force store/key for the per-user challenge counter
/// reset. Held as `Option` on the token manager so a build without a wired MFA store still
/// issues a (sign-only) challenge token; the store-backed single-use path engages only when
/// the support is present.
#[cfg(feature = "mfa")]
pub(crate) struct MfaTokenSupport {
    store: std::sync::Arc<dyn crate::traits::MfaStore>,
    brute_force: std::sync::Arc<dyn crate::traits::BruteForceStore>,
    challenge_hmac_key: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(feature = "mfa")]
impl MfaTokenSupport {
    /// Assemble the support bundle from the MFA store, the brute-force store, and the engine's
    /// derived identifier-hashing key (copied into a zeroizing buffer).
    pub(crate) fn new(
        store: std::sync::Arc<dyn crate::traits::MfaStore>,
        brute_force: std::sync::Arc<dyn crate::traits::BruteForceStore>,
        hmac_key: &[u8; 32],
    ) -> Self {
        Self {
            store,
            brute_force,
            challenge_hmac_key: zeroize::Zeroizing::new(*hmac_key),
        }
    }

    /// The hashed brute-force identifier for the per-user MFA-challenge counter
    /// (`hmac_sha256("challenge:{user_id}")`, hex). Namespaced as `challenge:` so it is
    /// isolated from the `disable:` counter the management ops use (§7.5.3).
    fn challenge_bf_id(&self, user_id: &str) -> String {
        crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            self.challenge_hmac_key.as_ref(),
            format!("challenge:{user_id}").as_bytes(),
        ))
    }
}

/// Hash an MFA temp-token `jti` into its `mfa:` marker key suffix (`sha256(jti)`, hex), so the
/// raw token id is never resident in the store.
#[cfg(feature = "mfa")]
fn jti_hash(jti: &str) -> String {
    crate::services::to_hex(&bymax_auth_crypto::mac::sha256(jti.as_bytes()))
}

/// Issues and rotates the dashboard token pair over the [`SessionStore`] seam. Platform
/// issuance (`SafeAuthPlatformUser`/`PlatformClaims`) is a separate identity surface and
/// is wired with the platform domain.
pub struct TokenManagerService {
    key: HsKey,
    session_store: Arc<dyn SessionStore>,
    access_ttl: Duration,
    refresh_ttl_secs: u64,
    grace_ttl_secs: u64,
    /// The MFA single-use temp-token support, wired only when an MFA store is supplied.
    #[cfg(feature = "mfa")]
    mfa: Option<MfaTokenSupport>,
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
            #[cfg(feature = "mfa")]
            mfa: None,
        }
    }

    /// Attach the MFA temp-token support (the single-use `mfa:` marker store and the
    /// brute-force counter reset), enabling the store-backed single-use challenge path. Set by
    /// the builder when an MFA store is wired.
    #[cfg(feature = "mfa")]
    pub(crate) fn with_mfa_support(mut self, support: MfaTokenSupport) -> Self {
        self.mfa = Some(support);
        self
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

        // Normalize the attacker-controlled metadata at the persistence point, so the stored
        // record matches what `list_sessions` and the new-session hook report (and the IP byte
        // bound actually reaches the store).
        let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
        let record = SessionRecord {
            user_id: user.id.clone(),
            tenant_id: Some(user.tenant_id.clone()),
            role: user.role.clone(),
            device,
            ip: stored_ip,
            created_at: now_offset(),
            // A fresh login opens a new refresh-token family; every rotation inherits this id,
            // so the whole lineage can be revoked together on reuse detection.
            family_id: new_uuid_v4(),
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
        // Reject a malformed/oversized token before hashing it — it could never match a
        // stored hash, and this caps the work an arbitrary input can force.
        if !is_refresh_token_shape(raw_refresh) {
            return Err(AuthError::RefreshTokenInvalid);
        }
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
            RotateOutcome::Reused(family) => {
                // A consumed refresh token was replayed after its grace window closed — the
                // signature of a stolen token. Revoke the whole family (every live descendant
                // of that login) so the thief's chain dies too, then reject: every holder must
                // re-authenticate (§12.5.2, OWASP rotation with automatic reuse detection).
                self.session_store
                    .revoke_family(SessionKind::Dashboard, &family)
                    .await?;
                Err(AuthError::RefreshTokenInvalid)
            }
            RotateOutcome::Invalid => Err(AuthError::RefreshTokenInvalid),
        }
    }

    /// Sign a platform access JWT (HS256). The claims carry NO `tenant_id` (the platform
    /// identity domain is never tenant-scoped) and a fresh `jti`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable for the
    /// crate's claim types).
    #[cfg(feature = "platform")]
    pub fn issue_platform_access(&self, claims: &PlatformClaims) -> Result<String, AuthError> {
        sign(claims, &self.key).map_err(signing_failed)
    }

    /// Issue a fresh platform access JWT plus an opaque refresh token for `admin`, persisting
    /// the refresh session in the **platform** keyspace ([`SessionKind::Platform`] →
    /// `prt`/`prp`/`psess`/`psd`). The minted [`PlatformClaims`] carry no `tenant_id`.
    /// `mfa_verified` flags whether this session cleared the second factor (always `false` at
    /// first issuance; `true` only after a platform MFA challenge succeeds).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if signing fails or the store rejects the session write.
    #[cfg(feature = "platform")]
    pub async fn issue_platform_tokens(
        &self,
        admin: &SafeAuthPlatformUser,
        ip: &str,
        user_agent: &str,
        mfa_verified: bool,
    ) -> Result<PlatformAuthResult, AuthError> {
        let refresh = RawRefreshToken::generate();
        let now = now_unix();
        let claims = PlatformClaims {
            sub: admin.id.clone(),
            jti: new_uuid_v4(),
            role: admin.role.clone(),
            token_type: PlatformType::Platform,
            mfa_enabled: admin.mfa_enabled,
            mfa_verified,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
        };
        let access_token = self.issue_platform_access(&claims)?;

        // The platform session record carries NO tenant scope (a platform admin is never
        // tenant-scoped). The device/IP are normalized at the persistence point, identically to
        // the dashboard path, so the stored record and any management projection agree.
        let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
        let record = SessionRecord {
            user_id: admin.id.clone(),
            tenant_id: None,
            role: admin.role.clone(),
            device,
            ip: stored_ip,
            created_at: now_offset(),
            // A fresh platform login opens a new refresh-token family (section 12.5.2).
            family_id: new_uuid_v4(),
        };
        self.session_store
            .create_session(
                SessionKind::Platform,
                &refresh.redis_hash(),
                &record,
                self.refresh_ttl_secs,
            )
            .await?;

        Ok(PlatformAuthResult {
            user: admin.clone(),
            access_token,
            refresh_token: refresh.expose_secret().to_owned(),
        })
    }

    /// Atomically rotate a presented platform refresh token into a fresh pair, honoring the
    /// grace window — the platform-keyspace analogue of [`Self::reissue_tokens`]. The rotation
    /// runs against [`SessionKind::Platform`] and the reissued access claims carry no
    /// `tenant_id`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RefreshTokenInvalid`] when the token is neither live nor inside the
    /// grace window, or a store/signing [`AuthError`] on failure.
    #[cfg(feature = "platform")]
    pub async fn reissue_platform_tokens(
        &self,
        raw_refresh: &str,
        ip: &str,
        user_agent: &str,
    ) -> Result<RotatedTokens, AuthError> {
        // Reject a malformed/oversized token before hashing it (it could never match a stored
        // hash and this caps attacker-forced work), mirroring the dashboard rotation.
        if !is_refresh_token_shape(raw_refresh) {
            return Err(AuthError::RefreshTokenInvalid);
        }
        let old = RawRefreshToken::from_raw(raw_refresh.to_owned());
        let old_hash = old.redis_hash();
        let new = RawRefreshToken::generate();

        let live = self
            .session_store
            .find_session(SessionKind::Platform, &old_hash)
            .await?;
        let seed = live.unwrap_or_else(|| placeholder_record(ip, user_agent));
        let new_record = platform_identity_record(&seed, ip, user_agent);

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
            .rotate(SessionKind::Platform, &rotation)
            .await?
        {
            RotateOutcome::Rotated(_old) => {
                let access_token =
                    self.issue_platform_access(&self.rotated_platform_claims(&new_record))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: new.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Grace(recovered) => {
                // Lost the rotation race: mint a fresh platform session for the recovered
                // identity rather than re-planting a grace pointer.
                let fresh = RawRefreshToken::generate();
                let fresh_record = platform_identity_record(&recovered, ip, user_agent);
                self.session_store
                    .create_session(
                        SessionKind::Platform,
                        &fresh.redis_hash(),
                        &fresh_record,
                        self.refresh_ttl_secs,
                    )
                    .await?;
                let access_token =
                    self.issue_platform_access(&self.rotated_platform_claims(&fresh_record))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: fresh.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Reused(family) => {
                // Post-grace replay of a consumed platform refresh token: revoke the whole
                // family and reject, the platform-keyspace analogue of the dashboard path.
                self.session_store
                    .revoke_family(SessionKind::Platform, &family)
                    .await?;
                Err(AuthError::RefreshTokenInvalid)
            }
            RotateOutcome::Invalid => Err(AuthError::RefreshTokenInvalid),
        }
    }

    /// Verify a platform access JWT (signature + algorithm + temporal, HS256-pinned) and reject
    /// it if its `jti` is blacklisted. The single-variant [`PlatformType`] discriminator means a
    /// dashboard token (whose `type` is `dashboard`) fails to deserialize here, so a dashboard
    /// JWT can never pass a platform verification.
    ///
    /// # Errors
    ///
    /// Returns the internal-only [`AuthError::TokenExpired`]/[`AuthError::TokenRevoked`] or the
    /// public [`AuthError::TokenInvalid`]; all collapse to `token_invalid` at the boundary.
    #[cfg(feature = "platform")]
    pub async fn verify_platform_access(&self, token: &str) -> Result<PlatformClaims, AuthError> {
        let claims = verify::<PlatformClaims>(token, &self.key, &VerifyOptions::default())
            .map_err(map_jwt_error)?;
        if self.session_store.is_blacklisted(&claims.jti).await? {
            return Err(AuthError::TokenRevoked);
        }
        Ok(claims)
    }

    /// Build the platform access claims for a rotated/recovered session. As with the dashboard
    /// rotation, `mfa_verified` is dropped (re-acquired only via the MFA challenge); the claims
    /// carry no `tenant_id`.
    #[cfg(feature = "platform")]
    fn rotated_platform_claims(&self, record: &SessionRecord) -> PlatformClaims {
        let now = now_unix();
        PlatformClaims {
            sub: record.user_id.clone(),
            jti: new_uuid_v4(),
            role: record.role.clone(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
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

    /// Build and sign a short-lived MFA temp token, returning the compact JWT and its `jti`.
    /// The JWT carries the `MfaTempClaims` bridging the password step and the second factor;
    /// the `jti` keys the single-use `mfa:` marker.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable for the
    /// concrete claim type).
    fn build_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<(String, String), AuthError> {
        let now = now_unix();
        let jti = new_uuid_v4();
        let claims = MfaTempClaims {
            sub: user_id.to_owned(),
            jti: jti.clone(),
            token_type: MfaTempType::MfaChallenge,
            context,
            iat: now,
            exp: now.saturating_add(MFA_TEMP_TOKEN_TTL_SECONDS),
        };
        let token = sign(&claims, &self.key).map_err(signing_failed)?;
        Ok((token, jti))
    }

    /// Issue a short-lived MFA temp token bridging the password step and the second factor
    /// (build-only fallback for a build without a wired MFA store: the signed challenge JWT is
    /// returned, but no single-use `mfa:` marker is planted).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable).
    #[cfg(not(feature = "mfa"))]
    pub async fn issue_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<String, AuthError> {
        Ok(self.build_mfa_temp_token(user_id, context)?.0)
    }

    /// Issue a short-lived MFA temp token bridging the password step and the second factor.
    /// When the single-use support is wired this signs the challenge JWT, plants the
    /// single-use `mfa:{sha256(jti)}` marker (300 s), and resets the per-user MFA-challenge
    /// brute-force counter (a fresh login restarts the challenge budget; §7.3.5). Without the
    /// support it falls back to signing only.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] if signing fails (unreachable), or a store
    /// [`AuthError`] if planting the marker or resetting the counter fails.
    #[cfg(feature = "mfa")]
    pub async fn issue_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<String, AuthError> {
        let (token, jti) = self.build_mfa_temp_token(user_id, context)?;
        if let Some(support) = &self.mfa {
            support
                .store
                .put_temp(
                    &jti_hash(&jti),
                    user_id,
                    MFA_TEMP_TOKEN_TTL_SECONDS.unsigned_abs(),
                )
                .await?;
            // A fresh login proves renewed password possession, so the challenge counter
            // restarts from zero. The `disable:` counter is a separate namespace and is left
            // untouched, so a pre-auth attacker can neither lock out nor clear the
            // authenticated user's management-op budget.
            support
                .brute_force
                .reset(&support.challenge_bf_id(user_id))
                .await?;
        }
        Ok(token)
    }

    /// Verify an MFA temp token (signature + expiry, HS256-pinned) and confirm its single-use
    /// `mfa:` marker is still present, **without** consuming it. The split verify/consume
    /// keeps the token alive for a retry on a mistyped code (§7.3.5): an atomic `GETDEL` here
    /// would dead-end the retry as `MfaTempTokenInvalid` instead of the retryable
    /// `MfaInvalidCode`. Cross-checks the stored `user_id` against the token `sub` in constant
    /// time (defense in depth).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] for any malformed, mis-signed, or expired
    /// token, an absent/expired marker, or a `user_id`/`sub` mismatch, or a store
    /// [`AuthError`] on a backend failure.
    #[cfg(feature = "mfa")]
    pub async fn verify_mfa_temp_token(&self, token: &str) -> Result<MfaTempVerified, AuthError> {
        let claims = verify::<MfaTempClaims>(token, &self.key, &VerifyOptions::default())
            .map_err(|_| AuthError::MfaTempTokenInvalid)?;
        let Some(support) = &self.mfa else {
            return Err(AuthError::MfaTempTokenInvalid);
        };
        // GET (never GETDEL) the marker so a retry stays possible within the token's TTL.
        let Some(stored_user) = support.store.get_temp(&jti_hash(&claims.jti)).await? else {
            return Err(AuthError::MfaTempTokenInvalid);
        };
        // Defense in depth: the marker must name the same user as the token subject.
        if !bymax_auth_crypto::compare::constant_time_eq(
            stored_user.as_bytes(),
            claims.sub.as_bytes(),
        ) {
            return Err(AuthError::MfaTempTokenInvalid);
        }
        Ok(MfaTempVerified {
            user_id: claims.sub,
            context: claims.context,
            jti: claims.jti,
        })
    }

    /// Consume an MFA temp token by deleting its `mfa:{sha256(jti)}` marker. Idempotent, and
    /// called only after the submitted code is confirmed valid (§7.5.3). For the TOTP path the
    /// consume is fused with the anti-replay mark in a single atomic step
    /// ([`crate::traits::MfaStore::challenge_consume`]); this standalone form serves the
    /// recovery-code path, whose code carries no `tu:` marker.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] when no single-use support is wired, or a
    /// store [`AuthError`] on a backend failure.
    #[cfg(feature = "mfa")]
    pub async fn consume_mfa_temp_token(&self, jti: &str) -> Result<(), AuthError> {
        let Some(support) = &self.mfa else {
            return Err(AuthError::MfaTempTokenInvalid);
        };
        support.store.del_temp(&jti_hash(jti)).await
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
/// stamping the current device/IP/time. The device/IP are normalized at this persistence
/// point (parsed UA + byte-bounded IP) so a rotated record matches what `list_sessions` and
/// the session hooks report.
fn identity_record(seed: &SessionRecord, ip: &str, user_agent: &str) -> SessionRecord {
    let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
    SessionRecord {
        user_id: seed.user_id.clone(),
        tenant_id: seed.tenant_id.clone(),
        role: seed.role.clone(),
        device,
        ip: stored_ip,
        created_at: now_offset(),
        // Rotation inherits the seed's family unchanged, so every descendant of one login
        // shares the id and the whole lineage is revocable together on reuse detection.
        family_id: seed.family_id.clone(),
    }
}

/// Build a fresh platform refresh-session record for a rotation, carrying the seed identity and
/// stamping the current device/IP/time. A platform record never carries a tenant scope, so
/// `tenant_id` is forced to `None` regardless of the seed (defense in depth: even a seed that
/// somehow held a tenant cannot leak one onto a platform session).
#[cfg(feature = "platform")]
fn platform_identity_record(seed: &SessionRecord, ip: &str, user_agent: &str) -> SessionRecord {
    let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
    SessionRecord {
        user_id: seed.user_id.clone(),
        tenant_id: None,
        role: seed.role.clone(),
        device,
        ip: stored_ip,
        created_at: now_offset(),
        // The platform rotation inherits the seed's family unchanged (section 12.5.2).
        family_id: seed.family_id.clone(),
    }
}

/// A placeholder identity used only when the live old token is absent; the rotation never
/// stores it (an absent live token can only yield Grace or Invalid), so its empty identity
/// is never observed. The device/IP are still normalized for consistency with the records
/// that are persisted.
fn placeholder_record(ip: &str, user_agent: &str) -> SessionRecord {
    let (device, stored_ip) = normalize_session_metadata(user_agent, ip);
    SessionRecord {
        user_id: String::new(),
        tenant_id: None,
        role: String::new(),
        device,
        ip: stored_ip,
        created_at: now_offset(),
        // The placeholder is never stored (an absent live token yields only Grace/Reused/Invalid),
        // so it carries no family.
        family_id: String::new(),
    }
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

        // A well-formed but never-issued token passes the shape guard, misses the store on
        // both the live and grace lookups, and is rejected as invalid.
        let unissued = "f".repeat(64);
        assert!(matches!(
            svc.reissue_tokens(&unissued, "10.0.0.1", "agent/1.0").await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        // A malformed/oversized token is rejected by the shape guard before any hashing.
        assert!(matches!(
            svc.reissue_tokens("too-short", "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn reused_refresh_token_after_grace_revokes_the_whole_family() {
        // Issue → rotate (the old token is consumed, a grace pointer planted). Drop the grace
        // pointer to simulate the grace window closing. Replaying the consumed old token is now
        // caught as a reuse: it is rejected AND the whole family is revoked, so the live rotated
        // token can no longer rotate either — a stolen token cannot keep a parallel chain alive.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let rotated = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };
        // The freshly rotated token is live right up until the reuse is detected.
        assert!(
            store
                .find_session(SessionKind::Dashboard, &rotated_hash(&rotated))
                .await
                .is_ok()
        );
        // Simulate the grace window elapsing so the old token is no longer grace-recoverable.
        assert!(
            store
                .delete_grace_pointer(SessionKind::Dashboard, &old_hash)
                .await
                .is_ok()
        );
        // Replaying the consumed old token is rejected as a detected reuse...
        assert!(matches!(
            svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        // ...and the reuse revoked the whole family, so the live rotated token no longer rotates.
        assert!(matches!(
            svc.reissue_tokens(&rotated.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    /// The store hash of a rotated pair's refresh token.
    fn rotated_hash(rotated: &RotatedTokens) -> String {
        RawRefreshToken::from_raw(rotated.refresh_token.clone()).redis_hash()
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn reused_platform_refresh_token_after_grace_revokes_the_family() {
        // The platform-keyspace analogue: a replayed consumed platform refresh token, past its
        // grace window, is rejected as a reuse and revokes the whole platform family.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let rotated = svc
            .reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };
        assert!(
            store
                .delete_grace_pointer(SessionKind::Platform, &old_hash)
                .await
                .is_ok()
        );
        assert!(matches!(
            svc.reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        assert!(matches!(
            svc.reissue_platform_tokens(&rotated.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
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

    #[cfg(feature = "platform")]
    fn platform_admin() -> SafeAuthPlatformUser {
        SafeAuthPlatformUser {
            id: "p1".to_owned(),
            email: "admin@example.com".to_owned(),
            name: "Admin".to_owned(),
            role: "SUPER_ADMIN".to_owned(),
            status: "ACTIVE".to_owned(),
            mfa_enabled: false,
            platform_id: None,
            last_login_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn platform_issue_carries_no_tenant_and_round_trips() {
        // Platform issuance mints an access JWT whose claims carry NO tenant_id, persists the
        // refresh session in the PLATFORM keyspace, and the token verifies through the manager.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        assert!(issued.is_ok());
        let Ok(issued) = issued else { return };
        let claims = svc.verify_platform_access(&issued.access_token).await;
        assert!(matches!(&claims, Ok(c) if c.sub == "p1" && c.role == "SUPER_ADMIN"));
        // The serialized claims must NOT carry a tenantId field at all.
        let body = issued.access_token.split('.').nth(1).unwrap_or_default();
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap_or_default();
        let json = String::from_utf8(decoded).unwrap_or_default();
        assert!(json.contains("\"type\":\"platform\""));
        assert!(!json.contains("tenantId"));

        // The refresh session landed in the PLATFORM keyspace, not the dashboard one.
        let hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        assert!(matches!(
            store.find_session(SessionKind::Platform, &hash).await,
            Ok(Some(_))
        ));
        assert!(matches!(
            store.find_session(SessionKind::Dashboard, &hash).await,
            Ok(None)
        ));
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn a_dashboard_token_never_verifies_as_a_platform_token_and_vice_versa() {
        // The single-variant discriminators isolate the two token families: a dashboard JWT
        // fails platform verification, and a platform JWT fails dashboard verification.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let issued_dash = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(dash) = issued_dash else { return };
        assert!(matches!(
            svc.verify_platform_access(&dash.access_token).await,
            Err(AuthError::TokenInvalid)
        ));
        let issued_plat = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(plat) = issued_plat else { return };
        assert!(matches!(
            svc.verify_access(&plat.access_token).await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn platform_rotation_produces_a_new_pair_and_grace_absorbs_a_retry() {
        // Platform rotation mirrors the dashboard one over the platform keyspace: the first
        // rotation consumes the old token, a concurrent retry hits the grace window, and a
        // never-issued / malformed token is rejected.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let issued_res = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued_res else { return };
        let rotated = svc
            .reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        assert!(matches!(&rotated, Ok(r) if r.refresh_token != issued.refresh_token));
        let Ok(rotated) = rotated else { return };
        // The rotated platform access token verifies and carries the platform role.
        assert!(matches!(
            svc.verify_platform_access(&rotated.access_token).await,
            Ok(c) if c.role == "SUPER_ADMIN"
        ));
        // Replaying the original token lands in the grace window and still succeeds.
        assert!(
            svc.reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await
                .is_ok()
        );
        // A never-issued (well-formed) token misses both lookups; a malformed one is rejected
        // by the shape guard before any hashing.
        assert!(matches!(
            svc.reissue_platform_tokens(&"f".repeat(64), "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        assert!(matches!(
            svc.reissue_platform_tokens("too-short", "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn platform_blacklist_rejects_a_revoked_access_token() {
        // Revoking a platform access jti makes verify_platform_access report the internal-only
        // token_revoked, the same revocation path the dashboard token uses.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let issued_res = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued_res else { return };
        let claims_res = svc.verify_platform_access(&issued.access_token).await;
        let Ok(claims) = claims_res else { return };
        assert!(svc.revoke_access(&claims.jti, 900).await.is_ok());
        assert!(matches!(
            svc.verify_platform_access(&issued.access_token).await,
            Err(AuthError::TokenRevoked)
        ));
    }

    #[tokio::test]
    async fn mfa_temp_token_is_signed_as_a_compact_jwt() {
        // Issuing a challenge token (no MFA store wired) signs a compact three-segment JWT;
        // this is the sign-only path a build without a single-use store falls back to.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let issued = svc.issue_mfa_temp_token("u1", MfaContext::Dashboard).await;
        assert!(matches!(&issued, Ok(t) if t.matches('.').count() == 2));
    }

    #[cfg(feature = "mfa")]
    fn service_with_mfa(store: Arc<InMemoryStores>) -> TokenManagerService {
        // A token manager whose MFA support is backed by the in-memory stores (which satisfy
        // both the MFA-marker and brute-force seams), under a fixed identifier-hashing key.
        let brute_force: Arc<dyn crate::traits::BruteForceStore> = store.clone();
        let mfa_store: Arc<dyn crate::traits::MfaStore> = store.clone();
        let support = MfaTokenSupport::new(mfa_store, brute_force, &[7u8; 32]);
        TokenManagerService::new(
            key(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
        )
        .with_mfa_support(support)
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn store_backed_temp_token_issues_verifies_non_consuming_and_consumes() {
        // With the single-use support wired: issue plants the `mfa:` marker and the
        // non-consuming verify returns the payload twice (a mistyped digit stays retryable);
        // consume then deletes the marker (idempotently), after which verify fails.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store);
        let Ok(token) = svc.issue_mfa_temp_token("u1", MfaContext::Dashboard).await else { return };
        let first = svc.verify_mfa_temp_token(&token).await;
        assert!(matches!(&first, Ok(v) if v.user_id == "u1"
            && v.context == MfaContext::Dashboard && v.jti.len() == 36));
        // Verify is non-consuming: a second verify still succeeds.
        assert!(svc.verify_mfa_temp_token(&token).await.is_ok());
        let Ok(verified) = first else { return };
        // Consume is idempotent: the first deletes the marker, the second is a no-op.
        assert!(svc.consume_mfa_temp_token(&verified.jti).await.is_ok());
        assert!(svc.consume_mfa_temp_token(&verified.jti).await.is_ok());
        // After consume the marker is gone, so verify now fails.
        assert!(matches!(
            svc.verify_mfa_temp_token(&token).await,
            Err(AuthError::MfaTempTokenInvalid)
        ));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn store_backed_verify_rejects_garbage_and_a_subject_mismatch() {
        // A malformed token is rejected before any store read; a marker naming a different
        // user than the token subject fails the constant-time cross-check.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store.clone());
        assert!(matches!(
            svc.verify_mfa_temp_token("garbage").await,
            Err(AuthError::MfaTempTokenInvalid)
        ));
        // Mint a token for "u1" but point its marker at "intruder": the cross-check rejects it.
        let built = svc.build_mfa_temp_token("u1", MfaContext::Dashboard);
        let Ok((token, jti)) = built else { return };
        let mfa_store: Arc<dyn crate::traits::MfaStore> = store;
        assert!(
            mfa_store
                .put_temp(&jti_hash(&jti), "intruder", 300)
                .await
                .is_ok()
        );
        assert!(matches!(
            svc.verify_mfa_temp_token(&token).await,
            Err(AuthError::MfaTempTokenInvalid)
        ));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn temp_token_methods_fail_closed_without_a_wired_store() {
        // Without the single-use support, issue falls back to a sign-only token (no marker),
        // and verify/consume fail closed as `MfaTempTokenInvalid` rather than panicking.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store); // `service` leaves the MFA support unset.
        let Ok(token) = svc.issue_mfa_temp_token("u1", MfaContext::Dashboard).await else { return };
        assert!(matches!(
            svc.verify_mfa_temp_token(&token).await,
            Err(AuthError::MfaTempTokenInvalid)
        ));
        assert!(matches!(
            svc.consume_mfa_temp_token("some-jti").await,
            Err(AuthError::MfaTempTokenInvalid)
        ));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn issue_resets_only_the_challenge_brute_force_namespace() {
        // Issuing a fresh temp token clears the `challenge:` counter (a fresh login restarts
        // the MFA budget) while leaving the `disable:` counter untouched, so the two
        // namespaces are isolated.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store.clone());
        let bf: Arc<dyn crate::traits::BruteForceStore> = store.clone();
        let key_bytes = [7u8; 32];
        let challenge_id = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            &key_bytes,
            b"challenge:u1",
        ));
        let disable_id = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            &key_bytes,
            b"disable:u1",
        ));
        // Seed both counters to the lockout threshold.
        for _ in 0..5 {
            assert!(bf.record_failure(&challenge_id, 900).await.is_ok());
            assert!(bf.record_failure(&disable_id, 900).await.is_ok());
        }
        assert!(matches!(bf.is_locked(&challenge_id, 5).await, Ok(true)));
        assert!(matches!(bf.is_locked(&disable_id, 5).await, Ok(true)));
        // Issuing a token resets the challenge counter only.
        assert!(
            svc.issue_mfa_temp_token("u1", MfaContext::Dashboard)
                .await
                .is_ok()
        );
        assert!(matches!(bf.is_locked(&challenge_id, 5).await, Ok(false)));
        assert!(matches!(bf.is_locked(&disable_id, 5).await, Ok(true)));
    }
}
