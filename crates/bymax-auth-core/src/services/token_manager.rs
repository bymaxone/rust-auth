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
    AuthError, AuthResult, DashboardClaims, DashboardType, MfaContext, MfaTempClaims,
    RotatedTokens, SafeAuthUser,
};
// Only the token-building path names the discriminant, and that path is `mfa`-gated: a build
// without the feature refuses the challenge rather than signing one nothing can redeem.
#[cfg(feature = "mfa")]
use bymax_auth_types::MfaTempType;
#[cfg(feature = "platform")]
use bymax_auth_types::{PlatformAuthResult, PlatformClaims, PlatformType, SafeAuthPlatformUser};

use crate::services::session::normalize_session_metadata;
use crate::services::{internal_error, is_refresh_token_shape, new_uuid_v4, now_offset, now_unix};
use crate::traits::{
    AuthHooks, HookContext, RotateOutcome, SessionKind, SessionRecord, SessionRotation,
    SessionStore,
};

/// MFA temp-token lifetime, in seconds (§7.3 constant `MFA_TEMP_TOKEN_TTL_SECONDS`).
///
/// Feature-gated with the only thing that mints one: a build without `mfa` refuses the
/// challenge rather than signing a token nothing can redeem, so nothing here reads it.
#[cfg(feature = "mfa")]
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

/// The collaborator the MFA temp-token methods need beyond JWT signing: the single-use
/// `mfa:` marker store. Held as `Option` on the token manager so a build without a wired MFA
/// store still issues a (sign-only) challenge token; the store-backed single-use path engages
/// only when the support is present.
///
/// It once also carried the brute-force store and identifier key, to clear the per-user
/// challenge counter on every issuance. That reset is gone — it made the per-account MFA
/// lockout unreachable for an attacker who holds the password — so the counter is owned
/// entirely by `MfaService`, which clears it on a successful challenge and nowhere else.
#[cfg(feature = "mfa")]
pub(crate) struct MfaTokenSupport {
    store: std::sync::Arc<dyn crate::traits::MfaStore>,
}

#[cfg(feature = "mfa")]
impl MfaTokenSupport {
    /// Assemble the support bundle from the MFA store.
    pub(crate) fn new(store: std::sync::Arc<dyn crate::traits::MfaStore>) -> Self {
        Self { store }
    }
}

/// Hash an MFA temp-token `jti` into its `mfa:` marker key suffix (`sha256(jti)`, hex), so the
/// raw token id is never resident in the store.
#[cfg(feature = "mfa")]
fn jti_hash(jti: &str) -> String {
    crate::services::to_hex(&bymax_auth_crypto::mac::sha256(jti.as_bytes()))
}

/// The `iss`/`aud` pair a deployment binds its tokens to, or neither.
///
/// Absent by default, so an existing deployment is unchanged. Both backends sharing a
/// deployment must carry the same pair or they stop accepting each other's tokens, which is
/// the one way this setting can split them — and the reason it is opt-in.
#[derive(Clone, Debug, Default)]
pub(crate) struct TokenBinding {
    /// The `iss` to stamp and require.
    pub issuer: Option<String>,
    /// The `aud` to stamp and require.
    pub audience: Option<String>,
}

/// Claims that can carry the binding. Implemented for the three minted shapes so one helper
/// stamps them all — a shape the stamping skipped would be a shape the verifier rejects.
pub(crate) trait Stampable {
    /// A copy of these claims carrying `iss`/`aud`.
    fn stamped(&self, issuer: Option<String>, audience: Option<String>) -> Self;
}

impl Stampable for DashboardClaims {
    fn stamped(&self, issuer: Option<String>, audience: Option<String>) -> Self {
        Self {
            iss: issuer,
            aud: audience,
            ..self.clone()
        }
    }
}

// Gated with the type it stamps: `PlatformClaims` only exists under the `platform` feature,
// and the feature matrix builds every combination.
#[cfg(feature = "platform")]
impl Stampable for PlatformClaims {
    fn stamped(&self, issuer: Option<String>, audience: Option<String>) -> Self {
        Self {
            iss: issuer,
            aud: audience,
            ..self.clone()
        }
    }
}

impl Stampable for MfaTempClaims {
    fn stamped(&self, issuer: Option<String>, audience: Option<String>) -> Self {
        Self {
            iss: issuer,
            aud: audience,
            ..self.clone()
        }
    }
}

/// Issues and rotates the dashboard token pair over the [`SessionStore`] seam. Platform
/// issuance (`SafeAuthPlatformUser`/`PlatformClaims`) is a separate identity surface and
/// is wired with the platform domain.
pub struct TokenManagerService {
    key: HsKey,
    /// Keys retired by a rotation, tried only after [`Self::key`] and only to verify. Empty
    /// unless a rotation is in progress; nothing is ever signed under one.
    previous_keys: Vec<HsKey>,
    session_store: Arc<dyn SessionStore>,
    access_ttl: Duration,
    refresh_ttl_secs: u64,
    grace_ttl_secs: u64,
    absolute_lifetime_secs: u64,
    /// The consumer's hooks, and the only reason this otherwise dependency-light service
    /// knows about them: refresh-token reuse is detected here and nowhere else, and it is the
    /// strongest evidence of compromise the library produces. Routing it out through the
    /// error would lose the family id, and losing it leaves a consumer with nothing to
    /// correlate against — every replay would look like any other invalid token.
    hooks: Arc<dyn AuthHooks>,
    /// The `iss`/`aud` pair to stamp and to require, empty when the deployment configured
    /// neither. Held here so the sign and the verify sides read the same value — a token
    /// stamped with an issuer the verifier does not require, or required where none is
    /// stamped, is a deployment that rejects its own tokens.
    binding: TokenBinding,
    /// The MFA single-use temp-token support, wired only when an MFA store is supplied.
    #[cfg(feature = "mfa")]
    mfa: Option<MfaTokenSupport>,
}

impl TokenManagerService {
    /// Verify a token against the current signing key, then against any retired by a rotation.
    ///
    /// The current key is always tried first, so the common path costs exactly what it did
    /// before. Retired keys verify only — nothing is ever signed under one, which is what makes
    /// a rotation one-way — and every other check the verifier makes (algorithm pinning,
    /// expiry, claim decoding) still applies to them, so a retired key buys a token nothing but
    /// signature acceptance.
    ///
    /// Every failure is the current key's failure: reporting *which* key rejected the token
    /// would tell an attacker whether a forgery was made under a key the deployment used to
    /// hold.
    fn verify_rotating<C: serde::de::DeserializeOwned + bymax_auth_jwt::JwtClaims>(
        &self,
        token: &str,
    ) -> Result<C, bymax_auth_jwt::JwtError> {
        self.verify_rotating_with(token, &VerifyOptions::default())
    }

    /// [`Self::verify_rotating`] under caller-chosen options, so one caller can waive the
    /// expiry check without every other verification inheriting that.
    fn verify_rotating_with<C: serde::de::DeserializeOwned + bymax_auth_jwt::JwtClaims>(
        &self,
        token: &str,
        opts: &VerifyOptions,
    ) -> Result<C, bymax_auth_jwt::JwtError> {
        // The configured binding travels INTO the verifier rather than being re-checked after
        // it. There is one rule and one implementation of it, which is what lets the edge — a
        // `wasm32` build that calls `bymax_auth_jwt::verify` directly, with no engine behind it
        // — apply the same `iss`/`aud` check the native server does.
        let opts = VerifyOptions {
            expected_iss: self.binding.issuer.as_deref(),
            expected_aud: self.binding.audience.as_deref(),
            ..*opts
        };
        let current = verify::<C>(token, &self.key, &opts);
        if current.is_ok() || self.previous_keys.is_empty() {
            return current;
        }
        for key in &self.previous_keys {
            // A retired signing key buys a signature acceptance and nothing else — the binding
            // is checked inside `verify`, so it still has to hold.
            if let Ok(claims) = verify::<C>(token, key, &opts) {
                return Ok(claims);
            }
        }
        current
    }

    /// Verify an access token's signature under the pinned algorithm while **ignoring its
    /// expiry**.
    ///
    /// Exactly one caller wants this: logout. An access token that expired while the user was
    /// away is the normal case there, and refusing the request leaves the refresh session —
    /// the long-lived credential logout exists to kill — alive for its whole lifetime. The
    /// signature still has to hold: the payload's `jti` decides which token gets blacklisted,
    /// so reading it unverified would let a caller revoke an access token they do not own by
    /// naming its id. The blacklist and epoch checks are skipped too: an already-revoked token
    /// is exactly the one whose owner is trying to finish signing out.
    ///
    /// # Errors
    ///
    /// [`AuthError`] when no configured signing key accepts the token.
    pub fn verify_access_ignoring_expiry(&self, token: &str) -> Result<DashboardClaims, AuthError> {
        self.verify_rotating_with::<DashboardClaims>(
            token,
            &VerifyOptions {
                validate_exp: false,
                ..VerifyOptions::default()
            },
        )
        .map_err(map_jwt_error)
    }

    /// The platform twin of [`TokenManagerService::verify_access_ignoring_expiry`], for the
    /// same single caller: logout.
    ///
    /// An operator who walks away for longer than the access-token lifetime and then signs out
    /// is the ordinary case, and refusing them leaves the refresh session of the
    /// highest-privilege identity in the system alive on a console they believed they had left.
    ///
    /// # Errors
    ///
    /// [`AuthError`] when no configured signing key accepts the token.
    #[cfg(feature = "platform")]
    pub fn verify_platform_access_ignoring_expiry(
        &self,
        token: &str,
    ) -> Result<PlatformClaims, AuthError> {
        self.verify_rotating_with::<PlatformClaims>(
            token,
            &VerifyOptions {
                validate_exp: false,
                ..VerifyOptions::default()
            },
        )
        .map_err(map_jwt_error)
    }

    /// Assemble the token manager from the signing key, the session store, and the
    /// resolved token lifetimes.
    pub(crate) fn new(
        key: HsKey,
        previous_keys: Vec<HsKey>,
        session_store: Arc<dyn SessionStore>,
        access_ttl: Duration,
        refresh_expires_in_days: u32,
        grace_window: Duration,
        absolute_session_lifetime_days: u32,
    ) -> Self {
        Self {
            key,
            previous_keys,
            session_store,
            access_ttl,
            refresh_ttl_secs: u64::from(refresh_expires_in_days) * 86_400,
            grace_ttl_secs: grace_window.as_secs(),
            absolute_lifetime_secs: u64::from(absolute_session_lifetime_days) * 86_400,
            hooks: Arc::new(crate::traits::NoOpAuthHooks),
            binding: TokenBinding::default(),
            #[cfg(feature = "mfa")]
            mfa: None,
        }
    }

    /// Install the consumer's hooks, so reuse detection can report itself.
    ///
    /// Separate from [`Self::new`] rather than a parameter, because the hooks are defaulted
    /// late in the builder (after the OAuth wiring check) and every other caller — the tests
    /// included — has no interest in them.
    #[must_use]
    pub(crate) fn with_hooks(mut self, hooks: Arc<dyn AuthHooks>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Bind every token this service mints — and every one it accepts — to an issuer and an
    /// audience.
    ///
    /// Absent by default. With HS256 the verifier can also sign, so audience binding is what
    /// stops a token minted for one service being replayed at another that trusts the same
    /// secret; issuer binding is what a verifier needs when it is not the issuer.
    #[must_use]
    pub(crate) fn with_binding(mut self, binding: TokenBinding) -> Self {
        self.binding = binding;
        self
    }

    /// Stamp the configured pair onto claims about to be signed.
    fn stamp<C: Stampable>(&self, claims: &C) -> C {
        claims.stamped(self.binding.issuer.clone(), self.binding.audience.clone())
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
        sign(&self.stamp(claims), &self.key).map_err(signing_failed)
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
        // Stamp the user's current token epoch so a later bump (a reset or sign-out-everywhere)
        // invalidates this token at verification.
        let epoch = self
            .session_store
            .current_epoch(SessionKind::Dashboard, &user.id)
            .await?;
        let claims = DashboardClaims {
            iss: None,
            aud: None,
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
            epoch,
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
            mfa_enabled: user.mfa_enabled,
            // A fresh login opens a new refresh-token family; every rotation inherits this id,
            // so the whole lineage can be revoked together on reuse detection.
            family_id: new_uuid_v4(),
            // …and stamps the lineage's birth, which the absolute-lifetime cap measures from.
            family_created_at: Some(now_offset()),
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
        self.assert_within_absolute_lifetime(&seed)?;
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
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Dashboard, &new_record.user_id)
                    .await?;
                let access_token = self.issue_access(&self.rotated_claims(&new_record, epoch))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: new.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Grace(recovered) => {
                // The cap is measured again here, against the RECOVERED record. The check
                // before the script ran against the seed — and on this path the seed is the
                // placeholder used when the live key is already gone, whose `family_created_at`
                // is `None`, so that check returned early and applied nothing. Without this
                // second check a lineage that had just passed its absolute cap could still mint
                // a fresh access token and a full-length refresh session by presenting a token
                // inside its grace window: the cap ends normal rotation and the one remaining
                // door stays open.
                self.assert_within_absolute_lifetime(&recovered)?;
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
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Dashboard, &fresh_record.user_id)
                    .await?;
                let access_token = self.issue_access(&self.rotated_claims(&fresh_record, epoch))?;
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
                tracing::warn!(
                    "refresh: reuse of a consumed refresh token detected — revoking the token family"
                );
                // The owner comes back from the revocation, and can come from nowhere
                // else: the replayed token's own key was deleted when it was rotated, so
                // the family index is the last surviving link to an account.
                let owner = self
                    .session_store
                    .revoke_family(SessionKind::Dashboard, &family)
                    .await?;
                self.fire_reuse_detected(owner.as_deref(), &family).await;
                Err(AuthError::RefreshTokenInvalid)
            }
            RotateOutcome::Invalid => {
                tracing::warn!("refresh: no live session or grace window for the presented token");
                Err(AuthError::RefreshTokenInvalid)
            }
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
        sign(&self.stamp(claims), &self.key).map_err(signing_failed)
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
        let epoch = self
            .session_store
            .current_epoch(SessionKind::Platform, &admin.id)
            .await?;
        let claims = PlatformClaims {
            iss: None,
            aud: None,
            sub: admin.id.clone(),
            jti: new_uuid_v4(),
            role: admin.role.clone(),
            token_type: PlatformType::Platform,
            mfa_enabled: admin.mfa_enabled,
            mfa_verified,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            epoch,
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
            mfa_enabled: admin.mfa_enabled,
            // A fresh platform login opens a new refresh-token family (section 12.5.2).
            family_id: new_uuid_v4(),
            family_created_at: Some(now_offset()),
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
            admin: admin.clone(),
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
        self.assert_within_absolute_lifetime(&seed)?;
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
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Platform, &new_record.user_id)
                    .await?;
                let access_token =
                    self.issue_platform_access(&self.rotated_platform_claims(&new_record, epoch))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: new.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Grace(recovered) => {
                // The cap is measured again here, against the RECOVERED record. The check
                // before the script ran against the seed — and on this path the seed is the
                // placeholder used when the live key is already gone, whose `family_created_at`
                // is `None`, so that check returned early and applied nothing. Without this
                // second check a lineage that had just passed its absolute cap could still mint
                // a fresh access token and a full-length refresh session by presenting a token
                // inside its grace window: the cap ends normal rotation and the one remaining
                // door stays open.
                self.assert_within_absolute_lifetime(&recovered)?;
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
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Platform, &fresh_record.user_id)
                    .await?;
                let access_token = self
                    .issue_platform_access(&self.rotated_platform_claims(&fresh_record, epoch))?;
                Ok(RotatedTokens {
                    access_token,
                    refresh_token: fresh.expose_secret().to_owned(),
                })
            }
            RotateOutcome::Reused(family) => {
                // Post-grace replay of a consumed platform refresh token: revoke the whole
                // family and reject, the platform-keyspace analogue of the dashboard path.
                tracing::warn!(
                    "platform refresh: reuse of a consumed refresh token detected — revoking the token family"
                );
                // The owner comes back from the revocation, and can come from nowhere
                // else: the replayed token's own key was deleted when it was rotated, so
                // the family index is the last surviving link to an account.
                let owner = self
                    .session_store
                    .revoke_family(SessionKind::Platform, &family)
                    .await?;
                self.fire_reuse_detected(owner.as_deref(), &family).await;
                Err(AuthError::RefreshTokenInvalid)
            }
            RotateOutcome::Invalid => {
                tracing::warn!(
                    "platform refresh: no live session or grace window for the presented token"
                );
                Err(AuthError::RefreshTokenInvalid)
            }
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
        let claims = self
            .verify_rotating::<PlatformClaims>(token)
            .map_err(map_jwt_error)?;
        if self.session_store.is_blacklisted(&claims.jti).await? {
            return Err(AuthError::TokenRevoked);
        }
        // A token stamped below the admin's current epoch predates an invalidating event (a
        // password reset or sign-out-everywhere) and is revoked.
        if claims.epoch
            < self
                .session_store
                .current_epoch(SessionKind::Platform, &claims.sub)
                .await?
        {
            return Err(AuthError::TokenRevoked);
        }
        Ok(claims)
    }

    /// Build the platform access claims for a rotated/recovered session. As with the dashboard
    /// rotation, `mfa_verified` is dropped (re-acquired only via the MFA challenge) while
    /// `mfa_enabled` is carried over from the stored record; the claims carry no `tenant_id`.
    /// The `epoch` is the admin's current generation, read at rotation time.
    #[cfg(feature = "platform")]
    fn rotated_platform_claims(&self, record: &SessionRecord, epoch: u64) -> PlatformClaims {
        let now = now_unix();
        PlatformClaims {
            iss: None,
            aud: None,
            sub: record.user_id.clone(),
            jti: new_uuid_v4(),
            role: record.role.clone(),
            token_type: PlatformType::Platform,
            mfa_enabled: record.mfa_enabled,
            mfa_verified: false,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            epoch,
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
        let claims = self
            .verify_rotating::<DashboardClaims>(token)
            .map_err(map_jwt_error)?;
        if self.session_store.is_blacklisted(&claims.jti).await? {
            return Err(AuthError::TokenRevoked);
        }
        // A token stamped below the user's current epoch predates an invalidating event (a
        // password reset or sign-out-everywhere) and is revoked.
        if claims.epoch
            < self
                .session_store
                .current_epoch(SessionKind::Dashboard, &claims.sub)
                .await?
        {
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
    ///
    /// Feature-gated: a build without `mfa` refuses the challenge rather than signing a token
    /// nothing can redeem, so it has no reason to build one.
    #[cfg(feature = "mfa")]
    fn build_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<(String, String), AuthError> {
        let now = now_unix();
        let jti = new_uuid_v4();
        let claims = MfaTempClaims {
            iss: None,
            aud: None,
            sub: user_id.to_owned(),
            jti: jti.clone(),
            token_type: MfaTempType::MfaChallenge,
            context,
            iat: now,
            exp: now.saturating_add(MFA_TEMP_TOKEN_TTL_SECONDS),
        };
        let token = sign(&self.stamp(&claims), &self.key).map_err(signing_failed)?;
        Ok((token, jti))
    }

    /// Refuse to issue an MFA challenge in a build compiled without the `mfa` feature.
    ///
    /// This used to sign and return the challenge JWT anyway. Nothing could redeem it: the
    /// verification surface is not compiled in, so an account whose stored `mfa_enabled` is
    /// true — a row left behind when a deployment turned the feature off, say — got a token
    /// with nowhere to spend it and a "challenge issued" line in the log. The user could not
    /// sign in and the log said the flow was working.
    ///
    /// The refusal is opaque and the cause goes to the log. It reveals nothing new: the caller
    /// has already proved the password, and a build WITH the feature answers the same account
    /// with a challenge, which says the same thing about it.
    ///
    /// # Errors
    ///
    /// Always returns [`AuthError::Internal`] — a build that cannot verify a second factor has
    /// no honest answer for an account that requires one.
    #[cfg(not(feature = "mfa"))]
    pub async fn issue_mfa_temp_token(
        &self,
        user_id: &str,
        context: MfaContext,
    ) -> Result<String, AuthError> {
        let _ = context;
        tracing::error!(
            %user_id,
            "mfa challenge requested, but this build has no MFA surface — enable the `mfa` \
             feature or clear `mfa_enabled` on the account"
        );
        Err(internal_error(
            "account requires MFA but this build has no MFA support",
        ))
    }

    /// Issue a short-lived MFA temp token bridging the password step and the second factor.
    /// When the single-use support is wired this signs the challenge JWT and plants the
    /// single-use `mfa:{sha256(jti)}` marker (300 s). Without the support it falls back to
    /// signing only.
    ///
    /// The per-user MFA-challenge brute-force counter is deliberately **not** reset here. It
    /// used to be, on the reasoning that a fresh login proves renewed password possession —
    /// but password possession is exactly the attacker's assumed capability in the threat
    /// model the second factor exists to cover. Resetting on every issuance let that attacker
    /// loop `login → five wrong codes → login` forever, so the per-account lockout never
    /// engaged and the only remaining control was the per-IP rate limit, which a distributed
    /// caller sidesteps. Exactly one event clears it: a SUCCESSFUL challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] if signing fails (unreachable), or a store
    /// [`AuthError`] if planting the marker fails.
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
        let claims = self
            .verify_rotating::<MfaTempClaims>(token)
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

    /// Consume an MFA temp token by deleting its `mfa:{sha256(jti)}` marker, reporting whether
    /// **this** call was the one that removed it. Called only after the submitted code is
    /// confirmed valid (§7.5.3). For the TOTP path the consume is fused with the anti-replay
    /// mark in a single atomic step ([`crate::traits::MfaStore::challenge_consume`]); this
    /// standalone form serves the recovery-code path, whose code carries no `tu:` marker.
    ///
    /// The caller **must** gate success on the returned flag. Without it, two concurrent
    /// challenges carrying the same temp token and the same recovery code both observed the
    /// marker, both deleted it, and both issued a full session — the exactly-once property the
    /// fused TOTP step has by construction.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaTempTokenInvalid`] when no single-use support is wired, or a
    /// store [`AuthError`] on a backend failure.
    #[cfg(feature = "mfa")]
    pub async fn consume_mfa_temp_token(&self, jti: &str) -> Result<bool, AuthError> {
        let Some(support) = &self.mfa else {
            return Err(AuthError::MfaTempTokenInvalid);
        };
        support.store.del_temp(&jti_hash(jti)).await
    }

    /// Fire the fire-and-forget [`AuthHooks::on_refresh_token_reuse_detected`] hook.
    ///
    /// Skipped when the owner is unknown: a replay of a token whose live key is already gone
    /// leaves nothing to read, and an event naming no account is worse than no event — a
    /// consumer would have to treat it as unattributable noise.
    ///
    /// [`AuthHooks::on_refresh_token_reuse_detected`]:
    ///     crate::traits::AuthHooks::on_refresh_token_reuse_detected
    async fn fire_reuse_detected(&self, user_id: Option<&str>, family_id: &str) {
        let Some(user_id) = user_id else { return };
        // The rotation carries no request context of its own — the identity fields are what
        // the hook itself already names.
        let ctx = HookContext::detached(user_id);
        if let Err(error) = self
            .hooks
            .on_refresh_token_reuse_detected(user_id, family_id, &ctx)
            .await
        {
            tracing::error!(%error, "refresh: reuse hook returned an error (ignored)");
        }
    }

    /// Refuse a rotation once the login it descends from has outlived the absolute cap.
    ///
    /// `refresh_expires_in_days` bounds a single refresh token, not a session: a client
    /// rotating every fifteen minutes renews that lifetime forever, so without this a session
    /// established once never has to be established again. The cap measures from the
    /// **family's** birth, which is carried unchanged through the lineage.
    ///
    /// A session with no birth time has no cap to measure from and is not capped — it ages out
    /// under the refresh lifetime like any other. A cap of `0` disables the check.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::RefreshTokenInvalid`] once the cap is passed. The caller cannot
    /// distinguish it from any other invalid refresh, which is deliberate: the remedy is the
    /// same, and a distinct code would tell whoever holds the token how old the session is.
    fn assert_within_absolute_lifetime(&self, record: &SessionRecord) -> Result<(), AuthError> {
        if self.absolute_lifetime_secs == 0 {
            return Ok(());
        }
        let Some(born_at) = record.family_created_at else {
            return Ok(());
        };
        let age = now_offset() - born_at;
        if age.whole_seconds().unsigned_abs() > self.absolute_lifetime_secs && age.is_positive() {
            tracing::warn!("rotation refused: session outlived the absolute lifetime cap");
            return Err(AuthError::RefreshTokenInvalid);
        }
        Ok(())
    }

    /// Build the access claims for a rotated/recovered session. Rotation always drops
    /// `mfa_verified` (the user re-acquires it only via the MFA challenge) and issues an
    /// empty `status` — status guards consult the repository/status cache, not the rotated
    /// JWT, because the stored session record carries no live status. The `epoch` is the user's
    /// current generation, read at rotation time.
    ///
    /// `mfa_enabled` is carried over from the stored record rather than reset: the MFA gate
    /// refuses a token only when `mfa_enabled && !mfa_verified`, so minting `false` here
    /// would let one routine refresh turn an enrolled account's token into one that clears
    /// every MFA-gated route without ever completing a challenge.
    /// Re-sign a rotated access token with the authority the account holds *now*.
    ///
    /// Rotation builds its claims from the session record written at login, so the role and
    /// tenant it carries are the ones the account had then. This re-stamps both from the
    /// freshly read account, keeping everything else the rotated token already established —
    /// including `mfa_verified`, because a second factor already cleared on this session must
    /// not be silently demanded again. A fresh `jti`, window, and epoch are issued: the token
    /// this replaces was never handed out.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable for the
    /// concrete claim type), or a store failure while reading the epoch.
    pub(crate) async fn reissue_access_with_authority(
        &self,
        claims: &DashboardClaims,
        role: &str,
        tenant_id: &str,
    ) -> Result<String, AuthError> {
        let now = now_unix();
        let epoch = self
            .session_store
            .current_epoch(SessionKind::Dashboard, &claims.sub)
            .await?;
        self.issue_access(&DashboardClaims {
            epoch,
            jti: new_uuid_v4(),
            role: role.to_owned(),
            tenant_id: tenant_id.to_owned(),
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            ..claims.clone()
        })
    }

    fn rotated_claims(&self, record: &SessionRecord, epoch: u64) -> DashboardClaims {
        let now = now_unix();
        DashboardClaims {
            iss: None,
            aud: None,
            sub: record.user_id.clone(),
            jti: new_uuid_v4(),
            tenant_id: record.tenant_id.clone().unwrap_or_default(),
            role: record.role.clone(),
            token_type: DashboardType::Dashboard,
            status: String::new(),
            mfa_enabled: record.mfa_enabled,
            mfa_verified: false,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            epoch,
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
        mfa_enabled: seed.mfa_enabled,
        // Rotation inherits the seed's family unchanged, so every descendant of one login
        // shares the id and the whole lineage is revocable together on reuse detection.
        family_id: seed.family_id.clone(),
        // The birth time is inherited too — measuring from this record's own `created_at`
        // would reset the clock on every rotation and make the cap unreachable.
        family_created_at: seed.family_created_at,
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
        mfa_enabled: seed.mfa_enabled,
        // The platform rotation inherits the seed's family unchanged (section 12.5.2).
        family_id: seed.family_id.clone(),
        family_created_at: seed.family_created_at,
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
        mfa_enabled: false,
        // The placeholder is never stored (an absent live token yields only Grace/Reused/Invalid),
        // so it carries no family and no birth time.
        family_id: String::new(),
        family_created_at: None,
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

    /// Issue a dashboard pair from `svc`, or `None` when it could not.
    ///
    /// A helper rather than an inline `let-else`: the chained call spans several lines, which
    /// pushes the `return` onto a line of its own — a line no run ever reaches, and one
    /// llvm-cov counts. Behind a helper the `else { return }` fits inline, which is the idiom
    /// the rest of the suite uses.
    async fn issued_for(svc: &TokenManagerService) -> Option<AuthResult> {
        svc.issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await
            .ok()
    }

    /// Rotate `refresh` through `svc`, or `None` when it could not.
    async fn rotated_for(svc: &TokenManagerService, refresh: &str) -> Option<RotatedTokens> {
        svc.reissue_tokens(refresh, "10.0.0.1", "agent/1.0")
            .await
            .ok()
    }

    /// Issue a platform pair from `svc`, or `None` when it could not. See [`issued_for`].
    async fn platform_issued_for(svc: &TokenManagerService) -> Option<PlatformAuthResult> {
        svc.issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await
            .ok()
    }

    /// Rotate a platform `refresh` through `svc`, or `None` when it could not.
    async fn platform_rotated_for(
        svc: &TokenManagerService,
        refresh: &str,
    ) -> Option<RotatedTokens> {
        svc.reissue_platform_tokens(refresh, "10.0.0.1", "agent/1.0")
            .await
            .ok()
    }

    fn service(store: Arc<InMemoryStores>) -> TokenManagerService {
        TokenManagerService::new(
            key(),
            Vec::new(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            // No absolute cap in the default fixture; the cap has its own tests.
            0,
        )
    }

    /// A manager whose current key is `key()` and which also accepts `retired` for verification.
    fn service_rotating(store: Arc<InMemoryStores>, retired: Vec<HsKey>) -> TokenManagerService {
        TokenManagerService::new(
            key(),
            retired,
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
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

    /// A hooks collaborator whose reuse handler always fails, so the swallowed arm is reachable.
    struct BrokenReuseHook;

    #[async_trait::async_trait]
    impl crate::traits::AuthHooks for BrokenReuseHook {
        async fn on_refresh_token_reuse_detected(
            &self,
            _user_id: &str,
            _family_id: &str,
            _ctx: &crate::traits::HookContext,
        ) -> Result<(), crate::traits::HookError> {
            Err(crate::traits::HookError::Internal("siem down".into()))
        }
    }

    #[tokio::test]
    async fn a_hook_that_fails_on_a_reuse_does_not_change_what_the_caller_sees() {
        // The event is fire-and-forget by design: a consumer's SIEM being down is not a reason
        // to answer a token replay differently, and it is certainly not a reason to let the
        // replay through. The failure is logged and the refusal stands — swallowed, which is
        // what leaves the arm unreachable against a hook that always succeeds.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone()).with_hooks(Arc::new(BrokenReuseHook));
        let Some(issued) = issued_for(&svc).await else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let Some(_rotated) = rotated_for(&svc, &issued.refresh_token).await else { return };
        assert!(
            store
                .delete_grace_pointer(SessionKind::Dashboard, &old_hash)
                .await
                .is_ok()
        );

        assert!(matches!(
            svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
    }

    /// Records the reuse events the rotation reports.
    #[derive(Default)]
    struct ReuseSpy {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::traits::AuthHooks for ReuseSpy {
        async fn on_refresh_token_reuse_detected(
            &self,
            user_id: &str,
            family_id: &str,
            ctx: &crate::traits::HookContext,
        ) -> Result<(), crate::traits::HookError> {
            if let Ok(mut calls) = self.calls.lock() {
                // The context names the account and nothing it never observed: an empty `ip`
                // is honest about a rotation carrying no request, where a placeholder would
                // read to a consumer as an address someone actually connected from.
                calls.push(format!(
                    "{user_id}:{family_id}:{}:{}",
                    ctx.user_id.clone().unwrap_or_default(),
                    ctx.ip
                ));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_detected_reuse_reports_the_owner_it_recovered_from_the_family() {
        // The replayed token's own key was deleted when it was rotated, so nothing about the
        // token still names an account — the family index is the only surviving link. Without
        // it the event would fire anonymously, which is worse than not firing: a consumer
        // cannot act on a takeover signal that names no victim.
        let spy = Arc::new(ReuseSpy::default());
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone()).with_hooks(spy.clone());
        let Some(issued) = issued_for(&svc).await else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let Some(_rotated) = rotated_for(&svc, &issued.refresh_token).await else { return };
        assert!(
            store
                .delete_grace_pointer(SessionKind::Dashboard, &old_hash)
                .await
                .is_ok()
        );

        assert!(matches!(
            svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));

        let seen = spy.calls.lock().map(|c| c.clone()).unwrap_or_default();
        assert_eq!(seen.len(), 1, "exactly one reuse event: {seen:?}");
        let owner = user().id;
        assert!(
            seen[0].starts_with(&format!("{owner}:")),
            "the event named no owner: {seen:?}"
        );
        // The family id is carried through, and the detached context repeats the owner while
        // inventing no request fields.
        assert!(seen[0].ends_with(&format!(":{owner}:")), "{seen:?}");
    }

    #[tokio::test]
    async fn a_reuse_with_no_recoverable_owner_fires_no_event() {
        // A family whose every member has expired names nobody. The refusal is unchanged and
        // the hook stays silent rather than emitting an unattributable alert.
        let spy = Arc::new(ReuseSpy::default());
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone()).with_hooks(spy.clone());
        let Some(issued) = issued_for(&svc).await else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let Some(rotated) = rotated_for(&svc, &issued.refresh_token).await else { return };
        assert!(
            store
                .delete_grace_pointer(SessionKind::Dashboard, &old_hash)
                .await
                .is_ok()
        );
        // Drop the only live descendant, so the family index survives with nothing readable.
        assert!(
            store
                .revoke_session(SessionKind::Dashboard, &user().id, &rotated_hash(&rotated))
                .await
                .is_ok()
        );

        assert!(matches!(
            svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));

        assert!(
            spy.calls.lock().map(|c| c.is_empty()).unwrap_or(false),
            "an unattributable reuse event was emitted"
        );
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn a_replayed_platform_token_reports_reuse_too() {
        // The plane that usually carries more authority. An operator watching for takeover
        // must not be blind on it.
        let spy = Arc::new(ReuseSpy::default());
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone()).with_hooks(spy.clone());
        let Some(issued) = platform_issued_for(&svc).await else { return };
        let old_hash = RawRefreshToken::from_raw(issued.refresh_token.clone()).redis_hash();
        let rotated = platform_rotated_for(&svc, &issued.refresh_token).await;
        let Some(_rotated) = rotated else { return };
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

        let seen = spy.calls.lock().map(|c| c.clone()).unwrap_or_default();
        assert_eq!(seen.len(), 1, "exactly one platform reuse event: {seen:?}");
        assert!(
            seen[0].starts_with(&format!("{}:", platform_admin().id)),
            "{seen:?}"
        );
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
    async fn a_bumped_epoch_rejects_every_access_token_issued_before_the_bump() {
        // A password reset / sign-out-everywhere bumps the user's token epoch. An access token
        // stamped before the bump — a stateless JWT that logout's jti-blacklist could not reach
        // without holding it — is now rejected on its next verification, so a reset takes effect
        // immediately instead of lingering for the access-token lifetime.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };
        // Freshly issued: it verifies (stamped at the current epoch 0).
        assert!(svc.verify_access(&issued.access_token).await.is_ok());
        // Bump the epoch (what a password reset does), then the pre-bump token is revoked...
        assert!(store.bump_epoch(SessionKind::Dashboard, "u1").await.is_ok());
        assert!(matches!(
            svc.verify_access(&issued.access_token).await,
            Err(AuthError::TokenRevoked)
        ));
        // ...while a token issued AFTER the bump carries the new epoch and still verifies.
        let after = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(after) = after else { return };
        assert!(svc.verify_access(&after.access_token).await.is_ok());
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn a_bumped_platform_epoch_rejects_a_pre_bump_platform_token() {
        // The platform-keyspace analogue: bumping a platform admin's epoch invalidates every
        // platform access token issued before it, and a later-issued token still verifies.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let issued = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };
        assert!(
            svc.verify_platform_access(&issued.access_token)
                .await
                .is_ok()
        );
        assert!(store.bump_epoch(SessionKind::Platform, "p1").await.is_ok());
        assert!(matches!(
            svc.verify_platform_access(&issued.access_token).await,
            Err(AuthError::TokenRevoked)
        ));
        let after = svc
            .issue_platform_tokens(&platform_admin(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(after) = after else { return };
        assert!(
            svc.verify_platform_access(&after.access_token)
                .await
                .is_ok()
        );
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
            iss: None,
            aud: None,
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
            epoch: 0,
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
    #[tokio::test]
    async fn rotation_preserves_mfa_enabled_so_the_gate_survives_a_refresh() {
        // The MFA gate refuses a token only when `mfa_enabled && !mfa_verified`. If rotation
        // reset `mfa_enabled` to false, one routine refresh (every ~15 min) would mint a token
        // that clears every MFA-gated route without the holder ever completing a challenge —
        // a silent bypass for an enrolled account. The flag must survive rotation; the
        // `mfa_verified` proof must NOT, so the second factor is re-acquired via the challenge.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let enrolled = SafeAuthUser {
            mfa_enabled: true,
            ..user()
        };

        let issued = svc
            .issue_tokens(&enrolled, "10.0.0.1", "agent/1.0", true)
            .await;
        let Ok(issued) = issued else { return };

        let rotated = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };

        let claims = svc.verify_access(&rotated.access_token).await;
        assert!(matches!(&claims, Ok(c) if c.mfa_enabled && !c.mfa_verified));
    }

    #[tokio::test]
    async fn rotation_keeps_mfa_enabled_false_for_an_unenrolled_user() {
        // The mirror of the test above: carrying the flag over must read it from the stored
        // record, not hardcode `true`. An account without MFA stays unenrolled across rotation.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);

        let issued = svc
            .issue_tokens(&user(), "10.0.0.1", "agent/1.0", false)
            .await;
        let Ok(issued) = issued else { return };

        let rotated = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };

        let claims = svc.verify_access(&rotated.access_token).await;
        assert!(matches!(&claims, Ok(c) if !c.mfa_enabled));
    }

    #[tokio::test]
    async fn platform_rotation_preserves_mfa_enabled() {
        // Same invariant on the platform plane, where the blast radius is larger: a rotated
        // operator token must keep demanding the second factor.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let enrolled = SafeAuthPlatformUser {
            mfa_enabled: true,
            ..platform_admin()
        };

        let issued = svc
            .issue_platform_tokens(&enrolled, "10.0.0.1", "agent/1.0", true)
            .await;
        let Ok(issued) = issued else { return };

        let rotated = svc
            .reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        let Ok(rotated) = rotated else { return };

        let claims = svc.verify_platform_access(&rotated.access_token).await;
        assert!(matches!(&claims, Ok(c) if c.mfa_enabled && !c.mfa_verified));
    }

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
        // A token manager whose MFA support is backed by the in-memory store satisfying the
        // MFA-marker seam. The brute-force counter is no longer this type's business.
        let mfa_store: Arc<dyn crate::traits::MfaStore> = store.clone();
        let support = MfaTokenSupport::new(mfa_store);
        TokenManagerService::new(
            key(),
            Vec::new(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
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
    async fn consuming_a_temp_token_reports_the_winner_exactly_once() {
        // The recovery-code challenge path has no `tu:` marker to fuse against, so it consumes
        // the temp token standalone and gates success on this flag. The flag is the whole
        // guarantee: when the consume reported nothing, two challenges carrying the same temp
        // token both observed the marker, both deleted it, and both issued a full session —
        // which is a recovery code, whose entire security model is single use, minting two.
        //
        // The property is exactly-once, so it is pinned here rather than through a concurrency
        // test: the in-memory repository serialises the recovery-code splice, so a spawned race
        // passes with or without the gate and would prove nothing.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store);

        let issued = svc.issue_mfa_temp_token("u1", MfaContext::Dashboard).await;
        let Ok(token) = issued else { return };
        let verified = svc.verify_mfa_temp_token(&token).await;
        let Ok(claims) = verified else { return };

        // The first consume wins; every later one loses, including for a jti that never existed.
        assert!(matches!(
            svc.consume_mfa_temp_token(&claims.jti).await,
            Ok(true)
        ));
        assert!(matches!(
            svc.consume_mfa_temp_token(&claims.jti).await,
            Ok(false)
        ));
        assert!(matches!(
            svc.consume_mfa_temp_token("never-issued").await,
            Ok(false)
        ));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn issuing_a_temp_token_clears_no_brute_force_counter() {
        // Issuing a fresh temp token used to clear the `challenge:` counter, on the reasoning
        // that a fresh login restarts the MFA budget. But password possession is exactly the
        // attacker's assumed capability in the threat model the second factor covers, so that
        // let them loop `login -> five wrong codes -> login` forever: the per-account lockout
        // never engaged and only the per-IP limit remained, which a distributed caller
        // sidesteps. Neither namespace is cleared here now; a SUCCESSFUL challenge is the one
        // event that clears the challenge counter.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store.clone());
        let bf: Arc<dyn crate::traits::BruteForceStore> = store.clone();
        let key_bytes = [7u8; 64];
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
        // Issuing a token leaves BOTH counters standing.
        assert!(
            svc.issue_mfa_temp_token("u1", MfaContext::Dashboard)
                .await
                .is_ok()
        );
        assert!(matches!(bf.is_locked(&challenge_id, 5).await, Ok(true)));
        assert!(matches!(bf.is_locked(&disable_id, 5).await, Ok(true)));
    }

    fn retired_key() -> HsKey {
        HsKey::from_bytes(b"the-previous-hs256-secret-abcdefgh")
    }

    #[tokio::test]
    async fn a_token_signed_under_a_retired_secret_still_verifies() {
        // Without this, rotating the signing secret signs every user out at the moment the new
        // configuration rolls out. Listing the old secret makes the rotation a rollout instead.
        let store = Arc::new(InMemoryStores::new());
        let old_manager = service_rotating(store.clone(), Vec::new());
        // Mint under the retired key by making it the CURRENT key of a throwaway manager.
        let minted_under_old = TokenManagerService::new(
            retired_key(),
            Vec::new(),
            store.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        );
        let issued = minted_under_old
            .issue_tokens(&user(), "1.2.3.4", "agent", false)
            .await;
        let Ok(issued) = issued else { return };
        drop(old_manager);

        // The current key alone rejects it…
        let strict = service_rotating(store.clone(), Vec::new());
        assert!(matches!(
            strict.verify_access(&issued.access_token).await,
            Err(AuthError::TokenInvalid)
        ));

        // …and with the retired key listed, it verifies.
        let rotating = service_rotating(store, vec![retired_key()]);
        assert!(matches!(
            rotating.verify_access(&issued.access_token).await,
            Ok(claims) if claims.sub == "u1"
        ));
    }

    #[tokio::test]
    async fn a_retired_secret_excuses_nothing_but_the_signature() {
        // A token nobody signed is still refused, and the failure is the CURRENT key's — which
        // is what keeps the error from reporting whether a forgery matched a key the deployment
        // used to hold.
        let store = Arc::new(InMemoryStores::new());
        let rotating = service_rotating(store.clone(), vec![retired_key()]);
        let forged = TokenManagerService::new(
            HsKey::from_bytes(b"a-key-nobody-in-this-deployment-holds"),
            Vec::new(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        );
        let issued = forged
            .issue_tokens(&user(), "1.2.3.4", "agent", false)
            .await;
        let Ok(issued) = issued else { return };

        assert!(matches!(
            rotating.verify_access(&issued.access_token).await,
            Err(AuthError::TokenInvalid)
        ));
    }

    #[tokio::test]
    async fn the_current_key_is_always_tried_first() {
        // The common path must not pay for a feature nobody switched on: a token under the
        // current key verifies whether or not retired keys are listed.
        let store = Arc::new(InMemoryStores::new());
        let rotating = service_rotating(store.clone(), vec![retired_key()]);
        let issued = rotating
            .issue_tokens(&user(), "1.2.3.4", "agent", false)
            .await;
        let Ok(issued) = issued else { return };

        assert!(matches!(
            rotating.verify_access(&issued.access_token).await,
            Ok(claims) if claims.sub == "u1"
        ));
    }
    // ---------------------------------------------------------------------------
    // iss / aud binding
    // ---------------------------------------------------------------------------

    /// A service bound to an issuer and/or an audience.
    fn bound_service(
        store: Arc<InMemoryStores>,
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> TokenManagerService {
        service(store).with_binding(TokenBinding {
            issuer: issuer.map(str::to_owned),
            audience: audience.map(str::to_owned),
        })
    }

    #[tokio::test]
    async fn an_unbound_deployment_mints_and_accepts_unstamped_tokens() {
        // Absent by default, so an existing deployment is unchanged.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);
        let Some(issued) = issued_for(&svc).await else { return };

        let verified = svc.verify_access(&issued.access_token).await;
        assert!(
            verified.is_ok(),
            "an unbound service rejected its own token"
        );
        let Ok(claims) = verified else { return };
        assert_eq!(claims.iss, None);
        assert_eq!(claims.aud, None);
    }

    #[tokio::test]
    async fn a_bound_deployment_stamps_what_it_mints() {
        // The claim has to be ON the token, or the verifier that requires it rejects the
        // backend's own output.
        let store = Arc::new(InMemoryStores::new());
        let svc = bound_service(store, Some("bymax"), Some("dashboard"));
        let Some(issued) = issued_for(&svc).await else { return };

        // Asserted, not `let-else`-ed: on this test the verification failing IS the failure
        // under test — a stamp that never happened makes the bound verifier reject the
        // backend's own token, and an early return would score that as a pass.
        let verified = svc.verify_access(&issued.access_token).await;
        assert!(
            verified.is_ok(),
            "a bound service rejected its own token: {verified:?}"
        );
        let Ok(claims) = verified else { return };
        assert_eq!(claims.iss.as_deref(), Some("bymax"));
        assert_eq!(claims.aud.as_deref(), Some("dashboard"));
    }

    #[tokio::test]
    async fn a_bound_verifier_refuses_an_unstamped_token() {
        // The whole point. A verifier that accepted an unstamped token would give an attacker
        // a way to opt out of the check simply by omitting the claim.
        let store = Arc::new(InMemoryStores::new());
        let unbound = service(store.clone());
        let Some(issued) = issued_for(&unbound).await else { return };

        // Same signing key, same session store — only the binding differs.
        let bound = bound_service(store, Some("bymax"), None);
        assert!(bound.verify_access(&issued.access_token).await.is_err());
    }

    #[tokio::test]
    async fn a_bound_verifier_refuses_the_wrong_value() {
        // The case that matters when one deployment's token is replayed at another that
        // happens to trust the same secret.
        let store = Arc::new(InMemoryStores::new());
        let theirs = bound_service(store.clone(), Some("someone-else"), Some("their-service"));
        let Some(issued) = issued_for(&theirs).await else { return };

        let ours = bound_service(store, Some("bymax"), Some("dashboard"));
        assert!(ours.verify_access(&issued.access_token).await.is_err());
    }

    #[tokio::test]
    async fn each_half_of_the_binding_is_checked_on_its_own() {
        // Both clauses need their own case. A token whose ISSUER matches but whose AUDIENCE
        // does not is the shape that catches an inverted audience comparison, and vice versa —
        // a test that only ever varies both at once cannot tell the two apart, and half the
        // check could be inverted without a single failure.
        let store = Arc::new(InMemoryStores::new());
        let ours = bound_service(store.clone(), Some("bymax"), Some("dashboard"));

        // Right issuer, wrong audience.
        let wrong_audience = bound_service(store.clone(), Some("bymax"), Some("another-service"));
        let Some(issued) = issued_for(&wrong_audience).await else { return };
        assert!(
            ours.verify_access(&issued.access_token).await.is_err(),
            "a token aimed at another audience was accepted"
        );

        // Wrong issuer, right audience.
        let wrong_issuer = bound_service(store, Some("someone-else"), Some("dashboard"));
        let Some(issued) = issued_for(&wrong_issuer).await else { return };
        assert!(
            ours.verify_access(&issued.access_token).await.is_err(),
            "a token from another issuer was accepted"
        );
    }

    #[tokio::test]
    async fn binding_only_one_half_leaves_the_other_unchecked() {
        // Configuring an issuer alone must not start requiring an audience: a deployment that
        // set one field would otherwise reject every token, including its own.
        let store = Arc::new(InMemoryStores::new());
        let issuer_only = bound_service(store.clone(), Some("bymax"), None);
        let Some(issued) = issued_for(&issuer_only).await else { return };

        let verified = issuer_only.verify_access(&issued.access_token).await;
        assert!(
            verified.is_ok(),
            "an issuer-only binding rejected its own token"
        );
        let Ok(claims) = verified else { return };
        assert_eq!(claims.iss.as_deref(), Some("bymax"));
        assert_eq!(claims.aud, None);

        // …and the same for an audience alone.
        let audience_only = bound_service(store, None, Some("dashboard"));
        let Some(issued) = issued_for(&audience_only).await else { return };
        let verified = audience_only.verify_access(&issued.access_token).await;
        assert!(
            verified.is_ok(),
            "an audience-only binding rejected its own token"
        );
        let Ok(claims) = verified else { return };
        assert_eq!(claims.iss, None);
        assert_eq!(claims.aud.as_deref(), Some("dashboard"));
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn the_mfa_challenge_token_is_stamped_like_every_other() {
        // The token that bridges the password step and the second factor is minted by this
        // service and verified by it, so it has to carry the binding too. Stamping the two
        // access shapes and forgetting this one would leave a bound deployment rejecting its
        // own challenge token — MFA login broken outright, and only for the deployments that
        // turned the binding on.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store).with_binding(TokenBinding {
            issuer: Some("bymax".to_owned()),
            audience: Some("dashboard".to_owned()),
        });

        let issued = svc
            .issue_mfa_temp_token("user-1", MfaContext::Dashboard)
            .await;
        assert!(
            issued.is_ok(),
            "a bound service must still mint an MFA challenge token"
        );
        let Ok(token) = issued else { return };

        let verified = svc.verify_mfa_temp_token(&token).await;
        assert!(
            verified.is_ok(),
            "a bound service rejected its own MFA challenge token: {verified:?}"
        );
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn the_platform_plane_is_bound_too() {
        // The plane that carries the most authority is not the one to leave unstamped.
        let store = Arc::new(InMemoryStores::new());
        let svc = bound_service(store.clone(), Some("bymax"), Some("platform"));
        let Some(issued) = platform_issued_for(&svc).await else { return };

        let verified = svc.verify_platform_access(&issued.access_token).await;
        assert!(
            verified.is_ok(),
            "a bound service rejected its own platform token: {verified:?}"
        );
        let Ok(claims) = verified else { return };
        assert_eq!(claims.iss.as_deref(), Some("bymax"));
        assert_eq!(claims.aud.as_deref(), Some("platform"));

        // …and a token minted without the binding is refused on this plane as on the other.
        let unbound = service(store);
        let Some(plain) = platform_issued_for(&unbound).await else { return };
        assert!(
            svc.verify_platform_access(&plain.access_token)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_retired_signing_key_does_not_waive_the_binding() {
        // A retired key buys a token signature acceptance and nothing else. Without this the
        // binding would be bypassable by anyone holding a secret the deployment used to use.
        let store = Arc::new(InMemoryStores::new());
        let retired = HsKey::from_bytes(b"retired-secret-retired-secret-32");
        let old = TokenManagerService::new(
            retired,
            Vec::new(),
            store.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        );
        let Some(issued) = issued_for(&old).await else { return };

        // A service that accepts the retired key, and requires the binding the old one never
        // stamped.
        let rotating = service_rotating(
            store,
            vec![HsKey::from_bytes(b"retired-secret-retired-secret-32")],
        )
        .with_binding(TokenBinding {
            issuer: Some("bymax".to_owned()),
            audience: None,
        });

        assert!(rotating.verify_access(&issued.access_token).await.is_err());
    }
}

#[cfg(test)]
mod absolute_lifetime_tests {
    use super::*;
    use crate::testing::InMemoryStores;
    use time::Duration as TimeDuration;

    /// A manager with a 30-day absolute cap.
    fn capped(store: Arc<InMemoryStores>) -> TokenManagerService {
        TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            store,
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            30,
        )
    }

    /// A session record born `days_ago`.
    fn record_born(days_ago: i64) -> SessionRecord {
        SessionRecord {
            user_id: "u1".to_owned(),
            tenant_id: Some("t1".to_owned()),
            role: "MEMBER".to_owned(),
            device: "Chrome".to_owned(),
            ip: "203.0.113.4".to_owned(),
            created_at: now_offset(),
            mfa_enabled: false,
            family_id: "fam-1".to_owned(),
            family_created_at: Some(now_offset() - TimeDuration::days(days_ago)),
        }
    }

    #[tokio::test]
    async fn a_grace_recovery_is_refused_once_the_family_outlives_the_cap() {
        // The cap must hold on the GRACE path too. The check before the script runs against the
        // seed, and on this path the seed is the placeholder used when the live key is already
        // gone — its `family_created_at` is `None`, so that check returns early and applies
        // nothing. Without a second check against the RECOVERED record, a lineage that had just
        // passed its cap could still mint a fresh access token and a full-length refresh
        // session by presenting a token inside its grace window: the cap ends normal rotation
        // and the one remaining door stays open.
        let store = Arc::new(InMemoryStores::new());
        // An UNCAPPED manager plants the grace pointer, because a capped one would refuse the
        // first rotation outright and there would be no pointer to recover from.
        let uncapped = TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            store.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        );
        let old = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &old.redis_hash(),
                    &record_born(31),
                    3600
                )
                .await
                .is_ok()
        );
        assert!(
            uncapped
                .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
                .await
                .is_ok(),
            "the first rotation plants the grace pointer"
        );

        // Now replay the consumed token against a CAPPED manager: the live key is gone, so this
        // takes the grace path, and the recovered record is 31 days old against a 30-day cap.
        let refused = capped(store.clone())
            .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
            .await;

        assert!(matches!(refused, Err(AuthError::RefreshTokenInvalid)));
    }

    #[tokio::test]
    async fn a_rotation_is_refused_once_the_family_outlives_the_cap() {
        // `refresh_expires_in_days` bounds a single token, not a session: a client rotating
        // every fifteen minutes renews that lifetime forever. The cap is what ends the lineage.
        let store = Arc::new(InMemoryStores::new());
        let manager = capped(store.clone());
        let old = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &old.redis_hash(),
                    &record_born(31),
                    3600
                )
                .await
                .is_ok()
        );

        let refused = manager
            .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
            .await;

        assert!(matches!(refused, Err(AuthError::RefreshTokenInvalid)));
        // Refused BEFORE the rotation ran, so nothing was consumed on the holder's behalf.
        assert!(matches!(
            store
                .find_session(SessionKind::Dashboard, &old.redis_hash())
                .await,
            Ok(Some(_))
        ));
    }

    #[tokio::test]
    async fn a_family_inside_the_cap_still_rotates() {
        // The boundary matters: an off-by-one here signs every user out a day early.
        let store = Arc::new(InMemoryStores::new());
        let manager = capped(store.clone());
        let old = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &old.redis_hash(),
                    &record_born(29),
                    3600
                )
                .await
                .is_ok()
        );

        assert!(
            manager
                .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_family_exactly_at_the_cap_still_rotates() {
        // The cap is a maximum, not an exclusive bound: a session whose age reads as exactly
        // 30 days is still inside it. Only a record sitting on the boundary can tell `>` from
        // `>=`, and the difference is a whole day of sessions ended early.
        let store = Arc::new(InMemoryStores::new());
        let manager = capped(store.clone());
        let old = RawRefreshToken::generate();
        let exactly = SessionRecord {
            family_created_at: Some(now_offset() - TimeDuration::days(30)),
            ..record_born(1)
        };
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old.redis_hash(), &exactly, 3600)
                .await
                .is_ok()
        );

        assert!(
            manager
                .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_record_with_no_birth_time_and_a_zero_cap_both_rotate() {
        // A record with no birth time has nothing to measure from and must not be ended by the
        // cap; a zero cap disables the check outright. Both are the "not capped" answer.
        let store = Arc::new(InMemoryStores::new());
        let uncapped = SessionRecord {
            family_created_at: None,
            ..record_born(365)
        };
        let old = RawRefreshToken::generate();
        assert!(
            store
                .create_session(SessionKind::Dashboard, &old.redis_hash(), &uncapped, 3600)
                .await
                .is_ok()
        );
        assert!(
            capped(store.clone())
                .reissue_tokens(old.expose_secret(), "203.0.113.4", "Chrome")
                .await
                .is_ok()
        );

        let uncapped = TokenManagerService::new(
            HsKey::from_bytes(b"0123456789abcdef0123456789abcdef"),
            Vec::new(),
            store.clone(),
            Duration::from_secs(900),
            7,
            Duration::from_secs(30),
            0,
        );
        let ancient = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &ancient.redis_hash(),
                    &record_born(365),
                    3600
                )
                .await
                .is_ok()
        );
        assert!(
            uncapped
                .reissue_tokens(ancient.expose_secret(), "203.0.113.4", "Chrome")
                .await
                .is_ok()
        );
    }
}
