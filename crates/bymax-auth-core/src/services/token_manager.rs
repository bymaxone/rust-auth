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

use zeroize::Zeroizing;

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
    /// The tenant the challenge belongs to: always `Some` on the dashboard plane — a token
    /// without it does not verify — and always `None` on the platform plane.
    pub tenant_id: Option<String>,
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

/// The four resolved token lifetimes, grouped so the manager's constructor takes one value for
/// them instead of four adjacent scalars — three of which are durations of different units and
/// two of which are bare `u32` day counts, which is exactly the argument list a caller silently
/// transposes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TokenLifetimes {
    /// How long a freshly-signed access token is valid.
    pub access_ttl: Duration,
    /// The refresh session's lifetime, in days.
    pub refresh_expires_in_days: u32,
    /// The rotation grace window; zero disables the grace pointer entirely.
    pub grace_window: Duration,
    /// The absolute cap on a login lineage, in days; zero means uncapped.
    pub absolute_session_lifetime_days: u32,
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

/// How long a completed authentication counts as recent, in seconds.
///
/// Five minutes, matching the MFA temp token's lifetime — the same span this library already
/// treats as "the user is still at the keyboard, mid-flow". Long enough that a user who signs in
/// and then opens their security settings is not sent back through the door; short enough that a
/// session lifted hours later cannot spend it. Held identical with nest-auth's
/// `RECENT_AUTH_TTL_SECONDS`.
pub const RECENT_AUTH_TTL_SECS: u64 = 300;

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
    /// The engine's identifier-hashing key. Derives the recent-authentication marker and the
    /// **session subject** — the suffix of the session index and the token epoch.
    ///
    /// A constructor parameter rather than an optional wither. It was optional while it fed
    /// only the recent-auth marker, where an absent key fails CLOSED (no marker is planted, so
    /// a flow requiring recent authentication refuses). The session subject has no such
    /// fallback: every session write needs one, and a manager that quietly derived a key
    /// without the engine's would put its sessions in a keyspace nothing else reads. Requiring
    /// it here is what stops a test double and a deployment keying the same session two ways.
    identifier_key: Zeroizing<[u8; 64]>,
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

    /// Assemble the token manager from the signing key, the session store, the resolved token
    /// lifetimes, and the identifier-hashing key.
    pub(crate) fn new(
        key: HsKey,
        previous_keys: Vec<HsKey>,
        session_store: Arc<dyn SessionStore>,
        lifetimes: TokenLifetimes,
        identifier_key: Zeroizing<[u8; 64]>,
    ) -> Self {
        Self {
            key,
            previous_keys,
            session_store,
            access_ttl: lifetimes.access_ttl,
            refresh_ttl_secs: u64::from(lifetimes.refresh_expires_in_days) * 86_400,
            grace_ttl_secs: lifetimes.grace_window.as_secs(),
            absolute_lifetime_secs: u64::from(lifetimes.absolute_session_lifetime_days) * 86_400,
            hooks: Arc::new(crate::traits::NoOpAuthHooks),
            binding: TokenBinding::default(),
            identifier_key,
            #[cfg(feature = "mfa")]
            mfa: None,
        }
    }

    /// The session-index / token-epoch key suffix for one account on one plane.
    ///
    /// `hmac_sha256(identifier_key, user_subject)`, the derivation the shared contract lists
    /// under `userSubjectDerivedKeys`. The dashboard arm carries the tenant, so one tenant's
    /// revocation can no longer reach another tenant's account of the same id; the platform arm
    /// carries none, because its admins are cross-tenant.
    fn subject_hash(&self, kind: SessionKind, tenant_id: Option<&str>, user_id: &str) -> String {
        crate::services::session_subject_hash(&self.identifier_key, kind, tenant_id, user_id)
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
        // The tenant-scoped subject every per-account session key derives from. Built once and
        // reused for the epoch read and the session write, so the two can never name different
        // accounts.
        let subject = self.subject_hash(SessionKind::Dashboard, Some(&user.tenant_id), &user.id);
        // Stamp the user's current token epoch so a later bump (a reset or sign-out-everywhere)
        // invalidates this token at verification.
        let epoch = self
            .session_store
            .current_epoch(SessionKind::Dashboard, &subject)
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
                &subject,
                &refresh.redis_hash(),
                &record,
                self.refresh_ttl_secs,
            )
            .await?;

        // Record that a REAL authentication just completed, for the flows that need to know how
        // recently rather than merely whether. Planted here and nowhere else: this method is the
        // single point where a dashboard session is born, while `reissue_tokens` deliberately
        // does not plant one, because a refresh proves possession of a token rather than of a
        // credential. That asymmetry is the whole value — an attacker holding a stolen session
        // can rotate it forever and never make the mark fresh again.
        // The SAME subject the session index and the epoch use. It had its own derivation —
        // `hmac_sha256("{plane}:{userId}")`, with no tenant and no length prefix — and that
        // derivation never matched the one the reader uses. `MfaService`'s re-authentication
        // gate reads `ra:{hmac_sha256(hmacKey, userSubject)}`, which is what the contract's
        // `recentAuthMarker` names, so on the dashboard plane the marker was planted at a key
        // nobody read: every password-less (OAuth-provisioned) account was refused MFA
        // enrolment with `ReauthenticationRequired`, permanently. It failed CLOSED, which is
        // why it was survivable, and it was invisible because the tests plant the marker by
        // hand at the reader's key rather than signing in — each half correct, never compared.
        //
        // The old preimage also carried no tenant, so two accounts sharing an id in different
        // tenants shared one marker. Inert only because nothing read that key.
        self.session_store
            .mark_recent_auth(&subject, RECENT_AUTH_TTL_SECS)
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
        // The index the rotation moves the membership within. Derived from the record the
        // rotation is FOR, which on the live path is the real owner — the only path on which
        // the script touches the index at all.
        let subject = self.subject_hash(
            SessionKind::Dashboard,
            new_record.tenant_id.as_deref(),
            &new_record.user_id,
        );

        let rotation = SessionRotation {
            old_hash,
            new_hash: new.redis_hash(),
            new_raw: new.expose_secret().to_owned(),
            new_record: new_record.clone(),
            subject_hash: subject.clone(),
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
                    .current_epoch(SessionKind::Dashboard, &subject)
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
                // The RECOVERED record names the owner; the placeholder that reached the script
                // did not, so the subject built before the rotation cannot be reused here.
                let recovered_subject = self.subject_hash(
                    SessionKind::Dashboard,
                    fresh_record.tenant_id.as_deref(),
                    &fresh_record.user_id,
                );
                // One atomic step, not a plain write. Written loosely, this landed several
                // awaits after the script returned, and a `revoke_all` arriving in that gap
                // swept an index the recovered session was not in yet — so it survived a
                // revocation the user was told had happened, and its access token, signed
                // below, carried the post-bump epoch and verified.
                if !self
                    .session_store
                    .create_recovered_session(
                        SessionKind::Dashboard,
                        &recovered_subject,
                        &fresh.redis_hash(),
                        &fresh_record,
                        self.refresh_ttl_secs,
                    )
                    .await?
                {
                    // The account was swept while this recovery was in flight. The grace
                    // pointer is already consumed, so there is nothing left to retry against —
                    // which is the right end state: the revocation is what the caller obeys.
                    return Err(AuthError::RefreshTokenInvalid);
                }
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Dashboard, &recovered_subject)
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
                // Named, on both lines. This is the strongest compromise signal the library
                // produces, and it used to be logged as bare prose: the account it concerns
                // reached only a consumer who had wired `on_refresh_token_reuse_detected`,
                // and the shipped hooks are no-ops. On a default deployment the one
                // unambiguous theft signal was anonymous in the log and nowhere else, so an
                // operator could tell that something happened and not to whom (ASVS 16.2.1).
                //
                // Two events rather than one: the detection is the finding and the revocation
                // is the response to it, and a `revoke_family` that fails must not take the
                // finding down with it.
                tracing::warn!(
                    family_id = %family,
                    "refresh: reuse of a consumed refresh token detected — revoking the token family"
                );
                // The owner is read from the family index, and can come from nowhere else: the
                // replayed token's own key was deleted when it was rotated, so the index is the
                // last surviving link to an account. Read BEFORE the revocation rather than
                // returned by it, because the revocation needs the owner's tenant-scoped
                // subject to prune the right session index — and the record is what carries the
                // tenant.
                let owner = self
                    .session_store
                    .find_family_owner(SessionKind::Dashboard, &family)
                    .await?;
                let owner_subject = owner.as_ref().map(|record| {
                    self.subject_hash(
                        SessionKind::Dashboard,
                        record.tenant_id.as_deref(),
                        &record.user_id,
                    )
                });
                self.session_store
                    .revoke_family(SessionKind::Dashboard, &family, owner_subject.as_deref())
                    .await?;
                let owner_id = owner.as_ref().map(|record| record.user_id.as_str());
                // Bound rather than inlined in the field; see the note in `login`.
                let logged_owner = owner_id.unwrap_or("<unknown>");
                tracing::warn!(
                    user_id = logged_owner,
                    family_id = %family,
                    "refresh: token family revoked after reuse detection"
                );
                self.fire_reuse_detected(owner_id, &family).await;
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
        // The platform subject carries no tenant segment — its admins are cross-tenant and have
        // none — but it is still an HMAC of `platform:{adminId}` rather than the bare id. A
        // platform epoch left on the bare id would be a different key from the one nest-auth
        // reads, and an epoch nobody bumps revalidates admin tokens a revocation had killed.
        let subject = self.subject_hash(SessionKind::Platform, None, &admin.id);
        let epoch = self
            .session_store
            .current_epoch(SessionKind::Platform, &subject)
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
                &subject,
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
        // The index the rotation moves the membership within; see the dashboard twin.
        let subject = self.subject_hash(SessionKind::Platform, None, &new_record.user_id);

        let rotation = SessionRotation {
            old_hash,
            new_hash: new.redis_hash(),
            new_raw: new.expose_secret().to_owned(),
            new_record: new_record.clone(),
            subject_hash: subject.clone(),
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
                    .current_epoch(SessionKind::Platform, &subject)
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
                // The RECOVERED record names the owner; the placeholder that reached the script
                // did not, so the subject built before the rotation cannot be reused here.
                let recovered_subject =
                    self.subject_hash(SessionKind::Platform, None, &fresh_record.user_id);
                // The platform twin of the dashboard grace write, atomic for the same reason —
                // on the plane where the surviving session is the highest-privilege identity
                // in the system.
                if !self
                    .session_store
                    .create_recovered_session(
                        SessionKind::Platform,
                        &recovered_subject,
                        &fresh.redis_hash(),
                        &fresh_record,
                        self.refresh_ttl_secs,
                    )
                    .await?
                {
                    return Err(AuthError::RefreshTokenInvalid);
                }
                let epoch = self
                    .session_store
                    .current_epoch(SessionKind::Platform, &recovered_subject)
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
                // Named for the same reason as the dashboard plane, and more so: this is the
                // highest-privilege identity in the system.
                tracing::warn!(
                    family_id = %family,
                    "platform refresh: reuse of a consumed refresh token detected — revoking the token family"
                );
                // The owner is read from the family index, and can come from nowhere else: the
                // replayed token's own key was deleted when it was rotated, so the index is the
                // last surviving link to an account. Read before the revocation, which needs
                // the owner's subject to prune the right session index.
                let owner = self
                    .session_store
                    .find_family_owner(SessionKind::Platform, &family)
                    .await?;
                let owner_subject = owner
                    .as_ref()
                    .map(|record| self.subject_hash(SessionKind::Platform, None, &record.user_id));
                self.session_store
                    .revoke_family(SessionKind::Platform, &family, owner_subject.as_deref())
                    .await?;
                let owner_id = owner.as_ref().map(|record| record.user_id.as_str());
                let logged_owner = owner_id.unwrap_or("<unknown>");
                tracing::warn!(
                    user_id = logged_owner,
                    family_id = %family,
                    "platform refresh: token family revoked after reuse detection"
                );
                self.fire_reuse_detected(owner_id, &family).await;
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
                .current_epoch(
                    SessionKind::Platform,
                    &self.subject_hash(SessionKind::Platform, None, &claims.sub),
                )
                .await?
        {
            return Err(AuthError::TokenRevoked);
        }
        Ok(claims)
    }

    /// Re-sign a rotated platform access token with the authority the administrator holds
    /// *now*.
    ///
    /// The platform twin of [`Self::reissue_access_with_authority`]. Platform rotation builds
    /// its claims from the `prt:` record written at login, so the role and MFA flag it carries
    /// are the ones the admin had then, inherited unchanged through every later rotation.
    /// Demoting a `super_admin` to `support` therefore had no effect on a live console
    /// session: it kept minting tokens with the old authority for the refresh token's whole
    /// lifetime, and every role check reads that claim — on the highest-privilege identity in
    /// the system. The dashboard plane closed this; the platform plane was left with the
    /// identical hole.
    ///
    /// Everything the rotated token already established is kept, including `mfa_verified`: a
    /// second factor already cleared on this session must not be silently demanded again. A
    /// fresh `jti`, window and epoch are issued — the token this replaces was never handed out.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if claim serialization fails (unreachable for the
    /// concrete claim type), or a store failure while reading the epoch.
    #[cfg(feature = "platform")]
    pub(crate) async fn reissue_platform_access_with_authority(
        &self,
        claims: &PlatformClaims,
        role: &str,
        mfa_enabled: bool,
    ) -> Result<String, AuthError> {
        let now = now_unix();
        let epoch = self
            .session_store
            .current_epoch(
                SessionKind::Platform,
                &self.subject_hash(SessionKind::Platform, None, &claims.sub),
            )
            .await?;
        self.issue_platform_access(&PlatformClaims {
            epoch,
            jti: new_uuid_v4(),
            role: role.to_owned(),
            mfa_enabled,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            ..claims.clone()
        })
    }

    /// Build the platform access claims for a rotated/recovered session. As with the dashboard
    /// rotation, `mfa_verified` is dropped (re-acquired only via the MFA challenge) while
    /// `mfa_enabled` is carried over from the stored record; the claims carry no `tenant_id`.
    /// The `epoch` is the admin's current generation, read at rotation time. `refresh` then
    /// re-stamps the role and MFA flag from the account it re-reads, via
    /// [`Self::reissue_platform_access_with_authority`].
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
                .current_epoch(
                    SessionKind::Dashboard,
                    &self.subject_hash(
                        SessionKind::Dashboard,
                        Some(&claims.tenant_id),
                        &claims.sub,
                    ),
                )
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
        tenant_id: Option<&str>,
        epoch: u64,
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
            tenant_id: tenant_id.map(ToOwned::to_owned),
            epoch,
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
        tenant_id: Option<&str>,
    ) -> Result<String, AuthError> {
        let _ = (context, tenant_id);
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
        tenant_id: Option<&str>,
    ) -> Result<String, AuthError> {
        // Refuse a malformed (plane, tenant) pair BEFORE signing anything. Verification applies
        // the same predicate, and when only verification applied it this method happily returned
        // `Ok` — and planted the single-use `mfa:` marker — for a shape that could never be
        // redeemed. A host calling the public core API got a signed credential that was dead on
        // arrival, and found out one round-trip later at the second factor, as an opaque invalid
        // token. Same predicate, so the two cannot drift.
        if !crate::services::mfa::plane_tenant_is_well_formed(context, tenant_id) {
            // Bound first so the field expression shares a line with the macro: a `tracing`
            // field on its own line is only evaluated when a subscriber is listening, so it
            // reads as uncovered in every run that does not install one.
            let plane = context.as_str();
            tracing::warn!(plane, "mfa challenge refused at issuance");
            return Err(AuthError::Validation {
                details: vec![bymax_auth_types::FieldError {
                    field: "tenantId".to_owned(),
                    message: "a dashboard MFA challenge requires a non-empty tenantId, and a \
                              platform one requires none"
                        .to_owned(),
                }],
            });
        }
        // Stamped so the challenge token dies with the rest of the account's credentials. See
        // the claim's own documentation for what it was surviving.
        let kind = crate::services::mfa::session_kind(context);
        let epoch = self
            .session_store
            .current_epoch(kind, &self.subject_hash(kind, tenant_id, user_id))
            .await?;
        let (token, jti) = self.build_mfa_temp_token(user_id, context, tenant_id, epoch)?;
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
        // The same bulk-revocation gate the access-token verifiers apply, on the plane the
        // challenge was issued for. A password reset bumps the epoch and kills every access
        // token, but nothing deleted an outstanding `mfa:` marker — so a challenge token minted
        // before the reset stayed redeemable for its whole TTL, and completing it handed back a
        // full session under the new epoch. The reset is supposed to end everything the old
        // credential could still reach, and this was the one credential it did not reach.
        //
        // The check lives here rather than in `MfaService::challenge` so every caller of the
        // temp token inherits it.
        let kind = crate::services::mfa::session_kind(claims.context);
        if claims.epoch
            < self
                .session_store
                .current_epoch(
                    kind,
                    &self.subject_hash(kind, claims.tenant_id.as_deref(), &claims.sub),
                )
                .await?
        {
            return Err(AuthError::MfaTempTokenInvalid);
        }
        // A dashboard challenge without a tenant is refused rather than resolved. Everything the
        // challenge decides — the status gate, `mfa_enabled`, the secret it decrypts, the
        // recovery digests it scans, and the account the session is finally minted for — comes
        // from a lookup that needs this value; the alternative to refusing is looking the account
        // up by id alone, which under a host schema that numbers users per tenant resolves to
        // whichever row the repository happens to return. Accepting the token and falling back
        // would leave that derivation reachable by omitting one optional field, so the claim is
        // optional on the wire and mandatory in effect.
        //
        // The platform plane is the exact inverse: its admins are cross-tenant and carry no
        // tenant at all, so a value here would have to be invented, and an invented one becomes
        // a lookup key. Both directions are refused for the same reason — the tenant a token
        // asserts must be the tenant the account actually belongs to.
        // The same predicate issuance applies, so a shape accepted there is redeemable here and
        // one rejected there can never arrive. The error differs by design: a caller ASKING for
        // a malformed challenge gets a validation error naming the field, while a caller
        // PRESENTING one gets the opaque invalid-token every other bad temp token gets — a
        // holder must not learn which part of a forged claim set was wrong.
        if !crate::services::mfa::plane_tenant_is_well_formed(
            claims.context,
            claims.tenant_id.as_deref(),
        ) {
            return Err(AuthError::MfaTempTokenInvalid);
        }
        let tenant_id = claims.tenant_id;
        Ok(MfaTempVerified {
            user_id: claims.sub,
            context: claims.context,
            tenant_id,
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

    /// Re-sign a rotated access token with the authority the account holds *now*.
    ///
    /// Rotation builds its claims from the session record written at login, so the role,
    /// tenant and MFA flag it carries are the ones the account had then. This re-stamps all
    /// three from the freshly read account, keeping everything else the rotated token already
    /// established — including `mfa_verified`, because a second factor already cleared on this
    /// session must not be silently demanded again. A fresh `jti`, window, and epoch are
    /// issued: the token this replaces was never handed out.
    ///
    /// `mfa_enabled` is re-stamped rather than inherited because it gates a security control:
    /// `MfaSatisfied` refuses a token only when `mfa_enabled && !mfa_verified`, so a session
    /// created while the account had no second factor would otherwise keep minting
    /// `mfa_enabled: false` tokens for the refresh token's whole lifetime, clearing every
    /// MFA-gated route without a challenge. That is reachable whenever the host enables MFA
    /// through its own admin surface rather than this library's `verify_and_enable`, which is
    /// the only path that revokes the sessions and bumps the epoch.
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
        mfa_enabled: bool,
    ) -> Result<String, AuthError> {
        let now = now_unix();
        // The tenant the token is about to carry, not the one in the stale claims: this method
        // re-signs precisely when the account's authority moved, and the epoch it stamps must be
        // the one `verify_access` will read back from the re-signed token.
        let epoch = self
            .session_store
            .current_epoch(
                SessionKind::Dashboard,
                &self.subject_hash(SessionKind::Dashboard, Some(tenant_id), &claims.sub),
            )
            .await?;
        self.issue_access(&DashboardClaims {
            epoch,
            jti: new_uuid_v4(),
            role: role.to_owned(),
            tenant_id: tenant_id.to_owned(),
            mfa_enabled,
            iat: now,
            exp: now.saturating_add(self.access_ttl.as_secs().min(i64::MAX as u64) as i64),
            ..claims.clone()
        })
    }

    /// Build the access claims for a rotated/recovered session. Rotation always drops
    /// `mfa_verified` (the user re-acquires it only via the MFA challenge) and issues an
    /// empty `status` — status guards consult the repository/status cache, not the rotated
    /// JWT, because the stored session record carries no live status. The `epoch` is the
    /// user's current generation, read at rotation time.
    ///
    /// `mfa_enabled` is carried over from the stored record rather than reset: the MFA gate
    /// refuses a token only when `mfa_enabled && !mfa_verified`, so minting `false` here
    /// would let one routine refresh turn an enrolled account's token into one that clears
    /// every MFA-gated route without ever completing a challenge. `refresh` then re-stamps it
    /// from the account it re-reads, via [`Self::reissue_access_with_authority`], so a flag
    /// the host changed outside this library does not stay stale for the session's lifetime.
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

/// The identifier-hashing key the test fixtures in this file derive every account-scoped key
/// under. Fixed rather than random so a test can recompute a subject and name the exact key a
/// flow wrote, and shared by both test modules so the two cannot key the same account apart.
#[cfg(test)]
const TEST_IDENTIFIER_KEY: [u8; 64] = [9u8; 64];

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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
        )
    }

    /// A manager whose current key is `key()` and which also accepts `retired` for verification.
    fn service_rotating(store: Arc<InMemoryStores>, retired: Vec<HsKey>) -> TokenManagerService {
        TokenManagerService::new(
            key(),
            retired,
            store,
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
        )
    }

    /// The dashboard session subject the fixtures' manager derives for [`user`] — the key its
    /// token epoch actually lives under.
    ///
    /// A test that bumped `ep:"u1"` by hand would write a key the verifier no longer reads, and
    /// would then assert that a pre-bump token is still accepted while calling that a pass.
    fn dashboard_subject() -> String {
        crate::services::session_subject_hash(
            &TEST_IDENTIFIER_KEY,
            SessionKind::Dashboard,
            Some(&user().tenant_id),
            &user().id,
        )
    }

    /// The platform twin, for [`platform_admin`]. No tenant segment — its admins have none.
    #[cfg(feature = "platform")]
    fn platform_subject() -> String {
        crate::services::session_subject_hash(
            &TEST_IDENTIFIER_KEY,
            SessionKind::Platform,
            None,
            &platform_admin().id,
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
        // Replaying the consumed old token is rejected as a detected reuse... Captured, because
        // the account the revocation hit is named only in the log: the caller is told
        // `RefreshTokenInvalid` either way, so which family was cut is otherwise unobservable.
        let (events, capture) = crate::log_capture::capture_events();
        assert!(matches!(
            svc.reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        drop(capture);
        assert!(events.contains_at(
            tracing::Level::WARN,
            "refresh: token family revoked after reuse detection"
        ));
        assert!(events.contains("user_id=u1"));
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
    async fn a_login_plants_the_recent_auth_marker_at_the_key_the_reader_looks_under() {
        // The writer and the reader of `ra:` had DIFFERENT preimages and nothing compared them.
        // `issue_tokens` planted `hmac_sha256("dashboard:{userId}")`; `MfaService`'s
        // re-authentication gate reads `hmac_sha256(userSubject)` —
        // `dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}` — which is what the shared
        // contract's `recentAuthMarker` names. So on the dashboard plane the marker was written
        // to a key nobody read, and every password-less account was refused MFA enrolment with
        // `ReauthenticationRequired`, permanently.
        //
        // It was invisible because the MFA fixtures plant the marker BY HAND at the reader's key
        // instead of signing in: both halves were correct in isolation and never met. So this
        // test derives the expectation by hand too — the same independence, aimed at the writer.
        // Calling the service's own helper here would follow the derivation wherever it goes and
        // assert nothing.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let user = user();
        let expected = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            &TEST_IDENTIFIER_KEY,
            format!(
                "dashboard:{}:{}:{}",
                user.tenant_id.len(),
                user.tenant_id,
                user.id
            )
            .as_bytes(),
        ));

        assert!(matches!(store.has_recent_auth(&expected).await, Ok(false)));
        assert!(
            svc.issue_tokens(&user, "10.0.0.1", "agent/1.0", false)
                .await
                .is_ok()
        );
        assert!(
            matches!(store.has_recent_auth(&expected).await, Ok(true)),
            "the login planted no marker at the tenant-scoped subject the MFA gate reads"
        );

        // …and NOT at the tenant-less preimage it used to use, which two accounts sharing an id
        // in different tenants would have shared.
        let old_shape = crate::services::to_hex(&bymax_auth_crypto::mac::hmac_sha256(
            &TEST_IDENTIFIER_KEY,
            format!("dashboard:{}", user.id).as_bytes(),
        ));
        assert!(
            matches!(store.has_recent_auth(&old_shape).await, Ok(false)),
            "the tenant-less recent-auth key is still being written"
        );
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
        // Through the account's SUBJECT, which is what the index is keyed by — passing the bare
        // id revokes nothing, the descendant stays readable, and the test then measures a
        // recoverable owner while claiming to measure an unrecoverable one.
        assert!(
            store
                .revoke_session(
                    SessionKind::Dashboard,
                    &dashboard_subject(),
                    &rotated_hash(&rotated)
                )
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
        // Captured for the same reason as the dashboard case: the revoked account is named in
        // the log and nowhere else.
        let (events, capture) = crate::log_capture::capture_events();
        assert!(matches!(
            svc.reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
                .await,
            Err(AuthError::RefreshTokenInvalid)
        ));
        drop(capture);
        assert!(events.contains_at(
            tracing::Level::WARN,
            "platform refresh: token family revoked after reuse detection"
        ));
        assert!(events.contains("user_id=p1"));
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
        assert!(
            store
                .bump_epoch(SessionKind::Dashboard, &dashboard_subject())
                .await
                .is_ok()
        );
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
        assert!(
            store
                .bump_epoch(SessionKind::Platform, &platform_subject())
                .await
                .is_ok()
        );
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
        let issued = svc
            .issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
            .await;
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
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
        let issued = svc
            .issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
            .await;
        let Ok(token) = issued else { return };
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
    async fn issuance_refuses_the_shapes_verification_would_reject() {
        // Issuance and verification apply the SAME predicate. When only verification applied it,
        // this method returned `Ok` — and planted the single-use `mfa:` marker — for a shape that
        // could never be redeemed: a host calling the public core API got back a signed
        // credential that was dead on arrival and found out one round-trip later, at the second
        // factor, as an opaque invalid-token. Refusing here turns that into a validation error
        // naming the field, at the call that got it wrong.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store);

        for (label, ctx, tenant) in [
            ("dashboard without a tenant", MfaContext::Dashboard, None),
            (
                "dashboard with a blank tenant",
                MfaContext::Dashboard,
                Some(""),
            ),
            ("platform with a tenant", MfaContext::Platform, Some("t1")),
        ] {
            let issued = svc.issue_mfa_temp_token("u1", ctx, tenant).await;
            assert!(
                matches!(issued, Err(AuthError::Validation { ref details })
                    if details.iter().any(|d| d.field == "tenantId")),
                "{label} must be refused at issuance, naming the field — got {issued:?}"
            );
        }

        // The two well-formed shapes still issue, so the guard rejects a shape rather than
        // everything.
        assert!(
            svc.issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
                .await
                .is_ok()
        );
        assert!(
            svc.issue_mfa_temp_token("p1", MfaContext::Platform, None)
                .await
                .is_ok()
        );
    }

    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn verify_refuses_a_challenge_token_whose_tenant_does_not_match_its_plane() {
        // The tenant claim is optional ON THE WIRE and mandatory IN EFFECT. Falling back when it
        // is absent would leave the tenant-blind derivation reachable by omitting one field —
        // the attacker picks the old path — so absent is refused instead, which is the pattern
        // RFC 8725 §3.9 sets for a missing audience and §3.12 asks for as mutually exclusive
        // validation rules per token kind. ASVS 5.0 6.6.2 is the requirement underneath: the
        // out-of-band token must be BOUND to the authentication request that generated it, and a
        // challenge token with no tenant is bound to nothing but an id.
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store.clone());
        let mfa_store: Arc<dyn crate::traits::MfaStore> = store;

        // A dashboard challenge with NO tenant: refused, not resolved by id alone.
        let built = svc.build_mfa_temp_token("u1", MfaContext::Dashboard, None, 0);
        let Ok((token, jti)) = built else { return };
        assert!(mfa_store.put_temp(&jti_hash(&jti), "u1", 300).await.is_ok());
        let refused = svc.verify_mfa_temp_token(&token).await;
        assert!(
            matches!(refused, Err(AuthError::MfaTempTokenInvalid)),
            "a dashboard challenge token without a tenant must be refused, never defaulted"
        );

        // An EMPTY tenant is the same refusal: it is a present-but-meaningless value that would
        // otherwise build `dashboard::{userId}` — a third preimage neither side derives.
        let built = svc.build_mfa_temp_token("u1", MfaContext::Dashboard, Some(""), 0);
        let Ok((token, jti)) = built else { return };
        assert!(mfa_store.put_temp(&jti_hash(&jti), "u1", 300).await.is_ok());
        assert!(matches!(
            svc.verify_mfa_temp_token(&token).await,
            Err(AuthError::MfaTempTokenInvalid)
        ));

        // And the inverse: a platform admin is cross-tenant and carries none, so a tenant here
        // is an assertion the account cannot satisfy. Refused rather than ignored — ignoring it
        // would accept a token that claims something false about the identity it names.
        let built = svc.build_mfa_temp_token("p1", MfaContext::Platform, Some("t1"), 0);
        let Ok((token, jti)) = built else { return };
        assert!(mfa_store.put_temp(&jti_hash(&jti), "p1", 300).await.is_ok());
        assert!(matches!(
            svc.verify_mfa_temp_token(&token).await,
            Err(AuthError::MfaTempTokenInvalid)
        ));

        // The two well-formed shapes still verify, and carry the tenant through to the caller —
        // otherwise this test would pass just as well against a verify that refuses everything.
        let built = svc.build_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"), 0);
        let Ok((token, jti)) = built else { return };
        assert!(mfa_store.put_temp(&jti_hash(&jti), "u1", 300).await.is_ok());
        let verified = svc.verify_mfa_temp_token(&token).await;
        assert!(matches!(
            verified,
            Ok(ref v) if v.tenant_id.as_deref() == Some("t1")
        ));

        let built = svc.build_mfa_temp_token("p1", MfaContext::Platform, None, 0);
        let Ok((token, jti)) = built else { return };
        assert!(mfa_store.put_temp(&jti_hash(&jti), "p1", 300).await.is_ok());
        let verified = svc.verify_mfa_temp_token(&token).await;
        assert!(matches!(verified, Ok(ref v) if v.tenant_id.is_none()));
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
        let built = svc.build_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"), 0);
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
        let issued = svc
            .issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
            .await;
        let Ok(token) = issued else { return };
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

        let issued = svc
            .issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
            .await;
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
            svc.issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
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
            .issue_mfa_temp_token("user-1", MfaContext::Dashboard, Some("t1"))
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
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

    /// A grace recovery that lands after a "log out everywhere" must not mint a session.
    ///
    /// The grace window exists so a rotation that lost a race can still recover. That makes it
    /// a way back in after a revoke: the sweep deletes the live sessions, the replay of a
    /// consumed token finds its grace pointer, and the recovery writes a fresh session on an
    /// account the user was told had been swept — carrying the post-bump epoch, so it verifies.
    /// The write is gated on the per-user index still existing, which is precisely "no sweep
    /// has run", and the caller is refused when it has.
    #[tokio::test]
    async fn a_recovery_whose_account_was_swept_is_refused() {
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let Some(issued) = issued_for(&svc).await else { return };

        // Rotate once, leaving the old token consumed but inside its grace window.
        let rotated = rotated_for(&svc, &issued.refresh_token).await;
        assert!(rotated.is_some(), "the first rotation must succeed");

        // The sweep lands between the grace pointer's read and the recovery's write. A store
        // cannot produce that ordering on its own — by the time it could answer, it would
        // already have refused the grace arm — so the answer is armed directly.
        store.refuse_next_recovered_writes(1);

        let replayed = svc
            .reissue_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        assert!(
            matches!(replayed, Err(AuthError::RefreshTokenInvalid)),
            "a recovery whose account was swept must be refused, got {replayed:?}"
        );
    }

    /// The same on the platform plane, whose grace arm is a separate code path — and the plane
    /// where an unswept console session is worth more.
    #[tokio::test]
    async fn a_platform_recovery_whose_account_was_swept_is_refused() {
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());
        let Some(issued) = platform_issued_for(&svc).await else { return };

        let rotated = platform_rotated_for(&svc, &issued.refresh_token).await;
        assert!(
            rotated.is_some(),
            "the first platform rotation must succeed"
        );

        store.refuse_next_recovered_writes(1);

        let replayed = svc
            .reissue_platform_tokens(&issued.refresh_token, "10.0.0.1", "agent/1.0")
            .await;
        assert!(
            matches!(replayed, Err(AuthError::RefreshTokenInvalid)),
            "a platform recovery whose account was swept must be refused, got {replayed:?}"
        );
    }

    /// An MFA temp token dies with the rest of the account's credentials.
    ///
    /// It is issued to someone who has proven a password and NOT a second factor, and it lives
    /// long enough to be worth revoking: without the epoch stamp, a password reset — which
    /// bumps the epoch precisely to kill everything outstanding — would leave a challenge token
    /// alive, and completing that challenge mints a full session on the account just secured.
    #[cfg(feature = "mfa")]
    #[tokio::test]
    async fn an_mfa_temp_token_issued_before_an_epoch_bump_stops_verifying() {
        let store = Arc::new(InMemoryStores::new());
        let svc = service_with_mfa(store.clone());

        let issued = svc
            .issue_mfa_temp_token("u1", MfaContext::Dashboard, Some("t1"))
            .await;
        let Ok(temp) = issued else { return };

        // Before the bump it verifies.
        let first = svc.verify_mfa_temp_token(&temp).await;
        assert!(
            first.is_ok(),
            "a freshly issued challenge token must verify: {first:?}"
        );

        assert!(
            store
                .bump_epoch(SessionKind::Dashboard, &dashboard_subject())
                .await
                .is_ok()
        );

        let after = svc.verify_mfa_temp_token(&temp).await;
        assert!(
            matches!(after, Err(AuthError::MfaTempTokenInvalid)),
            "a challenge token minted before the bump must stop verifying, got {after:?}"
        );
    }

    /// A deliberately stale set of dashboard claims: an id, a window and an epoch that a
    /// re-issue must all replace rather than inherit.
    ///
    /// Hand-built rather than taken from a freshly issued token, and that is the point. `iat`
    /// has one-second resolution, so claims minted moments earlier in the same test carry the
    /// same second as the re-issue — and a `window` assertion against them holds whether the
    /// field was replaced or inherited. Only a window that is unmistakably from another time
    /// can tell the two apart.
    fn stale_dashboard_claims() -> DashboardClaims {
        DashboardClaims {
            iss: None,
            aud: None,
            sub: "u1".to_owned(),
            jti: "00000000-0000-4000-8000-000000000000".to_owned(),
            tenant_id: "old-tenant".to_owned(),
            role: "MEMBER".to_owned(),
            token_type: DashboardType::Dashboard,
            status: String::new(),
            mfa_enabled: false,
            mfa_verified: true,
            iat: 1_000,
            exp: 1_900,
            epoch: 0,
        }
    }

    #[tokio::test]
    async fn a_reissued_access_token_gets_a_fresh_id_window_and_the_current_epoch() {
        // `reissue_access_with_authority` promises "a fresh `jti`, window, and epoch are
        // issued", and every one of those was unasserted: each field could be dropped from the
        // literal — inheriting the old value through `..claims.clone()` — with the whole suite
        // still green.
        //
        // They are not interchangeable in what they cost. A re-used `jti` collapses two tokens
        // into one revocation identity, so the `rv:{jti}` a logout writes for one silently
        // revokes the other, and a token minted after a logout is born already blacklisted. An
        // inherited `exp` re-mints a session with the ORIGINAL login's window, so a console
        // that has been refreshing for hours hands out tokens that are already expired. An
        // inherited `epoch` re-mints below the account's current generation, so the token a
        // refresh just issued is refused by the very check the refresh exists to satisfy.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());

        // The account's generation has moved on since the stale claims were minted. Bumped under
        // the subject of the tenant the re-issue is MOVING the account to (`new-tenant`), not the
        // stale claims' `old-tenant`: the re-signed token will carry the new tenant, so that is
        // the subject its next verification reads the epoch from, and stamping an epoch from the
        // old tenant's counter would hand back a token that verifies against a counter nobody
        // bumps.
        let subject = crate::services::session_subject_hash(
            &TEST_IDENTIFIER_KEY,
            SessionKind::Dashboard,
            Some("new-tenant"),
            &stale_dashboard_claims().sub,
        );
        let bumped = store.bump_epoch(SessionKind::Dashboard, &subject).await;
        let Ok(bumped) = bumped else { return };
        assert_eq!(bumped, 1, "the fixture epoch must start at zero");

        let stale = stale_dashboard_claims();
        let reissued = svc
            .reissue_access_with_authority(&stale, "ADMIN", "new-tenant", true)
            .await;
        // Asserted before unwrapping, for the same reason the verification below is: a re-issue
        // that fails outright would otherwise skip every freshness assertion and read as a pass.
        assert!(
            reissued.is_ok(),
            "the re-issue itself failed, so nothing below was checked: {reissued:?}"
        );
        let Ok(token) = reissued else { return };
        let verified = svc.verify_access(&token).await;
        // Asserted before it is unwrapped, and that is load-bearing: a `let-else` that returns
        // on `Err` makes this test vacuous for exactly the failures it exists to catch. An
        // inherited `exp` is already in the past and an inherited `epoch` sits below the
        // account's generation, so both come back from `verify_access` as an error rather than
        // as wrong values — and a silent `return` would call that a pass.
        assert!(
            verified.is_ok(),
            "a token this refresh just issued must verify: {verified:?}"
        );
        let Ok(fresh) = verified else { return };

        assert_ne!(
            fresh.jti, stale.jti,
            "the re-issued token kept the id it replaces, so one revocation now covers both"
        );
        assert!(
            fresh.iat > stale.iat && fresh.exp > stale.exp,
            "the re-issued token kept the window of the token it replaces: {} / {}",
            fresh.iat,
            fresh.exp
        );
        assert_eq!(
            fresh.exp - fresh.iat,
            900,
            "the re-issued window is not the configured access lifetime"
        );
        assert_eq!(
            fresh.epoch, bumped,
            "the re-issued token carries a generation the account has already moved past"
        );
        // The re-stamped authority, alongside, so the fresh-field assertions above cannot be
        // satisfied by a re-issue that quietly dropped what it was asked to carry.
        assert_eq!(fresh.role, "ADMIN");
        assert_eq!(fresh.tenant_id, "new-tenant");
        assert!(fresh.mfa_enabled);
        // Everything else rides through untouched — `mfa_verified` above all: a second factor
        // already cleared on this session must not be silently demanded again.
        assert_eq!(fresh.sub, stale.sub);
        assert!(fresh.mfa_verified);
    }

    #[tokio::test]
    async fn an_expired_access_token_still_verifies_on_the_logout_path() {
        // `verify_access_ignoring_expiry` exists for exactly one caller, logout, and the
        // `validate_exp: false` that makes it work was unasserted — dropping the field falls
        // back to the validating default, and nothing went red. What that costs is in the
        // method's own doc: an access token that expired while the user was away is the NORMAL
        // case at logout, and refusing it leaves the refresh session — the long-lived
        // credential logout exists to kill — alive for its whole remaining lifetime.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);

        // The stale fixture's window is already long past — that is what makes it stale.
        let expired = stale_dashboard_claims();
        let signed = svc.issue_access(&expired);
        let Ok(token) = signed else { return };

        // The ordinary verifier refuses it, which is what makes the logout path necessary.
        let ordinary = svc.verify_access(&token).await;
        assert!(
            matches!(ordinary, Err(AuthError::TokenExpired)),
            "a long-expired token must not pass the ordinary verifier: {ordinary:?}"
        );

        // The logout verifier accepts it, and the signature still had to hold — the `jti` it
        // returns is what decides which token gets blacklisted.
        let for_logout = svc.verify_access_ignoring_expiry(&token);
        assert!(
            matches!(&for_logout, Ok(claims) if claims.jti == expired.jti),
            "the logout path refused an expired token: {for_logout:?}"
        );

        // A garbage signature is still refused, so "ignoring expiry" has not become
        // "ignoring verification".
        let tampered = format!("{token}x");
        assert!(svc.verify_access_ignoring_expiry(&tampered).is_err());
    }

    /// The platform twin of [`stale_dashboard_claims`], hand-built for the same reason.
    #[cfg(feature = "platform")]
    fn stale_platform_claims() -> PlatformClaims {
        PlatformClaims {
            iss: None,
            aud: None,
            sub: "a1".to_owned(),
            jti: "00000000-0000-4000-8000-000000000001".to_owned(),
            role: "support".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: true,
            iat: 1_000,
            exp: 1_900,
            epoch: 0,
        }
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn a_reissued_platform_token_gets_a_fresh_id_window_and_the_current_epoch() {
        // The platform twin of the dashboard case above, and the plane where it costs the most:
        // these are the highest-privilege identities in the system, so a re-used `jti`, a
        // window inherited from the original sign-in, or a generation the operator has already
        // been moved past all land on the console rather than on a tenant user.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store.clone());

        // The stale claims name `a1`, not the `platform_admin` fixture, so the epoch has to be
        // bumped under THAT admin's subject — the one `reissue_platform_access_with_authority`
        // will read back.
        let subject = crate::services::session_subject_hash(
            &TEST_IDENTIFIER_KEY,
            SessionKind::Platform,
            None,
            &stale_platform_claims().sub,
        );
        let bumped = store.bump_epoch(SessionKind::Platform, &subject).await;
        let Ok(bumped) = bumped else { return };
        assert_eq!(bumped, 1, "the fixture epoch must start at zero");

        let stale = stale_platform_claims();
        let reissued = svc
            .reissue_platform_access_with_authority(&stale, "super_admin", true)
            .await;
        // Asserted before unwrapping, for the same reason the verification below is: a re-issue
        // that fails outright would otherwise skip every freshness assertion and read as a pass.
        assert!(
            reissued.is_ok(),
            "the re-issue itself failed, so nothing below was checked: {reissued:?}"
        );
        let Ok(token) = reissued else { return };
        let verified = svc.verify_platform_access(&token).await;
        // Asserted before unwrapping, for the reason the dashboard twin spells out.
        assert!(
            verified.is_ok(),
            "a token this refresh just issued must verify: {verified:?}"
        );
        let Ok(fresh) = verified else { return };

        assert_ne!(
            fresh.jti, stale.jti,
            "the re-issued admin token kept the id it replaces"
        );
        assert!(
            fresh.iat > stale.iat && fresh.exp > stale.exp,
            "the re-issued admin token kept the window of the token it replaces: {} / {}",
            fresh.iat,
            fresh.exp
        );
        assert_eq!(
            fresh.exp - fresh.iat,
            900,
            "the re-issued window is not the configured access lifetime"
        );
        assert_eq!(
            fresh.epoch, bumped,
            "the re-issued admin token carries a generation the account has moved past"
        );
        // The re-stamped authority is the whole reason this method exists: a demoted admin must
        // not keep minting tokens with the role they held at sign-in.
        assert_eq!(fresh.role, "super_admin");
        assert!(fresh.mfa_enabled);
        assert_eq!(fresh.sub, stale.sub);
        assert!(fresh.mfa_verified);
    }

    #[cfg(feature = "platform")]
    #[tokio::test]
    async fn an_expired_platform_token_still_verifies_on_the_logout_path() {
        // The platform twin, for the case its own doc names: an operator who walks away for
        // longer than the access lifetime and then signs out is ordinary, and refusing them
        // leaves the refresh session of the highest-privilege identity in the system alive on a
        // console they believed they had left.
        let store = Arc::new(InMemoryStores::new());
        let svc = service(store);

        let expired = stale_platform_claims();
        let signed = svc.issue_platform_access(&expired);
        let Ok(token) = signed else { return };

        let ordinary = svc.verify_platform_access(&token).await;
        assert!(
            matches!(ordinary, Err(AuthError::TokenExpired)),
            "a long-expired admin token must not pass the ordinary verifier: {ordinary:?}"
        );

        let for_logout = svc.verify_platform_access_ignoring_expiry(&token);
        assert!(
            matches!(&for_logout, Ok(claims) if claims.jti == expired.jti),
            "the platform logout path refused an expired token: {for_logout:?}"
        );

        let tampered = format!("{token}x");
        assert!(
            svc.verify_platform_access_ignoring_expiry(&tampered)
                .is_err()
        );
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 30,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
        )
    }

    /// The dashboard session subject the fixtures' manager derives for a record's account —
    /// the index a seeded session has to be registered under for the manager to find it.
    fn subject(record: &SessionRecord) -> String {
        crate::services::session_subject_hash(
            &TEST_IDENTIFIER_KEY,
            SessionKind::Dashboard,
            record.tenant_id.as_deref(),
            &record.user_id,
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
        );
        let old = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &subject(&record_born(31)),
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
                    &subject(&record_born(31)),
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
                    &subject(&record_born(29)),
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
                .create_session(
                    SessionKind::Dashboard,
                    &subject(&exactly),
                    &old.redis_hash(),
                    &exactly,
                    3600,
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
                .create_session(
                    SessionKind::Dashboard,
                    &subject(&uncapped),
                    &old.redis_hash(),
                    &uncapped,
                    3600,
                )
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
            TokenLifetimes {
                access_ttl: Duration::from_secs(900),
                refresh_expires_in_days: 7,
                grace_window: Duration::from_secs(30),
                absolute_session_lifetime_days: 0,
            },
            Zeroizing::new(TEST_IDENTIFIER_KEY),
        );
        let ancient = RawRefreshToken::generate();
        assert!(
            store
                .create_session(
                    SessionKind::Dashboard,
                    &subject(&record_born(365)),
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
