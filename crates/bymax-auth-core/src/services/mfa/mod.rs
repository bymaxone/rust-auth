//! The TOTP MFA lifecycle service (§7.5): setup, verify-and-enable, challenge, disable, and
//! recovery-code regeneration, for dashboard users and (routed but issuance-deferred)
//! platform admins.
//!
//! Every security property the spec mandates is enforced here: the TOTP secret is
//! AES-256-GCM encrypted before it touches the store or the user row and is returned in
//! plaintext **only** by [`MfaService::setup`]; recovery codes are persisted only as keyed
//! HMAC-SHA-256 digests and shown in plaintext exactly once; every TOTP verification is
//! anti-replayed (the standalone `tu:` marker here, the fused marker-plus-consume on the
//! challenge path); the pending-setup record, the completion gate, and the fused challenge
//! step are each a single atomic store transition; and a decrypt failure collapses to one
//! opaque error with no padding/format oracle. The whole module compiles only under the
//! `mfa` feature.

mod challenge;
mod manage;
mod setup;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use bymax_auth_crypto::compare::constant_time_eq;
use bymax_auth_crypto::mac::hmac_sha256;
use bymax_auth_crypto::{aead, token, totp};
use bymax_auth_types::{AuthError, AuthResult, MfaContext, SafeAuthUser};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::services::brute_force::BruteForceService;
use crate::services::session::SessionService;
use crate::services::token_manager::TokenManagerService;
use crate::services::{internal_error, now_unix, to_hex};
use crate::traits::{
    AuthHooks, EmailProvider, MfaStore, PlatformUserRepository, SessionKind, SessionStore,
    UserRepository,
};

/// The TTL of the AES-protected pending-setup record, in seconds (§7.5).
const MFA_SETUP_TTL_SECONDS: u64 = 600;
/// The TTL of a TOTP anti-replay marker, in seconds: covers the full ±1-period acceptance
/// span ((2·window+1)·30 = 90 s) plus buffer (§7.5).
const TOTP_ANTI_REPLAY_TTL_SECONDS: u64 = 90;
/// The number of random bytes behind one recovery code (96 bits of entropy, §7.5).
const RECOVERY_CODE_BYTES: usize = 12;
/// The number of random bytes behind a TOTP secret (160 bits, RFC 6238 / §7.5.1).
const TOTP_SECRET_BYTES: usize = 20;

/// The one-time result of [`MfaService::setup`]: the Base32 secret to enter manually, the
/// `otpauth://` provisioning URI to render as a QR code, and the plaintext recovery codes.
/// This is the **only** place the secret and the plaintext codes are ever returned.
///
/// The `Debug` impl redacts all three fields: the secret, the QR URI (which embeds the
/// secret), and the recovery codes are credential material, so a stray `{:?}` in a log line
/// can never leak them (§24).
#[derive(Clone)]
pub struct MfaSetupResult {
    /// The Base32-encoded TOTP secret (what a user types into an authenticator app).
    pub secret: String,
    /// The `otpauth://totp/...` provisioning URI, suitable for a QR code.
    pub qr_code_uri: String,
    /// The plaintext recovery codes, shown exactly once.
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for MfaSetupResult {
    /// Redacts the secret, the secret-bearing QR URI, and the plaintext recovery codes, keeping
    /// only the code count visible for diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaSetupResult")
            .field("secret", &"[REDACTED]")
            .field("qr_code_uri", &"[REDACTED]")
            .field(
                "recovery_codes",
                &format_args!("[{} REDACTED codes]", self.recovery_codes.len()),
            )
            .finish()
    }
}

/// The result of a successful MFA *challenge*. Discriminated by the temp token's context; in
/// this phase only the dashboard issuance path is wired (platform issuance lands with the
/// platform identity domain).
#[derive(Clone, Debug)]
pub enum LoginResultMfa {
    /// A full dashboard authentication (the second factor cleared, `mfa_verified = true`).
    Dashboard(AuthResult),
}

/// The AES-protected pending-setup record, held under `mfa_setup:{hmac(user_id)}` between
/// `setup` and `verify_and_enable`. Every field is already encrypted or keyed-hashed, so the
/// record carries no plaintext secret or recovery code. JSON is camelCase for parity with the
/// nest-auth payload shape (§12.4).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MfaSetupData {
    /// The AES-256-GCM wire string of the raw TOTP secret bytes.
    encrypted_secret: String,
    /// The keyed HMAC-SHA-256 digests of the recovery codes.
    hashed_codes: Vec<String>,
    /// The AES-256-GCM wire string of the JSON-encoded plaintext recovery codes, so the
    /// idempotent `setup` fast-path can re-return the same codes.
    encrypted_plain_codes: String,
}

/// A context-agnostic view of the MFA-relevant fields of the challenged account, plus the
/// credential-free dashboard projection when the context is `Dashboard` (used to issue tokens
/// and fire the user-facing hooks). For a `Platform` context `dashboard_user` is `None`.
struct MfaUserView {
    email: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    dashboard_user: Option<SafeAuthUser>,
}

/// The MFA lifecycle service. Constructed by the engine builder only when `config.mfa` is
/// present; the collaborators it shares with the engine (token manager, session service,
/// brute-force service) are held as `Arc` handles.
pub struct MfaService {
    mfa_store: Arc<dyn MfaStore>,
    user_repo: Arc<dyn UserRepository>,
    platform_repo: Option<Arc<dyn PlatformUserRepository>>,
    tokens: Arc<TokenManagerService>,
    sessions: Arc<SessionService>,
    session_store: Arc<dyn SessionStore>,
    brute_force: Arc<BruteForceService>,
    email: Arc<dyn EmailProvider>,
    hooks: Arc<dyn AuthHooks>,
    /// AES-256-GCM key for the TOTP secret and the plaintext-codes record.
    encryption_key: Zeroizing<[u8; 32]>,
    /// The engine's identifier-hashing key, keying every `mfa_setup:`/`tu:` suffix, the
    /// `challenge:`/`disable:` brute-force ids, and the recovery-code digests.
    identifier_key: Zeroizing<[u8; 32]>,
    issuer: String,
    totp_window: u8,
    recovery_code_count: u8,
    sessions_enabled: bool,
}

/// The collaborators an [`MfaService`] is assembled from. Grouped into a struct so the
/// constructor takes a single value rather than a long positional argument list (the
/// `clippy::too_many_arguments` ceiling is otherwise exceeded).
pub(crate) struct MfaServiceDeps {
    pub(crate) mfa_store: Arc<dyn MfaStore>,
    pub(crate) user_repo: Arc<dyn UserRepository>,
    pub(crate) platform_repo: Option<Arc<dyn PlatformUserRepository>>,
    pub(crate) tokens: Arc<TokenManagerService>,
    pub(crate) sessions: Arc<SessionService>,
    pub(crate) session_store: Arc<dyn SessionStore>,
    pub(crate) brute_force: Arc<BruteForceService>,
    pub(crate) email: Arc<dyn EmailProvider>,
    pub(crate) hooks: Arc<dyn AuthHooks>,
    pub(crate) encryption_key: Zeroizing<[u8; 32]>,
    pub(crate) identifier_key: Zeroizing<[u8; 32]>,
    pub(crate) issuer: String,
    pub(crate) totp_window: u8,
    pub(crate) recovery_code_count: u8,
    pub(crate) sessions_enabled: bool,
}

impl MfaService {
    /// Assemble the service from its resolved collaborators and MFA configuration.
    pub(crate) fn new(deps: MfaServiceDeps) -> Self {
        Self {
            mfa_store: deps.mfa_store,
            user_repo: deps.user_repo,
            platform_repo: deps.platform_repo,
            tokens: deps.tokens,
            sessions: deps.sessions,
            session_store: deps.session_store,
            brute_force: deps.brute_force,
            email: deps.email,
            hooks: deps.hooks,
            encryption_key: deps.encryption_key,
            identifier_key: deps.identifier_key,
            issuer: deps.issuer,
            totp_window: deps.totp_window,
            recovery_code_count: deps.recovery_code_count,
            sessions_enabled: deps.sessions_enabled,
        }
    }

    /// The `mfa_setup:` key suffix for a user (`hmac_sha256(user_id)`, hex). The low-entropy
    /// id is keyed, never used raw, so no PII reaches a store key.
    fn setup_key(&self, user_id: &str) -> String {
        to_hex(&hmac_sha256(
            self.identifier_key.as_ref(),
            user_id.as_bytes(),
        ))
    }

    /// The `tu:` anti-replay key suffix for a `(user_id, code)` pair
    /// (`hmac_sha256("{user_id}:{code}")`, hex) — ties the marker to both the user and the
    /// code value, with no plaintext code in the store and no cross-user replay.
    fn replay_id(&self, user_id: &str, code: &str) -> String {
        to_hex(&hmac_sha256(
            self.identifier_key.as_ref(),
            format!("{user_id}:{code}").as_bytes(),
        ))
    }

    /// The hashed brute-force identifier for the pre-auth challenge counter
    /// (`hmac_sha256("challenge:{user_id}")`, hex), isolated from the `disable:` namespace.
    fn challenge_bf_id(&self, user_id: &str) -> String {
        to_hex(&hmac_sha256(
            self.identifier_key.as_ref(),
            format!("challenge:{user_id}").as_bytes(),
        ))
    }

    /// The hashed brute-force identifier for the authenticated management counter
    /// (`hmac_sha256("disable:{user_id}")`, hex), shared by `disable` and `regenerate` and
    /// isolated from the `challenge:` namespace.
    fn disable_bf_id(&self, user_id: &str) -> String {
        to_hex(&hmac_sha256(
            self.identifier_key.as_ref(),
            format!("disable:{user_id}").as_bytes(),
        ))
    }

    /// The keyed HMAC-SHA-256 digest (hex) of a recovery code — the only form ever persisted.
    fn hash_recovery_code(&self, code: &str) -> String {
        to_hex(&hmac_sha256(self.identifier_key.as_ref(), code.as_bytes()))
    }

    /// AES-256-GCM-encrypt `plaintext` under the configured MFA key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] only if the cipher rejects an implausibly large input.
    fn encrypt(&self, plaintext: &[u8]) -> Result<String, AuthError> {
        // Encryption only fails on an implausibly large plaintext (MFA inputs are tiny); the
        // `.ok().ok_or` form maps that unreachable failure to the opaque error eagerly, so there
        // is no untestable closure on the always-succeeding path (mirrors `aead::encrypt`).
        aead::encrypt(plaintext, &self.encryption_key)
            .ok()
            .ok_or(internal_error("mfa secret encryption failed"))
    }

    /// AES-256-GCM-decrypt a wire string under the configured MFA key. Returns `None` on any
    /// failure (wrong key, tampered ciphertext, malformed wire) so the failure mode is opaque
    /// — the caller maps `None` to the appropriate flow error with no padding/format oracle.
    fn decrypt(&self, wire: &str) -> Option<Vec<u8>> {
        aead::decrypt(wire, &self.encryption_key).ok()
    }

    /// Verify a 6-digit TOTP `code` against `secret` and, on success, atomically mark it used
    /// (the standalone `tu:` marker, `NX EX 90`). A code that verifies but was already seen
    /// returns `Ok(false)` — the replay is rejected. Used by the enable / disable / regenerate
    /// paths, which carry no temp token to consume (§7.5.6).
    ///
    /// # Errors
    ///
    /// Returns a store [`AuthError`] only if the anti-replay marker cannot be written.
    async fn verify_totp_with_anti_replay(
        &self,
        user_id: &str,
        secret: &[u8],
        code: &str,
    ) -> Result<bool, AuthError> {
        if !totp::verify(secret, code, current_unix_time(), self.totp_window) {
            return Ok(false);
        }
        // The code is valid; mark it used. `mark_totp_used` returns whether the marker was
        // newly created — `false` means the code was already seen, i.e. a replay.
        self.mfa_store
            .mark_totp_used(&self.replay_id(user_id, code), TOTP_ANTI_REPLAY_TTL_SECONDS)
            .await
    }

    /// Load the MFA-relevant view of the challenged account for `ctx`. A `Platform` context
    /// with no platform repository fails fast with [`AuthError::MfaNotEnabled`] (never persist
    /// a platform secret on a tenant row); a missing account is also `MfaNotEnabled`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] for a misconfigured platform context or a missing
    /// account, or a repository [`AuthError::Internal`] on a backend failure.
    async fn fetch_user_mfa(
        &self,
        user_id: &str,
        ctx: MfaContext,
    ) -> Result<MfaUserView, AuthError> {
        match ctx {
            MfaContext::Dashboard => {
                let user = self
                    .user_repo
                    .find_by_id(user_id, None)
                    .await
                    .map_err(repository_error)?
                    .ok_or(AuthError::MfaNotEnabled)?;
                Ok(MfaUserView {
                    email: user.email.clone(),
                    mfa_enabled: user.mfa_enabled,
                    mfa_secret: user.mfa_secret.clone(),
                    dashboard_user: Some(SafeAuthUser::from(user)),
                })
            }
            MfaContext::Platform => {
                let repo = self
                    .platform_repo
                    .as_ref()
                    .ok_or(AuthError::MfaNotEnabled)?;
                let admin = repo
                    .find_by_id(user_id)
                    .await
                    .map_err(repository_error)?
                    .ok_or(AuthError::MfaNotEnabled)?;
                Ok(MfaUserView {
                    email: admin.email,
                    mfa_enabled: admin.mfa_enabled,
                    mfa_secret: admin.mfa_secret,
                    dashboard_user: None,
                })
            }
        }
    }

    /// Persist a new MFA configuration to the correct repository for `ctx`. The caller has
    /// already AES-encrypted the secret and keyed-hashed the recovery codes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MfaNotEnabled`] if a platform write is attempted with no platform
    /// repository, or a repository [`AuthError::Internal`] on a backend failure.
    async fn persist_mfa(
        &self,
        user_id: &str,
        ctx: MfaContext,
        enabled: bool,
        secret: Option<String>,
        codes: Option<Vec<String>>,
    ) -> Result<(), AuthError> {
        match ctx {
            MfaContext::Dashboard => self
                .user_repo
                .update_mfa(
                    user_id,
                    bymax_auth_types::UpdateMfaData {
                        mfa_enabled: enabled,
                        mfa_secret: secret,
                        mfa_recovery_codes: codes,
                    },
                )
                .await
                .map_err(repository_error),
            MfaContext::Platform => {
                let repo = self
                    .platform_repo
                    .as_ref()
                    .ok_or(AuthError::MfaNotEnabled)?;
                repo.update_mfa(
                    user_id,
                    bymax_auth_types::UpdatePlatformMfaData {
                        mfa_enabled: enabled,
                        mfa_secret: secret,
                        mfa_recovery_codes: codes,
                    },
                )
                .await
                .map_err(repository_error)
            }
        }
    }

    /// Reject the operation when the brute-force identifier is already locked out, surfacing
    /// the retry hint (mirrors the login lockout gate).
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AccountLocked`] when the window is tripped, or a store
    /// [`AuthError`] on failure.
    async fn assert_not_locked(&self, bf_id: &str) -> Result<(), AuthError> {
        if self.brute_force.is_locked(bf_id).await? {
            let retry = self.brute_force.remaining_lockout_secs(bf_id).await?;
            return Err(AuthError::AccountLocked {
                retry_after_seconds: Some(retry),
            });
        }
        Ok(())
    }

    /// Generate a fresh TOTP secret (raw bytes) and a fresh recovery-code set, returning the
    /// raw secret bytes, the plaintext codes, and the AES/keyed-hash-protected record to
    /// persist. The plaintext is never persisted directly; only the record is.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] if encrypting the secret or the plaintext-codes JSON
    /// fails (unreachable for these tiny inputs).
    fn generate_setup_material(&self) -> Result<(Vec<u8>, Vec<String>, MfaSetupData), AuthError> {
        let raw_secret = token::random_bytes(TOTP_SECRET_BYTES);
        let plain_codes: Vec<String> = (0..self.recovery_code_count)
            .map(|_| generate_recovery_code())
            .collect();
        let hashed_codes: Vec<String> = plain_codes
            .iter()
            .map(|code| self.hash_recovery_code(code))
            .collect();
        // Serializing a `Vec<String>` cannot fail; map the unreachable error eagerly so no
        // untestable closure sits on the success path.
        let plain_json = serde_json::to_string(&plain_codes)
            .ok()
            .ok_or(internal_error("mfa codes encode"))?;
        let data = MfaSetupData {
            encrypted_secret: self.encrypt(&raw_secret)?,
            hashed_codes,
            encrypted_plain_codes: self.encrypt(plain_json.as_bytes())?,
        };
        Ok((raw_secret, plain_codes, data))
    }

    /// Reconstruct the one-time [`MfaSetupResult`] from a stored pending record: decrypt the
    /// secret and the plaintext codes and rebuild the Base32 secret + provisioning URI. Used
    /// by the idempotent `setup` fast-path and the lost-NX-race recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Internal`] if the record cannot be decoded or decrypted (an
    /// internal inconsistency in our own record, never surfaced to the client as a decrypt
    /// oracle).
    fn setup_result_from_record(
        &self,
        email: &str,
        record_json: &str,
    ) -> Result<MfaSetupResult, AuthError> {
        let data: MfaSetupData = serde_json::from_str(record_json)
            .map_err(|_| internal_error("mfa setup record decode"))?;
        let raw_secret = self
            .decrypt(&data.encrypted_secret)
            .ok_or_else(|| internal_error("mfa setup record secret decrypt"))?;
        let plain_json = self
            .decrypt(&data.encrypted_plain_codes)
            .ok_or_else(|| internal_error("mfa setup record codes decrypt"))?;
        let recovery_codes: Vec<String> = serde_json::from_slice(&plain_json)
            .map_err(|_| internal_error("mfa setup record codes decode"))?;
        Ok(self.build_setup_result(email, &raw_secret, recovery_codes))
    }

    /// Build the one-time setup result from the raw secret bytes and the plaintext codes.
    fn build_setup_result(
        &self,
        email: &str,
        raw_secret: &[u8],
        recovery_codes: Vec<String>,
    ) -> MfaSetupResult {
        MfaSetupResult {
            secret: totp::encode_secret_base32(raw_secret),
            qr_code_uri: totp::provisioning_uri(raw_secret, email, &self.issuer),
            recovery_codes,
        }
    }

    /// Build the sanitized hook context for an MFA management operation from the identity
    /// already proven by the access token plus the request IP/user-agent.
    fn hook_context(
        &self,
        user_id: &str,
        email: &str,
        ip: &str,
        user_agent: &str,
    ) -> crate::traits::HookContext {
        crate::traits::HookContext {
            user_id: Some(user_id.to_owned()),
            email: Some(email.to_owned()),
            tenant_id: None,
            ip: ip.to_owned(),
            user_agent: user_agent.to_owned(),
            sanitized_headers: std::collections::BTreeMap::new(),
        }
    }
}

/// The session-domain selector for an MFA context.
fn session_kind(ctx: MfaContext) -> SessionKind {
    match ctx {
        MfaContext::Dashboard => SessionKind::Dashboard,
        MfaContext::Platform => SessionKind::Platform,
    }
}

/// The current Unix time as the `u64` seconds TOTP verification expects. A pre-epoch clock
/// (unreachable in practice) clamps to zero rather than wrapping.
fn current_unix_time() -> u64 {
    u64::try_from(now_unix()).unwrap_or(0)
}

/// Generate one recovery code: 12 CSPRNG bytes rendered as 24 upper-case hex characters,
/// grouped `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (96 bits of entropy, §7.5).
fn generate_recovery_code() -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = token::random_bytes(RECOVERY_CODE_BYTES);
    let mut hex = String::with_capacity(RECOVERY_CODE_BYTES * 2);
    for byte in bytes {
        hex.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
        hex.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
    }
    // Insert a hyphen between each group of four characters.
    let mut grouped = String::with_capacity(hex.len() + hex.len() / 4);
    for (index, ch) in hex.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(ch);
    }
    grouped
}

/// Find the index of the recovery code matching `code` among the stored keyed-HMAC digests,
/// in constant time across the whole set (no early return on a match), so neither which code
/// matched nor whether any matched leaks through timing. Returns the matched index, or `None`.
fn verify_recovery_code(stored_digests: &[String], candidate_digest: &str) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (index, digest) in stored_digests.iter().enumerate() {
        // Accumulate without short-circuiting: every element is compared. `or` keeps the FIRST
        // match (a later duplicate digest cannot overwrite it) while still visiting every
        // element, so the scan stays constant-time and the spliced index is unambiguous.
        if constant_time_eq(digest.as_bytes(), candidate_digest.as_bytes()) {
            found = found.or(Some(index));
        }
    }
    found
}

/// Map a repository failure to the opaque internal error (the concrete cause is carried for
/// logging, never serialized).
fn repository_error(error: crate::RepositoryError) -> AuthError {
    match error {
        crate::RepositoryError::Backend(source) => AuthError::Internal(source),
        crate::RepositoryError::Conflict(_) => internal_error("mfa repository conflict"),
    }
}
