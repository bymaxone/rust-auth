# Phase 7 — MFA (TOTP) end-to-end

> **Status**: ✅ Done · **Progress**: 6 / 6 tasks · **Last updated**: 2026-06-19
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P7
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

The cryptographic primitives MFA needs already exist: Phase 1 built the `mfa`-gated `bymax-auth-crypto` modules — `aead::encrypt`/`aead::decrypt` (AES-256-GCM), `totp::{totp, verify, encode_secret_base32, provisioning_uri}` (RFC 6238 over HMAC-SHA1), `mac::hmac_sha256`, and the constant-time `compare`. Phase 4 built `TokenManagerService` and the always-on flows; Phase 5 built the real Redis store layer + the atomic Lua harness; Phase 6 built the stateful services (sessions, OTP, password reset, invitations). This phase wires those pieces into the complete **TOTP MFA lifecycle** so local login (and, in later phases, platform login and OAuth) can require a second factor.

P7 spans three crates. In `bymax-auth-redis` it adds the **MFA storage layer**: the `MfaStore` trait impl plus the MFA-specific atomic Lua (the AES-protected pending-setup record under `SET NX`, the anti-replay `tu:` marker, and the **fused challenge Lua** that marks a TOTP code used and consumes the temp token in one atomic step). In `bymax-auth-core` it adds the **MFA temp-token methods** on `TokenManagerService` (split issue/verify/consume, §7.3.5) and the **`MfaService`** itself (`setup`, `verify_and_enable`, `challenge`, `disable`, `regenerate_recovery_codes`). The whole surface is `mfa`-feature-gated end to end: a no-MFA build links none of `aes-gcm`/`sha1`/`data-encoding` and none of the MFA service code.

When P7 is done, the full lifecycle — setup → verify-and-enable → challenge (TOTP and recovery code) → disable, plus recovery-code regeneration — works for dashboard login against both the in-memory and the real-Redis (testcontainers) tiers, every TOTP path is anti-replayed, the stored secret is encrypted at rest, recovery codes are stored only as keyed HMAC-SHA-256 digests, and the TOTP secret is never returned after `verify_and_enable`. **Platform MFA challenge wiring (P9), the OAuth MFA branch (P8), and all HTTP controllers/extractors (P10) are out of scope** — this phase delivers the engine-level MFA service and its storage, consumed by those phases through `MfaContext`.

---

## Rules-of-phase

1. **MFA crypto comes from Phase 1 — consume, don't re-implement.** `MfaService` calls `bymax-auth-crypto`'s `mfa`-gated `aead` / `totp` / `mac` / `compare`. No new crypto is written in this phase; the only new code is orchestration (core) and the MFA Lua/store (redis).
2. **Secret encrypted at rest; recovery codes hashed.** The TOTP secret is AES-256-GCM encrypted before it touches Redis or the user row; recovery codes are stored only as keyed HMAC-SHA-256 digests (the **intentional nest-auth divergence** — keyed HMAC, not scrypt, because the codes carry 96 bits of entropy). The plaintext secret is returned only by `setup`; the plaintext recovery codes are shown exactly once.
3. **Anti-replay on every TOTP path.** `verify_totp_with_anti_replay` sets a `tu:{hmac_sha256("{user_id}:{code}")}` marker `NX EX 90`; a re-seen code is rejected. On the *challenge* path the marker-set and the temp-token consume are a **single fused Lua step** so a replayed code can never consume a second token and a token can never be consumed without burning its code. The standalone form (no `mfa:` delete) is used by `verify_and_enable` / `disable` / `regenerate_recovery_codes`.
4. **Every racing transition is one atomic Lua step** — setup `SET NX`, completion `GETDEL`, the fused replay-mark + consume. No read-then-write across two round-trips.
5. **Split verify/consume on the temp token (§7.3.5).** `verify_mfa_temp_token` does `GET` (never `GETDEL`) so a single mistyped digit returns the retryable `MfaInvalidCode`, not a dead-ending `MfaTempTokenInvalid`; `consume_mfa_temp_token` deletes the `mfa:` key and is idempotent.
6. **Namespaced brute-force counters.** The challenge counter (`challenge:{user_id}`) is isolated from the disable/regenerate counter (`disable:{user_id}`) so a pre-auth attacker cannot exhaust the lockout and block the authenticated user's `disable`.
7. **TOTP-only for `disable` and `regenerate`** (never a recovery code). `disable` revokes all sessions; `regenerate_recovery_codes` intentionally does **not** (the factor is unchanged) — honor that documented divergence.
8. **Fail-fast on platform misconfiguration; decrypt failures are opaque.** A `Platform` context with no platform repo returns `MfaNotEnabled` (never persist a platform secret on a tenant row); any AES-GCM decrypt failure collapses to one opaque `AuthError` (no oracle).
9. **`mfa` feature-gating end to end.** A no-MFA build links none of the MFA crypto or service code; `cargo tree` shows `aes-gcm`/`sha1`/`data-encoding` only under `mfa`. 100% coverage, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on lib paths, English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 7.5 "`MfaService`" (incl. §7.5.1–§7.5.6) — `setup`, `verify_and_enable`, `challenge`, `disable`, `regenerate_recovery_codes`, `verify_totp_with_anti_replay`; `MfaContext`, `MfaSetupResult`, `MfaSetupData`; constants (`MFA_SETUP_TTL_SECONDS = 600`, `TOTP_ANTI_REPLAY_TTL_SECONDS = 90`, `DEFAULT_RECOVERY_CODE_COUNT = 8`); recovery-code format + keyed-HMAC hashing; the challenge-fusion Lua.
  - § 7.3.5 "MFA temp tokens (split verify/consume)" — `issue_mfa_temp_token` / `verify_mfa_temp_token` (no consume) / `consume_mfa_temp_token`; the `mfa:{sha256(jti)}` key, the bf-counter reset on issue, and the fused-consume note.
  - § 17.1 "Crate-by-crate crypto choices" — MFA secret encryption (AES-256-GCM), TOTP (RFC 6238 over `hmac`+`sha1`, base32 via `data-encoding`), HMAC split, constant-time compare. **These primitives already exist (Phase 1) — this is the contract, not a build target.**
  - § 12.4 (key catalog) + § 12.5 (Lua) — the `mfa_setup:`, `mfa:`, `tu:` keyspaces (all TTL'd, no PII) and the atomic-Lua patterns the MFA store follows.
  - § 13.3 — `MfaChallengeResult` / `MfaTempClaims` and the dashboard-vs-platform challenge result shapes.
  - § 5.1.5 — `MfaConfig` (issuer, window, recovery-code count, encryption key).
  - § 24 — Security Invariants 5 (secret never returned after setup/enable), 6 (recovery codes hashed), 13 (constant-time), 15 (atomic state / TOTP anti-replay), 16 (CSPRNG), 18 (secrets encrypted/hashed at rest).
- [`docs/development_plan.md`](../development_plan.md) — § P7, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 7.1 | `MfaStore` trait + Redis impl + MFA Lua (setup NX, `tu:` replay, fused challenge) | ✅ Done | P0 | M | 5.1 |
| 7.2 | MFA temp tokens on `TokenManagerService` (split verify/consume) | ✅ Done | P0 | M | 7.1, 4.2 |
| 7.3 | `MfaService::setup` + `verify_and_enable` | ✅ Done | P0 | L | 7.1, 1.5, 1.6 |
| 7.4 | `MfaService::challenge` (TOTP + recovery code, fused consume, issue tokens) | ✅ Done | P0 | L | 7.2, 7.3 |
| 7.5 | `MfaService::disable` + `regenerate_recovery_codes` | ✅ Done | P0 | M | 7.3 |
| 7.6 | `mfa` facade feature wiring + no-MFA build proof + lifecycle E2E | ✅ Done | P0 | M | 7.3, 7.4, 7.5 |

---

## Tasks

### Task 7.1 — `MfaStore` trait + Redis impl + MFA Lua (setup NX, `tu:` replay, fused challenge)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 5.1

#### Description

Define the `MfaStore` trait in `bymax-auth-core` and implement it in `bymax-auth-redis`: the AES-protected pending-setup record (`SET NX`/`GET`/`GETDEL`), the standalone anti-replay `tu:` marker, and the **fused challenge Lua** (mark code used + consume temp token in one atomic step). Provide the in-memory double for the hermetic tier.

#### Acceptance criteria

- [ ] `MfaStore` trait (object-safe, `#[async_trait]`) in core: `put_setup_nx`/`get_setup`/`take_setup` (`GETDEL`) over `mfa_setup:{hmac_sha256(user_id)}` with the 600 s TTL; `mark_totp_used` (standalone `tu:` `SET NX EX 90`, returns whether newly created); `challenge_consume` (the fused Lua: set `tu:` `NX EX 90`, iff new `DEL mfa:{sha256(jti)}`, return new?); plus the temp-token marker ops `put_temp`/`get_temp`/`del_temp` over `mfa:{sha256(jti)}`.
- [ ] Redis impl in `bymax-auth-redis` over the Phase-5 pool + `LuaScript` loader; keys namespaced; setup record stored as the AES-GCM ciphertext only (no plaintext secret/codes ever resident).
- [ ] `lua/mfa_challenge.lua` implements the fused step exactly: `SET tu:{...} "1" NX EX 90`; if newly created, `DEL mfa:{...}`; return whether new. Documented KEYS/ARGV/return.
- [ ] In-memory `MfaStore` double (Phase-3 `testing` module) reproduces the atomic NX/GETDEL/fused semantics for hermetic tests.
- [ ] Integration tests (testcontainers): setup NX wins once; a replayed code's `tu:` marker is rejected; the fused challenge consumes the temp token exactly once under two concurrent same-code submissions.
- [ ] The whole module is `mfa`-gated; 100% coverage; no PII in any key.

#### Files to create / modify

- `crates/bymax-auth-core/src/traits/store.rs` (add `MfaStore`, `mfa`-gated)
- `crates/bymax-auth-redis/src/stores/mfa.rs`
- `crates/bymax-auth-redis/src/lua/mfa_challenge.lua`
- `crates/bymax-auth-core/src/testing/mod.rs` (in-memory `MfaStore` double)
- `crates/bymax-auth-redis/tests/mfa_store_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async; full parity with @bymax-one/nest-auth. The engine (`bymax-auth-core`)
defines store TRAITS; `bymax-auth-redis` implements them atomically via Lua (Phase 5).

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.1 of 6 (FIRST)

PRECONDITIONS
- Phase 5 is done: `bymax-auth-redis` has the `deadpool-redis` pool, the namespace `key()` helper,
  the `LuaScript` loader (EVALSHA + EVAL fallback), and the testcontainers harness.
- Phase 1 is done: `bymax-auth-crypto::mac::hmac_sha256` and `sha256` are available.
- Phase 3 `testing` module hosts the in-memory store doubles.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.3.5 "MFA temp tokens" — the `mfa:{sha256(jti)}` marker.
- `docs/technical_specification.md` § 7.5.6 "verify_totp_with_anti_replay" — the `tu:` marker AND the
  fused challenge Lua (`SET tu:... NX EX 90`; iff new `DEL mfa:...`; return new?).
- `docs/technical_specification.md` § 12.4–§12.5 — the `mfa_setup:`/`mfa:`/`tu:` keyspaces (TTLs,
  no-PII) and the atomic-Lua pattern to follow.

TASK
Define `MfaStore` in core and implement it in redis: the AES-protected setup record (NX/GET/GETDEL),
the standalone `tu:` anti-replay marker, the fused challenge Lua, and the `mfa:` temp-token ops.

DELIVERABLES

1. `crates/bymax-auth-core/src/traits/store.rs` (add, `#[cfg(feature = "mfa")]`):
   ```rust
   #[async_trait]
   pub trait MfaStore: Send + Sync {
       async fn put_setup_nx(&self, user_id_hash: &str, value: &str, ttl: u64) -> Result<bool, AuthError>;
       async fn get_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError>;
       async fn take_setup(&self, user_id_hash: &str) -> Result<Option<String>, AuthError>; // GETDEL
       async fn put_temp(&self, jti_hash: &str, user_id: &str, ttl: u64) -> Result<(), AuthError>;
       async fn get_temp(&self, jti_hash: &str) -> Result<Option<String>, AuthError>;        // GET (not GETDEL)
       async fn del_temp(&self, jti_hash: &str) -> Result<(), AuthError>;                     // idempotent
       async fn mark_totp_used(&self, replay_id: &str, ttl: u64) -> Result<bool, AuthError>;  // standalone tu:
       async fn challenge_consume(&self, replay_id: &str, jti_hash: &str, ttl: u64) -> Result<bool, AuthError>; // fused
   }
   ```
2. `crates/bymax-auth-redis/src/stores/mfa.rs` — `impl MfaStore for RedisStores` over the pool +
   `LuaScript`; setup record stored as the AES-GCM wire string only (the service encrypts before
   calling — this layer never sees plaintext).
3. `crates/bymax-auth-redis/src/lua/mfa_challenge.lua` — the fused step; document KEYS (`tu:`, `mfa:`)
   / ARGV (ttl) / return (1 if newly marked, else 0).
4. `crates/bymax-auth-core/src/testing/mod.rs` — in-memory `MfaStore` double reproducing NX/GETDEL/
   fused atomicity.
5. `crates/bymax-auth-redis/tests/mfa_store_e2e.rs` — testcontainers: setup-NX-once, replay rejected,
   fused consume exactly once under two concurrent same-code calls.

Constraints:
- Every multi-step transition is ONE Lua script (atomic). Keys are namespaced and carry only hashes.
- The whole `MfaStore` surface is `#[cfg(feature = "mfa")]`. No `axum`/HTTP.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-redis --features mfa --test mfa_store_e2e` (with Docker) — expected: pass.
- `cargo build -p bymax-auth-core` (no mfa) — expected: `MfaStore` absent, builds clean.
- `cargo llvm-cov -p bymax-auth-redis --features mfa --lcov` — expected: `stores/mfa.rs` 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P7 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 7.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 7.2 — MFA temp tokens on `TokenManagerService` (split verify/consume)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 7.1, 4.2

#### Description

Add the three MFA temp-token methods to `TokenManagerService` per §7.3.5 — `issue_mfa_temp_token`, `verify_mfa_temp_token` (GET, does **not** consume), and `consume_mfa_temp_token` (idempotent `DEL`) — over the `MfaStore` `mfa:` marker, with the brute-force-counter reset on issue.

#### Acceptance criteria

- [ ] `issue_mfa_temp_token(user_id, ctx) -> String` signs a short-lived (300 s) HS256 temp token carrying `MfaTempClaims { sub, context, jti }`, stores `mfa:{sha256(jti)} = user_id` (TTL 300 s), and resets the per-user challenge counter (`del lf:{hmac_sha256("challenge:{user_id}")}`).
- [ ] `verify_mfa_temp_token(token) -> MfaTempVerified { user_id, context, jti }` verifies signature + expiry (HS256-pinned), `GET`s (never `GETDEL`) `mfa:{sha256(jti)}` (`None` → `MfaTempTokenInvalid`), and cross-checks stored `user_id == sub`. **Does not consume.**
- [ ] `consume_mfa_temp_token(jti)` deletes `mfa:{sha256(jti)}`; idempotent.
- [ ] The split rationale (a mistyped digit must stay retryable as `MfaInvalidCode`, not dead-end as `MfaTempTokenInvalid`) is documented in code.
- [ ] Hermetic unit tests: issue→verify round-trip; verify is non-consuming (two verifies succeed); consume is idempotent; an expired/forged token → `MfaTempTokenInvalid`; the challenge counter is reset on issue.
- [ ] **Adversarial namespace isolation (§7.3.5 / §7.5.3).** A hermetic test proves the reset on issue targets the `challenge:{user_id}` counter only: pre-seed both `lf:{hmac_sha256("challenge:{user_id}")}` and `lf:{hmac_sha256("disable:{user_id}")}` to the lockout threshold, call `issue_mfa_temp_token`, then assert the `challenge:` counter is cleared while the `disable:` counter is untouched — so a pre-auth attacker who exhausts the challenge budget can neither lock out the authenticated user's `disable`/`regenerate` (the namespaces are isolated) nor, conversely, clear that counter by issuing fresh temp tokens.
- [ ] `mfa`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/token_manager.rs` (extend, `mfa`-gated methods)
- `crates/bymax-auth-core/tests/mfa_temp_token.rs` (hermetic)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` holds the engine services over store
TRAITS; real Redis impls in `bymax-auth-redis`. Edition 2024; parity with @bymax-one/nest-auth.
MFA login uses a short-lived, single-use, brute-force-capped temp token between the password step and
the second factor.

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 7.1 is done: `MfaStore` exposes `put_temp`/`get_temp`/`del_temp` over `mfa:{sha256(jti)}`.
- Phase 4: `TokenManagerService` exists (HS256 issuance via `bymax-auth-jwt`); `BruteForceStore`
  exposes the counter reset; `MfaTempClaims` and `MfaContext` are defined (Phase 2/3).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.3.5 "MFA temp tokens (split verify/consume)" — the three
  methods, the `mfa:{sha256(jti)}` key, the counter reset on issue, and the split rationale.
- `docs/technical_specification.md` § 13.3 — `MfaTempClaims` / `MfaTempVerified` shapes.

TASK
Add `issue_mfa_temp_token` / `verify_mfa_temp_token` (non-consuming GET) / `consume_mfa_temp_token`
(idempotent DEL) to `TokenManagerService`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/token_manager.rs` (extend, `#[cfg(feature = "mfa")]`):
   ```rust
   pub async fn issue_mfa_temp_token(&self, user_id: &str, ctx: MfaContext) -> Result<String, AuthError>;
   pub async fn verify_mfa_temp_token(&self, token: &str) -> Result<MfaTempVerified, AuthError>; // GET, no consume
   pub async fn consume_mfa_temp_token(&self, jti: &str) -> Result<(), AuthError>;                // DEL, idempotent
   ```
   - issue: sign HS256 (300 s), `put_temp(sha256(jti), user_id, 300)`, reset the `challenge:` counter.
   - verify: signature + expiry, `get_temp` (None → `MfaTempTokenInvalid`), cross-check `user_id == sub`.
   - Document why verify is non-consuming (a mistyped digit stays retryable).

2. `crates/bymax-auth-core/tests/mfa_temp_token.rs`: hermetic — issue→verify round-trip, verify is
   non-consuming, consume idempotent, expired/forged → `MfaTempTokenInvalid`, counter reset on issue.

Constraints:
- `verify` uses GET, never GETDEL. HS256 pinned. `mfa`-gated. No `axum`/HTTP, no direct Redis client.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing mfa" --test mfa_temp_token` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing mfa" --lcov` — expected: the new methods 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P7 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 7.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 7.3 — `MfaService::setup` + `verify_and_enable`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 7.1, 1.5, 1.6

#### Description

Create the `MfaService` skeleton (`MfaContext`, `MfaSetupResult`, `MfaSetupData`, the shared `verify_totp_with_anti_replay` helper) and implement the idempotent `setup` (AES-protected pending record via `SET NX`, fast-path idempotency) and `verify_and_enable` (anti-replay verify + atomic `GETDEL` completion gate + `update_mfa` + `revoke_all` + email).

#### Acceptance criteria

- [ ] `MfaService` is constructed only when `config.mfa` is present; `MfaContext { Dashboard, Platform }` routes to the correct repository; a `Platform` context with no platform repo → `MfaNotEnabled` (fail-fast).
- [ ] `setup` is idempotent: `mfa_enabled` → `MfaAlreadyEnabled`; fast-path returns the existing pending record (decrypted) if present (blocks AES/KDF CPU-amplification via repeated `/mfa/setup`); first-time generates a 20-byte CSPRNG secret → base32, AES-256-GCM-encrypts it, generates + HMAC-hashes `recovery_code_count` codes (format `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, uppercased, 96-bit), AES-encrypts the plain-codes JSON, and `put_setup_nx` (600 s); returns `{ secret, qr_code_uri = provisioning_uri(...), recovery_codes }`.
- [ ] `verify_and_enable`: platform guard; `mfa_enabled` → `MfaAlreadyEnabled`; load + decrypt the pending record (corrupt → opaque `MfaSetupRequired`); `verify_totp_with_anti_replay` (invalid → `MfaInvalidCode`); **atomic `take_setup` (`GETDEL`) completion gate** (`None` → `MfaSetupRequired`, blocking duplicate enable); `update_mfa(enabled, encrypted_secret, hashed_codes)` on the correct repo; `sessions.revoke_all(kind, user_id)`; `send_mfa_enabled_notification` + `after_mfa_enabled` fire-and-forget.
- [ ] `verify_totp_with_anti_replay` (private): `totp::verify` then `mark_totp_used(tu:{hmac_sha256("{user_id}:{code}")}, 90)`; a re-seen code → `false`. The TOTP secret is never returned after `verify_and_enable` (Security Invariant 5).
- [ ] **No-secret-after-enable (Security Invariant 5).** `verify_and_enable` returns `Result<(), AuthError>` — its success value carries neither the plaintext secret nor `qr_code_uri`; and after a successful enable no read path on `MfaService` (or the post-enable user record exposed through it) yields the plaintext secret or `qr_code_uri` — both are obtainable only from the one-time `setup` result. A dedicated hermetic test asserts this directly at the service boundary (not only end-to-end in Task 7.6).
- [ ] Hermetic unit tests cover: setup idempotency (fast-path), enable happy path, the no-secret-after-enable assertion above, anti-replay rejection on enable, duplicate-enable race (`GETDEL` gate), corrupt-record → `MfaSetupRequired`, platform-misconfig fail-fast. E2E (testcontainers) proves the setup-NX + completion-gate atomicity.
- [ ] `mfa`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/mfa/mod.rs` (struct, types, `verify_totp_with_anti_replay`)
- `crates/bymax-auth-core/src/services/mfa/setup.rs` (`setup` + `verify_and_enable`)
- `crates/bymax-auth-core/tests/mfa_setup.rs` (hermetic)
- `crates/bymax-auth-redis/tests/mfa_setup_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend/cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; MFA
crypto primitives already exist in `bymax-auth-crypto` (Phase 1, `mfa` feature). Edition 2024; full
parity with @bymax-one/nest-auth.

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.3 of 6 (MIDDLE — the MFA service foundation)

PRECONDITIONS
- Task 7.1 is done: `MfaStore` (`put_setup_nx`/`get_setup`/`take_setup`, `mark_totp_used`).
- Phase 1 is done: `bymax-auth-crypto` `mfa` module — `aead::encrypt(&[u8], &[u8;32]) -> Result<String>`,
  `aead::decrypt(&str, &[u8;32]) -> Result<Vec<u8>>`, `totp::{encode_secret_base32, provisioning_uri,
  verify}`, `mac::hmac_sha256`, constant-time `compare`, and the CSPRNG `token` module.
- Phase 4: `UserRepository`/`PlatformUserRepository` (`find_by_id` + `update_mfa`), `SessionStore`
  `revoke_all`, `EmailProvider::send_mfa_enabled_notification`, the `after_mfa_enabled` hook.
- `config.mfa` (issuer, window, recovery_code_count, encryption_key) and `UpdateMfaData` exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.5 "MfaService" intro + §7.5.1 `setup` + §7.5.2
  `verify_and_enable` + §7.5.6 `verify_totp_with_anti_replay` (standalone form). Note `MfaSetupData
  { encrypted_secret, hashed_codes, encrypted_plain_codes }`, `MfaSetupResult { secret, qr_code_uri,
  recovery_codes }`, the constants (`MFA_SETUP_TTL_SECONDS = 600`, `DEFAULT_RECOVERY_CODE_COUNT = 8`,
  `TOTP_ANTI_REPLAY_TTL_SECONDS = 90`), and the recovery-code format + keyed-HMAC hashing.
- `docs/technical_specification.md` § 24 — invariants 5 (secret never returned after setup/enable), 6 (recovery codes hashed), 18 (TOTP secret AES-256-GCM-encrypted at rest).

TASK
Build the `MfaService` skeleton + `verify_totp_with_anti_replay`, then implement `setup` (idempotent,
AES-protected `SET NX`) and `verify_and_enable` (anti-replay + atomic `GETDEL` gate + enable).

DELIVERABLES

1. `crates/bymax-auth-core/src/services/mfa/mod.rs`:
   - `pub enum MfaContext { Dashboard, Platform }`; `pub struct MfaSetupResult { secret, qr_code_uri,
     recovery_codes }`; internal `MfaSetupData { encrypted_secret, hashed_codes: Vec<String>,
     encrypted_plain_codes }`.
   - `MfaService` struct (built only when `config.mfa` is present), the repo-routing helper
     (`Dashboard`/`Platform` → correct repo; missing platform repo → `MfaNotEnabled`).
   - `async fn verify_totp_with_anti_replay(&self, user_id, secret, code, window) -> Result<bool>` —
     `totp::verify` then `mark_totp_used`.
2. `crates/bymax-auth-core/src/services/mfa/setup.rs`:
   - `setup(user_id, ctx) -> Result<MfaSetupResult>` per §7.5.1 (fast-path idempotency, `put_setup_nx`,
     `provisioning_uri`).
   - `verify_and_enable(user_id, code, ip, ua, ctx) -> Result<()>` per §7.5.2 (anti-replay verify →
     atomic `take_setup` gate → `update_mfa` → `revoke_all` → email + hook).
3. `crates/bymax-auth-core/tests/mfa_setup.rs`: hermetic — idempotent setup, enable happy path,
   anti-replay-on-enable, duplicate-enable race, corrupt-record → `MfaSetupRequired`, platform-misconfig.
4. `crates/bymax-auth-redis/tests/mfa_setup_e2e.rs`: testcontainers — setup-NX + completion-gate atomicity.

Constraints:
- The TOTP secret is AES-256-GCM encrypted before any persistence; the plaintext secret is returned
  ONLY by `setup`, never after `verify_and_enable`. Recovery codes persisted only as keyed
  HMAC-SHA-256 digests. Decrypt failure → opaque error (no oracle).
- `mfa`-gated. No `axum`/HTTP, no direct Redis client (call `MfaStore`/repos/`SessionStore`).
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing mfa" --test mfa_setup` — expected: all pass.
- `cargo test -p bymax-auth-redis --features mfa --test mfa_setup_e2e` (with Docker) — expected: atomicity.
- `cargo llvm-cov -p bymax-auth-core --features "testing mfa" --lcov` — expected: `services/mfa/{mod,setup}.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P7 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 7.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 7.4 — `MfaService::challenge` (TOTP + recovery code, fused consume, issue tokens)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 7.2, 7.3

#### Description

Implement the public, pre-auth `challenge` flow: verify the temp token (non-consuming), early brute-force, accept a TOTP code (fused anti-replay + consume in one Lua) or a recovery code (constant-time scan + splice-out + standalone consume), and issue full tokens with `mfa_verified = true`.

#### Acceptance criteria

- [ ] `challenge(mfa_temp_token, code, ip, ua) -> LoginResultMfa` verifies the temp token (`verify_mfa_temp_token`, **not** consumed yet), checks `is_locked_out(hmac_sha256("challenge:{user_id}"))` → `AccountLocked`, fetches the user for the context (`!mfa_enabled || mfa_secret.is_none()` → `MfaNotEnabled`), decrypts the secret.
- [ ] TOTP path (`^\d{6}$`): validate via the **fused** `challenge_consume` Lua (mark `tu:` + `DEL mfa:` atomically); recovery-code path: constant-time scan of the hashed codes (`verify_recovery_code` returns the matching index), then `consume_mfa_temp_token(jti)` standalone.
- [ ] On invalid code: `record_failure(&bf_id)` + `MfaInvalidCode` (temp token stays alive → retryable; lockout eventually fires). On success: `reset_failures`.
- [ ] If a recovery code was used: splice that index out of the stored set and `update_mfa` on the correct repo.
- [ ] Issue full tokens with `mfa_verified = true`: dashboard → `issue_tokens` (+ `create_session` if `sessions.enabled`); platform → `issue_platform_tokens`. Spawn `after_login` fire-and-forget. Return the dashboard or platform result (§13.3).
- [ ] Hermetic unit tests: TOTP success, recovery-code success (+ splice), wrong code → `record_failure` + retryable, lockout after the cap, recovery-code single-use. E2E (testcontainers) proves the fused single-consume under two concurrent correct submissions (one session, the loser gets `MfaInvalidCode`).
- [ ] `mfa`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/mfa/challenge.rs`
- `crates/bymax-auth-core/tests/mfa_challenge.rs` (hermetic)
- `crates/bymax-auth-redis/tests/mfa_challenge_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls in `bymax-auth-redis`. Edition 2024; full parity with @bymax-one/nest-auth. The MFA
challenge is the public, pre-auth second-factor step: the holder has only a short-lived temp token.

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.4 of 6 (MIDDLE — the most intricate MFA flow)

PRECONDITIONS
- Task 7.2 is done: `verify_mfa_temp_token` (non-consuming) / `consume_mfa_temp_token` on
  `TokenManagerService`.
- Task 7.3 is done: `MfaService` skeleton + `verify_totp_with_anti_replay`; `MfaStore::challenge_consume`
  (the fused Lua) from Task 7.1.
- Phase 4: `issue_tokens` / `issue_platform_tokens`, `SessionService::create_session`, `BruteForceStore`,
  `EmailProvider`, the `after_login` hook. `bymax-auth-crypto` constant-time `compare` + `mac::hmac_sha256`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.5.3 "challenge" — the full ordered flow (verify temp token →
  brute-force → fetch/decrypt → TOTP fused-consume OR recovery-code scan → splice/update → issue).
- `docs/technical_specification.md` § 7.5.6 — the fused challenge Lua (mark `tu:` + `DEL mfa:`).
- `docs/technical_specification.md` § 13.3 — the dashboard vs platform challenge result shapes.

TASK
Implement `challenge`: temp-token verify (non-consuming), brute-force, TOTP (fused consume) or
recovery code (scan + splice + standalone consume), then full-token issuance with `mfa_verified=true`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/mfa/challenge.rs`:
   `challenge(mfa_temp_token, code, ip, ua) -> Result<LoginResultMfa, AuthError>` exactly per §7.5.3:
   - The `challenge:` brute-force namespace (isolated from `disable:`).
   - TOTP (`^\d{6}$`) → `challenge_consume` fused Lua; recovery code → constant-time `verify_recovery_code`
     index scan → `consume_mfa_temp_token(jti)`.
   - invalid → `record_failure` + `MfaInvalidCode`; success → `reset_failures`; recovery used → splice
     + `update_mfa`.
   - issue full tokens (`mfa_verified = true`): dashboard `issue_tokens` (+ `create_session`),
     platform `issue_platform_tokens`; spawn `after_login`.

2. `crates/bymax-auth-core/tests/mfa_challenge.rs`: hermetic — TOTP success, recovery success + splice,
   wrong code retryable, lockout after cap, recovery single-use.

3. `crates/bymax-auth-redis/tests/mfa_challenge_e2e.rs`: testcontainers — two concurrent correct TOTP
   submissions ⇒ exactly one consume + one session; the loser gets `MfaInvalidCode`.

Constraints:
- The temp token is consumed ONLY after the code is confirmed valid; for TOTP the consume is fused
  with the anti-replay mark (one Lua). Recovery-code comparison is constant-time. Decrypt failure →
  opaque error.
- `mfa`-gated. No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`;
  no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing mfa sessions" --test mfa_challenge` — expected: all pass.
- `cargo test -p bymax-auth-redis --features mfa --test mfa_challenge_e2e` (with Docker) — expected: single-consume.
- `cargo llvm-cov -p bymax-auth-core --features "testing mfa sessions" --lcov` — expected: `services/mfa/challenge.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P7 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 7.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 7.5 — `MfaService::disable` + `regenerate_recovery_codes`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 7.3

#### Description

Implement the two authenticated, TOTP-only management operations: `disable` (clears MFA + revokes all sessions) and `regenerate_recovery_codes` (atomic wholesale recovery-code replacement, sessions intentionally **not** invalidated), both gated by a strong TOTP re-auth and the shared `disable:` brute-force namespace.

#### Acceptance criteria

- [ ] `disable(user_id, code, ip, ua, ctx)`: fetch user (`!mfa_enabled` → `MfaNotEnabled`); `is_locked_out(hmac_sha256("disable:{user_id}"))` → `AccountLocked`; `mfa_secret` absent → `TokenInvalid`; decrypt; `verify_totp_with_anti_replay` (**TOTP only** — recovery codes cannot disable) → invalid → `record_failure` + `MfaInvalidCode`; on success `reset_failures`, `update_mfa(enabled:false, secret:None, codes:None)`, `sessions.revoke_all(kind, user_id)`, `send_mfa_disabled_notification` + `after_mfa_disabled`.
- [ ] `regenerate_recovery_codes(user_id, totp_code, ip, ua, ctx)`: same TOTP-only re-auth gate and `disable:` counter namespace, **but sessions are NOT invalidated** (factor unchanged); generate + HMAC-hash a fresh set (same entropy/format as setup), `update_mfa` **atomically replacing** `mfa_recovery_codes` while preserving `mfa_secret`; spawn `after_mfa_recovery_codes_regenerated`; return the new plaintext set **exactly once**.
- [ ] The documented divergence (disable revokes sessions; regenerate does not) is reflected in code + tests.
- [ ] Hermetic unit tests: disable happy path + session revocation; disable rejects a recovery code; regenerate replaces the set atomically (an old code no longer verifies) and keeps sessions; both honor the lockout. E2E (testcontainers) proves the atomic wholesale replacement.
- [ ] `mfa`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/mfa/manage.rs` (`disable` + `regenerate_recovery_codes`)
- `crates/bymax-auth-core/tests/mfa_manage.rs` (hermetic)
- `crates/bymax-auth-redis/tests/mfa_manage_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls in `bymax-auth-redis`. Edition 2024; parity with @bymax-one/nest-auth. `disable` and
`regenerate_recovery_codes` are authenticated, TOTP-only operations behind a strong re-auth gate.

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.5 of 6 (MIDDLE)

PRECONDITIONS
- Task 7.3 is done: `MfaService` skeleton + `verify_totp_with_anti_replay`; repo routing; the keyed-HMAC
  recovery-code hashing helper.
- Phase 4: `BruteForceStore`, `SessionStore::revoke_all`, `EmailProvider::send_mfa_disabled_notification`,
  the `after_mfa_disabled` + `after_mfa_recovery_codes_regenerated` hooks, `update_mfa` on both repos.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.5.4 "disable" + § 7.5.5 "regenerate_recovery_codes" — the
  TOTP-only re-auth gate, the shared `disable:` counter namespace, and the SESSION-INVALIDATION
  DIVERGENCE (disable revokes; regenerate does not).
- `docs/technical_specification.md` § 24 — invariant 6 (codes hashed), 13 (constant-time).

TASK
Implement `disable` (clear MFA + revoke sessions) and `regenerate_recovery_codes` (atomic wholesale
code replacement, sessions NOT invalidated), both TOTP-only.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/mfa/manage.rs`:
   - `disable(user_id, code, ip, ua, ctx) -> Result<()>` per §7.5.4 (TOTP-only; on success clear MFA +
     `revoke_all` + email + hook).
   - `regenerate_recovery_codes(user_id, totp_code, ip, ua, ctx) -> Result<Vec<String>>` per §7.5.5
     (TOTP-only; atomic wholesale replacement preserving `mfa_secret`; sessions NOT revoked; return the
     new plaintext set once).

2. `crates/bymax-auth-core/tests/mfa_manage.rs`: hermetic — disable + session revocation; disable
   rejects a recovery code; regenerate replaces the set (old code fails) and keeps sessions; lockout
   honored on both.

3. `crates/bymax-auth-redis/tests/mfa_manage_e2e.rs`: testcontainers — atomic wholesale replacement
   (an old recovery code can never coexist with the new set).

Constraints:
- TOTP ONLY for both (a recovery code can never disable MFA or regenerate). `disable` revokes sessions;
  `regenerate` does NOT — preserve that divergence. New codes persisted only as keyed HMAC-SHA-256
  digests; plaintext shown exactly once.
- `mfa`-gated. No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`;
  no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing mfa" --test mfa_manage` — expected: all pass.
- `cargo test -p bymax-auth-redis --features mfa --test mfa_manage_e2e` (with Docker) — expected: atomic replace.
- `cargo llvm-cov -p bymax-auth-core --features "testing mfa" --lcov` — expected: `services/mfa/manage.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P7 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 7.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 7.6 — `mfa` facade feature wiring + no-MFA build proof + lifecycle E2E

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 7.3, 7.4, 7.5

#### Description

Wire the `mfa` facade feature so the MFA crypto + service surface is present only under `mfa`, prove a no-MFA build links none of it, and add the full-lifecycle E2E (setup → verify-and-enable → challenge via TOTP and via recovery code → disable) against real Redis.

#### Acceptance criteria

- [ ] The facade crate `bymax-auth` exposes an `mfa` feature that turns on `bymax-auth-core/mfa` and `bymax-auth-crypto/mfa` (and, where wired, `bymax-auth-redis/mfa`); the `MfaService` + `MfaContext` are re-exported only under it.
- [ ] A no-MFA build (`--no-default-features --features scrypt`) links none of `aes-gcm`/`sha1`/`data-encoding` and none of the MFA service code; `cargo tree` confirms.
- [ ] The `MfaService` is constructed by `AuthEngineBuilder` only when `config.mfa` is present (and absent from the API surface without the `mfa` feature).
- [ ] A full-lifecycle E2E test (testcontainers Redis) runs: setup → verify_and_enable → login→challenge (TOTP) → login→challenge (recovery code) → disable, asserting no endpoint returns the secret after enable, anti-replay holds on every path, and recovery-code regeneration is atomic.
- [ ] `cargo hack --feature-powerset` (the MFA-relevant subset) builds; `cargo deny check` passes with the MFA deps; 100% coverage across the MFA surface.

#### Files to create / modify

- `crates/bymax-auth/Cargo.toml` (the `mfa` facade feature)
- `crates/bymax-auth/src/lib.rs` (re-exports under `#[cfg(feature = "mfa")]`)
- `crates/bymax-auth-core/src/services/mod.rs` + `builder` wiring (construct `MfaService` when `config.mfa`)
- `crates/bymax-auth-redis/tests/mfa_lifecycle_e2e.rs` (testcontainers, full lifecycle)

#### Agent prompt

````
You are a senior Rust engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the facade crate `bymax-auth` re-exports the workspace
crates behind a feature taxonomy; every heavy capability is feature-gated so consumers pay only for
what they use. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 7 (MFA TOTP end-to-end) — Task 7.6 of 6 (LAST)

PRECONDITIONS
- Tasks 7.1–7.5 are done: `MfaStore` + MFA Lua (redis), the temp-token methods, and the full
  `MfaService` (`setup`/`verify_and_enable`/`challenge`/`disable`/`regenerate_recovery_codes`).
- Phase 0/3: the facade crate `bymax-auth` and `AuthEngineBuilder` exist; the feature taxonomy
  (`scrypt`/`argon2`/`sessions`/`mfa`/…) is established.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 19 "Dependencies & Feature Flags" — the `mfa` feature and the
  "pay only for what you use" `cargo tree` assertions.
- `docs/technical_specification.md` § 7.5 intro — `MfaService` is constructed only when `config.mfa`
  is present.
- `docs/technical_specification.md` § 24 — invariant 5 (no secret returned after enable), 15 (atomic state transitions / TOTP anti-replay).

TASK
Wire the `mfa` facade feature, prove a no-MFA build excludes all MFA code/deps, and add the full MFA
lifecycle E2E against real Redis.

DELIVERABLES

1. `crates/bymax-auth/Cargo.toml`: an `mfa` feature → `bymax-auth-core/mfa`, `bymax-auth-crypto/mfa`
   (and `bymax-auth-redis/mfa` where applicable). No `mfa` in `default`.
2. `crates/bymax-auth/src/lib.rs`: re-export `MfaService` / `MfaContext` / `MfaSetupResult` under
   `#[cfg(feature = "mfa")]`.
3. Builder wiring (`services/mod.rs` + the builder): construct `MfaService` only when `config.mfa`
   is present.
4. `crates/bymax-auth-redis/tests/mfa_lifecycle_e2e.rs`: testcontainers — the full lifecycle (setup →
   enable → challenge TOTP → challenge recovery → disable), asserting no secret after enable,
   anti-replay on every path, atomic recovery-code regeneration.

Constraints:
- A no-MFA build links none of `aes-gcm`/`sha1`/`data-encoding` or the MFA service code (prove with
  `cargo tree`). Features are strictly additive.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo build -p bymax-auth --no-default-features --features scrypt` then `cargo tree -i aes-gcm` —
  expected: aes-gcm NOT in the tree.
- `cargo tree -p bymax-auth --features mfa -i aes-gcm` — expected: present only via `mfa`.
- `cargo test -p bymax-auth-redis --features mfa --test mfa_lifecycle_e2e` (with Docker) — expected: full lifecycle passes.
- `cargo deny check` — expected: passes with the MFA deps.
- `cargo llvm-cov --workspace --features "testing mfa sessions" --lcov` — expected: MFA surface 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P7 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall %. 7. Append `- 7.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.

- 7.1 ✅ 2026-06-19 — `MfaStore` trait (core, `mfa`-gated) + Redis impl over `mfa_setup:`/`mfa:`/`tu:` keyspaces with the fused `mfa_challenge.lua`; in-memory double; testcontainers store-e2e proving NX-once, replay-rejected, and single-consume under concurrency.
- 7.2 ✅ 2026-06-19 — split MFA temp-token methods on `TokenManagerService` (`issue` plants `mfa:` + resets the `challenge:` counter, `verify` is non-consuming GET + constant-time `sub` cross-check, `consume` idempotent DEL); namespace-isolation test.
- 7.3 ✅ 2026-06-19 — `MfaService` skeleton + `verify_totp_with_anti_replay`, idempotent AES-protected `setup` (SET NX, fast-path), and `verify_and_enable` (anti-replay + atomic GETDEL completion gate + revoke-all); no-secret-after-enable proven.
- 7.4 ✅ 2026-06-19 — `MfaService::challenge` (non-consuming temp-token verify, isolated `challenge:` brute-force, fused TOTP consume or constant-time recovery-code scan + splice, `mfa_verified=true` issuance); concurrent-same-code single-session e2e.
- 7.5 ✅ 2026-06-19 — TOTP-only `disable` (revokes sessions) and `regenerate_recovery_codes` (atomic wholesale replacement, sessions preserved), both on the shared `disable:` counter; documented session-invalidation divergence.
- 7.6 ✅ 2026-06-19 — `mfa` feature wired end to end (core + redis); no-MFA build proven to exclude `aes-gcm`/`data-encoding`/RustCrypto-`sha1`; full lifecycle E2E against real Redis; 100% line+function coverage, wasm purity preserved.
