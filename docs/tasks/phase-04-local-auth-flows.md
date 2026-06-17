# Phase 4 — Local auth flows + password + brute-force + session-fixation

> **Status**: 📋 ToDo · **Progress**: 0 / 7 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P4
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 3 built the `bymax-auth-core` skeleton: the plugin trait set, the `AuthConfig` with profiles + validation, and the `AuthEngine`/`AuthEngineBuilder` that assemble (proven with in-memory test doubles). **No flows existed yet.** This phase implements the **local authentication flows on the engine**: registration, login, logout, `me`, token refresh, email verification, and password-less issuance (`issue_tokens_for_user_id`), plus the supporting services — `PasswordService` (scrypt/Argon2id via `bymax-auth-crypto`, run in `spawn_blocking`, with rehash-on-verify and an anti-enumeration sentinel hash), `TokenManager` (HS256 access JWT + opaque refresh with atomic rotation + grace window + JTI revocation), `BruteForceService` (hashed-identifier fixed-window), and a focused `OtpService`.

Everything is implemented against the **store traits** (`SessionStore`/`OtpStore`/`BruteForceStore`) using P3's **in-memory test doubles** — the real Redis implementation is Phase 5. MFA is not verified here: a login on an MFA-enabled account returns an `MfaChallengeResult` (the challenge is completed in Phase 7); OAuth is Phase 8. When P4 is done, the full local credential lifecycle works end-to-end against the doubles, with session renewal after login (session-fixation resistance), uniform anti-enumeration responses, and tokens never accepted from a query string.

---

## Rules-of-phase

1. **Flows live in `bymax-auth-core`** and are implemented against the **store traits**, exercised with the Phase 3 in-memory doubles (`testing` feature). Do NOT add a `redis`/`axum`/HTTP dependency here.
2. **Heavy hashing runs in `tokio::task::spawn_blocking`** — `bymax-auth-crypto` is synchronous; never block the async runtime.
3. **Rehash-on-verify**: when a password verifies against a hash using a weaker algorithm/params than the active config, re-hash and persist (fire-and-forget) the upgraded hash.
4. **Anti-enumeration**: `login`, `forgot-password`-adjacent, `verify-email`, and `resend-verification` return uniform status/body and normalized timing regardless of account existence; an absent user is verified against a startup-loaded **sentinel hash** so login latency is uniform.
5. **Refresh tokens are opaque** (never JWT), hashed at rest in the store; rotation is atomic (via the store's Lua-backed `rotate`) with a configurable grace window; the access JWT is revocable via the `jti` blacklist.
6. **Session-fixation resistance**: a fresh session id is minted on login (and the spec's other auth boundaries); the previous session for that flow is not silently reused.
7. **Tokens are never accepted from a query string** (the access JWT and refresh token come only from the engine's typed inputs; the HTTP surface is Phase 10).
8. **MFA / OAuth not here**: login on an MFA-enabled account returns `MfaChallengeResult` (no TOTP verification); OAuth flows are Phase 8.
9. **Hooks**: invoke `before_register`/`after_register`/`before_login`/`after_login`/`after_logout`/`after_email_verified`/`on_new_session` at the documented points; fire-and-forget hooks are detached with a timeout and never block the response.
10. **100% coverage** via integration tests over the engine + doubles. `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, typed errors (`AuthError`), no `unwrap`/`expect`/`panic!` on library paths, English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 7.1 "Auth flows" (register/login/logout/me; the numbered steps + hook points; the MFA-challenge branch). § 7.1.9 "Session renewal and fixation resistance". § 7.2 "PasswordService" (scrypt/Argon2id, `spawn_blocking`, rehash-on-verify, sentinel hash). § 7.3 "TokenManager" (access JWT + opaque refresh, rotation + grace window, JTI revocation, MFA temp token). § 7.6 "OtpService". § 7.7 "BruteForceService" (hashed identifier, fixed window). § 15.5 "Security principles in errors" (anti-enumeration, generic credentials error, internal-only code remap).
- [`docs/development_plan.md`](../development_plan.md) — § P4, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 4.1 | `PasswordService`: hash/verify (spawn_blocking), rehash-on-verify, sentinel | 📋 ToDo | P0 | M | 3.6 |
| 4.2 | `TokenManager`: access JWT + opaque refresh, rotation + grace, JTI revocation | 📋 ToDo | P0 | L | 3.6 |
| 4.3 | `BruteForceService` + `OtpService` (store-backed primitives) | 📋 ToDo | P0 | M | 3.6 |
| 4.4 | Registration flow (`register`) | 📋 ToDo | P0 | M | 4.1, 4.2, 4.3 |
| 4.5 | Login / logout / me / refresh flows | 📋 ToDo | P0 | L | 4.1, 4.2, 4.3 |
| 4.6 | Email verification flows (`verify-email`, `resend-verification`) | 📋 ToDo | P0 | S | 4.3, 4.4 |
| 4.7 | `issue_tokens_for_user_id` (password-less issuance) | 📋 ToDo | P0 | S | 4.2, 4.5 |

---

## Tasks

### Task 4.1 — `PasswordService`: hash/verify (spawn_blocking), rehash-on-verify, sentinel

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.6

#### Description

Implement the engine's `PasswordService`: async hash/verify that wrap `bymax-auth-crypto` in `spawn_blocking`, rehash-on-verify when the stored hash is weaker than the active config, and a startup-loaded sentinel hash used to keep login latency uniform for absent users.

#### Acceptance criteria

- [ ] `hash(password) -> Result<String, AuthError>` and `verify(password, phc) -> Result<bool, AuthError>` run the crypto hashing inside `tokio::task::spawn_blocking`.
- [ ] `verify` reports whether the stored hash `needs_rehash` (per the active `PasswordConfig`); a successful verify against a stale hash triggers a fire-and-forget re-hash + `update_password` (rehash-on-verify).
- [ ] A `verify_sentinel(password)` (or equivalent) verifies against a startup-loaded dummy hash so an absent-user login path performs equivalent work (uniform timing).
- [ ] Uses the active algorithm/params from `AuthConfig` (scrypt by default; Argon2id under the `argon2` feature).
- [ ] 100% coverage including: hash→verify round-trip; wrong-password; rehash-on-verify triggers an `update_password`; sentinel path performs a verify.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/password.rs`
- `crates/bymax-auth-core/src/services/mod.rs` (declare the module)

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async engine; full parity with @bymax-one/nest-auth. `bymax-auth-crypto`
provides synchronous hashing; the engine must run it off the async runtime.

CURRENT PHASE: 4 (Local auth flows) — Task 4.1 of 7 (FIRST)

PRECONDITIONS
- Phase 3 is done: `bymax-auth-core` has `AuthEngine`/`AuthConfig` (with `PasswordConfig`,
  `active_algorithm`, scrypt/Argon2id params) and the in-memory test doubles (`testing` feature).
- Phase 1 is done: `bymax-auth-crypto::password` exposes `hash`, `verify`, `needs_rehash`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.2 "PasswordService" — the `spawn_blocking` requirement, the
  rehash-on-verify flow, and the anti-enumeration sentinel hash.
- `docs/technical_specification.md` § 15.5 "Security principles in errors" — uniform login latency.

TASK
Implement the async `PasswordService` (hash/verify via `spawn_blocking`, rehash-on-verify, sentinel).

DELIVERABLES

1. `crates/bymax-auth-core/src/services/password.rs`:
   - A `PasswordService` holding the active `PasswordConfig` and a startup-computed sentinel hash.
   - `pub async fn hash(&self, password: &str) -> Result<String, AuthError>` — `spawn_blocking` over
     `bymax_auth_crypto::password::hash`.
   - `pub async fn verify(&self, password: &str, phc: &str) -> Result<VerifyOutcome, AuthError>` —
     `spawn_blocking` over crypto verify; returns whether it matched AND whether the hash
     `needs_rehash`. (The caller performs the fire-and-forget `update_password` on a stale match —
     or expose a helper that does it given an `Arc<dyn UserRepository>`.)
   - `pub async fn verify_sentinel(&self, password: &str)` — verify against the sentinel so the
     absent-user path does equivalent work.
   - A `VerifyOutcome { matched: bool, needs_rehash: bool }`.

   ```rust
   pub async fn verify(&self, password: &str, phc: &str) -> Result<VerifyOutcome, AuthError> {
       let phc = phc.to_owned();
       let password = password.to_owned();
       let params = self.config.clone();
       tokio::task::spawn_blocking(move || { /* crypto verify + needs_rehash */ })
           .await
           .map_err(|_| AuthError::from(AuthErrorCode::Internal))?
   }
   ```

Constraints:
- All heavy hashing inside `spawn_blocking` (the crypto crate is sync; never block the runtime).
- Map crypto errors to a GENERIC `AuthError` (do not leak which step failed).
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-core --features testing password` — expected: round-trip, wrong-password,
  rehash-on-verify (asserts an `update_password` call on the in-memory repo), sentinel — all pass.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `services/password.rs` 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/7`. 5. Update the P4 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 4.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.2 — `TokenManager`: access JWT + opaque refresh, rotation + grace, JTI revocation

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 3.6

#### Description

Implement `TokenManager`: issue an HS256 access JWT (via `bymax-auth-jwt`) plus an opaque refresh token, create/rotate sessions through the `SessionStore` trait with a grace window, blacklist access tokens by `jti`, and issue/verify the short MFA temp token.

#### Acceptance criteria

- [ ] `issue_tokens(user, kind)` produces a `DashboardClaims`/`PlatformClaims` access JWT (short TTL, `jti`, both `mfaEnabled`/`mfaVerified`) and an opaque refresh token (hashed in the store via `create_session`).
- [ ] Every issued access/platform token carries a **fresh UUID v4 `jti`** (§13.3) — the `jti` is the `rv:` revocation-blacklist key; a test asserts the `jti` is present, parses as a v4 UUID, and is unique across two successive issuances for the same user (§24 invariant 2).
- [ ] `reissue_tokens(refresh)` rotates atomically via the store's `rotate -> RotateOutcome`, honoring the grace window (the previous token stays valid for the configured grace period).
- [ ] `verify_access(token)` validates the HS256 JWT and checks the `jti` blacklist; `revoke_access(jti, ttl)` blacklists a token for its remaining lifetime.
- [ ] `issue_mfa_temp_token(user_id, context)` / `verify_mfa_temp_token(token)` produce/validate the short (`mfa_challenge`) JWT (the MFA verification itself is Phase 7).
- [ ] Refresh tokens are opaque (never JWT) and stored only as `sha256(token)`; the grace pointer stores the new `SessionRecord` JSON — never a raw token or a token hash (§12.4).
- [ ] 100% coverage including: issue→verify; rotation produces a new pair and invalidates the old after grace; concurrent-refresh within grace both succeed; blacklist rejects a revoked token.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/token_manager.rs`

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Access tokens are short HS256 JWTs; refresh tokens are opaque and rotated atomically through the
`SessionStore` trait. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 4 (Local auth flows) — Task 4.2 of 7 (MIDDLE — the token core)

PRECONDITIONS
- Phase 3 is done: the engine, `AuthConfig` (jwt secret as `SecretString`, access/refresh TTLs,
  grace window), the `SessionStore` trait (domain-level `create_session`/`rotate`/`blacklist_access`/
  `is_blacklisted`, keyed by `SessionKind`), and the in-memory store doubles exist.
- Phases 1–2 are done: `bymax-auth-jwt` (HS256 sign/verify) and `bymax-auth-crypto` (secure tokens,
  sha256) are implemented; `bymax-auth-types` has the claim structs and the opaque `RefreshToken`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.3 "TokenManager" — issue/reissue/verify/revoke; the opaque
  refresh model; rotation + grace window; the JTI blacklist; the MFA temp token.
- `docs/technical_specification.md` § 13 "JWT & Token Strategy" — claim shapes; opaque refresh; the
  grace pointer storing the new session record (never the raw token).

TASK
Implement `TokenManager` against the `SessionStore` trait.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/token_manager.rs`:
   - `issue_tokens(&self, user: &SafeAuthUser, kind: SessionKind) -> Result<IssuedTokens, AuthError>`
     — mint the access JWT (fresh `jti`, claims per § 13) via `bymax-auth-jwt`; generate an opaque
     refresh token via `bymax-auth-crypto::token`; `create_session` (storing `sha256(refresh)` + the
     session record).
   - `reissue_tokens(&self, raw_refresh: &str) -> Result<RotatedTokens, AuthError>` — call the
     store's atomic `rotate`; honor the grace window; mint a new access+refresh pair.
   - `verify_access(&self, token: &str) -> Result<DashboardClaims, AuthError>` + `revoke_access(&self,
     jti, remaining_ttl)`; consult `is_blacklisted` on verify.
   - `issue_mfa_temp_token` / `verify_mfa_temp_token` (short `mfa_challenge` JWT; do NOT verify TOTP here).

Constraints:
- Refresh tokens are opaque; persist only `sha256(token)`; the grace pointer holds the new
  `SessionRecord` JSON, NEVER a raw token or a token hash.
- Constant-time where comparing token hashes (use `bymax-auth-crypto`).
- No `unwrap`/`expect`/`panic!`; map failures to GENERIC `AuthError`; `#![forbid(unsafe_code)]`;
  document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features testing token_manager` — expected: issue→verify, rotation
  + grace (old valid during grace, invalid after), concurrent-refresh-within-grace, blacklist
  rejection — all pass.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `token_manager.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/7`. 5. Update P4 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 4.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.3 — `BruteForceService` + `OtpService` (store-backed primitives)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.6

#### Description

Implement the two store-backed primitives used by the flows: `BruteForceService` (hashed-identifier fixed-window lockout via `BruteForceStore`) and `OtpService` (secure numeric OTP generation, store, and atomic attempt-bounded verify via `OtpStore`).

#### Acceptance criteria

- [ ] `BruteForceService`: `is_locked(identifier)`, `record_failure(identifier)` (fixed window — TTL does not extend on subsequent failures), `reset(identifier)`; the identifier is HMAC-hashed (no raw email/PII in the store key).
- [ ] `BruteForceService::validate_identifier` (§7.7) guards every entry point: it rejects any identifier containing `:`, `\n`, or `\r` (which would corrupt the namespaced key) or exceeding `MAX_IDENTIFIER_LENGTH = 512` bytes, returning `Forbidden` (logged at error level; no internal detail leaks to the response). A test asserts each rejection case.
- [ ] `OtpService`: `generate()` (CSPRNG numeric, configurable length), `store(...)` with an attempt counter + TTL, `verify(...)` (atomic: code match + attempt increment + TTL), with timing normalization; `try_begin_resend(...)` for resend throttling.
- [ ] Both use only the `BruteForceStore`/`OtpStore` traits (exercised with the in-memory doubles).
- [ ] 100% coverage including: lockout after `max_attempts`, window-does-not-extend, reset-on-success, `validate_identifier` rejection (`:`/`\n`/`\r`/over-512-bytes → `Forbidden`); OTP verify success/failure/max-attempts/expiry.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/brute_force.rs`
- `crates/bymax-auth-core/src/services/otp.rs`

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine. These
two primitives back the auth flows and use only the store traits. Edition 2024.

CURRENT PHASE: 4 (Local auth flows) — Task 4.3 of 7 (MIDDLE)

PRECONDITIONS
- Phase 3 is done: `BruteForceStore` (`is_locked`/`record_failure`/`reset`) and `OtpStore`
  (`put`/`verify`/`try_begin_resend`) traits + the in-memory doubles exist; `AuthConfig` has the
  `brute_force` and OTP-related settings.
- Phase 1 is done: `bymax-auth-crypto` provides `hmac_sha256` and CSPRNG (`token`/`random`).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.7 "BruteForceService" — hashed identifier, fixed window.
- `docs/technical_specification.md` § 7.6 "OtpService" — secure OTP gen, attempt-bounded verify,
  timing normalization, resend throttle.

TASK
Implement `BruteForceService` and `OtpService` over the store traits.

DELIVERABLES

1. `services/brute_force.rs` — `BruteForceService` with `is_locked`/`record_failure`/`reset`, the
   identifier HMAC-hashed via `bymax-auth-crypto::mac::hmac_sha256` (server secret from config), the
   fixed-window semantics (TTL set once, not extended), and a `validate_identifier` guard that
   rejects `:`/`\n`/`\r` or > `MAX_IDENTIFIER_LENGTH` (512 bytes) with `Forbidden` before any store
   call (§7.7 identifier contract — prevents key injection).
2. `services/otp.rs` — `OtpService` with `generate` (CSPRNG numeric, config length), `store`,
   `verify` (atomic match + attempt increment + TTL via `OtpStore`), `try_begin_resend`, and timing
   normalization (paths take a minimum duration before returning).

Constraints:
- No raw email/PII in store keys — always HMAC-hash the identifier.
- Use only the store traits (no direct Redis).
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-core --features testing brute_force otp` — expected: lockout after
  max_attempts, window-non-extension, reset-on-success; OTP success/failure/max-attempts/expiry — pass.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: both files 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/7`. 5. Update P4 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 4.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.4 — Registration flow (`register`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 4.1, 4.2, 4.3

#### Description

Implement `AuthService::register`: the `before_register` hook gate, tenant-scoped email uniqueness, password hashing, user creation, optional verification-OTP dispatch, session creation + token issuance, and the `after_register` hook.

#### Acceptance criteria

- [ ] `register(input, context)` resolves the tenant (resolver wins over the body), calls `before_register` (which can reject or modify role/status/email_verified), checks email uniqueness within the tenant, hashes the password (Task 4.1), creates the user, and — if `email_verification.required` — dispatches a verification OTP (Task 4.3 + `EmailProvider`).
- [ ] On success it issues tokens (Task 4.2), creating a session, and calls `after_register` (fire-and-forget).
- [ ] Returns `AuthResult` (or `MfaChallengeResult` only if a hook forces an MFA-required state — normally not for fresh registration).
- [ ] Email-already-exists is reported without leaking timing (consistent with anti-enumeration where applicable).
- [ ] 100% coverage via an integration test over the engine + in-memory doubles: happy path, `before_register` reject, duplicate email, email-verification-required branch.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/auth/register.rs`
- `crates/bymax-auth-core/src/services/auth/mod.rs`

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Edition 2024; full parity with @bymax-one/nest-auth. Flows run against the store/repository traits
and are tested with in-memory doubles.

CURRENT PHASE: 4 (Local auth flows) — Task 4.4 of 7 (MIDDLE)

PRECONDITIONS
- Tasks 4.1–4.3 are done: `PasswordService`, `TokenManager`, `BruteForceService`, `OtpService` exist.
- Phase 3: `UserRepository`, `EmailProvider`, `AuthHooks` traits + `TenantIdResolver`, the config,
  and the in-memory doubles exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.1 "Auth flows" — the `register` numbered steps and hook
  points (`before_register` gate + modifications; `after_register`).
- `docs/technical_specification.md` § 9 "Hooks System" — `before_register`/`after_register` semantics.

TASK
Implement `AuthService::register`.

DELIVERABLES

1. `services/auth/register.rs` — `register(&self, input: RegisterInput, ctx: RequestContext) ->
   Result<LoginResult, AuthError>`:
   - Resolve `tenant_id` via the resolver if configured (ignore any body-supplied tenant).
   - `before_register` → reject (`AuthError`) or apply `modified` role/status/email_verified.
   - Email uniqueness within the tenant (`find_by_email`).
   - Hash the password (Task 4.1); `create` the user (`CreateUserData`).
   - If `email_verification.required`: generate + store + email a verification OTP (Task 4.3 +
     `EmailProvider::send_email_verification_otp`).
   - Issue tokens (Task 4.2) creating a session; `after_register` (fire-and-forget, timeout-bounded).
   - Return `LoginResult::Success(AuthResult)`.

Constraints:
- Resolver-supplied `tenant_id` always wins over the body.
- Map failures to typed `AuthError` (e.g. `EmailAlreadyExists`); keep messages generic.
- Fire-and-forget hooks must not block or fail the response.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-core --features testing register` — expected: happy path, `before_register`
  reject, duplicate email, email-verification-required branch — all pass against the in-memory doubles.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `register.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/7`. 5. Update P4 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 4.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.5 — Login / logout / me / refresh flows

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 4.1, 4.2, 4.3

#### Description

Implement `AuthService::login`, `logout`, `me`, and token `refresh`: brute-force gating, the `before_login` hook, status/email-verification gates, constant-time password verification (with sentinel for absent users), the MFA-challenge branch, session renewal after login, brute-force reset, and the `after_login`/`after_logout` hooks.

#### Acceptance criteria

- [ ] `login(input, ctx)`: brute-force `is_locked` check (HMAC identifier); `before_login`; `find_by_email`; if absent, verify the sentinel and return a generic `InvalidCredentials` (uniform timing — see the `ANTI_ENUM_MIN_MS` floor below); status gate (`assert_user_not_blocked`, §7.1.8); constant-time password verify (+ rehash-on-verify); email-verification gate (`EMAIL_NOT_VERIFIED` when required & unverified); if `mfa_enabled`, return `MfaChallengeResult` (+ MFA temp token); else issue tokens with a **freshly minted session** (session-fixation), reset brute-force, fire `after_login`.
- [ ] On a failed attempt, `record_failure` runs; reaching `max_attempts` yields `ACCOUNT_LOCKED`.
- [ ] `logout(access, raw_refresh, user_id)` (§7.1.3): blacklist the access `jti` for its remaining TTL; derive `session_hash = sha256(raw_refresh)` and call `revoke_session(SessionKind::Dashboard, user_id, &session_hash)` (idempotent on `SessionNotFound`); `after_logout`.
- [ ] `me(access)`: return the `SafeAuthUser` for a valid access token.
- [ ] `refresh(raw_refresh)`: rotate via `TokenManager` (grace window) and return the new pair.
- [ ] Tokens are taken only from typed inputs — never a query string.
- [ ] The absent-user path and any other email-existence-revealing branch normalize total elapsed time to the `ANTI_ENUM_MIN_MS = 300` floor (§7.1 / §15.5 / §17.2); a test asserts the unknown-email and wrong-password responses are indistinguishable in status, body, and timing floor.
- [ ] `assert_user_not_blocked(&user)` (§7.1.8) maps `user.status` case-insensitively against `config.blocked_statuses` (default `["BANNED","INACTIVE","SUSPENDED"]`) and returns the status-specific 403: `banned → AccountBanned`, `inactive → AccountInactive`, `suspended → AccountSuspended`, `pending`/`pending_approval → PendingApproval`, fallback `AccountInactive`; it runs **before** the KDF so a blocked account never consumes hashing CPU.
- [ ] 100% coverage: success, wrong password, absent user (sentinel + uniform response), locked-out, each `blocked_statuses` status + `PendingApproval`, unverified email, MFA-enabled branch, logout revocation, refresh rotation.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/auth/login.rs`
- `crates/bymax-auth-core/src/services/auth/session_ops.rs` (logout / me / refresh)

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Edition 2024; full parity with @bymax-one/nest-auth. Login is the most security-sensitive flow:
anti-enumeration, constant-time verify, brute-force, session-fixation resistance.

CURRENT PHASE: 4 (Local auth flows) — Task 4.5 of 7 (MIDDLE — the security-critical flow)

PRECONDITIONS
- Tasks 4.1–4.4 are done: `PasswordService` (with sentinel), `TokenManager`, `BruteForceService`,
  `OtpService`, and `register` exist; the in-memory doubles + config are available.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.1 "Auth flows" — the `login`/`logout`/`me` numbered steps,
  the status gate, the email-verification gate, the MFA-challenge branch, the hook points, and the
  module-level `ANTI_ENUM_MIN_MS = 300` constant; § 7.1.8 "`assert_user_not_blocked`" — the exact
  `status → AuthError` mapping and the `blocked_statuses` default set.
- `docs/technical_specification.md` § 7.1.9 "Session renewal and fixation resistance" — mint a fresh
  session on login.
- `docs/technical_specification.md` § 15.5 "Security principles in errors" + § 17.2 "Threat model &
  mitigations" — generic `InvalidCredentials`, the sentinel-hash uniform-timing rule (the
  `ANTI_ENUM_MIN_MS` floor), internal-only code remap.

TASK
Implement `login`, `logout`, `me`, and `refresh`.

DELIVERABLES

1. `services/auth/login.rs` — `login(&self, input: LoginInput, ctx: RequestContext) ->
   Result<LoginResult, AuthError>` implementing the full numbered flow above, including: the
   brute-force gate (HMAC identifier), `before_login`, the absent-user sentinel path returning a
   GENERIC `InvalidCredentials`, the status + email-verification gates, constant-time verify +
   rehash-on-verify, the `MfaChallengeResult` branch when `mfa_enabled`, a freshly minted session on
   success, brute-force reset, and `after_login`.
2. `services/auth/session_ops.rs` — `logout(access, raw_refresh, user_id)` (blacklist `jti` + derive
   `session_hash = sha256(raw_refresh)` + ownership-checked `revoke_session` + `after_logout`),
   `me` (return `SafeAuthUser`), and `refresh` (delegate to `TokenManager::reissue_tokens`).

Constraints:
- An absent user must do equivalent work (sentinel verify) and return the SAME generic error/timing.
- A fresh session id is minted on successful login (session-fixation resistance).
- Tokens come only from typed inputs — never a query string.
- Internal-only codes (`token_expired`/`token_revoked`) never surface — remap to `token_invalid`.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-core --features testing login logout refresh` — expected: all listed
  scenarios pass against the in-memory doubles (incl. the absent-user uniform-response assertion and
  the lockout-after-max-attempts assertion).
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `login.rs`/`session_ops.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/7`. 5. Update P4 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 4.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.6 — Email verification flows (`verify-email`, `resend-verification`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 4.3, 4.4

#### Description

Implement `verify_email` (consume the OTP and mark the email verified) and `resend_verification` (re-issue an OTP, throttled), both with anti-enumeration.

#### Acceptance criteria

- [ ] `verify_email(input, ctx)` verifies the OTP via `OtpService` (attempt-bounded), then `update_email_verified(id, true)` and fires `after_email_verified`.
- [ ] `resend_verification(input, ctx)` re-issues a verification OTP via `OtpService::try_begin_resend` (throttled) and `EmailProvider`, returning a uniform response whether or not the account exists/needs verification (anti-enumeration).
- [ ] Both paths normalize timing and never reveal account existence or verification state.
- [ ] 100% coverage: valid OTP → verified; wrong/expired/max-attempts OTP; resend throttle; absent-account uniform response.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/auth/email_verification.rs`

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 4 (Local auth flows) — Task 4.6 of 7 (MIDDLE)

PRECONDITIONS
- Tasks 4.3–4.4 are done: `OtpService` exists and registration dispatches a verification OTP; the
  `UserRepository::update_email_verified`, `EmailProvider`, and `AuthHooks::after_email_verified`
  are available, plus the in-memory doubles.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.1 "Auth flows" — `verify-email` / `resend-verification`.
- `docs/technical_specification.md` § 7.6 "OtpService" — attempt-bounded verify + resend throttle.
- `docs/technical_specification.md` § 15.5 "Security principles in errors" — anti-enumeration on
  verification endpoints.

TASK
Implement `verify_email` and `resend_verification`.

DELIVERABLES

1. `services/auth/email_verification.rs`:
   - `verify_email(&self, input, ctx) -> Result<(), AuthError>` — `OtpService::verify`; on success
     `update_email_verified(id, true)` + `after_email_verified` (fire-and-forget).
   - `resend_verification(&self, input, ctx) -> Result<(), AuthError>` — `try_begin_resend` throttle;
     re-issue + email the OTP; return a UNIFORM response regardless of account existence/state.

Constraints:
- Anti-enumeration: identical status/body + normalized timing whether or not the account exists or
  is already verified.
- No `unwrap`/`expect`/`panic!`; typed `AuthError`; `#![forbid(unsafe_code)]`; document every public
  item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features testing email_verification` — expected: valid OTP verifies;
  wrong/expired/max-attempts rejected; resend throttle; absent-account uniform response — all pass.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `email_verification.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Set progress `6/7`. 5. Update the
P4 row in `docs/development_plan.md`. 6. Recompute the overall %. 7. Append
`- 4.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 4.7 — `issue_tokens_for_user_id` (password-less issuance)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 4.2, 4.5

#### Description

Implement `AuthEngine::issue_tokens_for_user_id` (§7.1.7): the password-less full-session issuance that backs workspace-switch / impersonation. Authorization is the caller's responsibility (the host must have already proven ownership); this method re-runs the status and email-verification gates and refuses to silently issue tokens for an MFA-enabled user.

#### Acceptance criteria

- [ ] `issue_tokens_for_user_id(user_id, ip, user_agent) -> Result<AuthResult, AuthError>` (§7.1.7): `find_by_id(user_id)` → `TokenInvalid` if absent.
- [ ] Re-runs `assert_user_not_blocked(&user)` (§7.1.8 status gate) so a BANNED/INACTIVE/SUSPENDED (or PendingApproval) user cannot be revived through a workspace-switch / impersonation.
- [ ] Re-runs the email-verification gate: if `email_verification.required && !email_verified`, return `EmailNotVerified`.
- [ ] If `user.mfa_enabled`, returns `MfaRequired` **without** issuing a challenge — distinct from login's `MfaChallenge`; the host must detect this before calling and route through the MFA challenge instead (issuing `mfa_verified = false` tokens here would 401 every subsequent guarded request).
- [ ] Otherwise projects to `SafeAuthUser`, issues full tokens (Task 4.2) creating a session when `sessions.enabled`, spawns `update_last_login` + `after_login` (fire-and-forget), and returns `AuthResult`.
- [ ] No password is read or verified on this path (password-less issuance); tokens come only from typed inputs — never a query string.
- [ ] 100% coverage: happy path, unknown user (`TokenInvalid`), each blocked status, unverified email when required, and the `mfa_enabled → MfaRequired` (no-challenge) branch.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/auth/session_ops.rs` (alongside logout / me / refresh)

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Edition 2024; full parity with @bymax-one/nest-auth. `issue_tokens_for_user_id` is the password-less
issuance primitive that backs workspace-switch and impersonation; the caller owns authorization.

CURRENT PHASE: 4 (Local auth flows) — Task 4.7 of 7 (LAST — password-less issuance)

PRECONDITIONS
- Tasks 4.2 and 4.5 are done: `TokenManager` (token issuance + session creation) and the
  `login`/`logout`/`me`/`refresh` flows exist, including the `assert_user_not_blocked` status helper
  and the email-verification gate; the in-memory doubles + config are available.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.1.7 "`issue_tokens_for_user_id` (password-less issuance)" —
  the numbered steps, the `MfaRequired` (no challenge) branch, and the "authorization is the
  caller's responsibility" contract.
- `docs/technical_specification.md` § 7.1.8 "`assert_user_not_blocked`" — the status → error mapping
  reused here.

TASK
Implement `AuthEngine::issue_tokens_for_user_id`.

DELIVERABLES

1. `services/auth/session_ops.rs` — `issue_tokens_for_user_id(&self, user_id: &str, ip: &str,
   user_agent: &str) -> Result<AuthResult, AuthError>`:
   - `find_by_id(user_id)` → `TokenInvalid` if `None`.
   - `assert_user_not_blocked(&user)` (reuse the Task 4.5 helper — identical status gate to `login`).
   - Email-verification gate: `EmailNotVerified` when `email_verification.required && !email_verified`.
   - If `user.mfa_enabled`, return `AuthError::MfaRequired` (NO challenge issued — this is distinct
     from login's `LoginResult::MfaChallenge`).
   - Else project to `SafeAuthUser`; `tokens.issue_tokens(...)`; `create_session(...)` when
     `sessions.enabled`; spawn `update_last_login` + `after_login` fire-and-forget; return `AuthResult`.

Constraints:
- This path is password-less — never read or verify a password here.
- The status and email-verification gates MUST run before issuance (no reviving a blocked account).
- Tokens come only from typed inputs — never a query string.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-core --features testing issue_tokens_for_user_id` — expected: happy path,
  unknown user, each blocked status, unverified-email, and the `mfa_enabled → MfaRequired` branch — all pass.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: the new surface 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `7/7`. 5. Update the P4 row in `docs/development_plan.md` (mark ✅ when all seven tasks are
done). 6. Recompute the overall %. 7. Append `- 4.7 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
