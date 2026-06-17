# Phase 6 — Sessions, OTP, password reset, email verification, invitations

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P6
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 4 implemented the always-on local auth lifecycle (register/login/logout/refresh/me/verify-email) against **in-memory store doubles**, and Phase 5 delivered the **real Redis backend** (`bymax-auth-redis`) with its atomic Lua scripts. This phase builds the **stateful, user-facing services** that sit on top of those stores and run against real Redis: `SessionService` (concurrent-session management with FIFO eviction), the canonical `OtpService` (timing-normalized, attempt-bounded verify), `PasswordResetService` (token / OTP / verified-token methods), the email-verification flow consolidated onto `OtpService`, and `InvitationService`.

All of these services live in `crates/bymax-auth-core` (they are engine collaborators, transport-agnostic, depending only on the store **traits**). Their hermetic unit tests run against the Phase 3 in-memory doubles (`--features testing`) for the 100% coverage gate; their **end-to-end** tests wire a real `AuthEngine` to `bymax-auth-redis` via `testcontainers` and live in `crates/bymax-auth-redis/tests/` (core cannot depend on redis — redis depends on core — so the integration tier is hosted on the redis side, exactly as Phase 5's `engine_e2e.rs` already is).

When P6 is done, every stateful flow — list/revoke sessions, FIFO eviction, OTP verify, password reset by both methods, email verification, invite/accept — works against real Redis with the atomic semantics proven in P5, all anti-enumeration and ownership-check invariants hold, and `sessions` / `invitations` are correctly gated by both a Cargo feature and a runtime toggle. **MFA, OAuth, platform auth, and the HTTP adapter are out of scope** (later phases).

---

## Rules-of-phase

1. **Services live in `bymax-auth-core` over the store traits.** No `axum`/HTTP and no direct Redis client here — the services call `SessionStore` / `OtpStore` / `BruteForceStore` (and `UserRepository` / `EmailProvider` / `AuthHooks`). The atomic Lua behavior is owned by `bymax-auth-redis` (P5); these services consume it through the traits.
2. **Anti-enumeration with normalized timing.** `initiate_reset` and `resend_otp` always return `Ok(())` (unknown email, blocked account, and email-send failure are indistinguishable from success) and always take ≥ `ANTI_ENUM_MIN_MS = 300`. OTP `verify` normalizes to ≥ `MIN_VERIFY_MS = 100` on every branch.
3. **Single-use atomic consumption.** Reset tokens, verified tokens, OTPs, and invitation tokens are consumed via the atomic store ops (`getdel` / the verify Lua) — never read-then-delete in two round-trips.
4. **`apply_password_reset` order is security-critical:** hash → `update_password` → `revoke_all` sessions, **in that order**. A crash between steps leaves stale refresh tokens alive only until TTL, but the old password is already dead.
5. **Session-hash hygiene.** Every session hash is validated (`^[a-f0-9]{64}$`) before use; an invalid format returns `SessionNotFound` (no format enumeration). Full hashes are never logged (truncate to 8 chars). `revoke_session` is ownership-checked (closes IDOR/BOLA). IP is truncated to `MAX_IP_LENGTH = 45` before storage.
6. **Invitation payloads are trusted on accept, so the role is re-validated** against the hierarchy as anti-tamper; the duplicate-email guard runs before user creation. Document the Redis-write-trust assumption and the optional HMAC-signed-payload hardening.
7. **Feature + runtime gating.** `sessions` and `invitations` are each gated by a Cargo feature **and** a runtime toggle (`ControllerToggles`), auto-promoted to active when their config block is present. A no-`sessions` / no-`invitations` build links none of the corresponding service code.
8. **100% coverage**, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on library paths, English-only, timeless comments. Every hash/verify still dispatches through `spawn_blocking` (inherited from P4).

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 7.4 "`SessionService`" (incl. §7.4.1–§7.4.6) — `create_session`, `enforce_session_limit` (FIFO + the `= 1` atomic-Lua caveat), `parse_user_agent`, `list_sessions`, `revoke_session`, `revoke_all_except_current`, `rotate_session`; `MAX_IP_LENGTH`, `SESSION_HASH_RE`, `SessionInfo` / `StoredSessionDetail`.
  - § 7.6 "`OtpService`" — `generate` / `store` / `verify`; `MAX_ATTEMPTS = 5`, `MIN_VERIFY_MS = 100`; `OtpRecord`; the timing-normalized branch table and the atomic `increment_attempts` Lua.
  - § 7.8 "`PasswordResetService`" (incl. §7.8.1–§7.8.5) — `initiate_reset` / `reset_password` / `verify_otp` / `resend_otp` / `apply_password_reset`; `ANTI_ENUM_MIN_MS`, `VERIFIED_TOKEN_TTL_SECONDS`, `ResetContext`, the digest-based context binding.
  - § 7.10 "`InvitationService`" — `invite` / `accept_invitation`; `StoredInvitation`, single-use `getdel`, role re-validation, duplicate-email guard, the Redis-write-trust note.
  - § 7.1.6 "`verify_email` / `resend_verification_email` / `send_verification_otp`" — the flow being consolidated onto `OtpService`.
  - § 9 "Hooks System" — `on_new_session`, `on_session_evicted`, `after_email_verified`, `after_password_reset`, `after_invitation_accepted` signatures and fire-and-forget discipline.
  - § 12 "Redis Strategy" — the key catalog (`otp`, `resend`, `sess`, `rt`, `sd`, `rp`, `pr`, `prv`, `inv`) and the atomic Lua contracts these services rely on.
  - § 5.1.6 — `SessionConfig` / `PasswordResetConfig` / `EmailVerificationConfig` / `InvitationConfig` shapes and defaults.
- [`docs/development_plan.md`](../development_plan.md) — § P6, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 6.1 | `OtpService` — canonical generate/store/timing-normalized verify | 📋 ToDo | P0 | M | 4.3, 5.3 |
| 6.2 | `SessionService` — create + FIFO eviction + metadata + hooks | 📋 ToDo | P0 | L | 4.5, 5.2 |
| 6.3 | `SessionService` — list + ownership-checked revoke + rotate | 📋 ToDo | P0 | M | 6.2 |
| 6.4 | `PasswordResetService` — token / OTP / verified-token | 📋 ToDo | P0 | L | 6.1 |
| 6.5 | Email verification consolidated onto `OtpService` | 📋 ToDo | P1 | S | 6.1 |
| 6.6 | `InvitationService` — invite + single-use accept | 📋 ToDo | P1 | M | 6.2 |

---

## Tasks

### Task 6.1 — `OtpService` — canonical generate/store/timing-normalized verify

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 4.3, 5.3

#### Description

Promote the minimal Phase-4 OTP helper into the canonical `OtpService`: CSPRNG `generate`, `store`, and an atomic, constant-time, timing-normalized `verify` with a five-attempt ceiling and fail-closed handling of corrupt records — running against the real `OtpStore` (P5).

#### Acceptance criteria

- [ ] `generate(length)` uses `OsRng` (`rand::rng().random_range(0..10^length)`), zero-padded to `length` digits (default 6).
- [ ] `store(purpose, id, code, ttl)` writes `OtpRecord { code, attempts: 0 }` under `otp:{purpose}:{id}` with `ttl`.
- [ ] `verify(purpose, id, code)` normalizes total elapsed to ≥ `MIN_VERIFY_MS = 100` on **every** branch: not-found → `OtpExpired`; corrupt JSON → `del` + `OtpExpired`; `attempts >= 5` → `del` + `OtpMaxAttempts`; length-mismatch or constant-time mismatch → atomic `increment_attempts` + `OtpInvalid`; success → `del` (single-use) + `Ok(())`.
- [ ] The attempt bump preserves the residual TTL via the store's atomic `increment_attempts` Lua (no GET+TTL+SET race) — consumed through the `OtpStore` trait.
- [ ] Hermetic unit tests (in-memory `OtpStore` double, `--features testing`) cover all five branches; a timing test asserts the not-found and wrong-code paths are indistinguishable (≥ 100 ms, same error family modulo the documented expiry/invalid split).
- [ ] An E2E test in `crates/bymax-auth-redis/tests/` proves single-use + the five-attempt cap against real Redis.
- [ ] 100% coverage; constant-time compare via `bymax-auth-crypto::timing_safe_compare`.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/otp.rs` (promote to the canonical service)
- `crates/bymax-auth-core/tests/otp_service.rs` (hermetic, in-memory double)
- `crates/bymax-auth-redis/tests/otp_service_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async engine; full parity with @bymax-one/nest-auth. The engine services live
in `bymax-auth-core` over store TRAITS; the real Redis impls (with atomic Lua) live in
`bymax-auth-redis` (already built in Phase 5).

CURRENT PHASE: 6 (Stateful services) — Task 6.1 of 6 (FIRST)

PRECONDITIONS
- Phase 4 is done: a minimal OTP helper exists in `services/otp.rs` for the email-verification flow,
  plus `BruteForceService`. `bymax-auth-crypto::timing_safe_compare` is available.
- Phase 5 is done: `bymax-auth-redis` implements `OtpStore` with the atomic attempt-bounded verify
  Lua and the residual-TTL-preserving `increment_attempts`. In-memory `OtpStore` double (Phase 3)
  reproduces the same atomic semantics for the hermetic tier.
- `bymax-auth-core::OtpStore` (`put`/`verify`/`try_begin_resend`) trait is defined.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.6 "OtpService" — the `generate`/`store`/`verify` signatures,
  `MAX_ATTEMPTS = 5`, `MIN_VERIFY_MS = 100`, `OtpRecord`, the timing-normalized branch table, and the
  atomic `increment_attempts` semantics.
- `docs/technical_specification.md` § 12 "Redis Strategy" — the `otp:{purpose}:{id}` key and the
  `otp_verify` Lua contract (so the service consumes the store correctly).

TASK
Promote the OTP helper into the canonical `OtpService` with a CSPRNG `generate`, `store`, and an
atomic, constant-time, timing-normalized `verify`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/otp.rs`:
   `OtpService` with:

   ```rust
   impl OtpService {
       pub fn generate(&self, length: usize) -> String;                                   // OsRng, zero-padded
       pub async fn store(&self, purpose: &str, id: &str, code: &str, ttl: u64) -> Result<(), AuthError>;
       pub async fn verify(&self, purpose: &str, id: &str, code: &str) -> Result<(), AuthError>;
   }
   ```
   - `verify` wraps the whole body in an elapsed-time normalizer (record `Instant::now()` at entry;
     before EVERY return, `tokio::time::sleep` the remainder up to `MIN_VERIFY_MS`).
   - Branch table EXACTLY per §7.6: None → `OtpExpired`; corrupt → `del` + `OtpExpired`;
     `attempts >= 5` → `del` + `OtpMaxAttempts`; length-mismatch short-circuit OR constant-time
     mismatch → atomic `increment_attempts` + `OtpInvalid`; match → `del` + `Ok`.
   - The attempt bump and the consume are the store's atomic ops (do not GET+SET in the service).

2. `crates/bymax-auth-core/tests/otp_service.rs`: hermetic tests against the in-memory `OtpStore`
   double (`--features testing`): success, wrong-then-success-within-cap, max-attempts lockout,
   expiry, corrupt-record-fails-closed, and a timing assertion (not-found vs wrong ≥ 100 ms, no
   observable oracle).

3. `crates/bymax-auth-redis/tests/otp_service_e2e.rs`: testcontainers test proving single-use and
   the five-attempt cap against a real Redis-backed `OtpStore`.

Constraints:
- No `axum`/HTTP, no direct Redis client in core — call the `OtpStore` trait only.
- Constant-time compare via `bymax-auth-crypto::timing_safe_compare`; never `==` on the code.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!` on lib paths;
  English-only, timeless comments (no plan/phase references in code).

Verification:
- `cargo test -p bymax-auth-core --features testing --test otp_service` — expected: all branches pass.
- `cargo test -p bymax-auth-redis --test otp_service_e2e` (with Docker) — expected: single-use + cap.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `services/otp.rs` 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P6 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 6.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 6.2 — `SessionService` — create + FIFO eviction + metadata + hooks

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 4.5, 5.2

#### Description

Implement the write/eviction half of `SessionService`: `create_session`, `enforce_session_limit` (FIFO eviction with the soft-cap default and the documented atomic-Lua hardening path for a strict `= 1` cap), the regex-only `parse_user_agent`, IP truncation, and the `on_new_session` / `on_session_evicted` hooks.

#### Acceptance criteria

- [ ] `create_session(user_id, raw_refresh, ip, ua) -> String` returns `sha256(raw_refresh)`, stores `StoredSessionDetail { device, ip, created_at, last_activity_at }` under `sd:{hash}` (IP truncated to `MAX_IP_LENGTH = 45`) with the refresh TTL, then calls `enforce_session_limit`. Caller-ordering contract documented (must run **after** `TokenManagerService` added `rt:{hash}` to `sess:{user_id}`).
- [ ] `enforce_session_limit` reads `sess:{user_id}` members (keep only `rt:`-prefixed, exclude `rp:` grace pointers), resolves the limit via `max_sessions_resolver` (falling back to `default_max_sessions`), sorts ascending by `created_at` (missing/unparseable → `0` = oldest), evicts the oldest `len - limit` **excluding** the just-created `new_hash`, and fires `on_session_evicted` per victim. Eviction errors are logged, not propagated (the new session is already committed).
- [ ] The soft-cap concurrency caveat and the strict `= 1` atomic-Lua path are documented in code; the strict path (single `enforce_session_limit` Lua) is implemented or clearly delegated to the store trait per §7.4.2.
- [ ] `parse_user_agent(ua)` is regex-only (no external UA crate): browser precedence Edge > Opera > Chrome > Firefox > Safari (Safari requires `Version/`); OS Android > iOS > Windows > macOS > Linux; unknowns → `"Unknown Browser" / "Unknown OS"`; returns `"{Browser} on {OS}"`.
- [ ] `on_new_session` fetches the user, projects `SafeAuthUser`, builds a minimal `SessionInfo` (`session_hash = hash[..8]`), and spawns the hook fire-and-forget.
- [ ] Hermetic unit tests cover eviction-at-limit, exclusion of the new session, hook firing, and a `parse_user_agent` table; an E2E test (testcontainers) fires eviction against real Redis.
- [ ] `sessions` feature + runtime toggle gating: a no-`sessions` build links none of this; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/session.rs`
- `crates/bymax-auth-core/src/services/user_agent.rs` (regex-only parser)
- `crates/bymax-auth-core/tests/session_service.rs` (hermetic)
- `crates/bymax-auth-redis/tests/session_service_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` holds the engine services over store
TRAITS; the real Redis impls (atomic Lua) live in `bymax-auth-redis` (Phase 5). Edition 2024; full
parity with @bymax-one/nest-auth.

CURRENT PHASE: 6 (Stateful services) — Task 6.2 of 6 (MIDDLE — the largest service)

PRECONDITIONS
- Phase 4 is done: `AuthEngine` flows + `TokenManagerService` (which adds `rt:{hash}` to
  `sess:{user_id}` on issuance). `RequestContext`/`HookContext` and the `SafeAuthUser` projection exist.
- Phase 5 is done: `bymax-auth-redis` implements `SessionStore` (create/rotate/revoke/revoke_all,
  ownership-checked Lua). Phase 3 in-memory `SessionStore` double reproduces the atomic semantics.
- `bymax-auth-core::AuthHooks` defines `on_new_session` + `on_session_evicted`; `UserRepository`
  exposes the user fetch + the optional `max_sessions_resolver`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.4 "SessionService" — focus on §7.4.1 `create_session`,
  §7.4.2 `enforce_session_limit` (the FIFO algorithm AND the soft-cap concurrency caveat + the strict
  `= 1` atomic-Lua hardening), `parse_user_agent`, `MAX_IP_LENGTH = 45`, `SESSION_HASH_RE`,
  `SessionInfo` / `StoredSessionDetail`.
- `docs/technical_specification.md` § 9 "Hooks System" — `on_new_session` / `on_session_evicted`
  signatures and the fire-and-forget discipline.

TASK
Implement the write/eviction half of `SessionService`: `create_session`, `enforce_session_limit`,
`parse_user_agent`, IP truncation, and the new-session / session-evicted hooks.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/session.rs`:
   - `create_session(user_id, raw_refresh, ip, ua) -> Result<String, AuthError>` (returns the
     sha256 hash); stores `StoredSessionDetail` under `sd:{hash}` with the refresh TTL (IP truncated
     to `MAX_IP_LENGTH`); calls `enforce_session_limit(user_id, &hash, ip, ua)`; document the
     caller-ordering contract.
   - `enforce_session_limit` — FIFO per §7.4.2: filter `rt:` members, resolve the limit, sort by
     `created_at`, evict oldest `len - limit` EXCLUDING `new_hash`, fire `on_session_evicted`
     fire-and-forget per victim (errors logged, not propagated). Document the soft-cap caveat and
     implement/delegate the strict `= 1` atomic-Lua path.
   - private `on_new_session` spawn helper (fetch user → `SafeAuthUser` → minimal `SessionInfo` with
     `session_hash = hash[..8]`).

2. `crates/bymax-auth-core/src/services/user_agent.rs`:
   `parse_user_agent(ua: &str) -> String` — regex-only (`regex` crate, compiled once via `OnceLock`/
   `LazyLock`), precedence per §7.4, `"{Browser} on {OS}"`, unknowns → `"Unknown Browser"/"Unknown OS"`.

3. `crates/bymax-auth-core/tests/session_service.rs`: hermetic tests (in-memory `SessionStore`
   double) — eviction at limit, new-session excluded from eviction, both hooks fire, a
   `parse_user_agent` table (Edge/Chrome/Firefox/Safari/Opera × Android/iOS/Windows/macOS/Linux +
   unknowns), IP truncation.

4. `crates/bymax-auth-redis/tests/session_service_e2e.rs`: testcontainers test — N logins over the
   limit evict the oldest down to the cap against real Redis.

Constraints:
- IP truncated to `MAX_IP_LENGTH` before storage (bounds attacker-controlled `X-Forwarded-For`).
- Full session hashes are NEVER logged (truncate to 8 chars). No `axum`/HTTP, no direct Redis client.
- `sessions` is gated by a Cargo feature AND a runtime toggle — a no-`sessions` build links none of
  this code.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!` on lib paths;
  English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing sessions" --test session_service` — expected: all pass.
- `cargo test -p bymax-auth-redis --test session_service_e2e` (with Docker) — expected: eviction works.
- `cargo build -p bymax-auth-core --no-default-features --features "scrypt"` — expected: no session code linked.
- `cargo llvm-cov -p bymax-auth-core --features "testing sessions" --lcov` — expected: `services/session.rs` + `services/user_agent.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P6 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 6.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 6.3 — `SessionService` — list + ownership-checked revoke + rotate

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 6.2

#### Description

Implement the read/mutate half of `SessionService`: `list_sessions` (with stale-key self-healing), the atomic ownership-checked `revoke_session`, `revoke_all_except_current`, and the atomic `rotate_session` detail rotation — all with session-hash validation.

#### Acceptance criteria

- [ ] `list_sessions(user_id, current_hash)` reads `sess:{user_id}`, fetches each `sd:{hash}`, marks missing/unparseable detail **stale** (skipped + async `srem` fire-and-forget), builds `SessionInfo` with `is_current = timing_safe_compare(hash, current_hash.unwrap_or(""))`, sorts by `created_at` descending; logs truncate keys to `rt:` + 8 chars.
- [ ] `revoke_session(user_id, session_hash)` runs `assert_valid_session_hash` first (non-64-hex → `SessionNotFound`), then the ownership-checked `REVOKE_SESSION_LUA` via the store (`SISMEMBER` → `0` ⇒ `SessionNotFound`; else atomic `DEL rt`/`SREM`/`DEL sd`). No cross-user revoke is possible.
- [ ] `revoke_all_except_current(user_id, current_hash)` validates `current`, iterates `rt:` members whose hash ≠ current (constant-time), calls `revoke_session`, swallows `SessionNotFound`, re-throws other errors.
- [ ] `rotate_session(old_hash, new_hash, ip, ua)` validates both hashes, early-returns if `old == new` (constant-time), preserves the original `created_at`, and runs the atomic `ROTATE_SESSION_DETAIL_LUA` (DEL old, SET new EX ttl) so a concurrent `list_sessions` never sees neither key.
- [ ] Hermetic unit tests: list with a stale member self-heals; non-owner revoke returns `SessionNotFound`; bad-format hash returns `SessionNotFound`; `revoke_all_except_current` keeps the current; rotate preserves `created_at`. E2E (testcontainers) proves ownership-checked atomic revoke.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/session.rs` (extend)
- `crates/bymax-auth-core/tests/session_service_ops.rs` (hermetic)
- `crates/bymax-auth-redis/tests/session_revoke_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls (atomic Lua) in `bymax-auth-redis` (Phase 5). Edition 2024; parity with @bymax-one/nest-auth.

CURRENT PHASE: 6 (Stateful services) — Task 6.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 6.2 is done: `SessionService` exists with `create_session`/`enforce_session_limit`/
  `parse_user_agent` and the new-session/evicted hooks.
- Phase 5: `bymax-auth-redis` exposes the ownership-checked revoke Lua and the atomic detail-rotation
  Lua through `SessionStore`. In-memory double reproduces them.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.4 "SessionService" — §7.4.3 `list_sessions`, §7.4.4
  `revoke_session` (the `REVOKE_SESSION_LUA` ownership check + `assert_valid_session_hash`), §7.4.5
  `revoke_all_except_current`, §7.4.6 `rotate_session` (the `ROTATE_SESSION_DETAIL_LUA`). Note
  `SESSION_HASH_RE = ^[a-f0-9]{64}$` and the "bad format ⇒ SessionNotFound" anti-enumeration rule.

TASK
Implement `list_sessions`, the ownership-checked `revoke_session`, `revoke_all_except_current`, and
the atomic `rotate_session`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/session.rs` (extend):
   - `list_sessions(user_id, current_hash: Option<&str>) -> Result<Vec<SessionInfo>, AuthError>` with
     stale-key self-heal (async `srem`, fire-and-forget), `is_current` via constant-time compare,
     newest-first sort.
   - `revoke_session(user_id, session_hash) -> Result<(), AuthError>` — `assert_valid_session_hash`
     (non-64-hex → `SessionNotFound`), then the store's ownership-checked revoke; result `0` ⇒
     `SessionNotFound`.
   - `revoke_all_except_current(user_id, current_hash)` — validate, iterate, constant-time skip the
     current, swallow `SessionNotFound`, re-throw the rest.
   - `rotate_session(old_hash, new_hash, ip, ua)` — validate both, early-return on equal (const-time),
     preserve `created_at`, atomic detail-rotation Lua via the store.
   - private `assert_valid_session_hash(hash) -> Result<(), AuthError>` (regex check → `SessionNotFound`).

2. `crates/bymax-auth-core/tests/session_service_ops.rs`: hermetic tests for stale self-heal,
   non-owner revoke (`SessionNotFound`), bad-format hash, `revoke_all_except_current` retaining the
   current, rotate preserving `created_at`.

3. `crates/bymax-auth-redis/tests/session_revoke_e2e.rs`: testcontainers — ownership-checked atomic
   revoke (a non-owner cannot revoke; the owner's `rt`/`sd`/`sess`-member all vanish in one step).

Constraints:
- Bad-format hash ⇒ `SessionNotFound` (no format enumeration). Full hashes never logged (8-char
  truncation). Revoke is ownership-checked (close IDOR/BOLA). Use `timing_safe_compare` for hash
  equality everywhere.
- No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing sessions" --test session_service_ops` — expected: all pass.
- `cargo test -p bymax-auth-redis --test session_revoke_e2e` (with Docker) — expected: ownership atomicity.
- `cargo llvm-cov -p bymax-auth-core --features "testing sessions" --lcov` — expected: `services/session.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P6 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 6.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 6.4 — `PasswordResetService` — token / OTP / verified-token

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 6.1

#### Description

Implement the full `PasswordResetService`: `initiate_reset` (anti-enumeration), `reset_password` (token | otp | verified_token), `verify_otp` (returns a short-lived verified token), `resend_otp` (atomic 60 s cooldown), and the private `apply_password_reset` with its security-critical operation order.

#### Acceptance criteria

- [ ] `initiate_reset` always returns `Ok(())` (unknown email, blocked account, email-send failure all indistinguishable) and always takes ≥ `ANTI_ENUM_MIN_MS = 300`. Token method: store `ResetContext` under `pr:{sha256(raw)}` with `token_ttl_seconds`, spawn email, **delete the key on send failure**. OTP method: `otp.store("password_reset", id, otp, otp_ttl)`, spawn email.
- [ ] `reset_password` enforces exactly-one proof (`> 1` present → `PasswordResetTokenInvalid`); routes by `config.password_reset.method`; token/verified-token use `getdel` (atomic single-use) + the digest-based context binding (`sha256(context.email) ⟂ sha256(email)` and tenant, constant-time); OTP path verifies + `find_by_email` + `apply_password_reset`.
- [ ] `verify_otp` consumes the OTP, `find_by_email` (vanished account → `PasswordResetTokenInvalid`), stores `ResetContext` under `prv:{sha256(raw_verified)}` (TTL `VERIFIED_TOKEN_TTL_SECONDS = 300`), returns the raw verified token.
- [ ] `resend_otp` is anti-enumerating with an atomic 60 s cooldown via `otp.try_begin_resend(...)`, always ≥ `ANTI_ENUM_MIN_MS`.
- [ ] `apply_password_reset` runs hash → `update_password` → `sessions.revoke_all(Dashboard, user_id)` → spawn `after_password_reset`, **in that order** (documented as security-critical).
- [ ] Hermetic unit tests cover both methods, the verified-token bridge, multi-proof rejection, context-binding mismatch, the anti-enum timing floor, and the revoke-all-on-reset. E2E (testcontainers) proves single-use token consumption and session revocation against real Redis.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/password_reset.rs`
- `crates/bymax-auth-core/tests/password_reset_service.rs` (hermetic)
- `crates/bymax-auth-redis/tests/password_reset_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls in `bymax-auth-redis` (Phase 5). Edition 2024; full parity with @bymax-one/nest-auth.
Password reset supports a token method and an OTP method (with a verified-token bridge), both
anti-enumerating.

CURRENT PHASE: 6 (Stateful services) — Task 6.4 of 6 (MIDDLE — the hardest flow service)

PRECONDITIONS
- Task 6.1 is done: the canonical `OtpService` (`generate`/`store`/`verify`/`try_begin_resend` via the
  `OtpStore` trait).
- Phase 4: `PasswordService` (hash/verify on `spawn_blocking`), `UserRepository::find_by_email` +
  `update_password`, the `SessionStore` revoke-all domain op, `generate_secure_token` in
  `bymax-auth-crypto`, and the `after_password_reset` hook contract.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.8 "PasswordResetService" — §7.8.1 `initiate_reset`, §7.8.2
  `reset_password`, §7.8.3 `verify_otp`, §7.8.4 `resend_otp`, §7.8.5 `apply_password_reset`; the
  constants (`ANTI_ENUM_MIN_MS = 300`, `VERIFIED_TOKEN_TTL_SECONDS = 300`), `ResetContext`, the
  `pr:`/`prv:` keys, the digest-based context binding, and the security-critical operation order.
- `docs/technical_specification.md` § 12 "Redis Strategy" — the `pr`/`prv`/`resend` keys (so the
  service consumes the store correctly).

TASK
Implement the full `PasswordResetService` (initiate / reset / verify_otp / resend / apply).

DELIVERABLES

1. `crates/bymax-auth-core/src/services/password_reset.rs`:

   ```rust
   impl PasswordResetService {
       pub async fn initiate_reset(&self, dto: ForgotPasswordDto) -> Result<(), AuthError>;  // never reveals existence
       pub async fn reset_password(&self, dto: ResetPasswordDto) -> Result<(), AuthError>;     // token | otp | verified_token
       pub async fn verify_otp(&self, dto: VerifyOtpDto) -> Result<String, AuthError>;         // -> verified_token
       pub async fn resend_otp(&self, dto: ResendOtpDto) -> Result<(), AuthError>;
   }
   ```
   - `initiate_reset` / `resend_otp`: anti-enum timer (≥ 300 ms), always `Ok(())`, fire-and-forget email.
   - token/verified-token consume via `getdel`; the digest-based context binding uses
     `timing_safe_compare` on `sha256(...)` of email + tenant.
   - `apply_password_reset` (private): `passwords.hash` → `update_password` → `sessions.revoke_all` →
     spawn `after_password_reset` — IN THAT ORDER (document why).
   - OTP identifier: `hmac_sha256("{tenant_id}:{email}", hmac_key)`. The verified token: 300 s TTL.

2. `crates/bymax-auth-core/tests/password_reset_service.rs`: hermetic tests — token method, OTP
   method, verified-token bridge, multi-proof rejection, context-binding mismatch, anti-enum timing
   floor (≥ 300 ms, identical body for unknown vs known email), revoke-all-after-reset.

3. `crates/bymax-auth-redis/tests/password_reset_e2e.rs`: testcontainers — single-use token
   consumption (replay → `PasswordResetTokenInvalid`) and session revocation against real Redis.

Constraints:
- `initiate_reset`/`resend_otp` NEVER reveal account existence and NEVER vary timing below 300 ms.
- Single-use atomic consumption (`getdel` / verify Lua) — never read-then-delete.
- `apply_password_reset` order is security-critical (password before sessions).
- No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features testing --test password_reset_service` — expected: all pass.
- `cargo test -p bymax-auth-redis --test password_reset_e2e` (with Docker) — expected: single-use + revoke.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `services/password_reset.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P6 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 6.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 6.5 — Email verification consolidated onto `OtpService`

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: S
- **Depends on**: 6.1

#### Description

Refactor the Phase-4 email-verification flow (`verify_email` / `resend_verification_email` / `send_verification_otp`) so it runs entirely on the canonical `OtpService` / `OtpStore` — atomic resend cooldown, attempt-bounded verify, and the `after_email_verified` hook — against real Redis.

#### Acceptance criteria

- [ ] `send_verification_otp` and `resend_verification_email` use `OtpService` (`generate` + `store`) and the atomic resend cooldown `otp.try_begin_resend(OtpPurpose::EmailVerification, &id, cooldown)`; resend is anti-enumerating (≥ `ANTI_ENUM_MIN_MS`).
- [ ] `verify_email` uses `OtpService::verify` (timing-normalized, attempt-capped, single-use), flips `email_verified` via `UserRepository`, and spawns `after_email_verified` fire-and-forget.
- [ ] The duplicated Phase-4 OTP logic in `services/auth/email_verification.rs` is removed — it now delegates to `OtpService` (no second OTP code path).
- [ ] Hermetic unit tests: verify success flips the flag + fires the hook; wrong code is attempt-capped; resend respects the cooldown and is anti-enumerating. E2E (testcontainers) proves the cooldown + verify against real Redis.
- [ ] 100% coverage; no behavioral regression vs the Phase-4 flow tests.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/auth/email_verification.rs` (delegate to `OtpService`)
- `crates/bymax-auth-core/tests/email_verification.rs` (hermetic; update if present)
- `crates/bymax-auth-redis/tests/email_verification_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls in `bymax-auth-redis` (Phase 5). Edition 2024; parity with @bymax-one/nest-auth.

CURRENT PHASE: 6 (Stateful services) — Task 6.5 of 6 (MIDDLE)

PRECONDITIONS
- Task 6.1 is done: the canonical `OtpService` (timing-normalized verify, atomic attempt bump,
  `try_begin_resend` cooldown).
- Phase 4 implemented the email-verification flow in `services/auth/email_verification.rs` with a
  minimal embedded OTP path; this task consolidates it onto `OtpService`.
- `bymax-auth-core::AuthHooks::after_email_verified` and `UserRepository` (the `email_verified` flip)
  exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.1.6 "verify_email / resend_verification_email /
  send_verification_otp" — the flow being consolidated.
- `docs/technical_specification.md` § 7.6 "OtpService" — the service it now delegates to.
- `docs/technical_specification.md` § 9 "Hooks System" — `after_email_verified` (fire-and-forget).

TASK
Refactor the email-verification flow to run entirely on `OtpService` / `OtpStore` — atomic resend
cooldown, attempt-bounded verify, `after_email_verified` hook — removing the duplicated OTP logic.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/auth/email_verification.rs`:
   - `send_verification_otp` / `resend_verification_email` → `OtpService::generate` + `store` +
     `try_begin_resend(OtpPurpose::EmailVerification, &id, cooldown)`; resend is anti-enumerating
     (≥ ANTI_ENUM_MIN_MS).
   - `verify_email` → `OtpService::verify`; on success flip `email_verified` and spawn
     `after_email_verified` fire-and-forget.
   - Delete the embedded OTP code path — a single OTP implementation (`OtpService`) from here on.

2. `crates/bymax-auth-core/tests/email_verification.rs`: hermetic — verify flips the flag + fires the
   hook; wrong code is attempt-capped; resend cooldown + anti-enumeration.

3. `crates/bymax-auth-redis/tests/email_verification_e2e.rs`: testcontainers — cooldown + verify
   against real Redis.

Constraints:
- One OTP implementation only (`OtpService`) — no second code path. Resend is anti-enumerating.
- No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features testing --test email_verification` — expected: all pass.
- `cargo test -p bymax-auth-redis --test email_verification_e2e` (with Docker) — expected: cooldown + verify.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: `services/auth/email_verification.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P6 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 6.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 6.6 — `InvitationService` — invite + single-use accept

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: M
- **Depends on**: 6.2

#### Description

Implement `InvitationService`: `invite` (role-authorization on the inviter + a secure single-use token) and `accept_invitation` (atomic single-use `getdel`, role re-validation against the hierarchy as anti-tamper, duplicate-email guard, user creation + full session issuance), gated by both the `invitations` feature and runtime toggle.

#### Acceptance criteria

- [ ] `invite` normalizes the email (trim + lowercase), rejects an unknown `role` (`InsufficientRole`), fetches the inviter (`None` → `TokenInvalid`), enforces `has_role(inviter.role, role, hierarchy)` (inviter ≥ invited, else `InsufficientRole`), stores `StoredInvitation` under `inv:{sha256(raw)}` (TTL `token_ttl_seconds`, default 172800), and spawns `email.send_invitation(...)` — the raw token is never logged/persisted.
- [ ] `accept_invitation` runs `getdel("inv:{sha256(token)}")` (atomic single-use; `None` → `InvalidInvitationToken`), structurally validates the JSON, **re-validates `invitation.role` against the hierarchy** (anti-tamper), checks `find_by_email` duplicate (`Some` → `EmailAlreadyExists`), hashes the password, `create(CreateUserData { email_verified: true, ... })`, issues full tokens, and (if `sessions.enabled`) `create_session(...)`.
- [ ] Spawns `after_invitation_accepted(safe_user, ctx)` fire-and-forget (ctx from `sanitize_headers(headers)`); returns `AuthResult`.
- [ ] The Redis-write-trust assumption and the optional HMAC-signed-payload hardening are documented in code.
- [ ] `invitations` feature + runtime toggle gating: a no-`invitations` build links none of this.
- [ ] Hermetic unit tests: invite role-authorization, single-use accept (replay → `InvalidInvitationToken`), tampered-role rejection, duplicate-email rejection, full-session issuance. E2E (testcontainers) proves single-use accept against real Redis.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/invitation.rs`
- `crates/bymax-auth-core/tests/invitation_service.rs` (hermetic)
- `crates/bymax-auth-redis/tests/invitation_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` engine services over store TRAITS; real
Redis impls in `bymax-auth-redis` (Phase 5). Edition 2024; full parity with @bymax-one/nest-auth.
Invitations create a tenant user from a secure single-use token.

CURRENT PHASE: 6 (Stateful services) — Task 6.6 of 6 (LAST)

PRECONDITIONS
- Task 6.2 is done: `SessionService::create_session` (for full-session issuance on accept).
- Phase 4: `PasswordService::hash`, `UserRepository::{find_by_id, find_by_email, create}`,
  `TokenManagerService::issue_tokens`, the roles util (`has_role` over `config.roles.hierarchy`),
  `generate_secure_token`, `sanitize_headers`, and the `after_invitation_accepted` hook contract.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.10 "InvitationService" — `invite` / `accept_invitation`;
  `StoredInvitation`, `inv:{sha256(token)}`, the single-use `getdel`, the role re-validation
  anti-tamper step, the duplicate-email guard, `email_verified: true` justification, and the
  Redis-write-trust assumption + optional HMAC-signed-payload hardening.
- `docs/technical_specification.md` § 5.1.6 — `InvitationConfig` (`token_ttl_seconds` default 172800).
- `docs/technical_specification.md` § 9 "Hooks System" — `after_invitation_accepted` (fire-and-forget).

TASK
Implement `InvitationService` (invite + atomic single-use accept), gated by the `invitations` feature
and runtime toggle.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/invitation.rs`:

   ```rust
   impl InvitationService {
       pub async fn invite(&self, inviter_user_id: &str, email: &str, role: &str, tenant_id: &str, tenant_name: Option<&str>) -> Result<(), AuthError>;
       pub async fn accept_invitation(&self, dto: AcceptInvitationDto, ip: &str, ua: &str, headers: BTreeMap<String, String>) -> Result<AuthResult, AuthError>;
   }
   ```
   - `invite`: normalize email, validate role is in the hierarchy, fetch inviter, `has_role` gate,
     store `StoredInvitation` under `inv:{sha256(raw)}` with the TTL, spawn email. Raw token never logged.
   - `accept_invitation`: atomic `getdel`; structural JSON validation; RE-VALIDATE the role against
     the hierarchy (anti-tamper); duplicate-email guard; hash password; `create(..., email_verified:
     true)`; `issue_tokens`; if `sessions.enabled` → `create_session`; spawn
     `after_invitation_accepted(sanitize_headers(headers))`; return `AuthResult`.
   - Document the Redis-write-trust assumption + optional HMAC-signed-payload hardening.

2. `crates/bymax-auth-core/tests/invitation_service.rs`: hermetic — invite role-authorization
   (inviter < invited → `InsufficientRole`), single-use accept (replay → `InvalidInvitationToken`),
   tampered-role rejection, duplicate-email rejection, full-session issuance.

3. `crates/bymax-auth-redis/tests/invitation_e2e.rs`: testcontainers — single-use accept against
   real Redis (the second accept finds nothing).

Constraints:
- Role authorization on create AND re-validation on accept (anti-tamper); single-use atomic `getdel`;
  raw token never stored/logged. `invitations` gated by a Cargo feature AND a runtime toggle —
  a no-`invitations` build links none of this code.
- No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing invitations sessions" --test invitation_service` — expected: all pass.
- `cargo test -p bymax-auth-redis --test invitation_e2e` (with Docker) — expected: single-use accept.
- `cargo build -p bymax-auth-core --no-default-features --features "scrypt"` — expected: no invitation code linked.
- `cargo llvm-cov -p bymax-auth-core --features "testing invitations sessions" --lcov` — expected: `services/invitation.rs` 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P6 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall %. 7. Append `- 6.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
