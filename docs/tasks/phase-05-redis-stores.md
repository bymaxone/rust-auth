# Phase 5 — `bymax-auth-redis`: stores + Lua + WS ticket (E2E Redis)

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P5
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 3 defined the store traits (`SessionStore`, `OtpStore`, `BruteForceStore`, `WsTicketStore`) and Phase 4 implemented the local auth flows against them using **in-memory doubles**. This phase implements the **real Redis backend** in `bymax-auth-redis`: concrete trait impls over `redis` + `deadpool-redis`, the **atomic Lua scripts** (refresh rotation with a grace window, ownership-checked revocation, fixed-window brute-force, attempt-bounded OTP verify, single-use WS ticket), namespace prefixing, and **no-PII keys** (every identifier hashed/HMAC'd). It is verified end-to-end against a **real Redis** via `testcontainers`.

When P5 is done, a consumer can swap the in-memory doubles for `RedisStores` and run the Phase 4 flows against Redis; every multi-step state transition is atomic (one Lua script), every key matches the spec's catalog prefix, and no raw email/token/PII appears in any key. **This crate implements the store traits only — it contains no flow logic** (the services that call the stores are Phases 4/6+).

---

## Rules-of-phase

1. **`bymax-auth-redis` implements the Phase 3 store traits** over `redis` + `deadpool-redis`. It depends on `bymax-auth-core` (traits) and `bymax-auth-crypto` (hashing) — never on `axum`/HTTP. (`fred` is the documented single-dependency alternative client — it owns its pool, so `deadpool-redis` is dropped in that configuration — but this crate uses `redis` + `deadpool-redis`; §12.1.)
2. **Atomicity via Lua.** Every read-decide-write invariant (rotation + grace, ownership-checked revoke, fixed-window lockout, OTP verify + attempts, single-use ticket) is a single Lua script with an explicit `KEYS`/`ARGV` → result contract; scripts are loaded once and invoked by SHA (`EVALSHA` with `EVAL` fallback).
3. **Key catalog conformance.** Every key uses the exact prefix from the spec's catalog (`rt`, `rv`, `sess`, `sd`, `rp`, `lf`, `otp`, `resend`, `wst`, `psess`, `psd`, …), namespaced with the configured prefix (default `auth`).
4. **No PII in keys.** Identifiers (email, raw tokens) are never in a key in plaintext — they are `sha256`/`hmac_sha256`'d (via `bymax-auth-crypto`). Refresh tokens are stored only as `sha256(token)`.
5. **Grace window correctness.** The rotation script keeps the previous refresh valid for the configured grace period and stores the NEW `SessionRecord` JSON under the grace pointer (`rp:`) — never a raw token or a token hash (§12.4).
6. **Connection pooling.** Use `deadpool-redis`; handle pool/connection errors as a typed store error mapped into the trait's error type — no panics.
7. **Integration tests use a real Redis via `testcontainers`** (Docker required); they are gated so a no-Docker `cargo test` still builds the crate. Each script's contract is asserted directly. These tests are where the no-PII-keys invariant (§24 inv 9) and the atomic-Lua-state-transition invariant (§24 inv 15) are asserted against real Redis.
8. **100% coverage** of the crate. `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on library paths, English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 12 "Redis Strategy" (the client choice; the COMPLETE key catalog with prefixes/TTLs; the four+ Lua scripts and their `KEYS`/`ARGV` → result contracts; namespace prefixing; no-PII rule). § 3 "Architecture" (the `redis_stores(...)` builder convenience — relevant to Task 5.6).
- [`docs/development_plan.md`](../development_plan.md) — § P5, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 5.1 | Crate setup: pool, namespace, `RedisStores`, Lua loader | 📋 ToDo | P0 | M | 3.6 |
| 5.2 | `SessionStore` impl + rotation/grace + revoke Lua + JTI blacklist | 📋 ToDo | P0 | L | 5.1 |
| 5.3 | `OtpStore` impl + attempt-bounded verify Lua | 📋 ToDo | P0 | M | 5.1 |
| 5.4 | `BruteForceStore` impl + fixed-window Lua | 📋 ToDo | P0 | M | 5.1 |
| 5.5 | `WsTicketStore` impl (single-use ticket via GETDEL) | 📋 ToDo | P0 | S | 5.1 |
| 5.6 | Key-catalog conformance + no-PII tests + builder wiring | 📋 ToDo | P0 | M | 5.2, 5.3, 5.4, 5.5 |

---

## Tasks

### Task 5.1 — Crate setup: pool, namespace, `RedisStores`, Lua loader

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.6

#### Description

Wire `bymax-auth-redis`: the `deadpool-redis` pool, the namespace-prefixing key builder, the `RedisStores` struct that will hold the trait impls, a Lua script loader (cache by SHA with `EVAL` fallback), and the testcontainers harness.

#### Acceptance criteria

- [ ] `Cargo.toml` depends on `bymax-auth-core` (traits), `bymax-auth-crypto` (hashing), `redis`, `deadpool-redis`, `serde`/`serde_json`, `thiserror`; dev-deps include `testcontainers` (+ a Redis image) and `tokio` test macros.
- [ ] `RedisStores::connect(url, namespace)` builds a `deadpool-redis` pool; a `key(prefix, id)` helper produces `"{namespace}:{prefix}:{id}"`.
- [ ] A `LuaScript` loader caches each script's SHA and invokes via `EVALSHA` with an `EVAL`/`NOSCRIPT` fallback.
- [ ] A `RedisStoreError` (thiserror) maps pool/Redis errors into the store trait's error type (no panics).
- [ ] `cargo build -p bymax-auth-redis` builds; a smoke integration test (gated, testcontainers) does a round-trip `SET`/`GET` through the pool + namespace.

#### Files to create / modify

- `crates/bymax-auth-redis/Cargo.toml`
- `crates/bymax-auth-redis/src/{lib.rs,pool.rs,keys.rs,script.rs,error.rs}`
- `crates/bymax-auth-redis/tests/common/mod.rs` (testcontainers harness)

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async engine; full parity with @bymax-one/nest-auth. `bymax-auth-redis`
implements the engine's store traits over `redis` + `deadpool-redis`, atomically via Lua.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.1 of 6 (FIRST)

PRECONDITIONS
- Phase 3 is done: `bymax-auth-core` exposes `SessionStore`/`OtpStore`/`BruteForceStore`/
  `WsTicketStore` (domain-level, `SessionKind`-keyed) + their value types.
- Phase 1 is done: `bymax-auth-crypto` provides `sha256`/`hmac_sha256`.
- `crates/bymax-auth-redis` is an empty skeleton with the lint headers.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the client choice (`redis` +
  `deadpool-redis`), namespace prefixing (default `auth`), and the Lua-by-SHA approach.

TASK
Set up the pool, namespace key builder, `RedisStores` skeleton, the Lua loader, and the
testcontainers harness. No trait impls yet.

DELIVERABLES

1. `Cargo.toml` — deps `bymax-auth-core`, `bymax-auth-crypto`, `redis` (tokio + connection-manager
   features), `deadpool-redis`, `serde`, `serde_json`, `thiserror`, `tracing`. Dev-deps:
   `testcontainers` (+ the Redis module/image), `tokio` (macros, rt-multi-thread).
2. `pool.rs` — `RedisStores { pool: deadpool_redis::Pool, namespace: String }` + `connect(url,
   namespace) -> Result<Self, RedisStoreError>`.
3. `keys.rs` — `fn key(namespace, prefix, id) -> String` → `"{namespace}:{prefix}:{id}"`; a typed
   `Prefix` enum or consts for every catalog prefix (`rt`,`rv`,`sess`,`sd`,`rp`,`lf`,`otp`,`resend`,
   `wst`,`psess`,`psd`, …) matching § 12.
4. `script.rs` — a `LuaScript` that holds the source + cached SHA and runs `EVALSHA` with an
   `EVAL`/`NOSCRIPT` fallback.
5. `error.rs` — `RedisStoreError` (thiserror) → mapped into the store trait error type.
6. `tests/common/mod.rs` — a `testcontainers` harness spinning up Redis and yielding a connected
   `RedisStores` (gated behind a `cfg` or an env guard so a no-Docker `cargo build` still works).

Constraints:
- No `axum`/HTTP deps. Pool/Redis errors map to a typed error — no panics.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-redis` — expected: builds.
- `cargo test -p bymax-auth-redis --test '*'` (with Docker) — expected: the smoke round-trip passes;
  the key helper produces `auth:<prefix>:<id>`.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P5 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 5.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 5.2 — `SessionStore` impl + rotation/grace + revoke Lua + JTI blacklist

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 5.1

#### Description

Implement `SessionStore` over Redis: `create_session`, the atomic refresh-rotation Lua (with grace window), the ownership-checked revoke/revoke-all Lua, and the `jti` access-token blacklist — all keyed by `SessionKind`.

#### Acceptance criteria

- [ ] `create_session(kind, ...)` stores the session under `rt:{sha256(token)}` (+ `sess`/`sd` detail) with the refresh TTL; platform sessions use the `psess`/`psd` prefixes.
- [ ] `rotate(kind, raw_refresh) -> RotateOutcome` is a single Lua script: read the old session, mint/return the new record, set the grace pointer (`rp:{old_hash}` → the new `SessionRecord` JSON, never a raw token or token hash) with the grace TTL, and delete/expire the old — atomically.
- [ ] `revoke(kind, session_id, owner)` is an ownership-checked Lua (only the owner's session is deleted); `revoke_all(kind, user)` is the atomic `invalidate_user_sessions` Lua (SMEMBERS → DEL each namespaced member → DEL the set, one transaction; §12.3/§12.5).
- [ ] `blacklist_access(jti, ttl)` / `is_blacklisted(jti)` implement the `rv:{jti}` blacklist with the remaining-lifetime TTL.
- [ ] Integration tests (testcontainers) assert: create→rotate produces a new pair and the old stays valid only within grace; ownership revoke rejects a non-owner; blacklist rejects a revoked `jti`.
- [ ] 100% coverage; no raw token in any key/value.

#### Files to create / modify

- `crates/bymax-auth-redis/src/stores/session.rs`
- `crates/bymax-auth-redis/src/lua/{rotate.lua,revoke.lua,invalidate_user_sessions.lua}`
- `crates/bymax-auth-redis/tests/session_store.rs`

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-redis` implements the engine's store traits
atomically via Lua. Refresh rotation with a grace window and ownership-checked revocation are the
trickiest correctness points. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.2 of 6 (MIDDLE — the hardest store)

PRECONDITIONS
- Task 5.1 is done: the pool, namespace `key()` helper, `LuaScript` loader, and testcontainers
  harness exist. `bymax-auth-core::SessionStore` (domain-level, `SessionKind`-keyed) + `RotateOutcome`
  are defined; `bymax-auth-crypto::sha256` is available.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the session/refresh keys (`rt`,`sess`,
  `sd`,`rp`,`rv`,`psess`,`psd`), the rotation+grace Lua contract, the ownership-checked revoke Lua,
  and the JTI blacklist (`rv`). Reproduce the KEYS/ARGV → result contracts exactly.

TASK
Implement `SessionStore` with the rotation/grace and revoke Lua scripts and the JTI blacklist.

DELIVERABLES

1. `stores/session.rs` — `impl SessionStore for RedisStores` with `create_session`, `rotate`,
   `revoke`, `revoke_all`, `blacklist_access`, `is_blacklisted`, keyed by `SessionKind`
   (dashboard → `rt`/`sess`/`sd`/`rp`; platform → `psess`/`psd`).
2. `lua/rotate.lua` — read the old session by `rt:{old_hash}`; if valid, write the new session
   (`rt:{new_hash}`), set the grace pointer `rp:{old_hash}` → the NEW `SessionRecord` JSON (never a
   raw token or token hash) with the grace TTL, and expire the old. Document the KEYS/ARGV/return.
3. `lua/revoke.lua` — delete the session only if the supplied owner matches the stored owner.
   `lua/invalidate_user_sessions.lua` — `revoke_all`: SMEMBERS the user's `sess:`/`psess:` set, DEL
   each namespaced member, then DEL the set, all in one atomic transaction (§12.3/§12.5).
4. `tests/session_store.rs` — testcontainers integration tests for: create→rotate, grace validity,
   ownership revoke rejection, revoke_all (asserts every member key and the set are gone), blacklist.

Constraints:
- Multi-step transitions MUST be a single Lua script (atomic). The grace pointer never stores the
  raw new token.
- Keys carry only hashes — never the raw refresh token or PII.
- No `unwrap`/`expect`/`panic!`; map errors to the trait error; `#![forbid(unsafe_code)]`; document
  every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-redis --test session_store` (with Docker) — expected: all scenarios pass.
- `cargo llvm-cov -p bymax-auth-redis --lcov` — expected: `stores/session.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update P5 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 5.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 5.3 — `OtpStore` impl + attempt-bounded verify Lua

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 5.1

#### Description

Implement `OtpStore` over Redis: `put` (OTP record + attempt counter + TTL), the atomic verify Lua (code match + attempt increment + delete-on-success/max-attempts), and `try_begin_resend` throttling.

#### Acceptance criteria

- [ ] `put(...)` stores the OTP record under `otp:{hashed_id}` with the configured TTL and a zeroed attempt counter.
- [ ] `verify(...)` is a single Lua: increment attempts, compare the code, delete on success OR when `max_attempts` is reached, and return a typed outcome (`Ok`/`Wrong`/`MaxAttempts`/`Expired`).
- [ ] `try_begin_resend(...)` enforces a resend throttle under `resend:{hashed_id}`.
- [ ] Keys carry only hashed identifiers (no raw email).
- [ ] Integration tests (testcontainers): success, wrong-then-success within attempts, max-attempts lockout, expiry, resend throttle.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-redis/src/stores/otp.rs`
- `crates/bymax-auth-redis/src/lua/otp_verify.lua`
- `crates/bymax-auth-redis/tests/otp_store.rs`

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-redis` implements the engine's store traits
atomically via Lua. Edition 2024.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 5.1 is done: pool, `key()`, `LuaScript`, testcontainers harness. `bymax-auth-core::OtpStore`
  (`put`/`verify`/`try_begin_resend`) is defined.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the OTP keys (`otp`, `resend`) and the
  attempt-bounded verify Lua contract.

TASK
Implement `OtpStore` with the attempt-bounded verify Lua and resend throttle.

DELIVERABLES

1. `stores/otp.rs` — `impl OtpStore for RedisStores` with `put`, `verify`, `try_begin_resend`.
2. `lua/otp_verify.lua` — atomic: INCR attempts; if code matches → delete + return Ok; if attempts
   ≥ max → delete + return MaxAttempts; else return Wrong; missing key → Expired. Document KEYS/ARGV/return.
3. `tests/otp_store.rs` — testcontainers tests for success, wrong-then-success, max-attempts, expiry,
   resend throttle.

Constraints:
- Verify is a single Lua script (atomic). Keys use hashed identifiers only.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-redis --test otp_store` (with Docker) — expected: all scenarios pass.
- `cargo llvm-cov -p bymax-auth-redis --lcov` — expected: `stores/otp.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update P5 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 5.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 5.4 — `BruteForceStore` impl + fixed-window Lua

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 5.1

#### Description

Implement `BruteForceStore` over Redis: `is_locked`, `record_failure` (fixed-window via Lua — INCR then EXPIRE only on the first failure so the window does not extend), and `reset`.

#### Acceptance criteria

- [ ] `record_failure(hashed_id)` is a Lua that INCRs `lf:{hashed_id}` and sets the TTL only when the counter transitions from 0→1 (the window does not slide on later failures).
- [ ] `is_locked(hashed_id)` returns true when the counter ≥ `max_attempts`; `reset(hashed_id)` deletes the counter.
- [ ] `remaining_lockout_secs(hashed_id)` returns the counter's residual TTL (`TTL` clamped to `>= 0`) so the caller can compute a `Retry-After` (§12.5.3).
- [ ] Keys use only the HMAC'd identifier (no raw email).
- [ ] Integration tests (testcontainers): lockout after `max_attempts`; the window does not extend across failures; reset clears it.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-redis/src/stores/brute_force.rs`
- `crates/bymax-auth-redis/src/lua/brute_force_incr.lua`
- `crates/bymax-auth-redis/tests/brute_force_store.rs`

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-redis` implements the engine's store traits
atomically via Lua. Edition 2024.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.4 of 6 (MIDDLE)

PRECONDITIONS
- Task 5.1 is done: pool, `key()`, `LuaScript`, testcontainers harness. `bymax-auth-core::BruteForceStore`
  (`is_locked`/`record_failure`/`reset`) is defined.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the `lf` key and the fixed-window
  INCR+EXPIRE-on-first Lua contract.

TASK
Implement `BruteForceStore` with the fixed-window Lua.

DELIVERABLES

1. `stores/brute_force.rs` — `impl BruteForceStore for RedisStores` with `is_locked`,
   `record_failure`, `reset`, `remaining_lockout_secs` (residual `TTL` clamped `>= 0`, for `Retry-After`).
2. `lua/brute_force_incr.lua` — INCR `lf:{id}`; if the new value == 1, set the window TTL; return the
   count. (The window TTL is set ONCE — it does not extend on subsequent failures.)
3. `tests/brute_force_store.rs` — testcontainers tests for lockout, window-non-extension, reset.

Constraints:
- Window does not slide — EXPIRE only on the 0→1 transition.
- Keys use the HMAC'd identifier only.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-redis --test brute_force_store` (with Docker) — expected: all pass,
  including a test that asserts the TTL is unchanged after a second failure.
- `cargo llvm-cov -p bymax-auth-redis --lcov` — expected: `stores/brute_force.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update P5 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 5.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 5.5 — `WsTicketStore` impl (single-use ticket via GETDEL)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 5.1

#### Description

Implement `WsTicketStore` over Redis: issue a short-TTL opaque WS upgrade ticket and redeem it exactly once via `GETDEL`.

#### Acceptance criteria

- [ ] `issue(...)` stores a snapshot under `wst:{sha256(ticket)}` with the configured short TTL (e.g. 30s).
- [ ] `redeem(raw_ticket)` is a single atomic `GETDEL` — the ticket is valid exactly once; a second redeem returns "not found".
- [ ] Keys carry only `sha256(ticket)` (no raw ticket).
- [ ] Integration tests (testcontainers): redeem-once-succeeds, second-redeem-fails, expiry.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-redis/src/stores/ws_ticket.rs`
- `crates/bymax-auth-redis/tests/ws_ticket_store.rs`

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-redis` implements the engine's store traits.
The WebSocket upgrade is authenticated by a single-use, short-TTL opaque ticket (never the access
JWT in the URL). Edition 2024.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.5 of 6 (MIDDLE)

PRECONDITIONS
- Task 5.1 is done: pool, `key()`, testcontainers harness. `bymax-auth-core::WsTicketStore` is defined.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the `wst` key, the 30s TTL, and the
  single-use `GETDEL` contract.

TASK
Implement `WsTicketStore` with a single-use `GETDEL` redeem.

DELIVERABLES

1. `stores/ws_ticket.rs` — `impl WsTicketStore for RedisStores` with `issue` (store snapshot under
   `wst:{sha256(ticket)}`, short TTL) and `redeem` (atomic `GETDEL`; returns the snapshot once, then
   not-found).
2. `tests/ws_ticket_store.rs` — testcontainers tests: redeem-once, second-redeem-fails, expiry.

Constraints:
- Redeem is exactly-once (atomic `GETDEL`). Keys carry only `sha256(ticket)`.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-redis --test ws_ticket_store` (with Docker) — expected: all pass.
- `cargo llvm-cov -p bymax-auth-redis --lcov` — expected: `stores/ws_ticket.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update P5 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 5.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 5.6 — Key-catalog conformance + no-PII tests + builder wiring

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 5.2, 5.3, 5.4, 5.5

#### Description

Assert every key matches the spec's catalog prefix and contains no raw PII, then wire `RedisStores` so it satisfies the `AuthEngineBuilder::redis_stores(...)` convenience and the Phase 4 flows run against real Redis.

#### Acceptance criteria

- [ ] A conformance test enumerates the keys written by every store operation — including the `us:` (`UserStatusCache`) key (§12.4) — and asserts each matches the spec's catalog prefix (namespaced) and contains only hashes (no raw email/token); the `us:` key is keyed on the opaque `userId` (not hashed, per §12.4), so its assertion is prefix-only.
- [ ] `RedisStores` implements all four store traits and is accepted by `AuthEngineBuilder::redis_stores(...)` (the convenience that fans out to the individual store setters).
- [ ] An end-to-end test assembles an `AuthEngine` with `redis_stores(RedisStores::connect(...))` and runs a Phase 4 flow (register → login → refresh → logout) against the testcontainers Redis.
- [ ] `cargo deny check` still passes with the new Redis dependencies.
- [ ] 100% coverage for the crate.

#### Files to create / modify

- `crates/bymax-auth-redis/src/lib.rs` (re-exports + `redis_stores` glue)
- `crates/bymax-auth-redis/tests/{key_conformance.rs,engine_e2e.rs}`

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-redis` is the real Redis backend for the
engine's store traits. Edition 2024; full parity with @bymax-one/nest-auth. Redis keys must match
the spec catalog and carry no PII.

CURRENT PHASE: 5 (bymax-auth-redis) — Task 5.6 of 6 (LAST)

PRECONDITIONS
- Tasks 5.2–5.5 are done: all four store traits are implemented over Redis with their Lua scripts.
- Phase 3/4: `AuthEngineBuilder::redis_stores(...)` exists; the Phase 4 flows run against the store
  traits (proven with in-memory doubles).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the COMPLETE key catalog (every prefix +
  TTL) and the no-PII rule.
- `docs/technical_specification.md` § 3 "Architecture" — the `redis_stores(...)` builder convenience.

TASK
Add key-catalog conformance + no-PII tests and wire `RedisStores` into the builder; prove the Phase
4 flows run against real Redis.

DELIVERABLES

1. `lib.rs` — re-export `RedisStores`; ensure it implements all four store traits and satisfies
   `AuthEngineBuilder::redis_stores(...)` (the convenience that fans out to the individual setters).
2. `tests/key_conformance.rs` — exercise every store op and assert (by scanning the keyspace) that
   each key matches the catalog prefix (namespaced) and contains only hashes (no raw email/token).
3. `tests/engine_e2e.rs` — assemble an `AuthEngine` with `redis_stores(RedisStores::connect(...))`
   and run register → login → refresh → logout against the testcontainers Redis.

Constraints:
- Every key must match § 12's catalog; no raw PII anywhere in a key.
- No `unwrap`/`expect`/`panic!` on library paths; `#![forbid(unsafe_code)]`; document every public
  item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-redis` (with Docker) — expected: conformance + e2e tests pass.
- `cargo deny check` — expected: passes with the Redis deps.
- `cargo llvm-cov -p bymax-auth-redis --lcov` — expected: crate at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Set progress `6/6`. 5. Update the
P5 row in `docs/development_plan.md` (mark ✅ when all six tasks are done). 6. Recompute the overall
%. 7. Append `- 5.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
