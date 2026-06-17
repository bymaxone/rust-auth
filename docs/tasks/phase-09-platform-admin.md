# Phase 9 — Platform admin identity domain

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P9
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

The platform-administrator surface is a **separate identity domain** sitting above tenants: platform admins are not tenant-scoped, have no email-verification flow and no OAuth, always have a local credential (`password_hash` is non-optional on `AuthPlatformUser`), and authenticate through their own routes with their own role hierarchy. Phase 2 defined the platform types (`AuthPlatformUser` / `SafeAuthPlatformUser`, `PlatformClaims`, `PlatformLoginResult` / `PlatformAuthResult`, `UpdatePlatformMfaData`); Phase 3 defined `PlatformUserRepository` and the config-validation rules that require a `platform_hierarchy` + a `PlatformUserRepository` when `platform.enabled`; Phase 4 built the local token machinery and the sentinel-hash anti-enumeration helper; Phase 5 built `SessionStore` with `SessionKind::Platform` (the `prt:`/`prp:`/`psess:`/`psd:` prefix family); Phase 7 built `MfaService` and the `MfaContext::Platform` challenge path. This phase assembles `PlatformAuthService` on top of those pieces — login (with the MFA-challenge branch), me, logout, refresh, and revoke-all — plus the platform-token methods on `TokenManagerService` and the isolated platform role hierarchy.

The defining rule is **domain isolation**: the platform role hierarchy (`roles.platform_hierarchy`) and the tenant hierarchy (`roles.hierarchy`) are provably disjoint — a tenant role grants nothing on the platform side and vice versa — platform claims never carry a `tenantId`, and no verification/OAuth path is reachable for an admin. Everything is gated by the `platform` facade feature and constructed only when `config.platform.enabled`.

When P9 is done, platform login/refresh/me/logout/revoke-all pass integration tests (including login → MFA-challenge → full-platform-token exchange for an MFA-enabled admin), the two hierarchies are proven isolated, logout blacklists the access `jti` and cleans both the primary and grace refresh keys, and revoke-all atomically invalidates every platform session. **All HTTP wiring — the `PlatformAuthController` / `PlatformMfaController` routes and the `PlatformUser` / `RequirePlatformRole` extractors — is out of scope (P10).**

---

## Rules-of-phase

1. **Platform is a distinct identity domain.** Never reuse the tenant role hierarchy, never attach a `tenantId` claim (platform rotation uses `tenant_id = ""`), and never expose email verification or OAuth on this surface. Platform sessions use the `prt:`/`prp:`/`psess:`/`psd:` prefix family (`SessionKind::Platform`) and bearer-mode delivery.
2. **Anti-enumeration parity with the tenant login (§7.1.2).** An HMAC-keyed brute-force identifier (`hmac_sha256("platform:{email}")` — no PII in Redis), a throw-away sentinel-hash `verify` on an unknown admin (uniform latency), and a generic `InvalidCredentials` for both unknown-admin and wrong-password.
3. **Logout cleans both keys.** Blacklist the access `jti` for its remaining lifetime, then the ownership-checked `revoke_session(SessionKind::Platform, ...)` removes the `prt:` record, its `psd:` detail, the `psess:{user_id}` membership, **and** the `prp:` grace pointer from the last rotation — so a later `revoke_all` sees an accurate set.
4. **Revoke-all is atomic.** `revoke_all(SessionKind::Platform, user_id)` is the single `invalidate_user_sessions` Lua (SMEMBERS → DEL each namespaced member → DEL the set, one round-trip).
5. **MFA-challenge integration via `MfaContext::Platform`.** The temp token issued on platform login carries the `context: platform` discriminant; the challenge routes persistence through the platform user store and issues platform tokens — the platform arm of `MfaService::challenge` (deferred from Phase 7) is completed here, now that `issue_platform_tokens` exists.
6. **Construction gating.** `PlatformAuthService` is built only when `config.platform.enabled`, which itself requires `roles.platform_hierarchy` + a `PlatformUserRepository` (the §5.5 rules 7–8 validated in Phase 3). The whole surface is `platform`-feature-gated — a no-`platform` build links none of it.
7. **100% coverage**, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on lib paths, English-only, timeless comments. Every password hash/verify (including the sentinel and any rehash) runs on `spawn_blocking`.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 7.9 "`PlatformAuthService`" — the five operations (`login` / `logout` / `refresh` / `me` / `revoke_all_platform_sessions`), the login step list (sentinel verify, generic creds, MFA branch), the logout key-cleanup contract, and the revoke-all Lua.
  - § 7.3 "`TokenManagerService`" — the platform methods `issue_platform_tokens` / `reissue_platform_tokens` (platform claims, `prt:`/`prp:`, `tenant_id = ""`) and the JTI blacklist.
  - § 6.3 "`PlatformUserRepository`" — `find_by_id` / `find_by_email` / `update_last_login` / `update_mfa(UpdatePlatformMfaData)`.
  - § 6.1.3 — `AuthPlatformUser` / `SafeAuthPlatformUser` (non-optional `password_hash`, no `email_verified`, `updated_at`).
  - § 13.3 — `PlatformClaims` (no `tenantId`) and the `MfaChallengeResult` returned by the MFA branch.
  - § 5.1.6 — `PlatformConfig` (`enabled` default false; requires `roles.platform_hierarchy`).
  - § 5.5 (rules 5–8) — the independent validation of the two hierarchies + the platform prerequisites (already enforced in Phase 3's `config/validation.rs`).
  - § 8.2.5–§8.2.6 — the platform routes/extractors this service backs (wired in P10; out of scope here).
  - § 24 — the anti-enumeration invariants (generic credential errors, uniform latency, no PII in Redis).
- [`docs/development_plan.md`](../development_plan.md) — § P9, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 9.1 | Platform claims + platform-token methods on `TokenManagerService` | 📋 ToDo | P0 | M | 4.2, 5.2 |
| 9.2 | Platform role hierarchy isolation (`has_platform_role`) | 📋 ToDo | P0 | S | 3.5 |
| 9.3 | `PlatformAuthService::login` (+ MFA-challenge branch) | 📋 ToDo | P0 | M | 9.1, 9.2, 4.3 |
| 9.4 | `PlatformAuthService` logout / refresh / me / revoke-all | 📋 ToDo | P0 | M | 9.1, 9.3 |
| 9.5 | Platform MFA challenge routing (`MfaContext::Platform`) | 📋 ToDo | P1 | S | 9.1, 9.3, 7.4 |
| 9.6 | `platform` facade feature + isolation proof + E2E | 📋 ToDo | P0 | M | 9.3, 9.4, 9.5 |

---

## Tasks

### Task 9.1 — Platform claims + platform-token methods on `TokenManagerService`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 4.2, 5.2

#### Description

Implement the platform-token methods on `TokenManagerService` — `issue_platform_tokens` and `reissue_platform_tokens` (atomic rotation + grace over `SessionKind::Platform`) — emitting `PlatformClaims` with no `tenantId` and the `prt:`/`prp:` key family, plus the platform JTI blacklist.

#### Acceptance criteria

- [ ] `issue_platform_tokens(admin: &SafeAuthPlatformUser, ip, ua, overrides) -> PlatformAuthResult` signs an HS256 access token with `PlatformClaims` (no `tenantId`; `mfa_verified` reflects the path) and issues an opaque refresh stored under the `prt:` family with `SessionKind::Platform`.
- [ ] `reissue_platform_tokens(old_refresh, ip, ua) -> RotatedTokens` mirrors the dashboard atomic rotation + single-shot grace window but with the `prt:`/`prp:` prefixes and `tenant_id = ""`.
- [ ] The platform refresh is registered in `psess:{user_id}` so `SessionService`/revoke-all see it; the access JTI blacklist (`rv:`) is shared with the dashboard path.
- [ ] Platform delivery is bearer-mode (no cookies) — the result carries the raw tokens for the caller.
- [ ] Hermetic unit tests (in-memory `SessionStore` double): issue→verify round-trip (claims carry no `tenantId`); rotation is single-use with a working grace window; the platform refresh lands in `psess:`.
- [ ] `platform`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/token_manager.rs` (extend, `platform`-gated methods)
- `crates/bymax-auth-core/tests/platform_tokens.rs` (hermetic)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async; full parity with @bymax-one/nest-auth. Platform admins are a separate
identity domain above tenants — their tokens carry NO tenantId and use the `prt:`/`prp:` key family.

CURRENT PHASE: 9 (Platform admin) — Task 9.1 of 6 (FIRST)

PRECONDITIONS
- Phase 4 is done: `TokenManagerService` exists with the dashboard `issue_tokens` / `reissue_tokens`
  (atomic rotation + grace) and the JTI blacklist over `SessionStore`.
- Phase 5 is done: `SessionStore` is keyed by `SessionKind { Dashboard, Platform }` — platform maps to
  `prt:`/`prp:`/`psess:`/`psd:`.
- Phase 2: `PlatformClaims` (no `tenantId`), `PlatformAuthResult`, `RotatedTokens`,
  `SafeAuthPlatformUser` are defined.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.3 "TokenManagerService" — the platform method signatures
  `issue_platform_tokens` / `reissue_platform_tokens`, the `prt:`/`prp:` prefixes, and `tenant_id = ""`.
- `docs/technical_specification.md` § 13.3 — `PlatformClaims` shape (no `tenantId`).

TASK
Implement `issue_platform_tokens` and `reissue_platform_tokens` on `TokenManagerService`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/token_manager.rs` (extend, `#[cfg(feature = "platform")]`):
   ```rust
   pub async fn issue_platform_tokens(&self, admin: &SafeAuthPlatformUser, ip: &str, ua: &str, overrides: Option<TokenOverrides>) -> Result<PlatformAuthResult, AuthError>;
   pub async fn reissue_platform_tokens(&self, old_refresh: &str, ip: &str, ua: &str) -> Result<RotatedTokens, AuthError>;
   ```
   - Access token = HS256 `PlatformClaims` (NO `tenantId`). Refresh = opaque, stored under the `prt:`
     family with `SessionKind::Platform`, registered in `psess:{user_id}`.
   - Rotation mirrors the dashboard path (single-use + grace) with `prt:`/`prp:` and `tenant_id = ""`.
   - Bearer delivery (no cookies) — the result carries the raw tokens.

2. `crates/bymax-auth-core/tests/platform_tokens.rs`: hermetic — issue→verify (no `tenantId`),
   single-use rotation + grace, refresh registered in `psess:`.

Constraints:
- Platform claims NEVER carry a `tenantId`. `platform`-gated. No `axum`/HTTP, no direct Redis client.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing platform" --test platform_tokens` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing platform" --lcov` — expected: the new methods 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P9 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 9.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 9.2 — Platform role hierarchy isolation (`has_platform_role`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 3.5

#### Description

Add `has_platform_role` over `roles.platform_hierarchy` alongside the existing tenant `has_role`, and prove the two hierarchies are disjoint — a tenant role can never satisfy a platform check and vice versa.

#### Acceptance criteria

- [ ] `has_platform_role(admin_role, required, &platform_hierarchy)` mirrors `has_role` semantics (a role satisfies the requirement when it is `required` or an ancestor in the hierarchy) but reads `roles.platform_hierarchy`.
- [ ] The tenant and platform hierarchies are looked up from separate config fields and never cross-reference; a role present only in one hierarchy yields `false` against the other.
- [ ] Unit tests prove isolation: a tenant role fails a platform-role check; a platform role fails a tenant-role check; an unknown role fails both.
- [ ] `platform`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/roles.rs` (add `has_platform_role`)
- `crates/bymax-auth-core/tests/platform_roles.rs`

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; tenant users and platform admins are SEPARATE identity
domains with SEPARATE role hierarchies that never share roles by accident. Edition 2024; full parity
with @bymax-one/nest-auth.

CURRENT PHASE: 9 (Platform admin) — Task 9.2 of 6 (MIDDLE)

PRECONDITIONS
- Phase 3 is done: the roles util exposes `has_role(role, required, &hierarchy)` over
  `config.roles.hierarchy`; `config.roles.platform_hierarchy: Option<HashMap<String, Vec<String>>>`
  exists and is validated when `platform.enabled` (§5.5 rules 7–8).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 24 / § "Tenant and platform are separate identity domains" — the
  isolation invariant (a tenant role grants nothing on the platform side, and vice versa).
- `docs/technical_specification.md` § 5.1.6 — `roles.platform_hierarchy`.

TASK
Add `has_platform_role` over `roles.platform_hierarchy` and prove the two hierarchies are disjoint.

DELIVERABLES

1. `crates/bymax-auth-core/src/roles.rs` (add):
   `pub fn has_platform_role(admin_role: &str, required: &str, platform_hierarchy: &HashMap<String, Vec<String>>) -> bool`
   — same ancestor-or-equal semantics as `has_role`, reading the platform hierarchy.
2. `crates/bymax-auth-core/tests/platform_roles.rs`: a tenant role fails a platform check; a platform
   role fails a tenant check; unknown role fails both; ancestor relationships resolve within the
   platform hierarchy only.

Constraints:
- The two hierarchies never cross-reference. `platform`-gated. `#![forbid(unsafe_code)]`;
  `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing platform" --test platform_roles` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing platform" --lcov` — expected: `has_platform_role` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P9 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 9.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 9.3 — `PlatformAuthService::login` (+ MFA-challenge branch)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 9.1, 9.2, 4.3

#### Description

Implement `PlatformAuthService::login`: HMAC-keyed brute-force, sentinel-hash anti-enumeration on an unknown admin, generic `InvalidCredentials`, and the MFA-challenge branch (`MfaContext::Platform` temp token) vs the full-token success path.

#### Acceptance criteria

- [ ] `login(dto, ip, ua) -> PlatformLoginResult` (enum `Success(PlatformAuthResult) | MfaChallenge(MfaChallengeResult)`): `bf_id = hmac_sha256("platform:{email}")`; `is_locked_out` → `AccountLocked` (429, `retry_after_seconds`).
- [ ] `platform_user_repo.find_by_email(email)`: on `None`, run a throw-away `passwords.verify(password, &SENTINEL_HASH)` (uniform latency), then `record_failure`, `InvalidCredentials`.
- [ ] `passwords.verify(password, admin.password_hash)`: on `false`, `record_failure`, `InvalidCredentials`. On success, `reset_failures` (rehash-on-verify may run fire-and-forget).
- [ ] If `admin.mfa_enabled`: `issue_mfa_temp_token(admin.id, MfaContext::Platform)` → `MfaChallenge(MfaChallengeResult { mfa_required: true, mfa_temp_token })`.
- [ ] Else: strip credentials → `SafeAuthPlatformUser`; `issue_platform_tokens(...)`; spawn `update_last_login` fire-and-forget; return `Success(PlatformAuthResult)`.
- [ ] Hermetic unit tests: unknown admin and wrong password are indistinguishable (same error, sentinel verify runs, uniform latency); lockout at `max_attempts`; MFA-enabled admin → `MfaChallenge`; happy path → `Success`. 100% coverage.
- [ ] `platform`-gated; the MFA branch is additionally `mfa`-gated.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/platform/mod.rs` (struct + shared helpers)
- `crates/bymax-auth-core/src/services/platform/login.rs`
- `crates/bymax-auth-core/tests/platform_login.rs` (hermetic)

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; platform login mirrors the tenant login's anti-enumeration
discipline (sentinel hash, generic creds, HMAC-keyed lockout) on a separate identity surface.
Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 9 (Platform admin) — Task 9.3 of 6 (MIDDLE — the platform security core)

PRECONDITIONS
- Task 9.1 done: `issue_platform_tokens`. Task 9.2 done: `has_platform_role`.
- Phase 4 done: the `BruteForceService` (HMAC-keyed lockout), the startup-loaded `SENTINEL_HASH`, the
  `PasswordService` (verify on `spawn_blocking`, rehash-on-verify), and the tenant login's anti-enum
  pattern (§7.1.2).
- The MFA temp-token path (`issue_mfa_temp_token`) is available under the `mfa` feature (Phase 7
  Task 7.2); `MfaContext::Platform` is defined. `PlatformUserRepository::find_by_email` +
  `update_last_login` exist (Phase 3).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.9 "PlatformAuthService" — the `login` step list (bf_id,
  sentinel verify, generic creds, MFA branch, success path) and `PlatformLoginResult`.
- `docs/technical_specification.md` § 7.1.2 — the tenant login anti-enumeration discipline to mirror.
- `docs/technical_specification.md` § 13.3 — `MfaChallengeResult`.

TASK
Implement `PlatformAuthService::login` with the anti-enumeration discipline and the MFA-challenge branch.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/platform/mod.rs`: the `PlatformAuthService` struct (built only
   when `config.platform.enabled`) + shared helpers.
2. `crates/bymax-auth-core/src/services/platform/login.rs`:
   `login(dto, ip, ua) -> Result<PlatformLoginResult, AuthError>` exactly per § 7.9 — HMAC lockout,
   sentinel verify on unknown, generic `InvalidCredentials`, `reset_failures` on success, MFA branch
   (`issue_mfa_temp_token(MfaContext::Platform)` → `MfaChallenge`) vs `issue_platform_tokens` →
   `Success`.
3. `crates/bymax-auth-core/tests/platform_login.rs`: hermetic — unknown vs wrong-password
   indistinguishable (sentinel verify runs, uniform latency, same error), lockout, MFA → `MfaChallenge`,
   happy path → `Success`.

Constraints:
- Generic `InvalidCredentials` for both unknown-admin and wrong-password; the sentinel verify ALWAYS
  runs; `bf_id` is HMAC'd (no PII in Redis). Every verify on `spawn_blocking`. `platform`-gated; the
  MFA branch additionally `mfa`-gated. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing platform" --test platform_login` — expected: all pass.
- `cargo test -p bymax-auth-core --features "testing platform mfa" --test platform_login` — expected: MFA branch covered.
- `cargo llvm-cov -p bymax-auth-core --features "testing platform mfa" --lcov` — expected: `services/platform/login.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P9 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 9.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 9.4 — `PlatformAuthService` logout / refresh / me / revoke-all

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 9.1, 9.3

#### Description

Implement the remaining platform operations: `logout` (blacklist `jti` + ownership-checked revoke cleaning both primary and grace keys), `refresh` (delegate to `reissue_platform_tokens`), `me` (`SafeAuthPlatformUser`), and `revoke_all_platform_sessions` (atomic `invalidate_user_sessions`).

#### Acceptance criteria

- [ ] `logout(user_id, jti, exp, raw_refresh)`: `remaining = max(0, exp - now)`; if `> 0`, `blacklist_access(jti, remaining)`; `hash = sha256(raw_refresh)`; `revoke_session(SessionKind::Platform, user_id, &hash)` removes the `prt:` record, the `psd:` detail, the `psess:{user_id}` membership, **and** the `prp:` grace pointer in one ownership-checked call.
- [ ] `refresh(raw_refresh, ip, ua)` delegates to `reissue_platform_tokens`.
- [ ] `me(user_id)`: `find_by_id`; `None` → `TokenInvalid`; strip credentials → `SafeAuthPlatformUser`.
- [ ] `revoke_all_platform_sessions(user_id)`: `revoke_all(SessionKind::Platform, user_id)` — the atomic `invalidate_user_sessions` Lua (SMEMBERS → DEL each namespaced member → DEL the set).
- [ ] Hermetic unit tests: logout blacklists the `jti` and cleans both `prt:`+`prp:`; a blacklisted `jti` is rejected; `me` for a vanished admin → `TokenInvalid`; revoke-all clears every platform session.
- [ ] `platform`-gated; 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/platform/session_ops.rs` (logout / refresh / me / revoke-all)
- `crates/bymax-auth-core/tests/platform_session_ops.rs` (hermetic)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; platform sessions use the `prt:`/`prp:`/`psess:`/`psd:` key
family and bearer-mode delivery; logout must clean BOTH the primary and the grace key so a later
revoke-all sees an accurate set. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 9 (Platform admin) — Task 9.4 of 6 (MIDDLE)

PRECONDITIONS
- Task 9.1 done: `reissue_platform_tokens`; the platform refresh registered in `psess:`. Task 9.3 done:
  `PlatformAuthService` struct + `login`.
- Phase 5: `SessionStore` ownership-checked `revoke_session` and the atomic `revoke_all`
  (`invalidate_user_sessions` Lua) over `SessionKind::Platform`; the `rv:` JTI blacklist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.9 "PlatformAuthService" — the `logout` key-cleanup contract
  (blacklist `jti`, then ownership-checked revoke cleaning `prt:`/`psd:`/`psess:`-member/`prp:`),
  `refresh`, `me`, and `revoke_all_platform_sessions`.

TASK
Implement `logout`, `refresh`, `me`, and `revoke_all_platform_sessions`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/platform/session_ops.rs`:
   - `logout(user_id, jti, exp, raw_refresh)` per § 7.9 (blacklist remaining lifetime, then
     `revoke_session(SessionKind::Platform, ...)` cleaning the primary + grace keys).
   - `refresh(raw_refresh, ip, ua)` → `reissue_platform_tokens`.
   - `me(user_id)` → `find_by_id` / `None → TokenInvalid` / `SafeAuthPlatformUser`.
   - `revoke_all_platform_sessions(user_id)` → atomic `revoke_all(SessionKind::Platform, user_id)`.

2. `crates/bymax-auth-core/tests/platform_session_ops.rs`: hermetic — logout blacklists + cleans both
   keys, blacklisted `jti` rejected, `me` for a vanished admin → `TokenInvalid`, revoke-all clears all.

Constraints:
- Logout cleans BOTH `prt:` and `prp:`. Revoke-all is the single atomic Lua. `platform`-gated.
- No `axum`/HTTP, no direct Redis client. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing platform" --test platform_session_ops` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing platform" --lcov` — expected: `services/platform/session_ops.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P9 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 9.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 9.5 — Platform MFA challenge routing (`MfaContext::Platform`)

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: S
- **Depends on**: 9.1, 9.3, 7.4

#### Description

Complete the platform arm of `MfaService::challenge` (deferred from Phase 7): when the temp token carries `context: platform`, route persistence through the platform user store and issue platform tokens, and prove the platform login → challenge → full-platform-token exchange path.

#### Acceptance criteria

- [ ] `MfaService::challenge` resolves the user via the platform repository when the verified temp token's `context == Platform`, and issues full tokens via `issue_platform_tokens`, returning the `LoginResultMfa::Platform(PlatformAuthResult)` arm (§13.3 — `MfaChallengeResult` is the pre-challenge response from `login`, not the challenge return type).
- [ ] The `challenge:`-namespaced brute-force counter and the anti-replay/fused-consume Lua behave identically to the dashboard path (no platform-specific weakening).
- [ ] A platform admin with MFA enabled completes `login` → `MfaChallenge` → `challenge(temp_token, totp)` → a full platform session (`mfa_verified: true`).
- [ ] Hermetic unit tests: the platform challenge arm issues platform tokens, routes persistence through the platform store, and rejects a replayed code; a recovery-code challenge works on the platform path.
- [ ] `platform` + `mfa`-gated; 100% coverage on the platform arm.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/mfa/challenge.rs` (complete the `Platform` arm)
- `crates/bymax-auth-core/tests/platform_mfa_challenge.rs` (hermetic)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `MfaService::challenge` is context-aware (`Dashboard` vs
`Platform`). Phase 7 built the dashboard arm; this task completes the platform arm now that
`issue_platform_tokens` exists. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 9 (Platform admin) — Task 9.5 of 6 (MIDDLE)

PRECONDITIONS
- Phase 7 Task 7.4 done: `MfaService::challenge` with the dashboard arm, the `challenge:` brute-force
  namespace, and the fused anti-replay/consume Lua; `MfaContext { Dashboard, Platform }`.
- Task 9.1 done: `issue_platform_tokens`. Task 9.3 done: platform login emits an `MfaContext::Platform`
  temp token. `PlatformUserRepository` (find/update_mfa) is available.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.5.3 "challenge" — the context routing (fetch the user for the
  context; platform → `issue_platform_tokens`).
- `docs/technical_specification.md` § 7.9 — the platform login → challenge → exchange path.

TASK
Complete the `MfaContext::Platform` arm of `MfaService::challenge` and prove the platform
login→challenge→exchange path.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/mfa/challenge.rs` (complete the `Platform` arm):
   - When the verified temp token's `context == Platform`, resolve the user via the platform repo,
     run the same brute-force + fused anti-replay/consume logic, and issue full tokens via
     `issue_platform_tokens`, returning the `LoginResultMfa::Platform(PlatformAuthResult)` arm.
2. `crates/bymax-auth-core/tests/platform_mfa_challenge.rs`: hermetic — platform challenge issues
   platform tokens, routes persistence through the platform store, rejects a replayed code; a recovery
   code works on the platform path; full `login → MfaChallenge → challenge → platform session`.

Constraints:
- No platform-specific weakening of brute-force or anti-replay. `platform` + `mfa`-gated. No `axum`/HTTP.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing platform mfa" --test platform_mfa_challenge` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing platform mfa" --lcov` — expected: the platform arm 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P9 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 9.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 9.6 — `platform` facade feature + isolation proof + E2E

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 9.3, 9.4, 9.5

#### Description

Wire the `platform` facade feature, construct `PlatformAuthService` only when `config.platform.enabled`, prove the platform/tenant hierarchy isolation and the no-tenant/verification/OAuth surface, and add the full platform E2E against real Redis.

#### Acceptance criteria

- [ ] The facade `platform` feature turns on `bymax-auth-core/platform`; `PlatformAuthService` is re-exported only under it and a no-`platform` build links none of the platform code.
- [ ] `AuthEngineBuilder` constructs `PlatformAuthService` only when `config.platform.enabled` (which, per the Phase-3 validation, requires `roles.platform_hierarchy` + a `PlatformUserRepository`).
- [ ] An isolation test proves a tenant role cannot satisfy a platform-role check and vice versa, and that no email-verification or OAuth path is reachable for a platform admin.
- [ ] A full E2E (testcontainers Redis) runs platform `login → refresh → me → logout → revoke-all`, plus the MFA-enabled `login → challenge → exchange`, asserting the access claims never carry a `tenantId` and logout cleans both `prt:`+`prp:`.
- [ ] `cargo deny check` passes; 100% coverage across the platform surface.

#### Files to create / modify

- `crates/bymax-auth/Cargo.toml` (the `platform` facade feature)
- `crates/bymax-auth/src/lib.rs` (re-exports under `#[cfg(feature = "platform")]`)
- `crates/bymax-auth-core/src/services/mod.rs` + builder wiring (construct when `config.platform.enabled`)
- `crates/bymax-auth-redis/tests/platform_e2e.rs` (testcontainers, full lifecycle)

#### Agent prompt

````
You are a senior Rust engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the platform admin surface is a separate, feature-gated
identity domain. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 9 (Platform admin) — Task 9.6 of 6 (LAST)

PRECONDITIONS
- Tasks 9.1–9.5 done: platform tokens, `has_platform_role`, `PlatformAuthService` (login/logout/
  refresh/me/revoke-all), and the platform MFA challenge arm.
- Phase 3: `config.platform.enabled` + the §5.5 validation (rules 7–8) already require
  `roles.platform_hierarchy` + a `PlatformUserRepository`; the facade feature taxonomy exists.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 5.1.6 (`PlatformConfig`) + § 7.9 (the service constructed only
  when `platform.enabled`).
- `docs/technical_specification.md` § 19.2 — the `platform` feature.
- `docs/technical_specification.md` § "Tenant and platform are separate identity domains" — the
  isolation invariant to prove.

TASK
Wire the `platform` facade feature, construct the service only when enabled, prove the hierarchy
isolation + no-tenant/verification/OAuth surface, and add the full platform E2E.

DELIVERABLES

1. `crates/bymax-auth/Cargo.toml` + `lib.rs`: the `platform` feature → `bymax-auth-core/platform`;
   re-export `PlatformAuthService` under `#[cfg(feature = "platform")]`.
2. Builder wiring (`services/mod.rs` + the builder): construct `PlatformAuthService` only when
   `config.platform.enabled`.
3. `crates/bymax-auth-redis/tests/platform_e2e.rs`: testcontainers — `login → refresh → me → logout →
   revoke-all` + MFA `login → challenge → exchange`; assert no `tenantId` in the claims and that
   logout cleans `prt:`+`prp:`. Include the isolation assertions (tenant role ⊥ platform check).

Constraints:
- A no-`platform` build links none of the platform code (prove with a build). The two hierarchies are
  provably disjoint; no verification/OAuth path is reachable for an admin. Features strictly additive.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo build -p bymax-auth --no-default-features --features scrypt` — expected: no platform code linked.
- `cargo test -p bymax-auth-redis --features "platform mfa" --test platform_e2e` (with Docker) — expected: full lifecycle.
- `cargo deny check` — expected: passes.
- `cargo llvm-cov --workspace --features "testing platform mfa" --lcov` — expected: platform surface 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P9 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall %. 7. Append `- 9.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
