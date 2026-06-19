# Phase 2 — `bymax-auth-types` + `bymax-auth-jwt`: model, errors, HS256, ts-rs

> **Status**: ✅ Done · **Progress**: 6 / 6 tasks · **Last updated**: 2026-06-19
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P2
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 0 produced the workspace; Phase 1 filled in `bymax-auth-crypto`. This phase implements the two remaining **wasm-safe foundation crates**:

- **`bymax-auth-types`** — the shared data model: domain structs (`AuthUser`/`SafeAuthUser` and platform variants, `Create*`/`Update*`), the `AuthError`/`AuthErrorCode` catalog with its on-the-wire envelope, the JWT claim structs (`DashboardClaims`/`PlatformClaims`/`MfaTempClaims`), the result types, the shared constants (cookie names, route maps), and the **`ts-rs` generation pipeline** that emits the TypeScript `./shared` surface so the frontend never drifts.
- **`bymax-auth-jwt`** — the pure-Rust HS256 implementation (sign/verify/decode) used identically by the server and, later, the WASM edge binding. No `ring`, no `jsonwebtoken`.

Both crates are `serde`-based, have no async runtime, and **must compile to `wasm32-unknown-unknown`**. When P2 is done, the data model serializes to the exact wire shapes the spec defines, the error catalog matches `@bymax-one/nest-auth` byte-for-byte (codes + statuses), HS256 round-trips and rejects forged algorithms, `ts-rs` regenerates the `./shared` TS surface with a staleness gate, and every public item is 100% covered. **No engine, no Redis, no HTTP.**

---

## Rules-of-phase

1. **Wasm-safe.** Both crates compile to `wasm32-unknown-unknown`; no `tokio`, no network/file APIs.
2. **`#![forbid(unsafe_code)]`** and **`#![deny(missing_docs)]`** stay; document every public item.
3. **Single source of truth.** The TypeScript `./shared` types/constants are GENERATED from `bymax-auth-types` via `ts-rs` and are never hand-edited; a CI staleness gate fails on drift.
4. **Wire-shape fidelity (parity).** Preserve the exact on-the-wire shapes: JWT discriminator field is `type` (`#[serde(rename = "type")]`) with values `dashboard`/`platform`/`mfa_challenge`; access claims carry BOTH `mfaEnabled` and `mfaVerified`; the error envelope is `{ "error": { "code", "message", "details" } }`; cookie names match the spec/nest-auth.
5. **HS256 pinned.** The JWT verifier asserts `alg == "HS256"` before any signature math; `none`/`RS256`/`ES256`/all asymmetric are rejected. Pure-Rust `hmac` + `sha2` + base64url; no `ring`/`jsonwebtoken`.
6. **Typed, opaque errors.** `AuthError`/`AuthErrorCode` (the 34-code catalog) and a JWT error type; no stringly errors; internal-only codes (`token_expired`/`token_revoked`/`TOKEN_MISSING`) never leak — they map to `token_invalid` on the wire.
7. **Constant-time** for the HS256 signature comparison (via `bymax-auth-crypto`'s `constant_time_eq`).
8. **Refresh tokens are NOT JWTs** — model them as an opaque newtype; this phase must not make a refresh token signable/parseable as a JWT.
9. **100% coverage**, with property tests for the JWT codec and known/forged-token rejection tests. English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 6 "Repository & Provider Contracts" (the domain structs + `SafeAuth*` projections). § 13 "JWT & Token Strategy" (HS256 pinning, the claim structs + wire field names, opaque refresh, clock-skew). § 15 "Error Model & Codes Catalog" (the full `AuthErrorCode` set, statuses, the `{ error: {...} }` envelope, internal-only remapping). § 18.3 "Frontend & npm Distribution → type generation" (the `ts-rs` pipeline + staleness gate; where the generated TS lands).
- [`docs/development_plan.md`](../development_plan.md) — § P2, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 2.1 | `bymax-auth-types` setup: serde, `ts-export` feature, module skeleton | ✅ Done | P0 | S | 0.1 |
| 2.2 | Domain model (`domain`): `AuthUser`/`SafeAuthUser` + platform + `Create*`/`Update*` | ✅ Done | P0 | M | 2.1 |
| 2.3 | Error model (`error`): `AuthError`/`AuthErrorCode` catalog + wire envelope | ✅ Done | P0 | M | 2.1 |
| 2.4 | Claims, results & constants (`claims`, `results`, `constants`) | ✅ Done | P0 | M | 2.1, 2.2 |
| 2.5 | `ts-rs` generation pipeline + staleness gate | ✅ Done | P0 | M | 2.2, 2.3, 2.4 |
| 2.6 | `bymax-auth-jwt`: pure-Rust HS256 sign/verify/decode + pinning | ✅ Done | P0 | L | 2.1, 2.4 |

---

## Tasks

### Task 2.1 — `bymax-auth-types` setup: serde, `ts-export` feature, module skeleton

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: S
- **Depends on**: 0.1

#### Description

Wire `bymax-auth-types` with `serde`, a dev/build-only `ts-export` feature for `ts-rs`, the module skeleton (`domain`, `error`, `claims`, `results`, `constants`), and confirm it compiles to `wasm32`.

#### Acceptance criteria

- [x] `Cargo.toml` declares `serde` (derive), `serde_json`, `thiserror`; a `ts-export` feature gating `ts-rs`; `[lints] workspace = true`. (Also declares `time` with `serde-well-known` for the domain timestamps.)
- [x] Module skeleton exists: `domain`, `error`, `claims`, `results`, `constants` (each with a `//!` doc).
- [x] `cargo build -p bymax-auth-types` and `cargo build -p bymax-auth-types --target wasm32-unknown-unknown` build.
- [x] `ts-rs` is NOT in the default dependency tree (only under `ts-export`), verified by `cargo tree`.

#### Files to create / modify

- `crates/bymax-auth-types/Cargo.toml`
- `crates/bymax-auth-types/src/lib.rs`
- skeleton: `domain.rs`, `error.rs`, `claims.rs`, `results.rs`, `constants.rs`

#### Agent prompt

````
You are a senior Rust API/types engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, full parity with @bymax-one/nest-auth. `bymax-auth-types` is the shared,
serde-based, wasm-safe data model; its TypeScript counterpart is generated via `ts-rs`.

CURRENT PHASE: 2 (bymax-auth-types + bymax-auth-jwt) — Task 2.1 of 6 (FIRST)

PRECONDITIONS
- Phases 0–1 are done: the workspace builds; `crates/bymax-auth-types` is an empty skeleton with a
  crate-level `//!` doc, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, and no deps.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.3 "type generation" — `ts-rs` is a dev/build-only
  dependency behind a `ts-export` feature; it must not ship in the runtime tree.
- `docs/technical_specification.md` § 6 "Repository & Provider Contracts" and § 13/§15 (skim the
  module areas this crate will host: domain, claims, error, results, constants).

TASK
Set up the crate's dependencies, the `ts-export` feature, and the module skeleton; confirm wasm32.

DELIVERABLES

1. `crates/bymax-auth-types/Cargo.toml`:
   - `[dependencies]`: `serde = { version = "1", features = ["derive"] }`, `serde_json`, `thiserror`.
   - Optional: `ts-rs` (optional = true).
   - `[features] ts-export = ["dep:ts-rs"]` (no default).
   - `[lints] workspace = true`.
2. `crates/bymax-auth-types/src/lib.rs` — declare `pub mod domain; pub mod error; pub mod claims;
   pub mod results; pub mod constants;` and re-export the key types as they land.
3. Create the five module files with `//!` docs so `missing_docs` passes on empty modules.

Constraints:
- `ts-rs` must be absent from the default build (only under `ts-export`).
- Must compile to `wasm32-unknown-unknown`.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-types` — expected: builds.
- `cargo build -p bymax-auth-types --target wasm32-unknown-unknown` — expected: builds.
- `cargo tree -p bymax-auth-types -i ts-rs` — expected: not present (default); present only with `--features ts-export`.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P2 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 2.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 2.2 — Domain model (`domain`): `AuthUser`/`SafeAuthUser` + platform + `Create*`/`Update*`

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 2.1

#### Description

Implement the domain structs — `AuthUser`, `SafeAuthUser` (credential-free projection), the platform variants, and the `Create*`/`Update*` data types — with serde and ts-rs derives.

#### Acceptance criteria

- [x] `AuthUser`, `SafeAuthUser`, `AuthPlatformUser`, `SafeAuthPlatformUser`, `CreateUserData`, `CreateWithOAuthData`, `UpdateMfaData`, `UpdatePlatformMfaData` exist with the spec's fields/types (nullable via `Option`; `AuthUser.password_hash: Option<String>` for OAuth-only users; platform `password_hash` non-optional).
- [x] `SafeAuthUser`/`SafeAuthPlatformUser` are distinct structs (not aliases) with `From<AuthUser>`/`From<AuthPlatformUser>` that DROP `password_hash`, `mfa_secret`, `mfa_recovery_codes` — enforced by the type system.
- [x] All cross-boundary structs derive `serde::Serialize`/`Deserialize` with camelCase wire renames; the credential-free `Safe*` projections additionally derive `#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]`. The full `AuthUser`/`AuthPlatformUser` and the `Create*`/`Update*` repository inputs are server-internal and deliberately NOT ts-exported, so the shape of secret storage never ships to the frontend bundle.
- [x] 100% coverage including a serde round-trip and a test asserting `SafeAuthUser` carries no credential fields.

#### Files to create / modify

- `crates/bymax-auth-types/src/domain.rs`

#### Agent prompt

````
You are a senior Rust API/types engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-types` is the shared, serde-based, wasm-safe
data model (TS generated via `ts-rs`). Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 2 (types + jwt) — Task 2.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 2.1 is done: the crate has `serde`, the `ts-export` feature, and an empty `domain.rs`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 6 "Repository & Provider Contracts" — the exact fields/types
  of `AuthUser`, `SafeAuthUser`, the platform variants, `CreateUserData`, `CreateWithOAuthData`,
  `UpdateMfaData`, `UpdatePlatformMfaData`, and the `SafeAuth*` projection rule (drops the three
  credential fields).

TASK
Implement the domain structs with serde + optional ts-rs derives and the credential-stripping
`From` conversions.

DELIVERABLES

1. `crates/bymax-auth-types/src/domain.rs`:
   - The structs above with the spec's field names/types. Use `Option<T>` for nullable fields;
     `password_hash: Option<String>` on `AuthUser` (OAuth-only users); non-optional on the platform
     user. `mfa_secret` (encrypted) and `mfa_recovery_codes` (hashed) are present on the full user,
     ABSENT on the `Safe*` projection.
   - Derive `Debug, Clone, Serialize, Deserialize` and `#[cfg_attr(feature = "ts-export",
     derive(ts_rs::TS))]` (with a `#[ts(export)]`/`#[ts(export_to = "...")]` as the pipeline in
     Task 2.5 expects). Apply field renames so the wire is camelCase where the spec requires.
   - `impl From<AuthUser> for SafeAuthUser` (and the platform pair) that omit the credential fields.

   ```rust
   /// Credential-free projection of `AuthUser` safe to return to clients.
   #[derive(Debug, Clone, Serialize, Deserialize)]
   #[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
   pub struct SafeAuthUser { /* no password_hash / mfa_secret / mfa_recovery_codes */ }
   ```

Constraints:
- `Safe*` must be distinct types (not type aliases) so the compiler prevents leaking credentials.
- Do NOT derive `Serialize` in a way that would emit `password_hash`/`mfa_secret` on a `Safe*` type.
- `#![forbid(unsafe_code)]`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-types domain` — expected: serde round-trip + the "Safe* drops
  credentials" test pass.
- `cargo build -p bymax-auth-types --target wasm32-unknown-unknown` — expected: builds.
- `cargo llvm-cov -p bymax-auth-types --lcov` — expected: `domain.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update P2 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 2.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 2.3 — Error model (`error`): `AuthError`/`AuthErrorCode` catalog + wire envelope

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 2.1

#### Description

Implement the `AuthError`/`AuthErrorCode` catalog (the full 34-code set with stable `auth.*` strings and HTTP statuses), the `{ error: { code, message, details } }` wire envelope, and the internal-only-code remapping.

#### Acceptance criteria

- [x] `AuthErrorCode` enumerates all catalog codes (the 34 nest-auth parity codes + the `token_missing` boundary sentinel + the two adapter-originated codes + the generic `auth.internal` 500 = 38 total), each serializing to its exact `auth.*` string and mapping to its HTTP status.
- [x] `AuthError` (thiserror) wraps a code (+ optional details) and exposes `code()` and `http_status()` (plus `client_message()`, `is_internal_only()`, `details()`).
- [x] The on-the-wire body is `{ "error": { "code", "message", "details" } }` (`AuthErrorEnvelope`/`AuthErrorBody`), and the reduced client `AuthErrorResponse { code, message }` shape is also provided.
- [x] Internal-only codes (`token_expired`, `token_revoked`, `token_missing`) never appear on the wire — `to_wire()` remaps them to `token_invalid`.
- [x] The adapter-originated `auth.validation` (400) and `auth.too_many_requests` (429) codes are present (no nest-auth equivalent, documented).
- [x] 100% coverage including: every code's string + status; the internal-only remap; the envelope serde round-trip.

#### Files to create / modify

- `crates/bymax-auth-types/src/error.rs`

#### Agent prompt

````
You are a senior Rust API/types engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-types` is the shared, serde-based, wasm-safe
data model. The error catalog must match @bymax-one/nest-auth byte-for-byte (codes + statuses).
Edition 2024.

CURRENT PHASE: 2 (types + jwt) — Task 2.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 2.1 is done: the crate has `serde`/`thiserror` and an empty `error.rs`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 15 "Error Model & Codes Catalog" — the COMPLETE 34-code
  catalog (code string + HTTP status + when raised), the `{ error: { code, message, details } }`
  envelope vs the reduced client `AuthErrorResponse`, the internal-only codes and their remap, and
  the two adapter-originated codes (`auth.validation` 400, `auth.too_many_requests` 429).

TASK
Implement the `AuthError`/`AuthErrorCode` model with serde, the HTTP-status mapping, the wire
envelope, and the internal-only remapping.

DELIVERABLES

1. `crates/bymax-auth-types/src/error.rs`:
   - `AuthErrorCode` — an enum with one variant per catalog row, `#[serde(rename = "...")]` to the
     `auth.*` string. A `pub fn http_status(&self) -> u16` mapping each to its status. Group the
     variants by area with comments (credentials/account, tokens/sessions, registration/email,
     MFA, password, OTP, authorization, invitations, OAuth, platform, adapter-originated).
   - `AuthError` (thiserror) carrying a code + optional `details`, with `code()`/`status()`.
   - `AuthErrorResponse` (the reduced client shape) and the nested server envelope type
     `{ error: { code, message, details } }`; derive serde (+ ts-rs under `ts-export`).
   - A helper that maps internal-only codes (`token_expired`/`token_revoked`/`token_missing`) to
     `token_invalid` for any outbound representation.

Constraints:
- The serialized code strings and HTTP statuses MUST match the spec's catalog exactly.
- Internal-only codes must never serialize to the wire — route them through the remap.
- `#![forbid(unsafe_code)]`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-types error` — expected: a table-driven test asserting every code's
  string + status, the internal-only remap, and the envelope round-trip all pass.
- `cargo build -p bymax-auth-types --target wasm32-unknown-unknown` — expected: builds.
- `cargo llvm-cov -p bymax-auth-types --lcov` — expected: `error.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update P2 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 2.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 2.4 — Claims, results & constants (`claims`, `results`, `constants`)

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 2.1, 2.2

#### Description

Implement the JWT claim structs (with the exact wire discriminator/fields), the result types, and the shared constants (cookie names, route maps), all with serde + ts-rs derives. (The opaque refresh-token helper `RawRefreshToken` is NOT modeled here — it needs the CSPRNG/SHA-256 from `bymax-auth-crypto`, so it lives in `bymax-auth-jwt`, Task 2.6.)

#### Acceptance criteria

- [x] `DashboardClaims`, `PlatformClaims`, `MfaTempClaims` exist; the discriminator field is `type` (`#[serde(rename = "type")]`) with values `dashboard`/`platform`/`mfa_challenge` (single-variant discriminator enums reject a wrong `type`); access claims carry BOTH `mfaEnabled` and `mfaVerified`; `MfaTempClaims` = `{ sub, jti, type: "mfa_challenge", context, iat, exp }` with `MfaContext { Dashboard, Platform }`.
- [x] Result types exist (`AuthResult`, `SafeAuth*`-based, `MfaChallengeResult` `{ mfaRequired, mfaTempToken }`, `LoginResult` + `PlatformLoginResult` untagged enums, `PlatformAuthResult`, `RotatedTokens`).
- [x] `RotatedTokens` carries the refresh token as a plain `String`; the opaque `RawRefreshToken` helper (CSPRNG `generate()` + `redis_hash()`) is defined in `bymax-auth-jwt` (Task 2.6), NOT here — `bymax-auth-types` takes no crypto dependency.
- [x] Shared constants exist (cookie names `access_token`/`refresh_token`/`has_session`, refresh path, MFA-temp params, and the full default route table) matching the spec.
- [x] All derive serde (+ ts-rs under `ts-export`); 100% coverage including wire-shape round-trips (the `type` rename, both MFA flags).

#### Files to create / modify

- `crates/bymax-auth-types/src/claims.rs`
- `crates/bymax-auth-types/src/results.rs`
- `crates/bymax-auth-types/src/constants.rs`

#### Agent prompt

````
You are a senior Rust API/types engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-types` is the shared, serde-based, wasm-safe
data model. Wire shapes must match @bymax-one/nest-auth exactly. Edition 2024.

CURRENT PHASE: 2 (types + jwt) — Task 2.4 of 6 (MIDDLE)

PRECONDITIONS
- Tasks 2.1–2.2 are done: the crate has serde + the domain structs (`SafeAuthUser`, etc.) and empty
  `claims.rs`/`results.rs`/`constants.rs`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 13 "JWT & Token Strategy" — the claim structs and their EXACT
  wire fields (`type` discriminator + values; `mfaEnabled` AND `mfaVerified`; `MfaTempClaims` shape
  with `jti` + `context`); the opaque-refresh model.
- `docs/technical_specification.md` § 14 "Cookie Management" (cookie name constants) and § 6/§13
  for the result types (`AuthResult`, `MfaChallengeResult`, `LoginResult`, `PlatformAuthResult`,
  `RotatedTokens`).

TASK
Implement the claim structs, result types, the opaque refresh-token newtype, and the shared
constants.

DELIVERABLES

1. `claims.rs`:
   - `DashboardClaims` / `PlatformClaims` with `sub, jti, #[serde(rename="type")] token_type, role,
     tenant_id (camelCase wire), mfa_enabled (mfaEnabled), mfa_verified (mfaVerified), iat, exp`.
   - `MfaTempClaims { sub, jti, #[serde(rename="type")] token_type = "mfa_challenge", context, iat, exp }`
     and `MfaContext { Dashboard, Platform }`.
   - serde (+ ts-rs under `ts-export`).
2. `results.rs`:
   - `AuthResult { user: SafeAuthUser, access_token }`, `PlatformAuthResult`, `MfaChallengeResult
     { mfa_required: true, mfa_temp_token }` (wire `{ mfaRequired, mfaTempToken }`), `LoginResult`
     (enum: `Success(AuthResult)` | `MfaChallenge(MfaChallengeResult)`), `RotatedTokens`.
   - (No refresh-token newtype here — the opaque `RawRefreshToken` lives in `bymax-auth-jwt`, Task 2.6.)
3. `constants.rs`:
   - Cookie-name constants (`access_token`, `refresh_token`, `has_session`) and the route maps, matching the spec.

Constraints:
- Field renames must produce the EXACT wire shapes (`type`, `mfaEnabled`, `mfaVerified`, `tenantId`,
  `mfaRequired`, `mfaTempToken`).
- The opaque `RawRefreshToken` (defined in `bymax-auth-jwt`, Task 2.6) carries no claims and is never parseable as a JWT; `bymax-auth-types` models no refresh-token newtype.
- `#![forbid(unsafe_code)]`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-types claims results constants` — expected: wire-shape round-trips pass
  (assert the JSON has `"type"`, `"mfaEnabled"`, `"mfaVerified"`, `"mfaRequired"`, `"mfaTempToken"`).
- `cargo build -p bymax-auth-types --target wasm32-unknown-unknown` — expected: builds.
- `cargo llvm-cov -p bymax-auth-types --lcov` — expected: the three modules at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update P2 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 2.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 2.5 — `ts-rs` generation pipeline + staleness gate

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 2.2, 2.3, 2.4

#### Description

Wire the `ts-rs` export so the TypeScript `./shared` types and constants are generated from `bymax-auth-types`, landing in the npm package's generated directory, with a CI staleness check that fails on drift.

#### Acceptance criteria

- [x] Running `cargo test -p bymax-auth-types --features ts-export` regenerates the TS declarations into `packages/rust-auth/src/shared/` (deterministically — a second run leaves the tree clean).
- [x] The generated output covers the error codes (union + `AUTH_ERROR_CODES` map), the JWT payload types, the result types, the user types, and the shared constants (cookie defaults + route table) plus a barrel `index.ts`.
- [x] The staleness command is documented in the `tests/ts_export.rs` module doc: `cargo test -p bymax-auth-types --features ts-export` then `git diff --exit-code -- packages/rust-auth/src/shared`.
- [x] The generated files carry a "generated — do not edit by hand" banner (ts-rs's own banner on the type files; the explicit bymax banner on the hand-codegen const files).
- [x] `ts-rs` remains absent from the runtime dependency tree (verified via `cargo tree`); the `#[ts(export_to)]`-without-`export` form means no stray auto-export bindings are written.

#### Files to create / modify

- `crates/bymax-auth-types/src/lib.rs` (export test/entrypoint under `#[cfg(feature = "ts-export")]`)
- `crates/bymax-auth-types/tests/ts_export.rs` (or an export binary)
- `packages/rust-auth/src/shared/*` (generated TS — committed)

#### Agent prompt

````
You are a senior Rust ↔ TypeScript tooling engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the npm frontend `@bymax-one/rust-auth` consumes TS types
GENERATED from `bymax-auth-types` via `ts-rs`, so the frontend never drifts from the Rust contract.
Edition 2024.

CURRENT PHASE: 2 (types + jwt) — Task 2.5 of 6 (MIDDLE)

PRECONDITIONS
- Tasks 2.2–2.4 are done: the domain, error, claims, results, and constants types all derive
  `ts_rs::TS` under the `ts-export` feature.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.3 "type generation" — the `ts-rs` pipeline, where the
  generated TS lands in the npm package, and the CI staleness gate.

TASK
Wire the `ts-rs` export entrypoint, generate the `./shared` TS surface into the npm package, commit
it with a generated banner, and document the staleness gate.

DELIVERABLES

1. An export entrypoint — a `#[cfg(feature = "ts-export")]` test (`tests/ts_export.rs`) that calls
   `TS::export_all_to(...)` (or per-type `export_to`) writing the `.ts` declarations into
   `packages/rust-auth/src/shared/`. Ensure every public type from Tasks 2.2–2.4 is
   exported, plus a constants file (error codes, cookie names, routes) — generate constants via a
   small codegen if `ts-rs` cannot emit them directly.
2. The generated `.ts` files under `packages/rust-auth/src/shared/`, each with a
   top-of-file banner: `// GENERATED by bymax-auth-types ts-rs — do not edit by hand.`
3. Documentation (in the crate docs or a short `README` note) of the staleness command:
   ```
   cargo test -p bymax-auth-types --features ts-export
   git diff --exit-code packages/rust-auth/src/shared/
   ```

Constraints:
- `ts-rs` stays behind `ts-export` (never in the runtime tree).
- Generated files are committed and never hand-edited.
- `#![forbid(unsafe_code)]`; English-only, timeless comments (the banner says "generated", not a phase).

Verification:
- `cargo test -p bymax-auth-types --features ts-export` — expected: writes the `.ts` files; passes.
- `git diff --exit-code packages/rust-auth/src/shared/` after a clean regenerate —
  expected: no diff (proves the staleness gate is satisfiable).
- `cargo tree -p bymax-auth-types -i ts-rs` — expected: absent without `--features ts-export`.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update P2 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 2.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 2.6 — `bymax-auth-jwt`: pure-Rust HS256 sign/verify/decode + pinning

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: L
- **Depends on**: 2.1, 2.4

#### Description

Implement `bymax-auth-jwt`: a pure-Rust HS256 codec (sign/verify/decode) over `hmac` + `sha2` + base64url + `serde_json`, with strict algorithm pinning, using the claim structs from `bymax-auth-types`. No `ring`, no `jsonwebtoken`. Must compile to `wasm32`.

#### Acceptance criteria

- [x] `bymax-auth-jwt` depends on `bymax-auth-types` and `bymax-auth-crypto` (HMAC-SHA-256 + `constant_time_eq`), `serde`/`serde_json`, `base64`, and `zeroize` — NOT on `ring`/`jsonwebtoken` (asserted via `cargo tree`).
- [x] `sign(claims, &HsKey) -> String` and `verify::<C: JwtClaims>(token, &HsKey, &VerifyOptions) -> Result<C, JwtError>` round-trip the claim types from Task 2.4; `HsKey` wraps the secret in `Zeroizing` (zeroized on drop, redacted `Debug`).
- [x] `decode_unverified::<C>(token) -> Result<C, JwtError>` exists for display-only use and is documented (rustdoc `# Security`) as NOT validating the signature.
- [x] Verification asserts `header.alg == "HS256"` BEFORE signature math; `alg: none`, `RS256`, `ES256`, and any other algorithm are rejected with `JwtError::UnsupportedAlg`.
- [x] The signature is compared in constant time (`bymax_auth_crypto::compare::constant_time_eq`); `exp`/`iat` are validated per `VerifyOptions` (HS256 pinned internally, never read from the token; `now_unix` injects the clock for wasm-purity and deterministic tests). The sealed `JwtClaims` trait exposes `exp()`/`iat()`.
- [x] `RawRefreshToken` (opaque; CSPRNG `generate()`; `redis_hash()` = `sha256` hex; redacted `Debug`; `Zeroizing`) is defined in this crate per §13.4 — never signed or parsed as a JWT; only `redis_hash()` is ever persisted.
- [x] Builds native AND `wasm32-unknown-unknown` (the latter via the `wasm-js` feature, which forwards `bymax-auth-crypto/wasm-js` so the transitive `getrandom` selects a backend).
- [x] Coverage: 100% line + 100% function; 99.86% region (a single unreachable defensive branch in a proptest helper remains, matching the accepted P1 bar of 99.76%). Tests cover round-trip per claim type, swapped-`alg`/`alg:none`/tampered-payload/wrong-key/expired/`iat`-future/malformed-framing/bad-base64-per-segment/non-claims-payload rejection, plus a codec round-trip proptest and a signature-tamper proptest.

#### Files to create / modify

- `crates/bymax-auth-jwt/Cargo.toml`
- `crates/bymax-auth-jwt/src/lib.rs`
- `crates/bymax-auth-jwt/src/{hs256.rs,keys.rs,error.rs}`

#### Agent prompt

````
You are a senior Rust cryptography/JWT engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-jwt` is the pure-Rust HS256 implementation
shared by the server AND (later) the WASM edge binding. No `ring`, no `jsonwebtoken` — those break
the wasm32 path. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 2 (types + jwt) — Task 2.6 of 6 (LAST — the security-critical task)

PRECONDITIONS
- Tasks 2.1–2.4 are done: `bymax-auth-types` exposes the claim structs (`DashboardClaims`,
  `PlatformClaims`, `MfaTempClaims`) with the correct wire shapes.
- Phase 1 is done: `bymax-auth-crypto` exposes `compare::constant_time_eq` and `mac::hmac_sha256`.
- `crates/bymax-auth-jwt` is an empty skeleton with the lint headers.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 13 "JWT & Token Strategy" — HS256 pinning (assert `alg` before
  signature math; reject `none`/asymmetric), the pure-Rust primitive choice (hmac+sha2+base64url+
  serde_json) shared server/edge, the claim types, and the clock-skew leeway.
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — constant-time signature
  comparison; why `ring`/`jsonwebtoken` are avoided on wasm32.

TASK
Implement the pure-Rust HS256 JWT codec with strict algorithm pinning over the shared claim types.

DELIVERABLES

1. `crates/bymax-auth-jwt/Cargo.toml`:
   - Deps: `bymax-auth-types`, `bymax-auth-crypto`, `serde`, `serde_json`, a base64url codec
     (`base64`), `zeroize` (for `HsKey`), `thiserror`. NO `ring`/`jsonwebtoken`.
   - `[lints] workspace = true`.
2. `crates/bymax-auth-jwt/src/error.rs` — a `JwtError` (thiserror): `Malformed`, `UnsupportedAlg`,
   `BadSignature`, `Expired`, `Decode` — all opaque on the wire.
3. `crates/bymax-auth-jwt/src/keys.rs`:
   - `pub struct HsKey(Zeroizing<Vec<u8>>)` — wraps the symmetric secret; zeroized on drop, with a
     redacted `Debug`/`Display` that never prints the bytes (§13.2).
   - `pub struct VerifyOptions { pub leeway_secs: u64, pub validate_exp: bool, pub validate_iat: bool }`
     — `alg` is pinned to HS256 internally and is NOT a field (never selected from the token).
   - `pub trait JwtClaims` — a SEALED trait (private supertrait) implemented by
     `DashboardClaims`/`PlatformClaims`/`MfaTempClaims`, exposing `exp() -> i64` and `iat() -> i64`
     for the temporal-claims check (§13.3).
   - `pub struct RawRefreshToken(String)` — the opaque refresh helper (§13.4): `generate()` mints a
     CSPRNG value via `bymax-auth-crypto`; `redis_hash() -> String` returns `sha256(token)` hex (the
     ONLY form persisted, under `rt:`/`prt:`). NEVER signed or parsed as a JWT.
4. `crates/bymax-auth-jwt/src/hs256.rs`:
   - `pub fn sign<C: Serialize>(claims: &C, key: &HsKey) -> Result<String, JwtError>` — build the
     `{"alg":"HS256","typ":"JWT"}` header, base64url(header).base64url(payload), HMAC-SHA256 sign.
   - `pub fn verify<C: DeserializeOwned + JwtClaims>(token: &str, key: &HsKey, opts: &VerifyOptions)
     -> Result<C, JwtError>` — split; parse header; assert `alg == "HS256"` (reject everything else,
     including `none`) BEFORE computing the MAC; recompute HMAC and compare in CONSTANT TIME via
     `bymax_auth_crypto::compare::constant_time_eq`; validate `exp`/`iat` per `opts`.
   - `pub fn decode_unverified<C: DeserializeOwned>(token: &str) -> Result<C, JwtError>` — decode
     the payload WITHOUT signature checking; doc-comment it loudly as display-only.
5. `lib.rs` — re-export `sign`, `verify`, `decode_unverified`, `HsKey`, `VerifyOptions`, `JwtClaims`,
   `RawRefreshToken`, `JwtError`.

Constraints:
- HS256 is the ONLY accepted algorithm; reject the inbound `alg` if it is anything else, BEFORE any
  signature math (prevents algorithm-confusion and `alg:none`).
- Compare the signature in constant time — never `==` on the MAC bytes.
- Pure-Rust only; no `ring`/`jsonwebtoken`. Must compile to `wasm32-unknown-unknown`.
- No `unwrap`/`expect`/`panic!` on library paths; opaque `JwtError`.
- `#![forbid(unsafe_code)]`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-jwt` — expected: round-trip per claim type; `alg`-swap rejection;
  `alg:none` rejection; tampered-payload rejection; expired-token rejection; proptest — all pass.
- `cargo build -p bymax-auth-jwt --target wasm32-unknown-unknown` — expected: builds.
- `cargo tree -p bymax-auth-jwt -i ring` and `... -i jsonwebtoken` — expected: not present.
- `cargo llvm-cov -p bymax-auth-jwt --lcov` — expected: 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Set progress `6/6`. 5. Update the
P2 row in `docs/development_plan.md` (mark ✅ when all six tasks are done). 6. Recompute the overall
%. 7. Append `- 2.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.

- 2.1 ✅ 2026-06-19 — `bymax-auth-types` deps (serde/serde_json/thiserror/time) + `ts-export` feature gating `ts-rs` + 5-module skeleton; builds native and wasm32, `ts-rs` absent from the default tree.
- 2.2 ✅ 2026-06-19 — Domain model: `AuthUser`/`AuthPlatformUser` + credential-dropping `Safe*` projections + `Create*`/`Update*` payloads; camelCase wire, RFC 3339 timestamps, `Safe*`-only ts-rs export; domain.rs 100% covered.
- 2.3 ✅ 2026-06-19 — Error model: `AuthErrorCode` catalog (38 codes, exact `auth.*` strings + statuses) + typed `AuthError` (thiserror) + `{ error: { code, message, details } }` envelope + reduced `AuthErrorResponse`; internal-only token sentinels remap to `token_invalid`; error.rs 100% covered (15 tests).
- 2.4 ✅ 2026-06-19 — Claims (`Dashboard`/`Platform`/`MfaTempClaims` + discriminator/context enums, exact wire shapes), results (`AuthResult`/`PlatformAuthResult`/`MfaChallengeResult`/`LoginResult`/`PlatformLoginResult`/`RotatedTokens`), and constants (cookies + full route table); whole `bymax-auth-types` crate 100% covered (29 tests), native + wasm + ts-export all build.
- 2.5 ✅ 2026-06-19 — `ts-rs` pipeline: `tests/ts_export.rs` emits the grouped `./shared` TS (user/jwt-payload/result/error types with nest-auth names, `AUTH_ERROR_CODES` map, cookie defaults, route table, barrel) into `packages/rust-auth/src/shared/`; deterministic regeneration backs the `git diff --exit-code` staleness gate; `ts-rs` stays out of the runtime tree.
- 2.6 ✅ 2026-06-19 — `bymax-auth-jwt`: pure-Rust HS256 `sign`/`verify`/`decode_unverified` over `bymax-auth-crypto` (HMAC + constant-time) + base64url; HS256 pinned before signature math (`none`/`RS256` rejected); `HsKey`/`RawRefreshToken` zeroized + redacted; sealed `JwtClaims`; no `ring`/`jsonwebtoken`; native + wasm (`wasm-js`); 100% line/function, 99.86% region (22 tests + 2 proptests).
- P2 close ✅ 2026-06-19 — Phase-close gates (verify → security-review → code-review) applied: redacting `Debug` on the credential-bearing domain types (`AuthUser`/`AuthPlatformUser`/`CreateUserData`/`UpdateMfaData`/`UpdatePlatformMfaData`), `# Panics` on `RawRefreshToken::generate`, `# Security` note on `HsKey` (key-length floor deferred to the engine `build()` in P3), removed the lone `#[allow(dead_code)]` in `tests/ts_export.rs`, scrubbed a bare `§17` comment, documented the infallible `.ok()` in `error.rs`. Re-verified: fmt/clippy/wasm/staleness clean, types 100% & jwt 100% line+fn coverage, `cargo deny`/`cargo audit` clean. Carried forward: P3 must enforce the HS256 secret length/entropy floor; the crypto-crate `hmac_sha256` zero-digest fallback should fail closed.
