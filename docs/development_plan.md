# Development Plan — rust-auth

> Source specification: [`docs/technical_specification.md`](./technical_specification.md) (25 sections)
> Last updated: 2026-06-19

This document is Layer 2 of the spec → roadmap → phase-tasks workflow. It decomposes the technical specification into an ordered set of delivery phases with explicit dependencies, a status dashboard, and a definition of done per phase. It does not restate the specification; it sequences the work and defines how progress is tracked. Per-task breakdowns are produced separately in Layer 3.

## Status legend

| Symbol | Meaning |
| --- | --- |
| 📋 | ToDo |
| 🔄 | In Progress |
| 👀 | Review |
| ✅ | Done |
| ⛔ | Blocked |
| 🟡 | Partial |

## Progress

- **Overall progress:** 🔄 5 / 13 phases done (38%)
- **Active phase:** **P5** (`bymax-auth-redis` — stores + Lua + WS ticket) 📋 ready to start, unblocked since **P3** is ✅ Done (independent of P4)
- **Blocked:** —

## Phase dashboard

| ID | Phase | Status | Progress | Size | Last updated |
| --- | --- | --- | --- | --- | --- |
| P0 | Foundation: workspace, toolchain & CI skeleton | ✅ Done | 6/6 | M | 2026-06-17 |
| P1 | `bymax-auth-crypto` — hashing, constant-time, tokens, MFA-gated AEAD/TOTP | ✅ Done | 6/6 | L | 2026-06-18 |
| P2 | `bymax-auth-types` + `bymax-auth-jwt` — model, errors, HS256, ts-rs | ✅ Done | 6/6 | L | 2026-06-19 |
| P3 | `bymax-auth-core` — engine, builder, config profiles, trait set | ✅ Done | 6/6 | L | 2026-06-19 |
| P4 | Local auth flows + password + brute-force + session-fixation | ✅ Done | 7/7 | L | 2026-06-19 |
| P5 | `bymax-auth-redis` — stores + Lua + WS ticket (E2E Redis) | 📋 ToDo | — | M | — |
| P6 | Sessions, OTP, password reset, email verification, invitations | 📋 ToDo | — | L | — |
| P7 | MFA (TOTP) end-to-end | 📋 ToDo | — | L | — |
| P8 | OAuth — `HttpClient` trait + Google + PKCE/state + linking | 📋 ToDo | — | L | — |
| P9 | Platform admin identity domain | 📋 ToDo | — | M | — |
| P10 | `bymax-auth-axum` — router, extractors, delivery, rate-limit, WS, validation (E2E) | 📋 ToDo | — | L | — |
| P11 | `bymax-auth-wasm` + `@bymax-one/rust-auth` (npm) + Rust client | 📋 ToDo | — | L | — |
| P12 | Release engineering, supply-chain, docs, examples, dogfood | 📋 ToDo | — | L | — |

## Dependency graph

The graph below is a directed acyclic graph: an edge `X → Y` means phase `X` must complete before phase `Y` can begin.

**How to read it.** Flow runs top to bottom. The drawn lines illustrate the dominant flow; the bracketed list after each node is the **authoritative, complete set of that node's direct prerequisites**. Any edge not drawn as a line is captured in a bracket.

```text
                        P0
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
            P1                      P2
            │                       │
            └───────────┬───────────┘
                        ▼
                        P3   [P1, P2]
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
            P4                      P5
            │                       │
            │                 ┌─────┴─────┐
            │                 ▼           ▼
            │                 P6          P7
            │              [P4, P5]   [P1, P4, P5]
            │                             │
            ├──▶ P8  [P4]                 │
            │                             ▼
            │                             P9   [P4, P7]
            │                             │
            └───────────┬─────────────────┘
                        ▼
                        P10  [P4, P6, P7, P8, P9]
                        │
                        ▼
                        P11  [P2, P10]
                        │
                        ▼
                        P12  [all phases P0–P11]
```

Edge list (canonical): `P0→P1`, `P0→P2`, `P1→P3`, `P2→P3`, `P3→P4`, `P3→P5`, `P4→P6`, `P5→P6`, `P4→P7`, `P5→P7`, `P1→P7`, `P4→P8`, `P4→P9`, `P7→P9`, `{P4,P6,P7,P8,P9}→P10`, `P2→P11`, `P10→P11`, `{all}→P12`.

## Parallelization notes

- **After P0**, the two leaf libraries are independent: **P1 ∥ P2** can proceed in parallel (crypto vs. types/JWT).
- **P3** is the first convergence point — it requires both P1 and P2 — and is the gateway to all flow work.
- **After P3**, **P4 and P5 overlap**: P5 (`bymax-auth-redis`) depends only on the trait definitions and shared value types surfaced by P3, so it can be built against those contracts while P4 implements the local auth flows.
- **After P4 + P5**, the flow phases **P6, P7, and P8 run in parallel** (sessions/OTP/reset/verification/invitations; MFA; OAuth) — each consumes the engine, the local flows, and the Redis stores but not one another.
- **P9** (platform admin identity) **follows P7**, since platform authentication reuses the MFA path in addition to the local-auth foundation from P4.
- **P10** (`bymax-auth-axum`) is the second convergence point: it **integrates the flow phases** — P4, P6, P7, P8, and P9 — into the HTTP adapter with extractors, delivery, rate-limiting, WebSocket tickets, and validation, validated end-to-end.
- **P11** is split: the **WASM half** (`bymax-auth-wasm`) needs only **P2** and can therefore start early, in parallel with the flow phases; the **frontend-client half** (`@bymax-one/rust-auth` npm package and Rust client) needs **P10** before it can integrate against the finished HTTP surface.
- **P12** (release engineering, supply-chain, docs, examples, dogfood) is **last** — it depends on every prior phase.

**Critical path:** `P0 → P1/P2 → P3 → P4/P5 → P7 → P9 → P10 → P11 → P12` (9 phases). P6 and P8 are depth-5 branches that feed P10 but do not lie on the longest chain; note P9's prerequisites are `[P4, P7]` (not P6), and P7 depends on P5 — both reflected above.

## Global conventions

These rules derive from the specification (notably §3.8, §4, §17, §19, §21, §24) and the Bymax engineering standards. Every phase respects them; per-phase Definitions of Done assume them as a baseline rather than restating them.

| Area | Rule |
| --- | --- |
| Workspace | Single Cargo workspace; Rust **edition 2024**; MSRV pinned via `rust-toolchain.toml` and `[workspace.package] rust-version`, enforced by a dedicated MSRV build job in CI. |
| Safety | `#![forbid(unsafe_code)]` on every first-party crate — the **sole exception** is `bymax-auth-wasm`, whose `wasm-bindgen` glue confines generated `unsafe` to the bindgen boundary under `#![deny(unsafe_op_in_unsafe_fn)]`. `#![deny(missing_docs)]` on all public crates. |
| Lint / format | `cargo fmt --check` and `cargo clippy -D warnings` are clean and CI-gating across the workspace. |
| Errors | Typed errors only (`AuthError` / `ConfigError` / `RepositoryError`); no stringly-typed errors. No `unwrap` / `expect` / `panic!` on library code paths; fallible items document their error conditions. |
| API design | Follows the Rust API Guidelines: builders for complex construction, strong/named types over boolean traps and magic strings, runnable rustdoc examples (compiled as doctests) on public items. Public surface snapshotted (`cargo public-api`) and semver-checked (`cargo-semver-checks`). |
| Tests | 100% line coverage via `cargo-llvm-cov` as a hard gate; each test documents its scenario; mutation testing (`cargo-mutants`) near-100% as a pre-release gate; fuzz / property tests for parsers; E2E tests for Axum + Redis using testcontainers; a mandatory `wasm32-unknown-unknown` build test; feature-combination matrix via `cargo-hack`; a `ts-rs` staleness gate; Criterion benchmarks (tracked, non-gating). |
| Dependencies | Minimal-footprint premise: a tiny always-compiled core; every heavy integration is feature-gated or trait-pluggable. Supply chain gated by `cargo-deny` (ban-list + licenses + advisories + sources), `cargo-audit`, and `cargo-vet`; `cargo-geiger` scans transitive `unsafe` (non-blocking, reviewed on jumps). Per-feature `cargo tree` assertions enforce the "pay only for what you use" premise. |
| Features | `default = ["scrypt"]`; one feature per capability — taxonomy `argon2` / `sessions` / `mfa` / `oauth` / `oauth-reqwest` / `platform` / `invitations` / `redis` / `axum` / `client`. No `core` feature (the core crate is non-optional). At least one hasher feature is required (a `compile_error!` fires if neither `scrypt` nor `argon2` is enabled). Features are strictly additive. |
| Security | HS256 pinned (no algorithm agility); refresh tokens are opaque; all secret comparisons are constant-time; secrets are never logged (wrapped in `secrecy`); tokens never travel in a query string. The §24 Security Invariants are CI-enforced. |
| Frontend | TypeScript `strict`; the `@bymax-one/rust-auth` package exposes subpaths (`./shared`, `./nextjs`, `./client`, `./react`); the `./shared` types and constants are generated from Rust via `ts-rs` and are never hand-edited; native `fetch` with single-flight refresh; React 19 / Next 16 as peer dependencies; dual ESM + CJS output; API docs via TypeDoc. |
| Commits | Conventional Commits, enforced by commitlint + husky; English only; source comments are timeless (no plan/phase/task references). |
| Publishing | Backend to crates.io (the facade `bymax-auth` plus `crates/*` only) and frontend to npm (`@bymax-one/rust-auth`), both via OIDC Trusted Publishing with provenance. `Cargo.lock` is committed. |

## Update protocol

When a phase changes state, apply the following steps so the dashboard, the progress counters, and the per-phase Definitions of Done stay consistent:

1. Set the phase row's **Status** emoji and **Last updated** date in the phase dashboard.
2. Recompute **Overall progress** as `N / 13` phases done and the corresponding percentage.
3. Update **Active phase** and **Blocked** in the Progress section to reflect what is in flight and what is stalled.
4. When a phase reaches ✅, confirm that every bullet of its **Definition of Done** in the "Phase details" section below is fully met.
5. Commit the plan update with a `docs(plan):` Conventional Commit.
6. Never mark a phase ✅ while any Definition-of-Done bullet is unmet — use 🟡 Partial until all bullets are satisfied.

## Phase details
## Phase Details — P0 through P6

This section is the authoritative per-phase contract for the foundation and core-engine
band of the build. Each phase below names the crates, modules, and file paths it owns,
the work it explicitly defers, and the observable conditions under which it is "done".
Workspace-wide conventions (100% line/branch/region coverage as a hard gate, `#![forbid(unsafe_code)]`
+ `#![deny(missing_docs)]` on every own crate, RustCrypto-only crypto, Conventional Commits,
timeless comments with no plan/phase references in committed files, and no placeholder
`.gitkeep` files) are stated once in the global conventions and are **not** repeated per phase —
each "Rules of phase" entry calls out only the conventions that bite specifically there.

---

### P0 — Foundation: workspace, toolchain & CI skeleton

**Goal:** Stand up the Cargo workspace, every crate skeleton, the pinned toolchain, the
CI gate, and supply-chain scaffolding so all later phases build on green, reproducible infrastructure.

**Scope — In**
- Workspace root `Cargo.toml` — `[workspace]` with `resolver = "3"`, a shared `[workspace.dependencies]` table, and `[workspace.package]` carrying `edition = "2024"` + a pinned `rust-version` (MSRV) inherited by all members; `Cargo.lock` committed.
- Library crate skeletons under `crates/`: `bymax-auth` (facade), `bymax-auth-types`, `bymax-auth-crypto`, `bymax-auth-jwt`, `bymax-auth-core`, `bymax-auth-redis`, `bymax-auth-axum`, `bymax-auth-client` — each a compiling empty stub with its lib header.
- WASM binding skeleton `bindings/bymax-auth-wasm` (`crate-type = ["cdylib"]`) and the npm package skeleton `packages/rust-auth` (directory + `package.json` `exports` map placeholder for `./shared` `./client` `./react` `./nextjs`); optional `xtask/` dev-automation bin shell.
- `rust-toolchain.toml` pinning the stable channel, components (`rustfmt`, `clippy`, `llvm-tools-preview`), the `wasm32-unknown-unknown` target, and `profile = "minimal"`.
- CI skeleton under `.github/workflows/` running fmt, clippy, build, test, and `cargo-llvm-cov`, plus a `cargo deny check` step on the committed lockfile.
- Supply-chain config: committed `deny.toml` (advisories/licenses/bans/sources), `cargo-audit` and `cargo-vet` scaffolding (`supply-chain/` ledger), and the documented dependency-count cap file alongside `deny.toml`.
- Repo files: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and a `README` stub.
- Lib headers on every own crate (`#![forbid(unsafe_code)]` + `#![deny(missing_docs)]`); the WASM binding uses `#![deny(unsafe_op_in_unsafe_fn)]` instead, since `wasm-bindgen` emits generated `unsafe` glue it cannot forbid.

**Scope — Out**
- Any real logic in any crate — all crates are stubs until P1+.
- The `codeql`, `scorecard`, `audit`, and `release` (OIDC dual-publish) workflows, plus the `cargo-mutants`, fuzz, and benchmark gates — these belong to a later release-hardening band.
- WASM build-integrity, generated-types staleness, and TS typecheck CI steps — wired only once the crates they check have content (P1/P2).
- TypeScript layer implementation and the `ts-rs` pipeline (P2).

**Definition of Done**
- `cargo build --workspace`, `cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -D warnings` are all green on the empty stubs.
- `cargo llvm-cov --workspace` runs and reports cleanly on the stub surface.
- The CI workflow executes fmt/clippy/test/llvm-cov on every PR.
- `cargo deny check` passes against the committed `Cargo.lock`; `deny.toml`, the cargo-vet ledger, and the dependency-budget cap file are present.
- `Cargo.lock` is committed, the toolchain is pinned, and every own crate carries its lint header.

**Context / preconditions:** None — this is the first phase.

**Rules of phase**
- Lib headers are present from the first commit of each crate (not retrofitted later); the WASM binding's `unsafe_op_in_unsafe_fn` exception is the only deviation.
- `deny.toml` restricts sources to crates.io only (no git/unknown registries), encodes the license allow-list, and bans `openssl`/`openssl-sys` (and `ring` on the wasm-targeted crates) and duplicate semver-major versions.
- Edition 2024 + MSRV live in `[workspace.package]` and are inherited; an MSRV bump is a deliberate, visible change.
- Directories materialize only when a real file lands in them — no empty scaffolding, no placeholder files.

**References:** §3, §4, §19, §21, §23 (the open questions are resolved during this foundation band).

**Size:** M

---

### P1 — `bymax-auth-crypto`

**Goal:** Implement the pure-Rust, wasm-safe cryptographic primitives crate — password hashing, constant-time comparison, CSPRNG token generation, and the MFA-gated AEAD/TOTP set.

**Scope — In** (crate `crates/bymax-auth-crypto`)
- Password hashing over RustCrypto: `scrypt` (default feature, the always-compiled writer) and `argon2`/Argon2id (the `argon2` feature); self-describing **PHC** strings (`$scrypt$…` / `$argon2id$…`) with a 16-byte random salt and 32-byte output; a compatibility parser for the legacy `scrypt:hex:hex` corpus that always reports as stale.
- `verify` is total — malformed/unknown hashes return `false`, never an error (uniform error-path timing); rehash-detection inputs (`needs_rehash`-style parse of algorithm + parameters) so a caller can compare a stored hash to current params.
- Constant-time comparison wrapper over `subtle` (the only sanctioned secret comparison), short-circuiting only on length mismatch over fixed-length digests.
- CSPRNG secure-token generation (opaque tokens, salts, IVs, OTP digits) via `rand`/`getrandom` (`OsRng`), with `getrandom`'s `wasm_js` backend on `wasm32` (enabled by the WASM leaf binding in P11, not the crypto crate itself).
- Mandatory hashing helpers: SHA-256 (high-entropy secret → key suffix) and keyed HMAC-SHA-256 (low-entropy identifier and recovery-code hashing).
- In-memory secret handling: `secrecy`/`zeroize`, with transient key bytes held in `Zeroizing` buffers.
- MFA-gated set (behind this crate's `mfa` feature): AES-256-GCM encrypt/decrypt (`aes-gcm`, wire `base64(iv):base64(tag):base64(ciphertext)`, fresh 12-byte IV per call, 16-byte tag), TOTP per RFC 6238/4226 over `hmac`+`sha1`, and Base32 via `data-encoding` for `otpauth://` URIs (`generate_totp_secret`, `build_totp_uri`, `verify_totp`).
- Documented `spawn_blocking` guidance: the primitives are synchronous and memory-hard, so callers must dispatch hash/verify to the blocking pool.

**Scope — Out**
- Any engine wiring or `PasswordService` construction (the service lives in `bymax-auth-core`; P3/P4).
- Startup parameter-floor validation (a `build()`/`ConfigError` concern in core; P3).
- HS256 JWT signing/verifying (`bymax-auth-jwt`; P2).

**Definition of Done**
- Builds on native **and** `wasm32-unknown-unknown`.
- The argon2-only build (`--no-default-features --features argon2`) compiles and drops the `scrypt` crate entirely; the default build has scrypt; a `compile_error!` fires when neither hasher feature is enabled.
- A no-`mfa` build links none of `aes-gcm`/`sha1`/`data-encoding`.
- 100% line/branch/region coverage.
- Property tests pass for: hash/verify round-trip and wrong-password rejection (both KDFs); AES-GCM `decrypt(encrypt(m,k),k) == m` with tamper/wrong-key failure; TOTP in-window verify / out-of-window reject + Base32 round-trip; constant-time compare matching `==`; secure-token format/uniqueness.

**Context / preconditions:** P0 (workspace, pinned toolchain with the wasm target, CI gate).

**Rules of phase**
- RustCrypto only — no `ring`, OpenSSL, or C/C++ bindings on any path; the crate must stay wasm-clean (it is part of the purity tripwire).
- No `tokio`, no async, no I/O in this crate — primitives are synchronous CPU work passed plain values (timestamps, byte buffers).
- A fresh `OsRng` IV per AES-GCM encryption is non-negotiable; all decrypt failure modes collapse to one opaque error so the failure type is not an oracle.
- Recovery codes are not KDF-hashed here — they are high-entropy and use keyed HMAC-SHA-256.
- `sha1` is used exclusively inside the TOTP HMAC and must never be substituted for general hashing.

**References:** §17.1, §19.2–§19.3, §20.3.

**Size:** L

---

### P2 — `bymax-auth-types` + `bymax-auth-jwt`

**Goal:** Define the shared domain/data and error contracts and the pure-Rust HS256 JWT primitive, and stand up the `ts-rs` generation pipeline that emits the `./shared` TypeScript surface.

**Scope — In**
- `crates/bymax-auth-types`: domain structs `AuthUser` / `SafeAuthUser` / `AuthPlatformUser` / `SafeAuthPlatformUser` with their infallible secret-dropping `From` projections; write payloads `CreateUserData` / `CreateWithOAuthData` / `UpdateMfaData` / `UpdatePlatformMfaData`; the `AuthError` / `AuthErrorCode` catalog (≈34–40 stable `auth.*` codes, snake_case wire form) with `is_internal_only()`; result and claims types `DashboardClaims` / `PlatformClaims` / `MfaTempClaims` plus `MfaChallengeResult` / `AuthResult` / `LoginResult` / `RotatedTokens`; cookie-name and route default constants; `RepositoryError`.
- `crates/bymax-auth-jwt`: hand-rolled HS256 `sign` / `verify` / `decode_unverified` over `hmac` + `sha2` + `base64` (URL_SAFE_NO_PAD) + `serde_json`; `HsKey` (zeroizing secret wrapper); `VerifyOptions` (HS256 pinned, `leeway_secs`, `validate_exp`/`validate_iat`); the sealed `JwtClaims` trait exposing `exp()`/`iat()`.
- Opaque-refresh helpers: `RawRefreshToken` (CSPRNG `generate` + `redis_hash` = `sha256` hex), placed in `bymax-auth-jwt` over `bymax-auth-crypto`.
- `ts-rs` derivation + generation pipeline + staleness check: the `ts-export` feature on `bymax-auth-types`, `#[ts(export, export_to = "shared/")]` on every cross-boundary type, the generated `./shared` data files (jwt-payload, auth-user, auth-result, auth-error, error-codes, auth-config, cookie-defaults, routes), and the `git diff --exit-code` staleness gate over `packages/rust-auth/src/shared`.

**Scope — Out**
- Engine, services, and HTTP adapter (P3+).
- JTI-blacklist consultation — `verify` performs signature + `alg` + temporal checks only; revocation is a guard/store step (P3/P5).
- Field-level DTO validation (an adapter concern, later).
- The hand-written TS surface that `ts-rs` cannot express (`AuthClientError`, `buildAuthRefreshSkipSuffixes`, the `AuthResponseCode` brand) — authored on the npm side in a later TS-layer phase.

**Definition of Done**
- Both crates build native **and** `wasm32`.
- HS256 sign/verify round-trips; `verify` rejects non-HS256 algorithms, `alg: none`, tampered segments, and an expired `exp`; `decode_unverified` is display-only and never feeds an authz decision.
- `ts-rs` emits the `./shared` data types + constants; the staleness gate is green (no working-tree drift).
- `AuthError` serializes to the exact `auth.*` strings; internal-only codes are gated by `is_internal_only()`.
- 100% coverage, with property tests on the JWT primitive (round-trip, single-bit mutation rejection, `alg` rejection, expiry).

**Context / preconditions:** P0 (workspace + toolchain). `bymax-auth-jwt` depends on `bymax-auth-crypto` for HMAC/SHA-256/CSPRNG, so P1 should be available or land in parallel; `bymax-auth-types` has no crypto dependency and can proceed independently.

**Rules of phase**
- `bymax-auth-types` takes no async/no I/O dependency (serde + ts-rs only); `bymax-auth-jwt` takes no `tokio` and is synchronous CPU work — both stay wasm-safe (the WASM build is the enforcing tripwire).
- HS256 is pinned at verify time; the inbound `alg` header is never read to select an algorithm, and only a symmetric key exists in the system.
- Wire parity with nest-auth: camelCase serde renames (`tenantId`, `mfaEnabled`, …), the `type` discriminator via `#[serde(rename = "type")]`, and byte-identical code strings.
- The signing secret is a `SecretString`/`HsKey`, zeroized on drop and redacted in `Debug`/`Display`.
- Generated TS is committed and drift-gated; the hand-written TS set stays hand-written — it is not forced through `ts-rs`.

**References:** §13, §15, §18.3, §19.2.

**Size:** L

---

### P3 — `bymax-auth-core` skeleton

**Goal:** Assemble the composition root — `AuthEngine` + `AuthEngineBuilder`, the resolved `AuthConfig`, startup validation, and the full plugin trait set with in-memory test doubles — without yet implementing any auth flow.

**Scope — In** (crate `crates/bymax-auth-core`)
- `AuthEngine` struct and `AuthEngineBuilder` with a setter per collaborator (`user_repository`, `platform_user_repository`, `email_provider`, `hooks`, the three individual store setters plus the `redis_stores` convenience, `oauth_provider`, `http_client`, `config`, `environment`) and a single fallible `build()`.
- `AuthConfig` and its nested groups (`JwtConfig`, `RolesConfig`, `PasswordConfig`, `CookieConfig`, `MfaConfig`, `SessionConfig`, `BruteForceConfig`, `PasswordResetConfig`, `EmailVerificationConfig`, `PlatformConfig`, `InvitationConfig`, `OAuthConfig`, `ControllerToggles`) with the two named constructors `nest_compat_defaults()` and `secure_defaults()` (the latter `#[cfg(feature = "argon2")]`), and `Default` ≡ `nest_compat_defaults()`.
- `ConfigError` and the full startup-validation rule set (all cross-field invariants), plus the two values derived during `build()` and stored on the resolved engine — the resolved `secure_cookies` bool and the identifier-hashing HMAC key (`SHA-256("bymax-auth:hmac-key:v1" || jwt.secret)`). The resolved `secure_cookies` and the production-gated OAuth-redirect checks derive from the builder's `Environment` input (default `Production`; §5.1.4/§5.5).
- Resolver traits `TenantIdResolver` and `MaxSessionsResolver` (`#[async_trait]`) and `CookieDomainResolver` (a sync, object-safe trait with no macro), plus the framework-neutral `RequestParts` view.
- The full plugin trait set, all object-safe: `UserRepository`, `PlatformUserRepository`, `EmailProvider`, `AuthHooks`, `SessionStore`, `OtpStore`, `BruteForceStore`, `OAuthProvider`, `HttpClient`.
- `RequestContext`, `HookContext`, the `to_safe_user` / `to_safe_platform_user` projections, and the `NoOpEmailProvider` / `NoOpAuthHooks` defaults.
- In-memory test doubles (HashMap-backed repositories, a recording email provider, a hook spy, and in-memory store fakes that reproduce the atomic semantics) for the hermetic coverage tier.
- Construction-only wiring of internal service collaborators from config (the `PasswordService`/`TokenManagerService`/etc. fields exist and are built), with their flow bodies deferred.

**Scope — Out**
- The actual auth flows (register/login/logout/refresh/me/verify-email, password reset, sessions, MFA, OAuth, platform, invitations) — P4+.
- Redis store implementations — P5 (this phase ships only the traits + in-memory fakes).
- The HTTP adapter (`bymax-auth-axum`) — a later phase.

**Definition of Done**
- The engine assembles from the builder with test doubles; `build()` returns `Ok` for a valid config and the matching `ConfigError` for each invariant violation.
- Config validation covers every cross-field rule (secret length/entropy, role referential integrity, platform hierarchy + repository presence, MFA key length/issuer, scrypt/argon2 floors, `SameSite=None` ⇒ secure, refresh-path coherence, OAuth toggle prerequisites, required stores/repository).
- `default()` ≡ `nest_compat_defaults()` and never names an uncompiled algorithm; `secure_defaults()` is absent from the API without the `argon2` feature.
- Every plugin trait is object-safe (`Arc<dyn _>` compiles); the NoOp defaults stand in for unset optional collaborators.
- 100% coverage; the in-memory doubles implement the trait-level atomic semantics they stand in for.

**Context / preconditions:** P1 (crypto primitives for the password service and the HMAC-key derivation) and P2 (config value types, claims, error catalog, and `HsKey`).

**Rules of phase**
- Object-safety discipline: every host-pluggable trait is `#[async_trait]` + `Send + Sync`; the cookie-domain resolver stays macro-free; internal, statically-dispatched call sites may use native `async fn`.
- The core is transport-agnostic and Redis-free — it depends only on the store traits, never on `axum`, a Redis client, or `reqwest` (the last only under `oauth-reqwest`).
- The resolved `secure_cookies` and the HMAC key are derived in `build()` and stored on the engine, never surfaced on `AuthConfig`; validation never logs the secret, only its measured properties.
- Hook discipline is declared here: only `before_register`/`on_oauth_login` may block; all `after_*`/`on_*` hooks are fire-and-forget under the 5 s timeout ceiling (exercised in P4+).
- There is no standalone `core`/`auth`/`password-reset` Cargo feature — the engine is always compiled and those flows are runtime toggles.

**References:** §3, §5, §6, §9, §10.

**Size:** L

---

### P4 — Local auth flows + password + brute-force + session-fixation

**Goal:** Implement the always-on local authentication lifecycle — register/login/logout/refresh/me/verify-email/resend — with `PasswordService`, brute-force throttling, session renewal, and the anti-enumeration guarantees.

**Scope — In** (in `crates/bymax-auth-core`, exercised against the in-memory store doubles)
- `AuthEngine` flows: `register`, `login`, `logout`, `refresh` (atomic rotation + grace window), `me`, `verify_email`, `resend_verification_email`, the private `send_verification_otp`, `issue_tokens_for_user_id`, and the `assert_user_not_blocked` status helper.
- `PasswordService`: scrypt + argon2 via P1, every hash/verify dispatched through `spawn_blocking`, PHC storage format, and rehash-on-verify gated by `config.password.rehash_on_verify`; a startup-loaded sentinel PHC hash for the user-not-found path.
- `TokenManagerService` (local subset): access-token issuance (`issue_access`/`issue_tokens`), opaque-refresh issuance, `reissue_tokens` (atomic rotation + single-shot grace), and the JTI revocation blacklist on logout via the `SessionStore` trait.
- `BruteForceService`: fixed-window failure counter keyed on a hashed identifier (`hmac_sha256(tenant:email)`), non-extending window, reset on success, `AccountLocked` carrying `retry_after_seconds`.
- Email-verification OTP path implemented against the `OtpStore` trait (in-memory fake from P3), including the atomic resend cooldown.
- Session renewal / fixation resistance (§7.1.9): a fresh opaque refresh token + fresh `jti` minted at every authentication boundary; no pre-auth or client-supplied value is ever adopted as a session key.
- Anti-enumeration: the `ANTI_ENUM_MIN_MS = 300` timing floor, a generic `InvalidCredentials` for both unknown-email and wrong-password, the always-run sentinel verify, internal-only code collapsing to `token_invalid`, and the no-token-in-query-string invariant.

**Scope — Out**
- Redis store implementations — P5; P4 runs entirely against the in-memory store doubles through the traits.
- `SessionService` concurrent-session tracking / FIFO eviction / list / revoke — P6 (P4 covers token issuance, rotation, brute-force, and the fixation invariants).
- The `TokenManagerService` MFA-temp-token and WebSocket-ticket methods — later phases.
- MFA, OAuth, platform login, password-reset service, and the HTTP adapter — later phases.

**Definition of Done**
- register/login/logout/refresh/me/verify-email/resend all pass integration tests with the in-memory doubles.
- Anti-enumeration is verified: identical timing, status, and body for unknown vs. known email on login and on the anti-enum endpoints; the sentinel verify always runs.
- Refresh rotation is single-use with a working grace window — a concurrent retry succeeds without logout, and a replay past the window returns `RefreshTokenInvalid` — against the in-memory atomic fake.
- rehash-on-verify upgrades a stale PHC hash fire-and-forget without blocking login; all hashing runs on `spawn_blocking`.
- Brute-force lockout triggers at `max_attempts`, holds a fixed window, resets on success, and surfaces `retry_after_seconds`.
- 100% coverage.

**Context / preconditions:** P3 (engine, builder, plugin traits, resolved config, in-memory doubles).

**Rules of phase**
- Never block the async runtime: every hash/verify, including the sentinel and the rehash, goes through `spawn_blocking`.
- Uniqueness-before-hash on register (no CPU-amplification oracle); the status and email-verification gates precede the KDF on login.
- A generic `InvalidCredentials` covers both unknown-email and wrong-password; the internal-only `token_expired`/`token_revoked` codes collapse to `token_invalid` at the boundary.
- Operation ordering is security-critical where flows mutate two stores (e.g. credential update before session invalidation).
- No access or refresh token is ever read from or written to a query string.
- `after_*` hooks run fire-and-forget under the 5 s ceiling and never roll back a committed DB/store mutation.

**References:** §7.1, §7.2, §7.3, §7.7, §15.5, §17.2, §24 (invariants 7, 8, 14).

**Size:** L

---

### P5 — `bymax-auth-redis` stores + Lua + WS ticket

**Goal:** Provide the canonical Redis-backed implementations of the store traits, with atomic Lua scripts, namespace prefixing, and no-PII keys.

**Scope — In** (crate `crates/bymax-auth-redis`)
- `SessionStore`, `OtpStore`, `BruteForceStore`, and `WsTicketStore` implementations over `redis` + `deadpool-redis` (`fred` documented as the alternative single-dependency client), plus the auxiliary single-purpose stores (`MfaStore`, `OAuthStateStore`, `PasswordResetStore`, `InvitationStore`, `UserStatusCache`) following the identical pattern.
- The `RedisConn` driver abstraction and the `NamespacedRedis` wrapper — the single component allowed to build a fully-qualified `{namespace}:` key (default namespace `auth`).
- The Lua scripts: `refresh_rotate` (rotation + grace pointer holding the new `SessionRecord`), `session_revoke` (ownership-checked single revoke), `brute_force_incr` (fixed-window `INCR` + `EXPIRE`-on-first), `otp_verify` (verify + attempts + consume, residual-TTL-preserving), the single-use WS ticket (`wst:` `GETDEL`), and `invalidate_user_sessions` (revoke-all in one transaction).
- The `RedisStores` handle that satisfies `SessionStore + OtpStore + BruteForceStore` together (backing the `redis_stores` builder convenience).
- Namespaced, no-PII keys: SHA-256 of high-entropy secrets and HMAC-SHA-256 of low-entropy identifiers as key suffixes; camelCase JSON value shapes byte-identical to nest-auth; a TTL on every key.
- `EVALSHA`-with-`EVAL` fallback on `NOSCRIPT`.

**Scope — Out**
- The services that call the stores (`SessionService`, `OtpService`, `PasswordResetService`, invitations, MFA) — P6+.
- Engine wiring beyond satisfying the traits (the builder already accepts the stores from P3).
- Anything wasm/edge — this crate is never linked into the `wasm32` build.

**Definition of Done**
- Stores pass integration tests against a real Redis via `testcontainers` (`redis:8`).
- Lua atomicity is verified: rotation cannot double-spend a refresh token; revoke is ownership-checked (no cross-user revoke); the brute-force window starts at the first failure and does not slide; `otp_verify` bumps attempts preserving residual TTL and consumes on success; the WS ticket is single-use via `GETDEL`.
- Every key is namespaced; no raw secret or PII is ever resident as a key (hashed/HMAC); every key carries a TTL.
- Stored JSON is camelCase and round-trips with the shared DTOs in `bymax-auth-types`.
- 100% coverage (the in-memory fake serves the hermetic coverage run; the testcontainers tier proves the real Lua/atomicity).

**Context / preconditions:** P3 (the store trait definitions, `SessionKind`, and the value DTOs live in `bymax-auth-core`/`bymax-auth-types`). Independent of P4 — P5 may proceed in parallel once P3 lands.

**Rules of phase**
- Parity contract: identical key prefixes, value encodings, TTLs, and Lua semantics to nest-auth so the two backends can share one Redis — the single exception is the additive `wst:` (WebSocket) prefix, which is outside the parity surface.
- Only `NamespacedRedis` constructs a fully-qualified key; `KEYS` arrive already namespaced, and the namespace is passed as an `ARGV` element wherever a script rebuilds member keys from a SET.
- The rotation grace pointer stores the new `SessionRecord` JSON, never a raw token; no raw refresh token is ever written to Redis.
- `#![forbid(unsafe_code)]`; the crate is never compiled into the edge build.
- The authoritative constant-time OTP comparison is re-done in Rust via `subtle` — the Lua compare only decides the attempts bump.

**References:** §12, §24 (invariants 9, 15).

**Size:** M

---

### P6 — Sessions, OTP, password reset, email verification, invitations

**Goal:** Implement the stateful, user-facing services on top of the real stores — session management, OTP, password reset, email verification, and invitations.

**Scope — In** (in `crates/bymax-auth-core`, exercised against `bymax-auth-redis`)
- `SessionService`: `create_session`, FIFO eviction at the limit (`enforce_session_limit`, a soft cap by default, with the atomic-Lua hardening path documented for a strict `default_max_sessions = 1`), device/IP metadata (`parse_user_agent`, IP truncated to `MAX_IP_LENGTH`), `list_sessions`, ownership-checked `revoke_session`, `revoke_all_except_current`, and atomic `rotate_session`; the new-session and session-evicted hooks.
- `OtpService`: CSPRNG `generate`, `store`, and the atomic, constant-time, timing-normalized (`MIN_VERIFY_MS = 100`) `verify` with a five-attempt ceiling and fail-closed handling of corrupt records.
- `PasswordResetService`: `initiate_reset` (anti-enumeration), `reset_password` (token | otp | verified_token), `verify_otp` (returning a short-lived verified token), `resend_otp` (atomic 60 s cooldown), and the private `apply_password_reset` (hash → `update_password` → `revoke_all`, in that security-critical order).
- The email-verification flow consolidated onto `OtpService`/`OtpStore` (resend cooldown, verify, `after_email_verified` hook).
- `InvitationService`: `invite` (role-authorization on the inviter + a secure single-use token) and `accept_invitation` (single-use `getdel`, role re-validation against the hierarchy as anti-tamper, duplicate-email guard, user creation + full session issuance).

**Scope — Out**
- MFA (`MfaService`, TOTP challenge, recovery codes), OAuth, platform auth, and the HTTP adapter — later phases.
- The Redis store internals themselves (delivered in P5; here they are consumed through the traits).

**Definition of Done**
- Each flow passes integration tests wired to the engine + a real Redis (testcontainers).
- Session-limit FIFO eviction fires at the configured limit, the new-session alert hook and the session-evicted hook both fire, and eviction excludes the just-created session.
- Password reset works via both the token and OTP methods; the verified-token bridges verify→reset; all sessions are revoked after reset; initiate/resend are uniformly anti-enumerating (≥ 300 ms, identical body).
- OTP verify is single-use, attempt-capped at five, and timing-normalized; corrupt records fail closed.
- Invitation accept is single-use, re-validates the role against the hierarchy, rejects a duplicate email, and issues a full session.
- 100% coverage.

**Context / preconditions:** P4 (token issuance, `PasswordService`, brute force, and the engine flow scaffolding) and P5 (the real stores + Lua needed to exercise the atomic session/OTP behavior).

**Rules of phase**
- Anti-enumeration with normalized timing on initiate/resend; single-use atomic token/OTP consumption via `getdel`.
- `apply_password_reset` order is security-critical — the password is updated before sessions are invalidated, so a crash between the two cannot leave the old password able to mint sessions.
- Session hashes are validated (64 lowercase hex) before use; full hashes are never logged (truncated to eight chars); revoke is ownership-checked to close IDOR/BOLA.
- The stored invitation payload is trusted on accept, so the role is re-validated; deployments that do not fully trust Redis should HMAC-sign the stored record.
- `sessions` and `invitations` are gated by both a Cargo feature and a runtime toggle, auto-promoted to active when their config is enabled.

**References:** §7.4, §7.6, §7.8, §7.10, §10.

**Size:** L
## Phase details — P7–P12 (MFA → publishable 1.0)

These detail entries continue the roadmap's per-phase layer; P1–P6 precede them. The global conventions — 100% line/branch/region coverage as a hard gate, RustCrypto-only with `#![forbid(unsafe_code)]`, timeless self-explanatory comments, Conventional Commits, and OIDC-only publishing — are defined once in the roadmap's conventions section and are referenced, not restated, below.

---

### P7 — MFA (TOTP) end-to-end

**Goal**
Deliver the complete TOTP MFA lifecycle as an engine service — encrypted-at-rest secrets, hashed show-once recovery codes, and anti-replay on every path — so that local-login MFA works end to end.

**Scope — In**
- `MfaService` in `crates/bymax-auth-core` implementing the §7.5 operations: `setup` (idempotent; secret + `otpauth://` URI + recovery codes), `verify_and_enable`, `challenge` (TOTP or recovery code), `disable`, and `regenerate_recovery_codes`.
- `regenerate_recovery_codes` as an official v1 capability: strong TOTP re-auth gate, atomic wholesale invalidation of the prior set, and one-time display of the new set.
- MFA-gated crypto primitives added to `crates/bymax-auth-crypto` under its `mfa` feature: AES-256-GCM (`Aes256Gcm`) secret encryption, RFC 6238 TOTP over `hmac`+`sha1`, Base32 via `data-encoding`, keyed HMAC-SHA-256 recovery-code hashing, constant-time compare.
- AES-256-GCM-protected pending-setup record (`MfaSetupData`, 600 s TTL) and `MfaContext { Dashboard, Platform }` routing to the correct repository.
- Anti-replay: `verify_totp_with_anti_replay` plus the fused challenge Lua (set the `tu:` replay marker and consume the `mfa:` temp token in one atomic step) over the Redis store layer; recovery-code single-use removal.
- Short-lived MFA temp-token issue/verify/consume on `TokenManagerService` (split verify/consume, §7.3.5) feeding the dashboard `MfaChallengeResult`.
- Namespaced brute-force counters (`challenge:` isolated from `disable:`) over `BruteForceStore`.
- `mfa` facade feature wiring so MFA crypto and code are absent from a no-MFA build.

**Scope — Out**
- OAuth MFA-branch wiring (P8 consumes the temp-token path) and platform MFA challenge/controller wiring (P9/P10 consume `MfaContext::Platform`).
- MFA HTTP controllers and extractors (P10).

**Definition of Done**
- The full lifecycle (setup → verify-and-enable → challenge via TOTP and via recovery code → disable) passes integration tests for local login against both the in-memory and the `testcontainers` Redis tiers.
- Recovery-code regeneration is atomic (old set invalidated wholesale) and returns the new plaintext set exactly once; no endpoint returns the TOTP secret after `verify_and_enable`.
- Anti-replay rejects a replayed TOTP on every path (enable, challenge, disable, regenerate); the fused challenge Lua proves single-consume under concurrent same-code submissions.
- MFA crypto (`aes-gcm`, `sha1`, Base32) compiles only under the `mfa` feature; a no-MFA build pulls none of it into its tree.
- 100% coverage on the new surface.

**Context / preconditions**
- P4 — core `AuthEngine` and always-on flows (`TokenManagerService`, repository/email/hooks contracts, `SafeAuthUser` projection).
- P5 — the Redis store layer (`BruteForceStore`, `SessionStore`, atomic Lua harness) for setup records, replay markers, and temp tokens.
- P1 — the `bymax-auth-crypto` crate (always-on `hmac`/`sha2`/`subtle`/`rand`/`secrecy`); this phase adds its `mfa`-gated primitives.

**Rules of phase**
- Uphold the §24 MFA invariants: the secret is returned only by `setup`; recovery codes are stored only as keyed HMAC-SHA-256 digests; the AES-GCM IV is unique per encryption; all secret/code comparisons are constant-time.
- Every racing transition (setup `SET NX`, completion `GETDEL`, replay-mark + consume) is a single atomic Lua step — no read-then-write.
- Decrypt failures collapse to one opaque `AuthError` (no oracle); platform misconfiguration fails fast.
- `disable` and `regenerate` accept TOTP only (never a recovery code) and honor the documented session-invalidation divergence between the two.
- Follow the intentional nest-auth divergence (keyed-HMAC recovery codes, not scrypt) exactly.

**References** §7.5 (incl. §7.5.1–§7.5.6), §17.1 (MFA secret encryption, TOTP, HMAC split, constant-time, secure-token generation), §7.3.5, §24 invariants 5–6, 13, 16, 18.

**Size** L

---

### P8 — OAuth — `HttpClient` trait + Google + PKCE/state + linking

**Goal**
Ship the provider-agnostic OAuth authorize→callback flow with a pluggable HTTP transport, a built-in Google provider, single-use `state` + PKCE, and the create/link/reject decision — all in the engine, with no hard-wired HTTP client.

**Scope — In**
- `OAuthProvider` trait and registry (`OAuthProviders`) in `crates/bymax-auth-core`, with `OAuthTokens` / `OAuthProfile` / `OAuthProviderError` supporting types.
- The object-safe `HttpClient` trait and its core-owned `HttpRequest` / `HttpResponse` / `HttpError` (no `http`/`reqwest` types in the contract), plus `ReqwestHttpClient` behind the `oauth-reqwest` facade feature.
- Built-in Google provider (§11.2) implemented over the injected `HttpClient`.
- Engine flow: `oauth_initiate` (resolve provider before any Redis write; 64-hex `state`; PKCE `code_verifier` → S256 `code_challenge`; `os:{sha256(state)}` at 600 s TTL) and `oauth_callback` (atomic `GETDEL` state check, code exchange, profile fetch, OAuth-identity lookup).
- `on_oauth_login` create/link/reject decisioning with tenant-membership enforcement, and `OAuthOutcome { Authenticated, MfaChallenge }` including the MFA-temp-token branch for MFA-enabled users (no MfaService dependency).
- Callback success/error/MFA branch separation and the three operator-configured redirect URLs with §11.4 hardening: no insecure (non-`https`) redirect in production, host allow-list (`oauth.redirect_allowlist`), re-serialization on `?error=` append.
- Unverified-provider-email handling collapsed to `OAuthFailed`.
- `oauth` facade feature (orchestration + traits, zero transport deps) kept distinct from `oauth-reqwest`.

**Scope — Out**
- Any provider beyond Google.
- The two Axum handlers, their query DTOs, and redirect-vs-JSON response shaping (P10; §8.2.7, §11.3.3).

**Definition of Done**
- The full authorize→callback flow is tested end to end against a mock `HttpClient`, covering the create, link, and reject paths and the MFA-challenge branch.
- `reqwest` is absent from the graph unless `oauth-reqwest` is enabled; the base `oauth` feature adds no HTTP/TLS crate.
- A missing/forged/replayed `state` is rejected; the PKCE `code_verifier` is forwarded on exchange; the NoOp hook default rejects sign-in and triggers a startup warning.
- Production startup rejects a non-`https` or off-allow-list redirect/callback URL.
- 100% coverage on the OAuth surface.

**Context / preconditions**
- P4 — core `AuthEngine`, the hooks contract (`AuthHooks::on_oauth_login`), the repository OAuth methods (`find_by_oauth_id`, `create_with_oauth`, `link_oauth`), token issuance, and the engine-minted MFA-temp-token path.

**Rules of phase**
- Security-critical logic (state, PKCE, exchange orchestration, hook invocation, issuance) lives in core; no HTTP handler logic in this phase.
- Every network call goes through `HttpClient`; a provider never embeds a client.
- Redirect targets are never request-derived; the `state` `GETDEL` is the single-use CSRF + consume step.
- Provider internals never reach the client — all provider errors map to `OAuthFailed`; only `OAuthFailed`-family errors become an error-redirect, while transport/programmer errors propagate as 500.
- OAuth is disabled by default until `on_oauth_login` is implemented (§24 invariant 12).

**References** §11 (incl. §11.1, §11.1.1, §11.2, §11.3.1–§11.3.3, §11.4), §19.2 (`oauth` / `oauth-reqwest`), §24 invariant 12.

**Size** L

---

### P9 — Platform admin identity domain

**Goal**
Provide the platform-administrator authentication domain — login (with MFA challenge), me, logout, refresh, and revoke-all — as a separate identity surface with its own role hierarchy and none of the tenant, email-verification, or OAuth machinery.

**Scope — In**
- `PlatformAuthService` in `crates/bymax-auth-core` (§7.9): `login` (`PlatformLoginResult = Success | MfaChallenge`), `logout`, `refresh`, `me`, `revoke_all_platform_sessions`.
- Platform JWT issuance/rotation over `TokenManagerService` (platform claims, no `tenantId`); platform session sets (`psess:`/`prt:`/`psd:`/`prp:`) and bearer-mode delivery.
- A platform role hierarchy (`roles.platform_hierarchy`) kept isolated from the tenant/dashboard hierarchy.
- Anti-enumeration parity: sentinel-hash verify on an unknown admin, HMAC-keyed brute-force identifier (`platform:{email}`), generic `InvalidCredentials`.
- MFA-challenge integration for platform admins via `MfaContext::Platform` — the temp token carries the `context: platform` discriminant so persistence routes through the platform user store.
- `PlatformUserRepository` consumption; `platform` facade-feature gating; no tenant scoping, no email-verification flow, no OAuth on this surface.

**Scope — Out**
- All HTTP wiring — the `PlatformAuthController` / `PlatformMfaController` routes and the `PlatformUser` / `RequirePlatformRole` extractors (P10; §8.2.5–§8.2.6).

**Definition of Done**
- Platform login, refresh, me, logout, and revoke-all pass integration tests, including the login → MFA-challenge → full-token exchange for an MFA-enabled admin.
- The platform and tenant role hierarchies are provably isolated (a tenant role cannot satisfy a platform-role check, and vice versa).
- Logout blacklists the access `jti` and cleans both the primary and grace refresh keys; revoke-all atomically invalidates every platform session.
- No tenant, email-verification, or OAuth path is reachable for platform admins.
- 100% coverage on the platform surface.

**Context / preconditions**
- P4 — core engine, `TokenManagerService`, the `SessionService`/store contracts, brute force, and the sentinel-hash anti-enumeration helper.
- P7 — `MfaService` and the `MfaContext::Platform` challenge path (platform login routes into it; the platform MFA management endpoints reuse it in P10).

**Rules of phase**
- Treat the platform identity as a distinct domain: never reuse the tenant role hierarchy, never attach a `tenantId` claim, never expose verification or OAuth.
- HMAC-keyed identifiers only (no PII in Redis); generic credential errors; uniform login latency via the sentinel hash.
- The service is only constructed when `config.platform.enabled`, which itself requires `roles.platform_hierarchy`.

**References** §5.1.6 (`PlatformConfig`), §7.9, §8.2.5–§8.2.6 (the routes this service backs, wired in P10), §13.3 (platform claims / `MfaChallengeResult`).

**Size** M

---

### P10 — `bymax-auth-axum` — router, extractors, delivery, rate-limit, WS, validation

**Goal**
Build the Axum adapter that exposes every engine capability over HTTP — the complete route table, all extractors/guards, validated DTOs, token delivery, per-route rate limiting, and the WebSocket upgrade-ticket flow — so the backend is reachable end to end.

**Scope — In**
- Router factory `auth_router` plus `AxumAuthConfig` / `AuthState` / `RouteGroups` in `crates/bymax-auth-axum`; group mounting feature- and toggle-gated and derived from the engine's resolved `ControllerToggles`.
- The COMPLETE route table (§8.2.1–§8.2.8): `auth`, `mfa`, `password_reset`, `sessions`, `platform`, `platform_mfa`, `oauth`, `invitations` — every endpoint across all controllers.
- Extractors via `FromRequestParts`: `AuthUser`, `OptionalAuthUser`, `RequireRole<R>`, `PlatformUser`, `RequirePlatformRole<R>`, `CurrentUser`, `SelfOrAdmin`, `UserStatus`, `MfaSatisfied`.
- `garde`-backed `ValidatedJson` / `ValidatedQuery` with `deny_unknown_fields`.
- `AuthError` → `IntoResponse` producing the canonical JSON envelope and status.
- The token-delivery helper (`cookie` / `bearer` / `both`) with secure cookies (HttpOnly, Secure-by-default, refresh path-scoped + `SameSite=Strict`, the non-HttpOnly `has_session` signal cookie) per §14.
- `tower-governor` per-route rate limiting (`RateLimitConfig` defaults mirroring `AUTH_THROTTLE_CONFIGS`) normalized into the `auth.too_many_requests` envelope with `Retry-After`.
- The WebSocket upgrade-ticket endpoint (`POST /auth/ws-ticket`, composing `AuthUser` + `UserStatus` + `MfaSatisfied`) and the `WsAuthUser` / `WsAuthUserFromHeader` extractors behind the `websocket` feature.
- The ordered tower middleware stack (trace, request-body limit, sensitive-header redaction, optional CORS, cookie manager).

**Scope — Out**
- All frontend/npm artefacts (P11) and release automation (P12).

**Definition of Done**
- Every endpoint in the route table works end to end under E2E tests (Axum router + real Redis via `testcontainers`) across register/login/refresh/logout, MFA, sessions, the OAuth callback, platform, and invitations.
- Per-route rate limiting returns 429 + `Retry-After` as the typed `TooManyRequests` envelope; the WS ticket is single-use (`GETDEL`) and refuses replay.
- Token delivery is verified in all three modes with correct cookie attributes; `SameSite=None` without `Secure` is rejected at resolution.
- An unconfigured group contributes zero routes (both the compile-time feature off and the runtime toggle off remove it).
- 100% coverage on the adapter.

**Context / preconditions**
- P4 — core `AuthEngine` and always-on flows.
- P6 — the remaining engine services the routes expose (sessions, token delivery, password-reset/OTP, invitations).
- P7 — `MfaService` (the `mfa` and `platform_mfa` routes).
- P8 — the OAuth engine flow (the `oauth` routes/handlers).
- P9 — `PlatformAuthService` (the `platform` and `platform_mfa` routes).

**Rules of phase**
- No HTTP guard ever sources a token from the query string — cookie or `Authorization` header only; the WS upgrade ticket is the sole, single-use, URL-borne exception (§24 invariant 4).
- Routing is derived from the engine, never configured independently, so the router cannot disagree with what the engine wired.
- Rate-limit layers attach per route group, never as one global layer; the adapter emits tracing spans but installs no subscriber.
- The wire contract (paths, status codes, cookie names, error envelope) matches nest-auth byte-for-byte.

**References** §8 (incl. §8.1–§8.8), §14 (cookie catalog, delivery modes, security constraints), §16 (rate limiting), §7.3.6 (WS ticket), §24 invariants 4, 11.

**Size** L

---

### P11 — `bymax-auth-wasm` + `@bymax-one/rust-auth` (npm) + Rust client

**Goal**
Publish the edge/frontend surface — the WASM edge JWT verifier, the four-subpath npm package, and the native Rust client — and prove a React app and a Next.js middleware authenticate against the running Rust backend with zero type drift.

**Scope — In**
- `bindings/bymax-auth-wasm` (`cdylib`): the wasm-bindgen edge surface (`decode_jwt`, `verify_jwt_hs256` with secret zeroization, `extract_claims`) over the wasm-safe subset of `bymax-auth-jwt`, built via `wasm-pack --target bundler` (npm-only, never crates.io); HS256 pinned, `getrandom` `wasm_js` backend (`features = ["wasm_js"]`).
- The npm package `@bymax-one/rust-auth` (`packages/rust-auth`) with `./shared` (ts-rs-generated types + constants, plus the hand-written `AuthClientError` and `buildAuthRefreshSkipSuffixes`), `./client` (native-`fetch` single-flight client), `./react` (`AuthProvider` / `useAuth` / `useSession` / `useAuthStatus`), and `./nextjs` (`createAuthProxy` + route handlers + the WASM-backed `verifyJwtToken`).
- Dual ESM+CJS build per subpath with the scoped `sideEffects` array and the bundled `wasm/` asset; no `.` root export.
- The Rust `crates/bymax-auth-client` crate (`reqwest`, `client` feature) — the native typed auth client for Rust consumers.
- The `ts-rs` generation pipeline (`ts-export` on `bymax-auth-types`) feeding `./shared`, with the staleness-gate wiring.

**Scope — Out**
- Final release/publish automation, SBOM, attestations, and registry publishing (P12).

**Definition of Done**
- The npm package builds dual ESM+CJS with a `.d.ts` per subpath and the WASM asset bundled; `tsc --noEmit` type-checks the kept layers against freshly generated `./shared`.
- A React app and a Next.js middleware authenticate against the running Rust backend; the Next.js edge verifies (via WASM) a token signed by the backend, demonstrating server/edge parity.
- Zero type drift: regenerating `ts-rs` output leaves the committed `./shared` unchanged (staleness gate green).
- The Rust client and the WASM tests pass (`wasm-pack test`, native client integration); 100% Rust coverage plus the `vitest` frontend suite.

**Context / preconditions**
- P2 — `bymax-auth-jwt` (pinned HS256 sign/verify) exists and is wasm-clean enough to compile into the edge binding.
- P10 — the running Axum backend the React/Next.js consumers and the Rust client authenticate against.

**Rules of phase**
- The WASM module and `verifyJwtToken` are server/edge-only and must never be imported into a client bundle (the HS256 secret must not reach the browser); an accidental client import is a security defect.
- `./shared` data types and constants are generated, never hand-authored; only `AuthClientError` and the refresh-skip builder are hand-written.
- The npm public API stays byte-for-byte compatible with nest-auth (consumers change only the import specifier); the proxy `{ proxy, config }` shape is preserved.
- `bymax-auth-wasm` never becomes a facade dependency or a crates.io crate.

**References** §18 (incl. §18.1–§18.5), §13.2 (one HS256 implementation, server + edge), §13.7 (no token in URL), §19.2 (`client` / `wasm` features), §20.8–§20.9 (frontend + type-gen tests).

**Size** L

---

### P12 — Release engineering, supply-chain, docs, examples, dogfood

**Goal**
Stand up the full CI/release pipeline, the supply-chain and provenance controls, the documentation, the official examples, and the production dogfood, so a tagged build publishes the 1.0 to both registries with provenance, SBOM, and attestations.

**Scope — In**
- The full `ci` workflow: `fmt`, `clippy -D warnings`, build, `llvm-cov` 100% (lines/regions) across the `cargo-hack` feature matrix, doctests, `cargo-deny`, `cargo-vet`, the dependency-budget gate, a short time-boxed `cargo-fuzz` smoke (§20.10), `cargo public-api` + `cargo-semver-checks` over the public surface (success criterion 10), WASM build-integrity + size budget, the `ts-rs` staleness gate, and `tsc`/ESLint over the npm package. (`cargo-geiger` runs at release, not per-PR — see the release workflow; `criterion` benchmarks are tracked observationally and stay non-gating, §20.11.)
- The `codeql`, `scorecard`, and scheduled `audit` (RustSec) workflows.
- `cargo-mutants` near-100% mutation testing as a pre-release (not per-PR) gate.
- The `release` workflow: tag↔version match; crates.io OIDC Trusted Publishing in leaf-first DAG order of `crates/*` only (facade last; `bymax-auth-wasm` excluded); npm OIDC `--provenance` publish; `wasm-pack` build into the npm `wasm/`; a CycloneDX SBOM per shipped artefact; a non-blocking `cargo-geiger` transitive-`unsafe` scan (§19.6/§21.10); GitHub Artifact Attestations for crate/npm/WASM/SBOM; fail-fast on any gate; and the WASM-only security-patch release policy.
- docs.rs config (feature `full`, `--cfg docsrs`) with `#![deny(missing_docs)]`; TypeDoc for the npm surface; the README (two-package map, feature matrix, the two default profiles, condensed threat model, badge row) and the required repo files (`SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `deny.toml`, `supply-chain/`, committed `Cargo.lock`, `.github/` workflows + `dependabot.yml`).
- The official examples under `examples/`: `axum-minimal`, `axum-mfa`, `axum-oauth-google`, `react-vite`, `nextjs`, and `bymax-live-auth` — built and linted in CI so they cannot rot.
- The crate and npm dogfood smoke tests before tagging, and CI enforcement of the §24 Security Invariants as a blocking gate.

**Scope — Out**
- Nothing — this is the publishable 1.0.

**Definition of Done**
- A tagged dry-run publishes to BOTH registries via OIDC (no long-lived tokens), emitting provenance, a CycloneDX SBOM, and Artifact Attestations for the crate tarball(s), the npm tarball, the `*_bg.wasm`, and the SBOM itself (verifiable with `gh attestation verify`).
- Every CI gate is green: 100% coverage across the feature matrix, doctests, WASM build-integrity + size budget, `cargo-deny` / `cargo-vet` / dependency-budget, `ts-rs` staleness, and `tsc`/ESLint.
- All six examples build and lint; both dogfood smokes (the crate Axum app and the npm Next.js app) pass against the to-be-published artefacts.
- The mutation score meets the agreed near-100% floor, and the §24 invariants are wired as a blocking review/CI contract.

**Context / preconditions**
- All prior phases (P1–P11) — the complete crate set, the npm package, the WASM binding, and the examples must exist and pass their own gates.

**Rules of phase**
- OIDC Trusted Publishing only — no `CARGO_REGISTRY_TOKEN` / `NPM_TOKEN` secrets; `release` runs one-at-a-time (`cancel-in-progress: false`) behind a protected, manually-approved environment.
- Fail-fast: a failure in type generation, the WASM build, the SBOM, the advisory audit, or any attestation aborts the release with nothing published.
- Publish `crates/*` only; `bymax-auth-wasm` ships solely inside the npm artefact; the tag↔version gate keeps the crate and npm versions in lockstep.
- Coverage stays a hard PR gate, mutation testing stays the pre-release gate, and any PR weakening a §24 invariant is blocked.

**References** §19 (dependencies, feature matrix, supply-chain posture), §20 (testing & quality gates), §21 (incl. §21.1–§21.10), §24 (Security Invariants), §25 (examples + the Bymax Live dogfood).

**Size** L
