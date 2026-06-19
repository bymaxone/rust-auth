# Phase 3 — `bymax-auth-core`: engine, builder, config profiles, trait set

> **Status**: ✅ Done · **Progress**: 6 / 6 tasks · **Last updated**: 2026-06-19
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P3
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phases 0–2 produced the workspace and the three wasm-safe foundation crates (`bymax-auth-crypto`, `bymax-auth-types`, `bymax-auth-jwt`). This phase builds the **framework-agnostic engine skeleton** in `bymax-auth-core`: the complete plugin **trait set** (the seam between the library and the host's database, email, sessions, and OAuth), the **configuration model** (`AuthConfig` with the two default profiles and startup `ConfigError` validation), and the **`AuthEngine` + `AuthEngineBuilder`** that assemble and validate everything. The engine assumes **Tokio** for its async runtime; it has NO dependency on Axum, Redis, or an HTTP client (the `reqwest`-backed `HttpClient` default arrives only behind `oauth-reqwest`).

This phase deliberately stops at the skeleton: it defines the traits and the wiring and proves the engine assembles from the builder using **in-memory test doubles** — but it implements **no authentication flows** (register/login/refresh/MFA/OAuth are Phase 4 and later). When P3 is done, a consumer can express their repositories/providers as trait impls, build an `AuthConfig` from a profile, and construct an `AuthEngine` whose config has passed full startup validation.

---

## Rules-of-phase

1. **Framework-agnostic core.** `bymax-auth-core` must NOT depend on `axum`, `tower`, `redis`, or an HTTP client. It depends on `bymax-auth-{types,crypto,jwt}`, `tokio`, `async-trait`, `tracing`, `secrecy`, `serde`, `thiserror`. `reqwest` enters ONLY behind the `oauth-reqwest` feature.
2. **Traits, not a DI container.** Pluggable parts are object-safe traits held as `Arc<dyn _>`. Object-safe async traits use `#[async_trait]`; purely-sync resolver traits (e.g. `CookieDomainResolver`) do not.
3. **Builder validates at startup.** `AuthEngineBuilder::build()` returns `Result<AuthEngine, ConfigError>` after running every cross-field validation; no panics.
4. **Default profiles.** `AuthConfig::default()` ≡ `AuthConfig::nest_compat_defaults()` (scrypt + the verified nest-auth operational values: `email_verification.required = true`, `brute_force.max_attempts = 5`, `password_reset.token_ttl = 600s`, `invitations.token_ttl = 172_800s`). `secure_defaults()` is `#[cfg(feature = "argon2")]` (Argon2id). The default must never name an uncompiled hasher.
5. **No flows.** This phase implements no auth logic — only traits, config, and the engine/builder skeleton. The store traits use the domain-level, `SessionKind`-parameterized surface.
6. **Secrets via `secrecy`.** The JWT secret and the MFA encryption key live in the config as `SecretString` (redacted `Debug`/`Display`, zeroized on drop). Never log them.
7. **Hooks isolation.** Fire-and-forget hooks are detached with a timeout ceiling and their errors are swallowed (logged via `tracing`); only `before_register`/`before_login`/`on_oauth_login` can block/decide.
8. **100% coverage** (traits, config validation, builder, profiles) using in-memory test doubles. `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 3 "Architecture" (the core/adapter split, the trait DI model, the builder, object-safety rules). § 5 "Configuration API" (`AuthConfig`, the sub-configs, the two default profiles, `ConfigError` and all cross-field validation rules, the resolver traits). § 6 "Repository & Provider Contracts" (`UserRepository`/`PlatformUserRepository` signatures). § 7.0 "Core Engine" (the authoritative `AuthEngine` struct shape). § 9 "Hooks System" (the 14-hook `AuthHooks` trait, `HookContext`, results, NoOp). § 10 "Email Provider Interface" (`EmailProvider`, `NoOpEmailProvider`).
- [`docs/development_plan.md`](../development_plan.md) — § P3, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 3.1 | `bymax-auth-core` setup: deps, features, errors, module skeleton | ✅ Done | P0 | S | 2.1 |
| 3.2 | Repository & email provider traits | ✅ Done | P0 | M | 3.1 |
| 3.3 | Hooks: `AuthHooks` (14 hooks) + `HookContext` + NoOp | ✅ Done | P0 | M | 3.1 |
| 3.4 | Store, OAuth & `HttpClient` traits | ✅ Done | P0 | M | 3.1 |
| 3.5 | Config model, default profiles, resolvers & `ConfigError` validation | ✅ Done | P0 | L | 3.1 |
| 3.6 | `AuthEngine` + `AuthEngineBuilder` + in-memory test doubles | ✅ Done | P0 | L | 3.2, 3.3, 3.4, 3.5 |

---

## Tasks

### Task 3.1 — `bymax-auth-core` setup: deps, features, errors, module skeleton

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: S
- **Depends on**: 2.1

#### Description

Wire `bymax-auth-core`'s dependencies and feature flags (`sessions`, `mfa`, `oauth`, `oauth-reqwest`, `platform`, `invitations`), define the crate's error types, and lay out the module skeleton (`config`, `traits`, `engine`).

#### Acceptance criteria

- [ ] `Cargo.toml` depends on `bymax-auth-{types,crypto,jwt}`, `tokio` (rt + macros), `async-trait`, `tracing`, `secrecy`, `serde`, `thiserror`; `reqwest` is optional and only enabled by `oauth-reqwest`.
- [ ] Features `sessions`, `mfa`, `oauth`, `oauth-reqwest` (= `["oauth", "dep:reqwest"]`), `platform`, `invitations` exist; there is no `core` feature; `bymax-auth-core` does NOT depend on `axum`/`redis`.
- [ ] `ConfigError` and `RepositoryError` (thiserror) exist; module skeleton `config`, `traits`, `engine` exists (each with `//!` docs).
- [ ] `cargo build -p bymax-auth-core` and `--features full` (all flows) build; `cargo tree` shows no `axum`/`redis`/`reqwest` in the default build.

#### Files to create / modify

- `crates/bymax-auth-core/Cargo.toml`
- `crates/bymax-auth-core/src/lib.rs`, `error.rs`
- skeleton: `config/mod.rs`, `traits/mod.rs`, `engine/mod.rs`

#### Agent prompt

````
You are a senior Rust backend architect working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async engine; full parity with @bymax-one/nest-auth. `bymax-auth-core` is the
framework-agnostic engine — NO axum/redis/http dependency.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.1 of 6 (FIRST)

PRECONDITIONS
- Phases 0–2 are done: the workspace builds; `bymax-auth-{types,crypto,jwt}` are implemented;
  `crates/bymax-auth-core` is an empty skeleton with the lint headers.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 3 "Architecture" — the framework-agnostic core (no axum/redis/
  http), the Tokio assumption, the feature taxonomy for `bymax-auth-core`.
- `docs/technical_specification.md` § 19 "Dependencies & Feature Flags" — the per-crate deps for
  `bymax-auth-core` and which features pull what (`oauth` vs `oauth-reqwest`).

TASK
Set up the crate's deps, features, error types, and module skeleton. No traits/config/engine bodies
yet — only scaffolding.

DELIVERABLES

1. `crates/bymax-auth-core/Cargo.toml`:
   - Deps: `bymax-auth-types`, `bymax-auth-crypto`, `bymax-auth-jwt`, `tokio` (features `rt`,
     `macros`, `time`), `async-trait`, `tracing`, `secrecy`, `serde`, `serde_json`, `thiserror`.
   - Optional: `reqwest` (optional = true).
   - `[features]`: `sessions`, `mfa`, `oauth`, `oauth-reqwest = ["oauth", "dep:reqwest"]`,
     `platform`, `invitations`; `full = ["sessions","mfa","oauth","oauth-reqwest","platform","invitations"]`.
     NO `core` feature. NO `axum`/`redis` deps.
   - `[lints] workspace = true`.
2. `crates/bymax-auth-core/src/error.rs` — `ConfigError` (thiserror; one variant per validation
   failure category — e.g. `JwtSecretTooWeak`, `MfaKeySize`, `TtlOutOfRange`, `MissingPlatformHierarchy`,
   `SameSiteRequiresSecure`, `HasherNotEnabled`, ...) and `RepositoryError` (opaque wrapper the host
   maps its DB errors into).
3. `crates/bymax-auth-core/src/lib.rs` — declare `pub mod config; pub mod traits; pub mod engine;`
   and re-export `ConfigError`, `RepositoryError`.
4. Create the skeleton module files with `//!` docs.

Constraints:
- `bymax-auth-core` must NOT depend on `axum`/`tower`/`redis`/an HTTP client (except `reqwest` behind
  `oauth-reqwest`).
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-core` — expected: builds.
- `cargo build -p bymax-auth-core --features full` — expected: builds.
- `cargo tree -p bymax-auth-core -i axum` / `... -i redis` / `... -i reqwest` (default) — expected: none present.
- `cargo tree -p bymax-auth-core --features oauth-reqwest -i reqwest` — expected: present.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P3 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 3.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 3.2 — Repository & email provider traits

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.1

#### Description

Define the object-safe `UserRepository` and `PlatformUserRepository` traits (full async signatures) and the `EmailProvider` trait with its `NoOpEmailProvider` default.

#### Acceptance criteria

- [ ] `UserRepository` and `PlatformUserRepository` are `#[async_trait]` traits with every method from the spec, returning `Result<_, RepositoryError>`, using the `bymax-auth-types` domain structs.
- [ ] `EmailProvider` is an `#[async_trait]` trait with all messaging methods (`send_password_reset_token`/`_otp`, `send_email_verification_otp`, `send_mfa_enabled`/`_disabled`, `send_new_session_alert`, `send_invitation`) taking `locale: Option<&str>`, plus the `SessionInfo`/`InviteData` support structs.
- [ ] `NoOpEmailProvider` implements `EmailProvider` as no-ops.
- [ ] All traits are object-safe (usable as `Arc<dyn _>`); a compile test constructs `Arc<dyn UserRepository>` etc.
- [ ] 100% coverage (the trait method coverage comes via the in-memory doubles in Task 3.6; the NoOp + object-safety tests live here).

#### Files to create / modify

- `crates/bymax-auth-core/src/traits/repository.rs`
- `crates/bymax-auth-core/src/traits/email.rs`

#### Agent prompt

````
You are a senior Rust backend architect working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Pluggable host integrations are object-safe `#[async_trait]` traits held as `Arc<dyn _>`. Edition 2024.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 3.1 is done: deps (`async-trait`, `bymax-auth-types`), `RepositoryError`, and the `traits`
  module skeleton exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 6 "Repository & Provider Contracts" — the exact method
  signatures of `UserRepository` and `PlatformUserRepository` (adapt to Rust snake_case + async),
  and which domain structs each uses.
- `docs/technical_specification.md` § 10 "Email Provider Interface" — the `EmailProvider` methods,
  `SessionInfo`/`InviteData`, and the `NoOpEmailProvider`.

TASK
Define the repository traits and the email-provider trait + NoOp.

DELIVERABLES

1. `traits/repository.rs`:
   - `#[async_trait] pub trait UserRepository: Send + Sync` with every method (find_by_id,
     find_by_email, create, update_password, update_mfa, update_last_login, update_status,
     update_email_verified, find_by_oauth_id, link_oauth, create_with_oauth), each `-> Result<_,
     RepositoryError>` and tenant-scoped where the spec says so.
   - `#[async_trait] pub trait PlatformUserRepository: Send + Sync` with its method set.
2. `traits/email.rs`:
   - `#[async_trait] pub trait EmailProvider: Send + Sync` with the messaging methods (each taking
     `locale: Option<&str>`), plus `SessionInfo`/`InviteData`.
   - `pub struct NoOpEmailProvider;` implementing it as no-ops.

Constraints:
- Traits must be object-safe (`Arc<dyn UserRepository>` must compile) — use `#[async_trait]`.
- No `unwrap`/`expect`/`panic!`; document every public item; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-core` — expected: builds.
- A `#[test]` constructing `let _: std::sync::Arc<dyn UserRepository> = ...;` (with a trivial impl)
  — expected: compiles (proves object-safety).
- `cargo clippy -p bymax-auth-core -- -D warnings` — expected: clean.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update P3 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 3.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 3.3 — Hooks: `AuthHooks` (14 hooks) + `HookContext` + NoOp

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.1

#### Description

Define the `AuthHooks` extensibility trait (all 14 hooks with default no-op bodies), the `HookContext`, the blocking/decision result types, and the `NoOpAuthHooks` default — documenting the blocking-vs-fire-and-forget semantics.

#### Acceptance criteria

- [ ] `AuthHooks` is an `#[async_trait]` trait with all 14 hooks (`before_register`, `before_login`, `on_oauth_login`, `after_register`, `after_login`, `after_logout`, `after_email_verified`, `after_password_reset`, `after_mfa_enabled`, `after_mfa_disabled`, `after_mfa_recovery_codes_regenerated`, `after_invitation_accepted`, `on_new_session`, `on_session_evicted`), each with a default no-op body so consumers override selectively.
- [ ] `HookContext` (ip, user_agent, sanitized_headers, ids), `BeforeRegisterResult`, and `OAuthLoginResult` (`Create`/`Link`/`Reject`) exist; the `on_oauth_login` default returns `Reject`.
- [ ] Doc comments state: only `before_register`/`before_login`/`on_oauth_login` block/decide; the `after_*`/`on_*` hooks are fire-and-forget (detached, timeout-bounded, errors logged not propagated).
- [ ] `NoOpAuthHooks` implements the trait (all defaults).
- [ ] 100% coverage of the NoOp + default-decision behavior.

#### Files to create / modify

- `crates/bymax-auth-core/src/traits/hooks.rs`

#### Agent prompt

````
You are a senior Rust backend architect working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Hooks let the host observe/gate auth events. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 3.1 is done: `async-trait`, `tracing`, and the `traits` module skeleton exist; the
  `SafeAuthUser` projection is available from `bymax-auth-types`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 9 "Hooks System" — the COMPLETE 14-hook `AuthHooks` trait,
  `HookContext`, `BeforeRegisterResult`, `OAuthLoginResult` (Create/Link/Reject — default Reject),
  the blocking-vs-fire-and-forget split, and the error-isolation/timeout semantics.

TASK
Define the `AuthHooks` trait, its context/result types, and the NoOp default.

DELIVERABLES

1. `traits/hooks.rs`:
   - `#[async_trait] pub trait AuthHooks: Send + Sync` with all 14 hooks, each with a default body
     (no-op for `after_*`/`on_*`; `before_register` returns an allow result; `before_login` returns
     `Ok(())`; `on_oauth_login` returns `OAuthLoginResult::Reject`). Use `SafeAuthUser`/`SafeAuthPlatformUser`
     in signatures — never the credential-bearing structs.
   - `pub struct HookContext { ip, user_agent, sanitized_headers, user_id, email, tenant_id }`.
   - `BeforeRegisterResult` (allow + optional modified role/status/email_verified) and
     `OAuthLoginResult { Create, Link, Reject }`.
   - `pub struct NoOpAuthHooks;` (relies on the trait defaults).
   - Doc the semantics: only `before_register`/`before_login`/`on_oauth_login` can block/decide; the
     rest are fire-and-forget (the engine detaches them with a timeout and swallows errors).

Constraints:
- Default `on_oauth_login` = `Reject` (deny-by-default; the host must opt in).
- Object-safe (`Arc<dyn AuthHooks>`).
- No `unwrap`/`expect`/`panic!`; document every public item; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-core` — expected: builds.
- `cargo test -p bymax-auth-core hooks` — expected: NoOp returns the documented defaults
  (`on_oauth_login` → Reject; `before_register` → allow) — passes.
- `cargo clippy -p bymax-auth-core -- -D warnings` — expected: clean.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update P3 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 3.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 3.4 — Store, OAuth & `HttpClient` traits

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: M
- **Depends on**: 3.1

#### Description

Define the Redis-store abstraction (`SessionStore`/`OtpStore`/`BruteForceStore`/`WsTicketStore`, domain-level and `SessionKind`-parameterized), and the `OAuthProvider` + pluggable `HttpClient` traits (with their `HttpRequest`/`HttpResponse`/`HttpError` value types).

#### Acceptance criteria

- [ ] `SessionStore`, `OtpStore`, `BruteForceStore`, `WsTicketStore` are `#[async_trait]` traits using the **domain-level** method surface (e.g. `create_session`/`rotate -> RotateOutcome`/`revoke`/`revoke_all`/`blacklist_access`/`is_blacklisted`; brute-force `is_locked`/`record_failure`/`reset`; otp `put`/`verify`/`try_begin_resend`), keyed by `SessionKind { Dashboard, Platform }`.
- [ ] `OAuthProvider` is an `#[async_trait]` trait (`authorize_url`, `exchange_code`, `fetch_profile`) returning the spec's `OAuthProfile`/`OAuthTokens`.
- [ ] `HttpClient` is an object-safe `#[async_trait]` trait (`send`) with core-owned `HttpRequest`/`HttpResponse`/`HttpError` types and NO external HTTP dependency in the trait itself.
- [ ] All traits are object-safe; the store traits are feature-agnostic (defined regardless of `sessions`/`mfa`).
- [ ] 100% coverage (object-safety + value-type round-trips here; behavior via doubles in Task 3.6).

#### Files to create / modify

- `crates/bymax-auth-core/src/traits/store.rs`
- `crates/bymax-auth-core/src/traits/oauth.rs`
- `crates/bymax-auth-core/src/traits/http.rs`

#### Agent prompt

````
You are a senior Rust backend architect working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine. The
Redis store, OAuth providers, and the OAuth HTTP transport are all pluggable object-safe traits, so
the core depends on none of redis/reqwest. Edition 2024.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.4 of 6 (MIDDLE)

PRECONDITIONS
- Task 3.1 is done: `async-trait` and the `traits` module skeleton exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 12 "Redis Strategy" — the `SessionStore`/`OtpStore`/
  `BruteForceStore`/`WsTicketStore` DOMAIN-LEVEL trait surface and the `SessionKind` parameter (NOT
  low-level Redis verbs).
- `docs/technical_specification.md` § 11 "OAuth System" — the `OAuthProvider` trait and the
  `HttpClient` trait (§ 11.1.1) with `HttpRequest`/`HttpResponse`/`HttpError`.

TASK
Define the store traits, the OAuth provider trait, and the pluggable HTTP-client trait.

DELIVERABLES

1. `traits/store.rs` — `#[async_trait]` `SessionStore`, `OtpStore`, `BruteForceStore`,
   `WsTicketStore` using the domain-level methods, parameterized by `pub enum SessionKind {
   Dashboard, Platform }`. Include the supporting value types (`RotateOutcome`, session records,
   etc.) as plain serde structs.
2. `traits/oauth.rs` — `#[async_trait] pub trait OAuthProvider: Send + Sync` (`authorize_url`,
   `exchange_code`, `fetch_profile`) + `OAuthProfile`/`OAuthTokens`.
3. `traits/http.rs` — `#[async_trait] pub trait HttpClient: Send + Sync { async fn send(&self,
   req: HttpRequest) -> Result<HttpResponse, HttpError>; }` + the core-owned `HttpRequest`/
   `HttpResponse`/`HttpError`/`HttpMethod` value types (no external HTTP dep).

Constraints:
- The store trait surface is domain-level (no Redis verbs); keying via `SessionKind`.
- `HttpClient` carries no `reqwest`/`hyper` types in its signature — only core value types.
- All traits object-safe; no `unwrap`/`expect`/`panic!`; document every public item; English-only.

Verification:
- `cargo build -p bymax-auth-core` — expected: builds.
- A compile test constructing `Arc<dyn SessionStore>`, `Arc<dyn OAuthProvider>`, `Arc<dyn HttpClient>`
  (trivial impls) — expected: compiles.
- `cargo tree -p bymax-auth-core -i reqwest` (default) — expected: not present (the trait pulls no HTTP dep).

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update P3 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 3.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 3.5 — Config model, default profiles, resolvers & `ConfigError` validation

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: L
- **Depends on**: 3.1

#### Description

Implement `AuthConfig` and all sub-configs, the two default-profile constructors, the resolver traits, and the full startup validation that produces typed `ConfigError`s.

#### Acceptance criteria

- [ ] `AuthConfig` and the sub-config structs exist (jwt, password with `active_algorithm` + scrypt/argon2 params, cookies, token-delivery, mfa, sessions, brute_force, password_reset, email_verification, platform, invitations, oauth, rate-limiting, routing/tenancy) with the spec's fields/defaults.
- [ ] The JWT secret and MFA key are `secrecy::SecretString`.
- [ ] `AuthConfig::default()` ≡ `AuthConfig::nest_compat_defaults()` (scrypt; `email_verification.required = true`, `brute_force.max_attempts = 5`, `password_reset.token_ttl = 600s`, `invitations.token_ttl = 172_800s`); `secure_defaults()` is `#[cfg(feature = "argon2")]` (Argon2id). The default never names an uncompiled hasher.
- [ ] Resolver traits exist: `#[async_trait] TenantIdResolver`, `#[async_trait] MaxSessionsResolver`, and the sync `CookieDomainResolver`.
- [ ] An `Environment { Production, Development, Test }` enum exists with `Production` as the `Default`; it is the only input that drives "is this a production deployment" — the library never reads the ambient process env (no `NODE_ENV`/`std::env` lookup).
- [ ] `build()` resolves `secure_cookies` from `Environment`: `config.secure_cookies` if `Some`, else `secure_cookies == (environment == Production)`; the resolved bool is stored on the engine and never surfaced on `AuthConfig`. The production-gated OAuth-redirect validation (§5.5 rules 16, 18) is applied only when `environment == Production` and is skipped under `Development`/`Test`.
- [ ] A `validate()` (or `resolve()`) returns `Result<_, ConfigError>` covering every cross-field rule (secret entropy/length, MFA key size, TTL ranges, `SameSite=None ⇒ Secure`, grace < refresh lifetime, `platform ⇒ platformHierarchy`, OAuth-redirect-vs-delivery, route-prefix-vs-refresh-path, ≥1 hasher).
- [ ] 100% coverage including a passing/failing case for each `ConfigError` variant; the profile defaults match the values above.

#### Files to create / modify

- `crates/bymax-auth-core/src/config/{mod.rs,profiles.rs,validate.rs,resolvers.rs}`

#### Agent prompt

````
You are a senior Rust API/config engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine.
Configuration is a strongly-typed `AuthConfig` with two named default profiles and startup
validation. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.5 of 6 (MIDDLE — the largest config task)

PRECONDITIONS
- Task 3.1 is done: deps (`secrecy`, `async-trait`, `thiserror`) and the `config` module + `ConfigError`
  exist. `bymax-auth-types` provides the role/result types.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 5 "Configuration API" — `AuthConfig` and every sub-config + its
  defaults; the `Default profiles` subsection (`nest_compat_defaults()` ≡ `Default` = scrypt + the
  verified nest-auth values; `secure_defaults()` = `#[cfg(argon2)]` Argon2id); the resolver traits
  (`TenantIdResolver` authoritative over the body; `CookieDomainResolver`; `MaxSessionsResolver`);
  the `Environment` enum (§5.1.4) and how `build()` derives `secure_cookies` and gates the
  production-only OAuth-redirect checks (§5.5 rules 16, 18) from it; and the COMPLETE list of
  `ConfigError` cross-field validation rules.

TASK
Implement the config model, the two profiles, the resolver traits, and the full startup validation.

DELIVERABLES

1. `config/mod.rs` — `AuthConfig` + the sub-config structs (fields/types/defaults per the spec). The
   JWT secret and MFA key are `secrecy::SecretString`. `PasswordAlgorithm`'s `Argon2id` variant is
   `#[cfg(feature = "argon2")]`; default `active_algorithm = Scrypt`. Also define
   `pub enum Environment { Production, Development, Test }` with `#[default] Production` — the explicit
   builder input that stands in for `NODE_ENV`; the library never reads the ambient process env.
2. `config/profiles.rs` — `AuthConfig::nest_compat_defaults()` (scrypt + `required=true`,
   `max_attempts=5`, password-reset TTL 600s, invitations TTL 172_800s) and `impl Default for
   AuthConfig` delegating to it; `AuthConfig::secure_defaults()` (`#[cfg(feature = "argon2")]`,
   Argon2id, same operational defaults). Document the "full parity" clarification.
3. `config/resolvers.rs` — `#[async_trait] TenantIdResolver`, `#[async_trait] MaxSessionsResolver`,
   sync `CookieDomainResolver` (object-safe; held as `Arc<dyn _>` in the config).
4. `config/validate.rs` — `fn validate(&self) -> Result<(), ConfigError>` (or a `resolve()` that
   returns a `ResolvedConfig`) covering EVERY cross-field rule, each mapped to a typed `ConfigError`.
   Validation takes the builder's `Environment` as input: it resolves `secure_cookies`
   (`config.secure_cookies` if `Some`, else `environment == Production`) and applies the
   production-gated OAuth-redirect rules (§5.5 rules 16, 18) only when `environment == Production`.

Constraints:
- The default profile must never reference an uncompiled hasher (scrypt is the default feature; a
  no-scrypt build uses `secure_defaults()`).
- Secrets are `SecretString` (never logged); resolvers are `Arc<dyn _>`.
- No `unwrap`/`expect`/`panic!`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core config` — expected: each `ConfigError` variant has a failing case
  and the valid profiles pass; the profile default values are asserted.
- `cargo build -p bymax-auth-core --no-default-features` then with `--features argon2` — expected:
  both build; `secure_defaults()` exists only with `argon2`.
- `cargo llvm-cov -p bymax-auth-core --lcov` — expected: `config/*` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update P3 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 3.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 3.6 — `AuthEngine` + `AuthEngineBuilder` + in-memory test doubles

- **Status**: ✅ Done
- **Priority**: P0
- **Size**: L
- **Depends on**: 3.2, 3.3, 3.4, 3.5

#### Description

Implement the `AuthEngine` struct (holding the validated config and the `Arc<dyn _>` plugin dependencies), the `AuthEngineBuilder` that validates and assembles it, and a `testing` module of in-memory trait doubles so the engine can be constructed in tests.

#### Acceptance criteria

- [ ] `AuthEngine` holds the resolved config plus `Arc<dyn UserRepository>`, optional `Arc<dyn PlatformUserRepository>`, `Arc<dyn EmailProvider>`, `Arc<dyn AuthHooks>`, the store handles, the OAuth providers map, and the `Arc<dyn HttpClient>` (per the spec's § 7.0 shape) — but NO flow methods yet.
- [ ] `AuthEngineBuilder` exposes setters for each dependency (incl. a `redis_stores(...)` convenience and individual store setters, and `http_client(...)`), the config, an `environment(Environment)` setter (default `Production`), and `build() -> Result<AuthEngine, ConfigError>` which runs `AuthConfig` validation — feeding the resolved `Environment` into the `secure_cookies` resolution and the production-gated OAuth-redirect checks — and checks required deps (e.g. `platform` ⇒ a platform repository).
- [ ] A `testing` module (feature `testing` or `#[cfg(any(test, feature = "testing"))]`) provides in-memory doubles: `InMemoryUserRepository`, `InMemoryStores`, plus `NoOpEmailProvider`/`NoOpAuthHooks` and a mock `HttpClient`/`OAuthProvider`.
- [ ] An integration test assembles a full `AuthEngine` from the builder using the doubles and a `secure_defaults()`/`nest_compat_defaults()` config — and a negative test asserts `build()` returns the right `ConfigError` on a misconfiguration (e.g. `platform` enabled without a platform repository).
- [ ] 100% coverage; `default()` never names an uncompiled algorithm.

#### Files to create / modify

- `crates/bymax-auth-core/src/engine/{mod.rs,builder.rs}`
- `crates/bymax-auth-core/src/testing/mod.rs`
- `crates/bymax-auth-core/tests/engine_assembly.rs`

#### Agent prompt

````
You are a senior Rust backend architect working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-core` is the framework-agnostic engine. The
engine is assembled and validated at startup by a builder; pluggable parts are `Arc<dyn _>`. This
task builds the skeleton ONLY — no auth flows (those are Phase 4+). Edition 2024.

CURRENT PHASE: 3 (bymax-auth-core) — Task 3.6 of 6 (LAST)

PRECONDITIONS
- Tasks 3.2–3.5 are done: all plugin traits (`UserRepository`, `PlatformUserRepository`,
  `EmailProvider`, `AuthHooks`, `SessionStore`/`OtpStore`/`BruteForceStore`/`WsTicketStore`,
  `OAuthProvider`, `HttpClient`), the `AuthConfig` model + profiles + `validate()`, and the resolver
  traits all exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 7.0 "Core Engine" — the authoritative `AuthEngine` struct
  shape (config + `Arc<dyn _>` deps + `oauth_providers` map + `HttpClient`).
- `docs/technical_specification.md` § 3 "Architecture" — the builder pattern + the store-injection
  API (individual setters AND a `redis_stores(...)` convenience) + validation-at-`build()`.

TASK
Implement the `AuthEngine` struct, the `AuthEngineBuilder`, and the in-memory test doubles; prove
assembly + validation. Do NOT implement any auth flow methods.

DELIVERABLES

1. `engine/mod.rs` — `pub struct AuthEngine` per § 7.0 (resolved config + the `Arc<dyn _>` deps +
   `oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>` + `Arc<dyn HttpClient>`). No flow
   methods — only the fields, accessors the later phases need, and constructors used by the builder.
2. `engine/builder.rs` — `pub struct AuthEngineBuilder` with `config(..)`, `environment(Environment)`
   (defaulting to `Production` when unset), per-dependency setters (`user_repository`,
   `platform_user_repository`, `email_provider`, `hooks`, the individual store setters AND
   `redis_stores(impl Into<...>)`, `http_client`, `oauth_provider(name, ..)`), and
   `pub fn build(self) -> Result<AuthEngine, ConfigError>` that runs `AuthConfig::validate()` with the
   resolved `Environment` (driving the `secure_cookies` resolution and the production-gated
   OAuth-redirect checks) and checks required-dependency rules (e.g. `platform` ⇒ platform repository
   present; `oauth` ⇒ at least one provider; `oauth-reqwest` default wires `ReqwestHttpClient` only
   when that feature is on).
3. `testing/mod.rs` (`#[cfg(any(test, feature = "testing"))]`) — `InMemoryUserRepository`,
   `InMemoryStores` (impl the store traits over `Mutex<HashMap<...>>`), a mock `HttpClient` and
   `OAuthProvider`, re-exporting `NoOpEmailProvider`/`NoOpAuthHooks`. Add a `testing` feature.
4. `tests/engine_assembly.rs` — a positive test assembling a full `AuthEngine` from the builder with
   the doubles + a profile config; a negative test asserting the expected `ConfigError` on a
   misconfiguration (e.g. `platform` enabled but no platform repository).

Constraints:
- No auth flow logic in this phase — only assembly + validation.
- `build()` never panics; all failure is a typed `ConfigError`.
- `default()`/`nest_compat_defaults()` must construct without naming an uncompiled hasher.
- No `unwrap`/`expect`/`panic!` on library paths (tests may use them); `#![forbid(unsafe_code)]`;
  document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features testing` — expected: the assembly + validation tests pass.
- `cargo build -p bymax-auth-core --features full,testing` — expected: builds.
- `cargo llvm-cov -p bymax-auth-core --features testing --lcov` — expected: 100%.
- `cargo clippy -p bymax-auth-core --features full,testing -- -D warnings` — expected: clean.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Set progress `6/6`. 5. Update the
P3 row in `docs/development_plan.md` (mark ✅ when all six tasks are done). 6. Recompute the overall
%. 7. Append `- 3.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.

- 3.1 ✅ 2026-06-19 — Wired `bymax-auth-core` deps + features (`sessions`/`mfa`/`oauth`/`oauth-reqwest`/`platform`/`invitations`/`scrypt`/`argon2`/`testing`/`full`, no `core`), `ConfigError`/`RepositoryError`, and the `config`/`traits`/`engine`/`context` module skeleton; default graph carries no axum/redis/reqwest.
- 3.2 ✅ 2026-06-19 — Object-safe `UserRepository`/`PlatformUserRepository` and `EmailProvider` (+`SessionInfo`/`InviteData`/`EmailError`) with `NoOpEmailProvider`.
- 3.3 ✅ 2026-06-19 — `AuthHooks` (14 hooks, default bodies; `on_oauth_login` deny-by-default), `HookContext`/`RegisterAttempt`/`BeforeRegisterResult`/`OAuthLoginResult`/`HookError`, and `NoOpAuthHooks`.
- 3.4 ✅ 2026-06-19 — Domain-level `SessionStore`/`OtpStore`/`BruteForceStore`/`WsTicketStore` (`SessionKind`/`OtpPurpose` + value DTOs), `OAuthProvider`/`OAuthProviders`, and the dependency-free `HttpClient` (+ ring-free `ReqwestHttpClient` under `oauth-reqwest`).
- 3.5 ✅ 2026-06-19 — `AuthConfig` + sub-configs, `nest_compat_defaults()`/`secure_defaults()` (`#[cfg(argon2)]`)/`Default`, the `Environment` input, resolver traits, and the full `ConfigError` validation with `secure_cookies` resolution + derived HMAC key in `ResolvedConfig`.
- 3.6 ✅ 2026-06-19 — `AuthEngine` + `AuthEngineBuilder` (validate-at-`build()`, toggle auto-promotion, collaborator-presence rules) and the in-memory `testing` doubles; 100% line/function coverage.
