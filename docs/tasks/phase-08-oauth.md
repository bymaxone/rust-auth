# Phase 8 — OAuth: `HttpClient` trait + Google + PKCE/state + linking

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P8
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 3 defined the object-safe plugin traits — including `OAuthProvider` (`traits/oauth.rs`) and `HttpClient` (`traits/http.rs`) with their core-owned supporting types (`OAuthTokens` / `OAuthProfile` / `OAuthProviderError`; `HttpRequest` / `HttpResponse` / `HttpError` / `HttpMethod`) — and the `AuthHooks::on_oauth_login` decision hook. Phase 4 built the engine, token issuance, and the repository OAuth methods (`find_by_oauth_id` / `create_with_oauth` / `link_oauth`). This phase **implements** the provider-agnostic OAuth authorize→callback flow on top of those contracts: a bundled `ReqwestHttpClient` (opt-in), the built-in Google provider over the injected transport, the `OAuthStateStore` for single-use CSRF state, and the two engine flows `oauth_initiate` / `oauth_callback` with the create/link/reject decision and the MFA-challenge branch.

The defining architectural rule of this phase is **transport independence**: the base `oauth` feature adds the orchestration and the provider contracts but pulls **no HTTP client** — every network call goes through `Arc<dyn HttpClient>`. `reqwest` enters the dependency graph only under the separate `oauth-reqwest` feature (the bundled `ReqwestHttpClient`). The flow is stateless across instances: all transient state (`os:{sha256(state)}`) lives in shared Redis with a 600 s TTL, consumed once via `GETDEL`. PKCE (S256) is always used. OAuth is **deny-by-default**: the NoOp `on_oauth_login` returns `Reject`, so an install that has not implemented the hook has OAuth sign-in disabled and emits a startup warning.

When P8 is done, the full authorize→callback flow works end to end against a **mock `HttpClient`** — create, link, and reject paths plus the MFA-challenge branch — `reqwest` is absent unless `oauth-reqwest` is enabled, a forged/replayed/missing `state` is rejected, and production startup refuses a non-`https` or off-allow-list redirect. **All HTTP handlers, query-DTO wiring, and redirect-vs-JSON response shaping are out of scope (P10)** — this phase delivers the engine-level OAuth flow and its provider/transport/state implementations.

---

## Rules-of-phase

1. **Security-critical logic lives in core.** State generation/validation, PKCE, exchange orchestration, `on_oauth_login` invocation, and token issuance are all engine concerns. **No HTTP handler logic in this phase** (the two Axum handlers, their query DTOs, and the redirect-vs-JSON shaping are P10). The MFA-temp cookie attributes (`Max-Age=300`, path-scoped to `cookies.mfa_temp_cookie_path`, `SameSite`) that carry the temp token on the MFA-challenge redirect (§11.3.3) are owned and wired by P10 (the Axum adapter); this phase only issues the temp token value.
2. **Every network call goes through `HttpClient`.** A provider never embeds a concrete client; `GoogleOAuthProvider` holds an `Arc<dyn HttpClient>`. The base `oauth` feature pulls no HTTP/TLS crate; `reqwest` is pulled **only** by `oauth-reqwest`.
3. **Single-use state = CSRF + consume in one step.** `os:{sha256(state)}` is written on initiate (raw `state` never stored — only its hash is the key; the PKCE `code_verifier` is held server-side) and `GETDEL`'d on callback. A missing key (expired/forged/replayed) → `OAuthFailed`.
4. **Redirect targets are never request-derived.** The three redirect URLs and the provider `callback_url` are operator-configured at startup; §11.4 hardening (no insecure redirect in production, host allow-list, re-serialization on `?error=` append) is applied at construction time, not per request.
5. **Provider internals never reach the client.** Every `OAuthProviderError` / `HttpError` from a provider maps to the opaque `OAuthFailed` (cause logged for monitoring); only `OAuthFailed`-family errors become an error-redirect — transport/programmer errors propagate as 500 so monitoring sees them.
6. **OAuth is deny-by-default (§24 invariant 12).** The NoOp `on_oauth_login` returns `Reject`; enabling OAuth while the hook is still the NoOp default emits a startup warning and every callback `OAuthFailed`s. Tenant membership is enforced **only** in `on_oauth_login` (the `tenant_id` from initiate is carried in Redis state, never validated server-side).
7. **Verified-email gate.** Google's `fetch_profile` rejects the profile unless the provider positively returns `verified_email == true` (→ `EmailNotVerified` → `OAuthFailed`); a token's `token_type` must be `bearer` (case-insensitive) before it is used as a credential.
8. **100% coverage**, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on lib paths, English-only, timeless comments. Secrets (`client_secret`, `access_token`, token-endpoint payloads) are never logged.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 11.1 "`OAuthProvider` trait" + § 11.1.1 "Pluggable HTTP transport — the `HttpClient` trait" — the trait shapes (already defined in P3) and the bring-your-own vs bundled-`ReqwestHttpClient` model.
  - § 11.2 "Built-in Google provider" — `GoogleOAuthProvider` / `GoogleOAuthConfig`, the three endpoints, `authorize_url` (+ PKCE S256), `exchange_code` (`token_type == bearer` assert), `fetch_profile` (`verified_email` gate, field mapping).
  - § 11.3 "Full authorize → callback flow" (§11.3.1 initiate, §11.3.2 callback, §11.3.3 result modes) — the engine signatures `oauth_initiate` / `oauth_callback`, the `os:{sha256(state)}` lifecycle, the create/link/reject execution, the MFA branch, and `OAuthOutcome`.
  - § 11.4 "CSRF / state protection, error codes, and open-redirect safety" — single-use state, always-PKCE, `auth.oauth_failed` / `auth.oauth_email_mismatch`, and the three startup-hardening rules.
  - § 9.1 "`AuthHooks` trait" — `on_oauth_login` signature, `OAuthLoginResult` (`Create` / `Link` / `Reject`), and the NoOp deny-by-default.
  - § 6.2 — the repository OAuth methods `find_by_oauth_id` / `create_with_oauth` / `link_oauth` (tenant-scoped).
  - § 12.4 — the `os:` keyspace (TTL, no-PII) the `OAuthStateStore` follows.
  - § 13.3 — `MfaChallengeResult` (the MFA-branch result shape, shared with password login).
  - § 19.2 / § 19.6 — the `oauth` vs `oauth-reqwest` feature split and the "pay only for what you use" `cargo tree` assertions.
  - § 24 — invariant 12 (OAuth disabled until `on_oauth_login` is implemented).
- [`docs/development_plan.md`](../development_plan.md) — § P8, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 8.1 | `ReqwestHttpClient` (`oauth-reqwest`) + `MockHttpClient` double | 📋 ToDo | P0 | S | 3.4 |
| 8.2 | Built-in Google provider + `OAuthProviders` registry | 📋 ToDo | P0 | M | 8.1 |
| 8.3 | `OAuthStateStore` trait + Redis impl (`os:` GETDEL) | 📋 ToDo | P0 | S | 5.1 |
| 8.4 | `oauth_initiate` engine flow (state + PKCE) | 📋 ToDo | P0 | M | 8.2, 8.3 |
| 8.5 | `oauth_callback` engine flow (exchange + create/link/reject + MFA branch) | 📋 ToDo | P0 | L | 8.2, 8.3, 4.5 |
| 8.6 | §11.4 startup hardening + `oauth`/`oauth-reqwest` features + E2E | 📋 ToDo | P0 | M | 8.4, 8.5 |

---

## Tasks

### Task 8.1 — `ReqwestHttpClient` (`oauth-reqwest`) + `MockHttpClient` double

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 3.4

#### Description

Implement the bundled `ReqwestHttpClient` (a thin `reqwest` adapter behind the `oauth-reqwest` feature) over the P3 `HttpClient` trait, plus a `MockHttpClient` test double used by every later OAuth test. The base `oauth` path must pull no HTTP/TLS crate.

#### Acceptance criteria

- [ ] `ReqwestHttpClient` implements `HttpClient` (`send(HttpRequest) -> Result<HttpResponse, HttpError>`) over `reqwest` with rustls TLS and a 10 s per-request timeout; it is `#[cfg(feature = "oauth-reqwest")]`.
- [ ] `HttpError` mapping: connect/DNS → `Connect`, timeout → `Timeout`, body/transport → `Transport` (no `reqwest` types leak across the trait boundary).
- [ ] The `AuthEngineBuilder` defaults `http_client` to `ReqwestHttpClient` only when `oauth-reqwest` is enabled; otherwise the consumer must supply an `HttpClient` (and pulls in no HTTP dependency).
- [ ] A `MockHttpClient` test double (queued/scripted responses keyed by URL+method) lives behind a `testing` cfg for the later OAuth tests.
- [ ] `cargo tree` shows `reqwest` only under `oauth-reqwest`; a base-`oauth` build links no HTTP/TLS crate.
- [ ] 100% coverage on the new code.

#### Files to create / modify

- `crates/bymax-auth-core/src/oauth/reqwest_client.rs` (`#[cfg(feature = "oauth-reqwest")]`)
- `crates/bymax-auth-core/src/testing/http.rs` (`MockHttpClient`)
- `crates/bymax-auth-core/src/oauth/mod.rs` (module wiring)
- `crates/bymax-auth-core/Cargo.toml` (optional `reqwest` under `oauth-reqwest`)

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async; full parity with @bymax-one/nest-auth. OAuth providers perform every
network call through an injected `Arc<dyn HttpClient>` so the base `oauth` feature carries no HTTP
dependency.

CURRENT PHASE: 8 (OAuth) — Task 8.1 of 6 (FIRST)

PRECONDITIONS
- Phase 3 is done: `bymax-auth-core::traits::http` defines the object-safe `HttpClient` trait and the
  core-owned `HttpRequest` / `HttpResponse` / `HttpError` / `HttpMethod` (NO `http`/`reqwest` types).
  `AuthEngineBuilder::http_client(Arc<dyn HttpClient>)` exists.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.1.1 "Pluggable HTTP transport — the `HttpClient` trait" —
  the trait + value types, the bring-your-own vs bundled-`ReqwestHttpClient` model, and the rustls /
  10 s-timeout defaults.
- `docs/technical_specification.md` § 19.2 / § 19.6 — the `oauth` vs `oauth-reqwest` split and the
  `cargo tree` "pay only for what you use" assertions.

TASK
Implement `ReqwestHttpClient` (behind `oauth-reqwest`) over the P3 `HttpClient` trait, plus a
`MockHttpClient` test double. The base `oauth` path must pull no HTTP/TLS crate.

DELIVERABLES

1. `crates/bymax-auth-core/src/oauth/reqwest_client.rs` (`#[cfg(feature = "oauth-reqwest")]`):
   ```rust
   pub struct ReqwestHttpClient { /* reqwest::Client (rustls), 10s timeout */ }
   #[async_trait]
   impl HttpClient for ReqwestHttpClient {
       async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> { /* map errors */ }
   }
   ```
   Map reqwest errors: connect/DNS → `Connect`, timeout → `Timeout`, body/other → `Transport`. No
   `reqwest` type crosses the trait boundary.
2. `crates/bymax-auth-core/src/testing/http.rs`: `MockHttpClient` — scripted responses keyed by
   (method, url); used by the later OAuth tests.
3. `Cargo.toml`: `reqwest` as an OPTIONAL dep enabled only by `oauth-reqwest` (rustls, no default TLS).
   Builder default-wires `ReqwestHttpClient` only under `oauth-reqwest`.

Constraints:
- The base `oauth` feature pulls NO HTTP/TLS crate. `reqwest` is enabled solely by `oauth-reqwest`.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!` on lib paths;
  English-only, timeless comments. `access_token`/secrets never logged.

Verification:
- `cargo build -p bymax-auth-core --features oauth` then `cargo tree -i reqwest` — expected: reqwest NOT present.
- `cargo tree -p bymax-auth-core --features oauth-reqwest -i reqwest` — expected: present only via oauth-reqwest.
- `cargo llvm-cov -p bymax-auth-core --features "testing oauth-reqwest" --lcov` — expected: new code 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P8 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 8.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 8.2 — Built-in Google provider + `OAuthProviders` registry

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 8.1

#### Description

Implement `GoogleOAuthProvider` over the P3 `OAuthProvider` trait and the injected `HttpClient` — `authorize_url` (with PKCE S256), `exchange_code` (`token_type == bearer` assert), `fetch_profile` (`verified_email` gate) — plus the `OAuthProviders` registry and `name()`-based resolution.

#### Acceptance criteria

- [ ] `GoogleOAuthProvider::new(GoogleOAuthConfig, Arc<dyn HttpClient>)` holds the injected transport (no concrete client); endpoints are the three Google constants; default scope `["openid","email","profile"]`.
- [ ] `authorize_url(state, code_challenge)` builds the URL with `client_id`, `redirect_uri = callback_url`, `response_type=code`, space-joined `scope`, `state`, and — when `code_challenge` is `Some` — `code_challenge` + `code_challenge_method=S256`.
- [ ] `exchange_code(code, code_verifier)` POSTs `application/x-www-form-urlencoded` (`code`, `client_id`, `client_secret`, `redirect_uri`, `grant_type=authorization_code`, `code_verifier` when present) through the `HttpClient`; non-2xx → `Http`; asserts `token_type == "bearer"` (case-insensitive) else `UnexpectedTokenType`.
- [ ] `fetch_profile(access_token)` GETs UserInfo with `Authorization: Bearer`; **rejects unless `verified_email == true`** (→ `EmailNotVerified`); maps `id → provider_id`, `email`, optional `name`, `picture → avatar`; `provider = "google"`.
- [ ] `OAuthProviders` registry resolves a provider by `name()` (format `^[a-z0-9-]{1,64}$`); an unknown name is resolvable to `None` for the engine to map to `OAuthFailed`.
- [ ] Unit tests (against `MockHttpClient`): authorize-URL shape (with/without PKCE), bearer-type assertion, unverified-email rejection, profile field mapping, registry resolution. 100% coverage.
- [ ] `client_secret` / `access_token` / token payloads never logged.

#### Files to create / modify

- `crates/bymax-auth-core/src/oauth/google.rs`
- `crates/bymax-auth-core/src/oauth/registry.rs` (`OAuthProviders` resolution helper)
- `crates/bymax-auth-core/tests/oauth_google.rs`

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; OAuth providers implement the P3 `OAuthProvider` trait over
an injected `Arc<dyn HttpClient>` — no embedded HTTP client, no third-party OAuth crate for the
built-in Google path. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 8 (OAuth) — Task 8.2 of 6 (MIDDLE)

PRECONDITIONS
- Phase 3 is done: `traits::oauth` defines `OAuthProvider` (`#[async_trait]`), `OAuthTokens`,
  `OAuthProfile`, `OAuthProviderError`, and `OAuthProviders`.
- Task 8.1 is done: `MockHttpClient` test double over the `HttpClient` trait.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.2 "Built-in Google provider" — `GoogleOAuthProvider` /
  `GoogleOAuthConfig`, the three endpoint constants, and the exact behavior of `authorize_url`
  (PKCE S256), `exchange_code` (`token_type == bearer` assert), `fetch_profile` (`verified_email`
  gate + field mapping).
- `docs/technical_specification.md` § 11.1 "OAuthProvider trait" — the trait + `OAuthProviders` registry.

TASK
Implement `GoogleOAuthProvider` over the injected `HttpClient` and the `OAuthProviders` registry.

DELIVERABLES

1. `crates/bymax-auth-core/src/oauth/google.rs`:
   - `GoogleOAuthProvider { client_id, client_secret, callback_url, scope, http: Arc<dyn HttpClient> }`
     with `new(GoogleOAuthConfig, Arc<dyn HttpClient>)`.
   - `authorize_url` / `exchange_code` / `fetch_profile` exactly per § 11.2 (PKCE S256, bearer assert,
     verified-email gate, field mapping, `provider = "google"`).
2. `crates/bymax-auth-core/src/oauth/registry.rs`: resolution of a provider by `name()` (validate
   `^[a-z0-9-]{1,64}$`; unknown → `None`).
3. `crates/bymax-auth-core/tests/oauth_google.rs`: tests vs `MockHttpClient` — authorize URL with/
   without PKCE, bearer-type assert, unverified-email rejection, profile mapping, registry resolution.

Constraints:
- Every network call goes through the injected `HttpClient` — never embed a client. Provider errors
  map to `OAuthProviderError` variants (the engine later collapses them to `OAuthFailed`).
- `client_secret`/`access_token`/token payloads never logged. `#![forbid(unsafe_code)]`;
  `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing oauth" --test oauth_google` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing oauth" --lcov` — expected: `oauth/google.rs` + `oauth/registry.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P8 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 8.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 8.3 — `OAuthStateStore` trait + Redis impl (`os:` GETDEL)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 5.1

#### Description

Define the `OAuthStateStore` trait in core and implement it in `bymax-auth-redis`: store the `{ tenant_id, code_verifier }` payload under `os:{sha256(state)}` with a 600 s TTL, and consume it once via atomic `GETDEL`. Provide the in-memory double.

#### Acceptance criteria

- [ ] `OAuthStateStore` trait (object-safe, `#[async_trait]`, `oauth`-gated) in core: `put_state(state_hash, payload_json, ttl)` and `take_state(state_hash) -> Option<String>` (atomic `GETDEL`).
- [ ] Redis impl over the Phase-5 pool; the key is `os:{sha256(state)}` (namespaced); the raw `state` is never a key or value; the payload carries `tenant_id` + the PKCE `code_verifier` only.
- [ ] In-memory `OAuthStateStore` double (Phase-3 `testing` module) reproduces the `GETDEL` single-use semantics.
- [ ] Integration tests (testcontainers): a stored state is readable exactly once; a second `take_state` returns `None`; expiry removes it.
- [ ] `oauth`-gated; 100% coverage; no PII in the key.

#### Files to create / modify

- `crates/bymax-auth-core/src/traits/store.rs` (add `OAuthStateStore`, `oauth`-gated)
- `crates/bymax-auth-redis/src/stores/oauth_state.rs`
- `crates/bymax-auth-core/src/testing/mod.rs` (in-memory double)
- `crates/bymax-auth-redis/tests/oauth_state_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust backend/Redis engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the engine defines store TRAITS, `bymax-auth-redis`
implements them atomically (Phase 5). The OAuth flow is stateless across instances — all transient
state lives in shared Redis. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 8 (OAuth) — Task 8.3 of 6 (MIDDLE)

PRECONDITIONS
- Phase 5 is done: `bymax-auth-redis` has the pool, namespace `key()` helper, and testcontainers harness.
- Phase 1: `bymax-auth-crypto::sha256` is available.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.3.1 (the `os:{sha256(state)} → { tenant_id, code_verifier }`
  write, 600 s TTL) and § 11.4 (the single-use `GETDEL` CSRF/consume step).
- `docs/technical_specification.md` § 12.4 — the `os:` keyspace (TTL, no-PII).

TASK
Define `OAuthStateStore` in core and implement it in redis with an atomic `GETDEL` consume.

DELIVERABLES

1. `crates/bymax-auth-core/src/traits/store.rs` (add, `#[cfg(feature = "oauth")]`):
   ```rust
   #[async_trait]
   pub trait OAuthStateStore: Send + Sync {
       async fn put_state(&self, state_hash: &str, payload: &str, ttl: u64) -> Result<(), AuthError>;
       async fn take_state(&self, state_hash: &str) -> Result<Option<String>, AuthError>; // GETDEL
   }
   ```
2. `crates/bymax-auth-redis/src/stores/oauth_state.rs` — `impl OAuthStateStore for RedisStores`;
   key `os:{state_hash}` (namespaced); raw state never resident; payload = `{ tenant_id, code_verifier }`.
3. `crates/bymax-auth-core/src/testing/mod.rs` — in-memory double with `GETDEL` single-use semantics.
4. `crates/bymax-auth-redis/tests/oauth_state_e2e.rs` — testcontainers: read-once, second-take None, expiry.

Constraints:
- `take_state` is atomic single-use (`GETDEL`). No raw state / PII in any key or value. `oauth`-gated.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-redis --features oauth --test oauth_state_e2e` (with Docker) — expected: pass.
- `cargo llvm-cov -p bymax-auth-redis --features oauth --lcov` — expected: `stores/oauth_state.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P8 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 8.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 8.4 — `oauth_initiate` engine flow (state + PKCE)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 8.2, 8.3

#### Description

Implement `AuthEngine::oauth_initiate(provider, tenant_id)`: resolve the provider **before** any Redis write, mint a 64-hex `state` and a PKCE `code_verifier`/`code_challenge`, store the state payload (600 s TTL), and return the provider authorization URL.

#### Acceptance criteria

- [ ] Validates the `provider` format (`^[a-z0-9-]{1,64}$`) and resolves the registered provider **before** any Redis write; an unknown provider → `OAuthFailed` with no resource consumed.
- [ ] Generates a 32-byte (64-hex) CSPRNG `state` and a 32-byte PKCE `code_verifier`; derives `code_challenge = base64url(SHA-256(code_verifier))`.
- [ ] Stores `os:{sha256(state)} → { tenant_id, code_verifier }` via `OAuthStateStore::put_state` with a 600 s TTL (raw state never stored).
- [ ] Returns `provider.authorize_url(state, Some(code_challenge))` (PKCE always on).
- [ ] Hermetic unit tests (mock provider + in-memory state store): unknown provider → `OAuthFailed` (no state written); a valid initiate writes exactly one state and the URL carries the challenge. 100% coverage.
- [ ] `oauth`-gated.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/oauth/mod.rs` (module + shared helpers)
- `crates/bymax-auth-core/src/services/oauth/initiate.rs`
- `crates/bymax-auth-core/tests/oauth_initiate.rs`

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; OAuth is provider-agnostic with single-use Redis-held state
and always-on PKCE. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 8 (OAuth) — Task 8.4 of 6 (MIDDLE)

PRECONDITIONS
- Task 8.2 is done: `OAuthProviders` registry + provider resolution; the Google provider's `authorize_url`.
- Task 8.3 is done: `OAuthStateStore::put_state` (`os:{sha256(state)}`).
- Phase 1: `bymax-auth-crypto` CSPRNG `token` module + `sha256` + base64url helpers.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.3.1 "Initiate" — the engine signature, the resolve-before-write
  rule, the 64-hex state, the PKCE verifier/challenge derivation, and the `os:` store write (600 s TTL).
- `docs/technical_specification.md` § 11.4 — always-PKCE + single-use state rationale.

TASK
Implement `AuthEngine::oauth_initiate(provider, tenant_id) -> Result<String /* authorize_url */, AuthError>`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/oauth/initiate.rs`:
   - Validate provider format + resolve BEFORE any Redis write (unknown → `OAuthFailed`).
   - Mint 64-hex `state`; mint 32-byte PKCE `code_verifier`; `code_challenge = base64url(SHA-256(verifier))`.
   - `put_state(sha256(state), json({ tenant_id, code_verifier }), 600)`.
   - Return `provider.authorize_url(state, Some(code_challenge))`.
2. `crates/bymax-auth-core/src/services/oauth/mod.rs`: module wiring + shared helpers (state/PKCE gen).
3. `crates/bymax-auth-core/tests/oauth_initiate.rs`: unknown provider → `OAuthFailed` (no write);
   valid initiate writes one state and returns a challenge-bearing URL.

Constraints:
- Resolve the provider BEFORE writing state (no resource consumed on an unknown provider). Raw state
  never stored. `oauth`-gated. No HTTP handler logic. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`;
  no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing oauth" --test oauth_initiate` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-core --features "testing oauth" --lcov` — expected: `services/oauth/initiate.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P8 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 8.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 8.5 — `oauth_callback` engine flow (exchange + create/link/reject + MFA branch)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 8.2, 8.3, 4.5

#### Description

Implement `AuthEngine::oauth_callback(...)`: atomic `GETDEL` state check, code exchange + profile fetch, OAuth-identity lookup, the `on_oauth_login` create/link/reject decision (with the deny-by-default + tenant-membership gate), the MFA-challenge branch, and the `OAuthOutcome` return.

#### Acceptance criteria

- [ ] Resolves the provider **before** consuming state (a misconfigured provider must not burn the user's single-use state); then atomic `GETDEL os:{sha256(state)}` — missing → `OAuthFailed` (the combined CSRF + single-use check).
- [ ] Recovers `tenant_id` + `code_verifier` (malformed payload → `OAuthFailed`); `provider.exchange_code(code, verifier)` then `provider.fetch_profile(access_token)`; any provider error logged + surfaced as `OAuthFailed`.
- [ ] `find_by_oauth_id(provider, provider_id, tenant_id)`; strip credentials to a safe projection before the hook; invoke `on_oauth_login(profile, existing_user, ctx)`.
- [ ] Executes the decision: `Create` → `create_with_oauth({ email, name?, tenant_id, email_verified: true, oauth_provider, oauth_provider_id })` (name falls back to the email local-part); `Link` → requires an existing user (else `OAuthFailed`), `link_oauth` + re-fetch; `Reject` (or hook `Err`) → `OAuthFailed`.
- [ ] The email-conflict case (a provider email that collides with an account resolving to a different identity, surfaced by `on_oauth_login`/store) maps to `OAuthEmailMismatch` (`auth.oauth_email_mismatch`, HTTP 409 — §15), kept distinct from the generic `OAuthFailed`.
- [ ] **MFA branch** (`#[cfg(feature = "mfa")]`): if the resolved user has MFA enabled, issue a short-lived MFA temp token (`context: dashboard`, 300 s) via the existing `issue_mfa_temp_token` path and return `OAuthOutcome::MfaChallenge(MfaChallengeResult)` — **no MfaService dependency**. Otherwise issue dashboard tokens (+ a tracked session when `sessions` is enabled) → `OAuthOutcome::Authenticated(AuthResult)`.
- [ ] Hermetic unit tests (mock provider + in-memory stores): missing/forged/replayed state → `OAuthFailed`; create path; link path (+ link-with-no-user → `OAuthFailed`); reject (NoOp default) → `OAuthFailed`; unverified-email → `OAuthFailed`; an email-conflict decision → `OAuthEmailMismatch` (409); MFA-enabled user → `MfaChallenge`. 100% coverage.
- [ ] `oauth`-gated; provider internals never reach the caller.

#### Files to create / modify

- `crates/bymax-auth-core/src/services/oauth/callback.rs`
- `crates/bymax-auth-core/tests/oauth_callback.rs`

#### Agent prompt

````
You are a senior Rust backend/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the OAuth callback is the security core of the OAuth flow:
single-use CSRF state, code exchange via the injected transport, the create/link/reject decision, and
the MFA branch — all in the engine, no HTTP handler logic. Edition 2024; parity with @bymax-one/nest-auth.

CURRENT PHASE: 8 (OAuth) — Task 8.5 of 6 (MIDDLE — the OAuth security core)

PRECONDITIONS
- Tasks 8.2 + 8.3 done: provider resolution + `exchange_code`/`fetch_profile`; `OAuthStateStore::take_state`.
- Phase 4 done: token issuance (`issue_tokens` + tracked session), the repository OAuth methods
  (`find_by_oauth_id` / `create_with_oauth` / `link_oauth`), the `AuthHooks::on_oauth_login` decision
  hook (NoOp default = `Reject`), and the safe-user projection.
- The MFA temp-token path (`issue_mfa_temp_token`) is available under the `mfa` feature (Phase 7
  Task 7.2); the MFA branch here is `#[cfg(feature = "mfa")]` and reuses it WITHOUT an MfaService dep.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.3.2 "Callback" — the full ordered flow (resolve → GETDEL state
  → exchange → profile → find_by_oauth_id → on_oauth_login → execute decision → MFA branch → issue) and
  the `OAuthOutcome` enum.
- `docs/technical_specification.md` § 9.1 — `on_oauth_login` / `OAuthLoginResult` (Create/Link/Reject)
  + the deny-by-default NoOp.
- `docs/technical_specification.md` § 11.4 — error mapping (only `OAuthFailed`-family → redirect; the
  generic code never leaks which step failed).
- `docs/technical_specification.md` § 13.3 — `MfaChallengeResult`.

TASK
Implement `AuthEngine::oauth_callback(provider, code, state, ip, user_agent, headers) -> Result<OAuthOutcome, AuthError>`.

DELIVERABLES

1. `crates/bymax-auth-core/src/services/oauth/callback.rs`:
   - Resolve provider BEFORE `take_state` (atomic `GETDEL`; missing → `OAuthFailed`).
   - Recover `tenant_id` + `code_verifier`; `exchange_code` + `fetch_profile` (errors → `OAuthFailed`).
   - `find_by_oauth_id`; safe-project; `on_oauth_login` → execute `Create`/`Link`/`Reject` per § 11.3.2.
   - MFA branch (`#[cfg(feature = "mfa")]`): MFA-enabled user → `issue_mfa_temp_token(dashboard, 300)`
     → `OAuthOutcome::MfaChallenge`; else `issue_tokens` (+ session if enabled) →
     `OAuthOutcome::Authenticated`.

2. `crates/bymax-auth-core/tests/oauth_callback.rs`: missing/forged/replayed state, create, link,
   link-no-user, reject (NoOp), unverified-email, MFA-enabled → MfaChallenge.

Constraints:
- The `state` `GETDEL` is the single-use CSRF + consume step. Provider internals NEVER reach the caller
  — every provider/transport error → opaque `OAuthFailed` (cause logged). Tenant membership is enforced
  ONLY in `on_oauth_login`. No HTTP handler logic (P10 owns redirect/JSON shaping).
- `oauth`-gated; the MFA branch is additionally `mfa`-gated. `#![forbid(unsafe_code)]`;
  `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-core --features "testing oauth" --test oauth_callback` — expected: all pass.
- `cargo test -p bymax-auth-core --features "testing oauth mfa sessions" --test oauth_callback` — expected: MFA branch covered.
- `cargo llvm-cov -p bymax-auth-core --features "testing oauth mfa sessions" --lcov` — expected: `services/oauth/callback.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P8 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 8.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 8.6 — §11.4 startup hardening + `oauth`/`oauth-reqwest` features + E2E

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 8.4, 8.5

#### Description

Add the §11.4 startup hardening (no insecure redirect in production, host allow-list, re-serialization on `?error=` append) to config validation, wire the `oauth` / `oauth-reqwest` facade features, and prove the full authorize→callback flow end to end against a mock `HttpClient`.

#### Acceptance criteria

- [ ] At `build()`, each configured redirect/callback URL is parsed with the `url` crate: outside a dev profile, a non-`https` absolute URL → `ConfigError` (same-origin relative paths allowed; `http://localhost` only under dev); a host outside `oauth.redirect_allowlist` → `ConfigError`.
- [ ] The `?error=` append re-serializes the already-validated URL (absolute via `Url::parse`; relative via a placeholder base) and surfaces only the short code suffix (`oauth_failed`, not `auth.oauth_failed`); the helper lives in core (consumed by P10's handler).
- [ ] `ControllerToggles.oauth` defaults to `false` (opt-in, §5.1.8) — OAuth stays disabled until `on_oauth_login` is implemented: the NoOp hook returns `Reject` (every callback `OAuthFailed`s) and enabling OAuth while the hook is still the NoOp default emits a startup warning (deny-by-default, §24 invariant 12).
- [ ] The facade `oauth` feature turns on `bymax-auth-core/oauth` + the provider/state plumbing with **no** HTTP dep; `oauth-reqwest` adds `bymax-auth-core/oauth-reqwest` (`ReqwestHttpClient`). `cargo tree` confirms `reqwest` only under `oauth-reqwest`.
- [ ] A full-flow E2E (mock `HttpClient`, real or in-memory state store) exercises authorize→callback for create, link, and reject, plus the MFA-challenge branch; production startup rejects a non-`https`/off-allow-list redirect.
- [ ] `cargo deny check` passes with the OAuth deps; 100% coverage across the OAuth surface.

#### Files to create / modify

- `crates/bymax-auth-core/src/oauth/redirect.rs` (startup validation + `?error=` re-serialization)
- `crates/bymax-auth-core/src/config/validation.rs` (wire the redirect hardening into `build()`)
- `crates/bymax-auth/Cargo.toml` (the `oauth` / `oauth-reqwest` features)
- `crates/bymax-auth/src/lib.rs` (re-exports under `#[cfg(feature = "oauth")]`)
- `crates/bymax-auth-core/tests/oauth_flow_e2e.rs` (mock HttpClient, full flow)

#### Agent prompt

````
You are a senior Rust engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; OAuth redirect targets are operator-configured and hardened
at startup; the facade gates `oauth` (zero transport deps) separately from `oauth-reqwest` (bundled
`ReqwestHttpClient`). Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 8 (OAuth) — Task 8.6 of 6 (LAST)

PRECONDITIONS
- Tasks 8.1–8.5 are done: transport, Google provider, state store, `oauth_initiate`, `oauth_callback`.
- Phase 3: `ConfigError` + the startup-validation framework; the facade feature taxonomy.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 11.4 "open-redirect safety" — the three startup-hardening rules
  (no insecure redirect in production, host allow-list, re-serialization on append) + the short-code
  `?error=` suffix.
- `docs/technical_specification.md` § 19.2 / § 19.6 — the `oauth` / `oauth-reqwest` split + `cargo tree`.
- `docs/technical_specification.md` § 24 — invariant 12 (deny-by-default OAuth).

TASK
Add the §11.4 startup hardening to config validation, wire the `oauth`/`oauth-reqwest` facade
features, and prove the full authorize→callback flow E2E against a mock `HttpClient`.

DELIVERABLES

1. `crates/bymax-auth-core/src/oauth/redirect.rs`: parse each redirect/callback URL with the `url`
   crate; non-https-in-prod / off-allow-list → `ConfigError`; the `?error=` re-serialization helper
   (short code suffix only).
2. `crates/bymax-auth-core/src/config/validation.rs`: call the hardening in `build()`; emit the
   deny-by-default startup warning when OAuth is on but `on_oauth_login` is NoOp.
3. `crates/bymax-auth/Cargo.toml` + `lib.rs`: the `oauth` (no HTTP dep) and `oauth-reqwest` features;
   re-export the OAuth surface under `#[cfg(feature = "oauth")]`.
4. `crates/bymax-auth-core/tests/oauth_flow_e2e.rs`: full authorize→callback (create/link/reject +
   MFA-challenge) vs a mock `HttpClient`; a startup test rejecting a non-https/off-allow-list redirect.

Constraints:
- Redirect targets are NEVER request-derived; hardening is applied at construction time. `reqwest` only
  under `oauth-reqwest`. Features strictly additive. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`;
  no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth --features oauth` then `cargo tree -i reqwest` — expected: reqwest NOT present.
- `cargo tree -p bymax-auth --features oauth-reqwest -i reqwest` — expected: present only via oauth-reqwest.
- `cargo test -p bymax-auth-core --features "testing oauth mfa sessions" --test oauth_flow_e2e` — expected: full flow passes.
- `cargo deny check` — expected: passes with the OAuth deps.
- `cargo llvm-cov --workspace --features "testing oauth oauth-reqwest mfa sessions" --lcov` — expected: OAuth surface 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P8 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall %. 7. Append `- 8.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
