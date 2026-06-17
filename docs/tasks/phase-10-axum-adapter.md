# Phase 10 — `bymax-auth-axum`: router, extractors, delivery, rate-limit, WS, validation

> **Status**: 📋 ToDo · **Progress**: 0 / 7 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P10
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Every engine capability now exists: the always-on local flows (P4), the stateful services (P6), MFA (P7), OAuth (P8), and the platform identity domain (P9), all over the real Redis stores (P5). This phase is the second convergence point — the **Axum HTTP adapter** (`crates/bymax-auth-axum`) that exposes all of it over HTTP: the complete route table, every extractor/guard, validated DTOs, token delivery, per-route rate limiting, and the WebSocket upgrade-ticket flow. After P10 the backend is reachable end to end.

The adapter is a thin translation layer — it owns **no** auth logic. Extractors source a token (cookie or `Authorization` header, never a query string) and ask the engine to verify it; handlers deserialize+validate a DTO and call an engine method; `AuthError` renders itself into the canonical JSON envelope. The router is **derived from the engine's resolved `ControllerToggles`** (with `platform_mfa = platform && mfa`), so the route surface can never disagree with what the engine actually wired — a disabled toggle (or absent Cargo feature) contributes zero routes. Axum 0.8 specifics shape the design: `FromRequestParts` is a native `async fn` trait (no `#[async_trait]` on extractors), body-consuming `ValidatedJson<T>` must be the last handler argument, and stacked auth extractors verify the JWT once by caching the claims on `parts.extensions`.

When P10 is done, every endpoint in §8.2 works end to end under E2E tests (Axum router + real Redis via `testcontainers`), per-route rate limiting returns 429 + `Retry-After`, the WS ticket is single-use, token delivery is correct in all three modes, an unconfigured group contributes zero routes, and the wire contract (paths, status codes, cookie names, error envelope) matches nest-auth byte-for-byte. **The frontend/npm artefacts (P11) and release automation (P12) are out of scope.**

---

## Rules-of-phase

1. **No token from the query string.** Every HTTP guard (`AuthUser`, `PlatformUser`, …) sources the token from the cookie or the `Authorization` header only. The single-use WebSocket upgrade ticket is the sole, deliberately narrow URL-borne exception (§24 invariant 4) — and it is not a JWT.
2. **Routing is derived from the engine, never configured independently.** `RouteGroups` is read from the engine's resolved `ControllerToggles` (`platform_mfa = platform && mfa`); a `false` toggle or an absent Cargo feature mounts no routes. The router cannot disagree with the engine.
3. **The adapter owns no auth logic.** Extractors and handlers only source tokens, validate DTOs, call engine methods, and render `AuthError`. Signature/type/revocation/role/status/MFA decisions are engine calls.
4. **Rate-limit layers attach per route group, never globally.** `tower_governor` is applied per group (mirroring nest-auth's per-handler `@Throttle`), not as one global layer. The adapter emits `tracing` spans but installs **no** subscriber (the consumer owns that).
5. **Wire parity with nest-auth, byte-for-byte.** Paths, HTTP methods, success codes, cookie names/attributes, and the `{ "error": { code, message, details } }` envelope match §8.6 / §14 exactly. Axum 0.8 path syntax uses braces (`/{id}`).
6. **Security posture is locally readable at each handler signature.** Public = no auth extractor; MFA-exempt-but-authenticated = `AuthUser` without `MfaSatisfied`. `create_invitation` derives `tenant_id` from the claims, never the body.
7. **Feature-gating.** `mfa` / `sessions` / `platform` / `oauth` / `invitations` / `websocket` gate their controllers and extractors; a disabled feature compiles none of the corresponding code. 100% coverage, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no `unwrap`/`expect`/`panic!` on lib paths, English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 8.1 "Router factory" — `auth_router` / `AxumAuthConfig` / `AuthState` / `RouteGroups` (derived from `ControllerToggles`), the per-group `*_routes()` factories.
  - § 8.2 "Complete route table" (§8.2.1–§8.2.8) — every endpoint: method, path, handler, extractor composition, success code, DTO, enabling feature.
  - § 8.3 "Extractors" (§8.3.1–§8.3.7) — the NestJS→Axum mapping table; `AuthUser` / `OptionalAuthUser` / `RequireRole<R>` / `PlatformUser` / `RequirePlatformRole<R>` / `CurrentUser` / `UserStatus` / `MfaSatisfied` / `SelfOrAdmin`; the claims-caching performance note.
  - § 8.4 "Request validation" (§8.4.1) — `ValidatedJson` / `ValidatedQuery` (garde + `deny_unknown_fields`) and the complete input-DTO catalog.
  - § 8.5 "Token delivery in handlers" + § 14 "Cookie Management & Token Delivery" — the `TokenDelivery` helper, the cookie catalog (`access_token`/`refresh_token`/`has_session`/`mfa_temp`), the three modes, and the §14.5 security constraints.
  - § 8.6 "`AuthError` → `IntoResponse`" — the canonical envelope + the authoritative status map + `Retry-After`.
  - § 8.7 "WebSocket authentication" + § 7.3.6 — the `POST /auth/ws-ticket` mint, `WsAuthUser` (`GETDEL` redeem) / `WsAuthUserFromHeader`, the `websocket` feature.
  - § 8.8 "Tower middleware layering" — the ordered stack (trace, body-limit, sensitive-header redaction, optional CORS, cookie manager) and the no-subscriber rule.
  - § 16 "Rate Limiting" (§16.2–§16.4) — `tower_governor` per route group, the `AUTH_THROTTLE_CONFIGS` defaults, the `auth.too_many_requests` 429 envelope + `Retry-After`.
  - § 24 — invariants 4 (no token in URL) and 11 (router derived from engine).
- [`docs/development_plan.md`](../development_plan.md) — § P10, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 10.1 | Adapter skeleton: `auth_router` / `AuthState` / `RouteGroups` + `IntoResponse` + middleware | 📋 ToDo | P0 | M | 4.5 |
| 10.2 | Token extractors (`AuthUser`/`OptionalAuthUser`/`CurrentUser`) + `ValidatedJson`/`ValidatedQuery` | 📋 ToDo | P0 | L | 10.1 |
| 10.3 | Authz extractors (`RequireRole`/`PlatformUser`/`RequirePlatformRole`/`UserStatus`/`MfaSatisfied`/`SelfOrAdmin`) | 📋 ToDo | P0 | M | 10.2 |
| 10.4 | `auth` + `password_reset` groups + `TokenDelivery` (cookie/bearer/both) | 📋 ToDo | P0 | L | 10.2, 10.3 |
| 10.5 | Optional groups: `mfa`/`sessions`/`platform`/`platform_mfa`/`oauth`/`invitations` | 📋 ToDo | P0 | L | 10.3, 10.4 |
| 10.6 | Per-route rate limiting (`tower_governor`) + `RateLimitConfig` + `Retry-After` | 📋 ToDo | P0 | M | 10.4 |
| 10.7 | WS ticket endpoint + `WsAuthUser`/`WsAuthUserFromHeader` + full-router E2E | 📋 ToDo | P0 | L | 10.4, 10.5, 10.6 |

---

## Tasks

### Task 10.1 — Adapter skeleton: `auth_router` / `AuthState` / `RouteGroups` + `IntoResponse` + middleware

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 4.5

#### Description

Stand up the `bymax-auth-axum` crate: the `auth_router` factory + `AxumAuthConfig` / `AuthState` / `RouteGroups` derived from the engine's resolved `ControllerToggles`, the `AuthError` → `IntoResponse` impl (canonical envelope + full status map + `Retry-After`), and the ordered tower middleware stack.

#### Acceptance criteria

- [ ] `auth_router(engine, config) -> Router` (and `AuthRouter::from_engine`) reads the engine's resolved `ControllerToggles` to mount exactly the enabled groups under `route_prefix` (default `auth`); `platform_mfa = platform && mfa`; a `false` toggle or absent feature mounts no routes.
- [ ] `AuthState` is `Clone` and carries the `Arc<AuthEngine>` + the resolved delivery/cookie config; extractors obtain it via `FromRef`.
- [ ] `AuthError` implements `IntoResponse` producing `{ "error": { code, message, details } }` with the authoritative §8.6 status map; `AccountLocked` / `OtpMaxAttempts` / the rate-limit code add `Retry-After`. `AuthError::Internal` maps to HTTP 500 with a generic "Internal server error" message — the underlying cause is logged but **never** serialized into the envelope (§15.1/§15.5).
- [ ] The ordered tower stack (`TraceLayer`, `RequestBodyLimitLayer`, sensitive-header redaction, optional CORS, `CookieManagerLayer`) is applied; the adapter installs **no** tracing subscriber.
- [ ] An empty-but-wired router compiles and serves; a toggle-off group test proves zero routes are mounted.
- [ ] 100% coverage on the new code.

#### Files to create / modify

- `crates/bymax-auth-axum/Cargo.toml`
- `crates/bymax-auth-axum/src/{lib.rs,router.rs,state.rs,response.rs,middleware.rs}`
- `crates/bymax-auth-axum/tests/router_skeleton.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio async; full parity with @bymax-one/nest-auth. `bymax-auth-axum` is the HTTP
adapter over the framework-agnostic engine — it owns NO auth logic.

CURRENT PHASE: 10 (Axum adapter) — Task 10.1 of 7 (FIRST)

PRECONDITIONS
- Phase 0 produced the `crates/bymax-auth-axum` skeleton (lint headers, empty lib).
- Phase 3/4: `AuthEngine` exposes resolved `ControllerToggles`; `AuthError` is the single engine error
  type with its code/status mapping data; `Arc<AuthEngine>` is shareable.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.1 "Router factory" — `auth_router` / `AxumAuthConfig` /
  `AuthState` / `RouteGroups` derived from `ControllerToggles`; `platform_mfa = platform && mfa`.
- `docs/technical_specification.md` § 8.6 "AuthError → IntoResponse" — the envelope + the authoritative
  status map + `Retry-After`.
- `docs/technical_specification.md` § 8.8 "Tower middleware layering" — the ordered stack + no-subscriber rule.

TASK
Build the adapter skeleton: `auth_router`/`AuthState`/`RouteGroups` (from engine toggles), the
`AuthError` `IntoResponse`, and the tower middleware stack.

DELIVERABLES

1. `Cargo.toml` — deps: `bymax-auth-core`, `axum` (0.8), `tower`, `tower-http` (trace, limit,
   sensitive-headers, cors), `tower-cookies`/`axum-extra` (CookieJar), `serde`/`serde_json`, `tracing`.
   Feature flags mirroring the engine groups (`mfa`/`sessions`/`platform`/`oauth`/`invitations`/`websocket`).
2. `state.rs` — `AuthState { engine: Arc<AuthEngine>, delivery: ResolvedDelivery }` (Clone + `FromRef`);
   `AxumAuthConfig { route_prefix, ... }`; `RouteGroups` read from the engine's `ControllerToggles`.
3. `router.rs` — `auth_router(engine, config) -> Router` mounting only the enabled group sub-routers
   under `route_prefix`; the per-group `*_routes()` stubs (filled in 10.4/10.5/10.7).
4. `response.rs` — `impl IntoResponse for AuthError` (envelope + §8.6 status map + `Retry-After`).
5. `middleware.rs` — the ordered tower stack; NO tracing subscriber installed.
6. `tests/router_skeleton.rs` — a wired empty router serves; a toggle-off group mounts zero routes.

Constraints:
- Routing is derived from the engine's `ControllerToggles`, never configured independently. The adapter
  owns no auth logic. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`
  on lib paths; English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-axum` — expected: builds.
- `cargo test -p bymax-auth-axum --test router_skeleton` — expected: zero-routes-when-off passes.
- `cargo llvm-cov -p bymax-auth-axum --lcov` — expected: new code 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/7`. 5. Update the P10 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 10.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.2 — Token extractors (`AuthUser`/`OptionalAuthUser`/`CurrentUser`) + `ValidatedJson`/`ValidatedQuery`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 10.1

#### Description

Implement the dashboard token extractors over Axum 0.8 `FromRequestParts` — `AuthUser`, `OptionalAuthUser`, `CurrentUser` (HS256-pinned, `type=dashboard`, `rv:` revocation, claims cached on `parts.extensions`) — and the `ValidatedJson<T>` / `ValidatedQuery<T>` validation extractors with the full input-DTO catalog.

#### Acceptance criteria

- [ ] `AuthUser` sources the token per the configured `TokenDelivery` (cookie first, then `Authorization: Bearer`, or one only), calls `AuthEngine::verify_access_token` (HS256 pinned, `token_type == "dashboard"`, `rv:{jti}` revocation), and rejects with the right `AuthError` (missing/invalid/expired → `TokenInvalid`/`TokenExpired`; revoked → `TokenRevoked`).
- [ ] At the HTTP boundary the extractors remap the internal-only codes (`token_expired` / `token_revoked`, gated by `AuthError::is_internal_only()`) to the single public `token_invalid` (401), so the rejection never gives an attacker an oracle distinguishing expired vs revoked vs malformed (§15.5).
- [ ] `OptionalAuthUser` is identical but yields `None` (never rejects) on absent/invalid/expired/revoked; `CurrentUser` is the `@CurrentUser()` parameter form exposing the verified claims.
- [ ] The first auth extractor to run caches the verified claims on `parts.extensions`; subsequent stacked extractors read from there (one HMAC verification per request).
- [ ] `ValidatedJson<T>` (FromRequest, last param) deserializes with `deny_unknown_fields`, runs `garde` validation, and maps any failure to `AuthError::Validation` (400) with per-field `details`; `ValidatedQuery<T>` is the query-string twin.
- [ ] The complete input-DTO catalog (§8.4.1) is defined with the exact `garde` rules and `deny_unknown_fields`.
- [ ] Extractors use native `async fn` (no `#[async_trait]`). Tests cover: valid/missing/invalid/expired/revoked token, optional-none, unknown-field rejection, field-rule rejection, and the single-verification caching. 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-axum/src/extractors/{mod.rs,auth_user.rs,optional.rs,current_user.rs}`
- `crates/bymax-auth-axum/src/{validation.rs,dto.rs}`
- `crates/bymax-auth-axum/tests/extractors_token.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-axum` extractors source a token and ask the
engine to verify it — they own no auth logic. Axum 0.8: `FromRequestParts` is native `async fn` (NO
`#[async_trait]`); body extractors implement `FromRequest` and must be the last handler arg.
Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.2 of 7 (MIDDLE — the security gate every route depends on)

PRECONDITIONS
- Task 10.1 done: `AuthState` (FromRef), the `AuthError` `IntoResponse`.
- Phase 4: `AuthEngine::verify_access_token` (HS256-pinned signature, `token_type` assertion, `rv:{jti}`
  revocation). `DashboardClaims` defined (Phase 2). The resolved `TokenDelivery` mode on `AuthState`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.3 "Extractors" — §8.3.2 `AuthUser`, §8.3.3 `OptionalAuthUser`,
  §8.3.7 `CurrentUser`, the native-async-fn rule, and the claims-caching performance note.
- `docs/technical_specification.md` § 8.4 "Request validation" + §8.4.1 — `ValidatedJson`/`ValidatedQuery`
  and the COMPLETE input-DTO catalog with the exact `garde` rules + `deny_unknown_fields`.

TASK
Implement `AuthUser`/`OptionalAuthUser`/`CurrentUser` and `ValidatedJson`/`ValidatedQuery` + the DTOs.

DELIVERABLES

1. `extractors/auth_user.rs` — `AuthUser(DashboardClaims)` per §8.3.2 (source token cookie-or-bearer,
   `verify_access_token`, map result to `Rejection`); cache claims on `parts.extensions`, read-through
   on subsequent extractors.
2. `extractors/optional.rs` — `OptionalAuthUser(Option<DashboardClaims>)` (never rejects).
3. `extractors/current_user.rs` — `CurrentUser(DashboardClaims)`.
4. `validation.rs` — `ValidatedJson<T>` (FromRequest, last arg; `deny_unknown_fields` + `garde` →
   `AuthError::Validation` with per-field details) + `ValidatedQuery<T>`.
5. `dto.rs` — the complete §8.4.1 DTO catalog (Register/Login/ForgotPassword/ResetPassword/VerifyOtp/
   ResendOtp/VerifyEmail/ResendVerification/MfaVerify/MfaChallenge/MfaDisable/MfaRegenerateRecoveryCodes/
   PlatformLogin/CreateInvitation/AcceptInvitation/Refresh) with exact garde rules.
6. `tests/extractors_token.rs` — valid/missing/invalid/expired/revoked, optional-none, unknown-field,
   field-rule rejection, single-verification caching.

Constraints:
- Token sourced from cookie or `Authorization` header ONLY — never a query string. Native `async fn`
  extractors. One JWT verification per request (cache on `parts.extensions`). `#![forbid(unsafe_code)]`;
  `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --test extractors_token` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-axum --lcov` — expected: extractors + validation 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/7`. 5. Update the P10 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 10.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.3 — Authz extractors (`RequireRole`/`PlatformUser`/`RequirePlatformRole`/`UserStatus`/`MfaSatisfied`/`SelfOrAdmin`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 10.2

#### Description

Implement the authorization extractors: `RequireRole<R>` (const-generic role marker), `PlatformUser` / `RequirePlatformRole<R>`, `UserStatus` (Redis-cached blocked-status), `MfaSatisfied`, and the path-aware `SelfOrAdmin`.

#### Acceptance criteria

- [ ] `Role` / `PlatformRole` marker traits (`const NAME`); `RequireRole<R>` resolves `AuthUser` then `AuthEngine::role_satisfies(user_role, R::NAME)` against the dashboard hierarchy → `InsufficientRole` (403); `RequirePlatformRole<R>` is the platform analogue against the platform hierarchy.
- [ ] `PlatformUser(PlatformClaims)` validates the platform JWT (`token_type == "platform"`); a dashboard token here → `PlatformAuthRequired` (401).
- [ ] `UserStatus` resolves `AuthUser` then `AuthEngine::assert_user_active(sub)` (Redis `us:{sub}` cache + store fallback), rejecting blocked statuses with the status-specific code (`AccountBanned`/`AccountInactive`/`AccountSuspended`/`PendingApproval`, all 403).
- [ ] `MfaSatisfied` resolves `AuthUser` and requires `claims.mfa_verified == true` when the account has MFA → else `MfaRequired` (403); its **omission** is the `@SkipMfa()` semantic.
- [ ] `SelfOrAdmin` resolves `AuthUser` + the `{user_id}` path segment and admits when `path.user_id == claims.sub` OR the role satisfies the configured admin role.
- [ ] All re-use the cached claims from 10.2 (no redundant verification). Tests cover pass/fail for each, including the composition of several on one route. 100% coverage; `platform` extractors are `platform`-gated.

#### Files to create / modify

- `crates/bymax-auth-axum/src/extractors/{role.rs,platform.rs,status.rs,mfa.rs,self_or_admin.rs}`
- `crates/bymax-auth-axum/tests/extractors_authz.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; authorization is opt-in per handler by declaring the
relevant extractor (no global guards). Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.3 of 7 (MIDDLE)

PRECONDITIONS
- Task 10.2 done: `AuthUser`/`CurrentUser` + the `parts.extensions` claims cache.
- Phase 4/9: `AuthEngine::role_satisfies` (dashboard) + the platform role check, `assert_user_active`
  (status cache), and the `DashboardClaims`/`PlatformClaims` types; `PlatformUser` JWT verification.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.3 — §8.3.4 `RequireRole<R>`, §8.3.5 `PlatformUser`, §8.3.6
  `RequirePlatformRole<R>`, §8.3.7 `UserStatus`/`MfaSatisfied`/`SelfOrAdmin`, and the
  composition/caching note.

TASK
Implement the authorization extractors.

DELIVERABLES

1. `extractors/role.rs` — `Role` trait (`const NAME`) + `RequireRole<R>(DashboardClaims, PhantomData<R>)`
   (resolves `AuthUser`, checks the dashboard hierarchy; 403 `InsufficientRole`).
2. `extractors/platform.rs` (`#[cfg(feature = "platform")]`) — `PlatformUser(PlatformClaims)` (assert
   `type == platform`; dashboard token → `PlatformAuthRequired`); `PlatformRole` + `RequirePlatformRole<R>`.
3. `extractors/status.rs` — `UserStatus` (`assert_user_active(sub)` → status-specific 403s).
4. `extractors/mfa.rs` — `MfaSatisfied` (require `mfa_verified` when MFA enabled → else `MfaRequired`).
5. `extractors/self_or_admin.rs` — `SelfOrAdmin` (path `{user_id}` == `sub` OR role ≥ admin).
6. `tests/extractors_authz.rs` — pass/fail per extractor + a multi-extractor composition route.

Constraints:
- Re-use the cached claims (no redundant verification). `platform` extractors are `platform`-gated.
- The `MfaSatisfied` omission IS `@SkipMfa()`. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --features "platform" --test extractors_authz` — expected: all pass.
- `cargo llvm-cov -p bymax-auth-axum --features "platform" --lcov` — expected: authz extractors 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/7`. 5. Update the P10 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 10.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.4 — `auth` + `password_reset` groups + `TokenDelivery` (cookie/bearer/both)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 10.2, 10.3

#### Description

Wire the always-on `auth` and `password_reset` route groups (§8.2.1, §8.2.3) and the `TokenDelivery` helper that writes the auth outcome into the response per the configured mode (cookie / bearer / both) with the §14 secure-cookie attributes.

#### Acceptance criteria

- [ ] The `auth` group mounts `register`/`login`/`logout`/`refresh`/`me`/`verify-email`/`resend-verification` with the exact extractor composition and success codes from §8.2.1; `logout`/`me` require `AuthUser`, the rest are public; `refresh` reads the refresh token from the cookie or body.
- [ ] The `password_reset` group mounts `forgot-password`/`reset-password`/`verify-otp`/`resend-otp` (§8.2.3); `forgot-password`/`resend-otp` return the same status/body regardless of email existence.
- [ ] `TokenDelivery` (on `AuthState`, backed by the resolved §14 config) implements the three modes: `cookie` (set `access_token`, path-scoped `refresh_token`, non-HttpOnly `has_session`; body = safe user), `bearer` (no cookies; body = `{ user, access_token, refresh_token }`), `both`. Cookies are HttpOnly (except `has_session`) + Secure-by-default + refresh path-scoped; `SameSite` is per-cookie and explicit — `access_token` = `Lax`, `refresh_token` = `Strict`, `has_session` = `Lax` (§14.1/§14.5); `SameSite=None` without `Secure` is rejected at resolution.
- [ ] On the MFA-gated OAuth callback path the ephemeral `mfa_temp_token` cookie is planted (§14.1): name `mfa_temp_token`, path `/{route_prefix}/mfa`, HttpOnly, Secure-by-default, `SameSite` aligned with the refresh cookie, `Max-Age` 300 s (pinned to the MFA-temp JWT lifetime); it is consumed and cleared on a successful challenge.
- [ ] Cookie `Domain` follows §14.2: when `resolve_domains` is set it MUST validate the request host against a configured allowlist and only emit an allowlisted value; the library NEVER derives a registrable/parent domain from the `Host` header; when unset, no `Domain` is set (host-only).
- [ ] `logout` clears `access_token`, `refresh_token`, and `has_session` on **every** resolved domain, reusing the exact `Path`+`Domain` each cookie was set with (§14.3/§14.5 clear-on-logout fidelity) so no ghost cookie remains.
- [ ] Handlers call engine methods + `delivery.deliver(result)` — no hand-rolled cookies.
- [ ] E2E (testcontainers Redis): register→login→refresh→logout→me works in all three delivery modes with the correct cookie attributes; the anti-enum endpoints return identical responses for known vs unknown email.
- [ ] 100% coverage; wire parity (paths/codes/cookie names) with nest-auth.

#### Files to create / modify

- `crates/bymax-auth-axum/src/routes/{auth.rs,password_reset.rs}`
- `crates/bymax-auth-axum/src/delivery.rs`
- `crates/bymax-auth-axum/tests/auth_routes_e2e.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; handlers call engine methods and deliver tokens via a helper
that honors the configured mode (cookie/bearer/both) with secure cookies. Edition 2024; full parity
with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.4 of 7 (MIDDLE)

PRECONDITIONS
- Tasks 10.2/10.3 done: the extractors + DTOs.
- Phase 4/6: the engine flows `register`/`login`/`logout`/`refresh`/`me`/`verify_email`/`resend` and the
  `PasswordResetService` (forgot/reset/verify-otp/resend-otp). The resolved cookie/delivery config (§14)
  on `AuthState`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.2.1 (auth) + § 8.2.3 (password_reset) — the exact routes,
  extractors, and success codes.
- `docs/technical_specification.md` § 8.5 "Token delivery in handlers" + § 14 (cookie catalog, the three
  modes, §14.5 security constraints — `SameSite=None` ⇒ Secure).

TASK
Wire the `auth` + `password_reset` route groups and the `TokenDelivery` helper.

DELIVERABLES

1. `routes/auth.rs` — `auth_routes()` mounting §8.2.1 exactly (public vs `AuthUser`; refresh from
   cookie/body).
2. `routes/password_reset.rs` — `password_reset_routes()` mounting §8.2.3 (anti-enum identical responses
   for forgot/resend).
3. `delivery.rs` — `TokenDelivery::deliver(result) -> impl IntoResponse` for cookie/bearer/both;
   HttpOnly + Secure-default + refresh path-scoped + `SameSite`; the non-HttpOnly `has_session` cookie.
4. `tests/auth_routes_e2e.rs` — testcontainers: register→login→refresh→logout→me in all three modes
   with correct cookie attributes; anti-enum parity.

Constraints:
- No hand-rolled cookies — use `TokenDelivery`. `SameSite=None` without `Secure` is rejected at
  resolution. Wire contract (paths/codes/cookie names) matches nest-auth byte-for-byte.
  `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --test auth_routes_e2e` (with Docker) — expected: all modes pass.
- `cargo llvm-cov -p bymax-auth-axum --lcov` — expected: `routes/auth.rs`+`routes/password_reset.rs`+`delivery.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/7`. 5. Update the P10 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 10.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.5 — Optional groups: `mfa`/`sessions`/`platform`/`platform_mfa`/`oauth`/`invitations`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 10.3, 10.4

#### Description

Wire the remaining feature-gated route groups (§8.2.2, §8.2.4–§8.2.8) to their engine services, including the OAuth redirect-vs-JSON response shaping and the per-group feature gating.

#### Acceptance criteria

- [ ] `mfa` (§8.2.2): setup/verify-enable/challenge/disable/recovery-codes — `setup`/`verify-enable` take `AuthUser` **without** `MfaSatisfied` (enrolment), `challenge` is public.
- [ ] `sessions` (§8.2.4): list/revoke-all/revoke-`{id}` with `AuthUser`+`UserStatus`; Axum 0.8 `/{id}` braces; static `all` wins over the `{id}` capture.
- [ ] `platform` (§8.2.5) + `platform_mfa` (§8.2.6): login/mfa-challenge/me/logout/refresh/revoke-all and the platform MFA management routes, gated by `platform` (+ `mfa`).
- [ ] `oauth` (§8.2.7): `oauth_initiate` (302 to provider), `oauth_callback` shaping `OAuthOutcome` into 200-JSON or 302-redirect per the §11.3.3 table (success/mfa/error redirect URLs; the `?error=` short-code suffix); `ValidatedQuery` DTOs.
- [ ] `invitations` (§8.2.8): `create_invitation` (`AuthUser` + optional `RequireRole`, `tenant_id` from claims **never** the body) and public `accept`.
- [ ] Each group mounts only under its Cargo feature + runtime toggle; an off group contributes zero routes. E2E (testcontainers) exercises a representative endpoint per group (incl. the OAuth callback against a mock `HttpClient`). 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-axum/src/routes/{mfa.rs,sessions.rs,platform.rs,platform_mfa.rs,oauth.rs,invitations.rs}`
- `crates/bymax-auth-axum/tests/optional_groups_e2e.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; each optional controller is a feature- and toggle-gated route
group wired to an engine service. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.5 of 7 (MIDDLE — the broadest task)

PRECONDITIONS
- Tasks 10.3/10.4 done: all extractors, `TokenDelivery`, the always-on groups.
- Phases 6/7/8/9: the engine services behind each group — sessions, `MfaService`, the OAuth flow
  (`oauth_initiate`/`oauth_callback` + `OAuthOutcome`), `PlatformAuthService`, `InvitationService`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.2.2 / §8.2.4 / §8.2.5 / §8.2.6 / §8.2.7 / §8.2.8 — the exact
  routes/extractors/codes for each group, the `@SkipMfa` omission, the `/{id}` braces note, and the
  `tenant_id`-from-claims rule.
- `docs/technical_specification.md` § 11.3.3 — the OAuth `OAuthOutcome` → redirect-vs-JSON response table.

TASK
Wire the `mfa`/`sessions`/`platform`/`platform_mfa`/`oauth`/`invitations` route groups to their services.

DELIVERABLES

1. `routes/mfa.rs` (`#[cfg(feature = "mfa")]`) — §8.2.2 (setup/verify-enable without `MfaSatisfied`;
   public challenge).
2. `routes/sessions.rs` (`#[cfg(feature = "sessions")]`) — §8.2.4 (`AuthUser`+`UserStatus`; `/{id}` braces).
3. `routes/platform.rs` + `routes/platform_mfa.rs` (`platform`, +`mfa`) — §8.2.5/§8.2.6.
4. `routes/oauth.rs` (`#[cfg(feature = "oauth")]`) — §8.2.7 + the §11.3.3 redirect-vs-JSON shaping
   (success/mfa/error redirect URLs; `?error=` short-code suffix); `ValidatedQuery` DTOs.
5. `routes/invitations.rs` (`#[cfg(feature = "invitations")]`) — §8.2.8 (`tenant_id` from claims; public accept).
6. `tests/optional_groups_e2e.rs` — testcontainers: a representative endpoint per group (OAuth callback
   vs a mock `HttpClient`); an off-group mounts zero routes.

Constraints:
- Each group mounts only under its feature + runtime toggle. `create_invitation` derives `tenant_id`
  from the claims, never the body. OAuth redirect targets are operator-configured (never request-derived).
  `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only,
  timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --features "mfa sessions platform oauth invitations" --test optional_groups_e2e` (with Docker) — expected: all pass.
- `cargo llvm-cov -p bymax-auth-axum --features "mfa sessions platform oauth invitations" --lcov` — expected: route modules 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/7`. 5. Update the P10 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 10.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.6 — Per-route rate limiting (`tower_governor`) + `RateLimitConfig` + `Retry-After`

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 10.4

#### Description

Add per-route-group rate limiting via `tower_governor` with `RateLimitConfig` defaults mirroring nest-auth's `AUTH_THROTTLE_CONFIGS`, normalizing a throttle hit into the `auth.too_many_requests` (429) envelope with a `Retry-After` header.

#### Acceptance criteria

- [ ] `RateLimitConfig` exposes per-endpoint-class limits as `Option<RateLimit { burst, per_seconds }>` with `Default` reproducing the §16.3 `AUTH_THROTTLE_CONFIGS` values one-for-one: `login` 5/60s, `register` 10/3600s, `refresh` 10/60s, `forgot_password` 3/300s, `reset_password` 3/300s, `verify_otp` 3/300s, `resend_password_otp` 3/300s, `verify_email` 5/60s, `resend_verification` 3/300s, `mfa_setup` 5/60s, `mfa_verify_enable` 5/60s, `mfa_challenge` 5/60s, `mfa_disable` 3/300s, `platform_login` 5/60s, `invitation_create` 10/3600s, `invitation_accept` 5/60s, `list_sessions` 30/60s, `revoke_session` 10/60s, `revoke_all_sessions` 5/60s, `oauth_initiate` 10/60s, `oauth_callback` 10/60s. Platform and dashboard refresh share the `refresh` limit.
- [ ] The platform MFA-management routes (`/auth/platform/mfa/*`) reuse the dashboard MFA limits (`mfa_setup` / `mfa_verify_enable` / `mfa_disable`) rather than defining their own (§16.3).
- [ ] `tower_governor` layers are attached **per route group / endpoint class**, never as one global layer; the limiter keys on the edge IP.
- [ ] The client-IP key uses a **configurable** trusted-proxy / `X-Forwarded-For` strategy (settable on `AxumAuthConfig`, §16.2/§16.4): it does **not** trust a raw `X-Forwarded-For` by default; it uses the socket peer IP unless a trusted-proxy hop count / header is configured — preventing rate-limit bypass via a spoofed `X-Forwarded-For`.
- [ ] A throttle hit is normalized into the canonical `auth.too_many_requests` (429) JSON envelope with a `Retry-After` header (governor's retry interval) — not governor's default plaintext 429.
- [ ] Consumers can override the defaults via `RateLimitConfig`.
- [ ] `POST /auth/ws-ticket` is **not** assigned a dedicated edge limit in §16.3 (no `RateLimitConfig` field): it is an authenticated, `UserStatus`- and `MfaSatisfied`-gated route, not a credential-entry path — note this explicitly so the absence is a deliberate decision, not an oversight. (Consumers needing to cap mint volume add an outer-router limit per §16.4.)
- [ ] Tests: exceeding a route's limit returns 429 + `Retry-After` in the canonical envelope; a different route's limit is independent; an override changes the threshold.
- [ ] 100% coverage.

#### Files to create / modify

- `crates/bymax-auth-axum/src/rate_limit.rs`
- `crates/bymax-auth-axum/src/router.rs` (attach per-group governor layers)
- `crates/bymax-auth-axum/tests/rate_limit.rs`

#### Agent prompt

````
You are a senior Rust/Axum backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; rate limiting is per-route (mirroring nest-auth's per-handler
`@Throttle`), normalized into the canonical error envelope. Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.6 of 7 (MIDDLE)

PRECONDITIONS
- Task 10.4 done: the route groups + the `AuthError` `IntoResponse` (so the 429 envelope renders).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 16 "Rate Limiting" — §16.2 `tower_governor` per route group,
  §16.3 the `AUTH_THROTTLE_CONFIGS` defaults, §16.4 consumer overrides; the `auth.too_many_requests`
  (429) + `Retry-After` mapping.
- `docs/technical_specification.md` § 8.8 — rate-limit layers attach per route, NOT in the global stack.

TASK
Add per-route-group rate limiting with `tower_governor` + `RateLimitConfig`, normalized to the 429 envelope.

DELIVERABLES

1. `rate_limit.rs` — `RateLimitConfig` (per-endpoint-class limits; defaults mirroring `AUTH_THROTTLE_CONFIGS`)
   + the governor layer builder + the 429-envelope normalization (`auth.too_many_requests` + `Retry-After`).
2. `router.rs` — attach the per-group governor layers (NOT a global layer).
3. `tests/rate_limit.rs` — exceed a route limit → 429 + `Retry-After` (canonical envelope); independent
   per-route limits; override changes the threshold.

Constraints:
- Per-route attachment only — never one global layer. The 429 renders as the canonical
  `auth.too_many_requests` envelope, not governor's plaintext default. `#![forbid(unsafe_code)]`;
  `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --test rate_limit` — expected: 429 + Retry-After in the envelope.
- `cargo llvm-cov -p bymax-auth-axum --lcov` — expected: `rate_limit.rs` 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `6/7`. 5. Update the P10 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 10.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 10.7 — WS ticket endpoint + `WsAuthUser`/`WsAuthUserFromHeader` + full-router E2E

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 10.4, 10.5, 10.6

#### Description

Implement the `websocket`-gated WebSocket auth surface — the `POST /auth/ws-ticket` mint endpoint (composing `AuthUser`+`UserStatus`+`MfaSatisfied`), the single-use `WsAuthUser` (`GETDEL` redeem) and the `WsAuthUserFromHeader` extractors — and the full-router E2E proving every group end to end against real Redis.

#### Acceptance criteria

- [ ] `POST /auth/ws-ticket` composes `AuthUser` + `UserStatus` + `MfaSatisfied`, calls `AuthEngine::issue_ws_ticket` (opaque CSPRNG ticket, `wst:{sha256(ticket)}` snapshot, ~30 s TTL), and returns `{ ticket }` — the access token is read from cookie/header, **never** echoed into a URL.
- [ ] `WsAuthUser` reads the `ticket` query parameter and `GETDEL`s `wst:{sha256(ticket)}` (atomic single-use), reconstructing `DashboardClaims`; a missing/expired/already-redeemed ticket refuses the handshake (401). `WsAuthUserFromHeader` validates the access JWT in the handshake `Authorization` header (HS256-pinned, `type=dashboard`, `rv:` revocation) — never from the URL.
- [ ] All three (`ws-ticket`, `WsAuthUser`, `WsAuthUserFromHeader`) compile only under the `websocket` feature; with it off, none of the code exists.
- [ ] The single-use property holds: a second redemption of the same ticket is refused.
- [ ] A full-router E2E (testcontainers Redis) exercises every group — register/login/refresh/logout, MFA, sessions, the OAuth callback (mock `HttpClient`), platform, invitations — plus the WS ticket mint+redeem, asserting wire parity and that no token ever appears in a URL.
- [ ] 100% coverage across the adapter; `cargo deny check` passes.

#### Files to create / modify

- `crates/bymax-auth-axum/src/ws.rs` (`#[cfg(feature = "websocket")]`)
- `crates/bymax-auth-axum/src/routes/auth.rs` (mount `ws-ticket` under `websocket`)
- `crates/bymax-auth-axum/tests/full_router_e2e.rs` (testcontainers)

#### Agent prompt

````
You are a senior Rust/Axum/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the WebSocket upgrade is authenticated by a single-use,
short-lived ticket (never a JWT in the URL). Edition 2024; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 10 (Axum adapter) — Task 10.7 of 7 (LAST)

PRECONDITIONS
- Tasks 10.4–10.6 done: all route groups + delivery + rate limiting.
- Phase 5/7: `AuthEngine::issue_ws_ticket` + the `WsTicketStore` (`wst:{sha256(ticket)}` GETDEL, ~30 s
  TTL); the `AuthUser`/`UserStatus`/`MfaSatisfied` extractors (10.2/10.3).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 8.7 "WebSocket authentication" — the two-step mint/redeem flow,
  `WsAuthUser` (GETDEL) / `WsAuthUserFromHeader`, and the no-token-in-URL rationale.
- `docs/technical_specification.md` § 7.3.6 — `issue_ws_ticket`.
- `docs/technical_specification.md` § 24 — invariant 4 (no token in URL; the ticket is the sole exception).

TASK
Implement the `websocket`-gated WS auth surface (mint endpoint + the two extractors) and the
full-router E2E across every group.

DELIVERABLES

1. `ws.rs` (`#[cfg(feature = "websocket")]`) — the `ws_ticket` handler (composes
   `AuthUser`+`UserStatus`+`MfaSatisfied`, `issue_ws_ticket`, returns `{ ticket }`); `WsAuthUser`
   (read `ticket` query param, atomic `GETDEL`, reconstruct claims; 401 on miss/expired/replay);
   `WsAuthUserFromHeader` (access JWT in the handshake `Authorization` header — never the URL).
2. `routes/auth.rs` — mount `POST /auth/ws-ticket` under the `websocket` feature.
3. `tests/full_router_e2e.rs` — testcontainers: every group end to end (register/login/refresh/logout,
   MFA, sessions, OAuth callback vs mock `HttpClient`, platform, invitations) + WS ticket mint+redeem
   + single-use refusal; assert no token ever appears in a URL.

Constraints:
- The access JWT is NEVER read from a URL; the WS ticket is the sole single-use URL-borne credential.
  The WS surface compiles only under `websocket`. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; no
  `unwrap`/`expect`/`panic!`; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-axum --features "mfa sessions platform oauth invitations websocket" --test full_router_e2e` (with Docker) — expected: full stack passes; ticket single-use.
- `cargo deny check` — expected: passes.
- `cargo llvm-cov -p bymax-auth-axum --features "mfa sessions platform oauth invitations websocket" --lcov` — expected: adapter 100%.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `7/7`. 5. Update the P10 row in `docs/development_plan.md` (mark ✅ when all seven tasks are
done). 6. Recompute the overall %. 7. Append `- 10.7 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
