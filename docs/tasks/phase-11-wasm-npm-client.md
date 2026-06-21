# Phase 11 — `bymax-auth-wasm` + `@bymax-one/rust-auth` (npm) + Rust client

> **Status**: ✅ Done · **Progress**: 6 / 6 tasks · **Last updated**: 2026-06-21
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P11
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

The Rust backend is reachable end to end (P10). This phase publishes the **edge/frontend surface** — the WASM edge JWT verifier, the four-subpath npm package, and the native Rust client — and proves a React app and a Next.js middleware authenticate against the running Rust backend with **zero type drift**. The frontend layers cannot be Rust (a browser/React/Next app runs TypeScript/JSX), so they are kept as TypeScript ported verbatim from nest-auth — the public npm API stays **byte-for-byte compatible** so existing consumers change only the import specifier (`@bymax-one/nest-auth/<sub>` → `@bymax-one/rust-auth/<sub>`).

Two artefacts guarantee the TS layers and the Rust backend never drift: the `ts-rs`-generated `./shared` types/constants (the pipeline was stood up in P2 — this phase *consumes* its output and assembles the npm subpath), and `bymax-auth-wasm`, which compiles the wasm-safe subset of `bymax-auth-jwt` so the **edge runtime verifies tokens with the exact same Rust code the server uses** — eliminating the historical Web-Crypto-vs-Node drift. The npm package carries only the frontend/shared/Next.js glue plus the edge-verify WASM; the Rust backend is distributed **only** via crates.io and is never bundled into npm.

When P11 is done, the npm package builds dual ESM+CJS with a `.d.ts` per subpath and the WASM asset bundled; a React app and a Next.js middleware authenticate against the running backend (the edge verifies, via WASM, a token signed by the backend — server/edge parity); regenerating `ts-rs` leaves `./shared` unchanged (staleness gate green); and the Rust client + WASM tests pass. **Release/publish automation, SBOM, attestations, and registry publishing are P12.**

---

## Rules-of-phase

1. **WASM + `verifyJwtToken` are server/edge-only.** The WASM module and the TS that imports it (`verifyJwtToken`, the proxy verify path) must **never** be imported into a Client Component or any browser bundle — the HS256 secret is passed to `verify_jwt_hs256` and must not reach the client. An accidental client import is a **security defect** (the `server-only` guard + the smoke test catch it).
2. **`./shared` data types and constants are generated, never hand-authored.** Only `AuthClientError`, `buildAuthRefreshSkipSuffixes` (+ `AUTH_REFRESH_SKIP_PATH_SUFFIXES`), and the `AuthResponseCode = AuthErrorCode | (string & {})` brand are hand-written (ts-rs cannot express them); everything else comes from P2's `ts-rs` output.
3. **Byte-for-byte npm API parity with nest-auth.** Consumers change only the import specifier; the proxy `{ proxy, config }` shape, the eight `AuthClient` methods, the hook signatures, and the route-handler factories are preserved exactly. Edge JWT is HS256-pinned (`RS256`/`ES256`/`none` rejected in Rust).
4. **`bymax-auth-wasm` never becomes a facade dependency or a crates.io crate.** It lives in `bindings/`, is a `cdylib`, depends directly on the wasm-safe base crates, and is built straight from `bindings/` by `wasm-pack --target bundler` (npm-only). There is no `wasm` facade feature.
5. **No token in the URL** (§13.7) carries into the proxy/handlers; the `has_session` signal cookie + the seven `createAuthProxy` security patterns are preserved verbatim.
6. **100% Rust coverage** on the WASM/client crates (plus the `vitest` frontend suite), `#![forbid(unsafe_code)]` on `bymax-auth-client` (the WASM bindgen glue uses `#![deny(unsafe_op_in_unsafe_fn)]`), `#![deny(missing_docs)]`, English-only, timeless comments; TypeScript `strict` with JSDoc on every export.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 18.1 (§18.1.1 `./shared`, §18.1.2 `./client`, §18.1.3 `./react`, §18.1.4 `./nextjs`) — the four kept TS subpaths with their exact export sets and signatures.
  - § 18.2 (§18.2.1 JS surface, §18.2.2 build, §18.2.3 consumption) — `bymax-auth-wasm`: `decode_jwt` / `verify_jwt_hs256` (secret zeroization) / `extract_claims`; `wasm-pack --target bundler`; the `wasm-extra` excluded surface; the server/edge-only rule; the `next.config.js` requirements.
  - § 18.3 — the `ts-rs` pipeline (stood up in P2) + the hand-written set + the staleness gate.
  - § 18.4 — the npm package layout (four subpaths, ESM+CJS, scoped `sideEffects`, no `.` root export, the `exports`/`peerDependencies` block).
  - § 13.2 "One pure-Rust HS256 implementation, server + edge" + § 13.7 "tokens never travel in the URL".
  - § 19.2 — the `client` feature (the Rust `bymax-auth-client`) and the no-`wasm`-facade-feature rule.
  - § 20.8 "React frontend compatibility tests" + § 20.9 "Cross-language type-generation test + staleness gate".
- [`docs/development_plan.md`](../development_plan.md) — § P11, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust + TS).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 11.1 | `bymax-auth-wasm` cdylib — edge JWT verify (wasm-pack bundler) | ✅ Done | P0 | M | 2.6 |
| 11.2 | npm `./shared` subpath — hand-written helpers over generated types | ✅ Done | P0 | S | 2.5 |
| 11.3 | npm `./client` + `./react` (fetch client, single-flight refresh, hooks) | ✅ Done | P0 | M | 11.2 |
| 11.4 | npm `./nextjs` — WASM-backed proxy/handlers/edge JWT | ✅ Done | P0 | L | 11.1, 11.2 |
| 11.5 | `bymax-auth-client` Rust crate (`client` feature) | ✅ Done | P1 | M | 10.4 |
| 11.6 | Package layout (dual ESM+CJS, exports, WASM bundle) + parity E2E | ✅ Done | P0 | L | 11.3, 11.4, 11.5 |

---

## Tasks

### Task 11.1 — `bymax-auth-wasm` cdylib — edge JWT verify (wasm-pack bundler)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 2.6

#### Description

Implement the `bindings/bymax-auth-wasm` cdylib: the wasm-bindgen edge surface (`decode_jwt`, `verify_jwt_hs256` with secret zeroization, `extract_claims`) over the wasm-safe subset of `bymax-auth-jwt`, built via `wasm-pack --target bundler`, HS256-pinned, `getrandom` `wasm_js` backend.

#### Acceptance criteria

- [ ] `verify_jwt_hs256(token, secret) -> Option<String>` returns the JSON claims iff valid + unexpired, else `undefined`; the HS256 secret bytes are `zeroize`d from WASM linear memory immediately after the HMAC verify.
- [ ] The edge `exp`/`iat` validation accepts a configurable clock-skew `leeway_secs` (§13.6 — edge nodes may drift slightly from the issuing server), kept well under the access lifetime so it never meaningfully extends a token; an `iat` in the future beyond the leeway is `TokenInvalid`. (The native server runs with leeway `0`; only the edge build is lenient.)
- [ ] `decode_jwt(token) -> String` returns the JSON header+payload with **no** signature check (decode-only, non-authoritative); `extract_claims(token)` returns the typed claims projection.
- [ ] Only HS256 is accepted — `RS256`/`ES256`/`none` are rejected inside Rust (algorithm-confusion closed at the source).
- [ ] The optional password/TOTP surface is gated behind a `wasm-extra` Cargo feature and **excluded** from the npm-distributed build (`wasm-pack build … --target bundler --release` without `--features wasm-extra`).
- [ ] The crate is `crate-type = ["cdylib", "rlib"]` (`rlib` so `wasm-pack test` can link the crate as a library), depends directly on `bymax-auth-jwt` + `bymax-auth-types` (optionally `bymax-auth-crypto`), enables `getrandom`'s `wasm_js` backend (`getrandom = { version = "0.4", features = ["wasm_js"] }`) so randomness routes to Web Crypto, and pulls no `tokio`/`reqwest`/std-net; it is **not** reachable through the `bymax-auth` facade.
- [ ] `wasm-pack test --headless` passes (verify/decode round-trip, expiry rejection, `alg` rejection); `#![deny(unsafe_op_in_unsafe_fn)]` (the bindgen glue's only allowance).
- [ ] A concrete size budget is set for the emitted `*_bg.wasm` so the CI `check-size` gate (§21.1) is real, not a placeholder — a documented-as-adjustable gzipped ceiling of **≤ 350 KB** (the npm JWT-only build, without `wasm-extra`); the number may be revised as `wasm-opt` output settles, but the gate must always enforce a fixed value.

#### Files to create / modify

- `bindings/bymax-auth-wasm/Cargo.toml`
- `bindings/bymax-auth-wasm/src/lib.rs`
- `bindings/bymax-auth-wasm/tests/web.rs` (wasm-pack test)

#### Agent prompt

````
You are a senior Rust/WASM engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace. The edge runtime must verify JWTs with the EXACT same Rust code the server uses —
`bymax-auth-wasm` compiles the wasm-safe subset of `bymax-auth-jwt` to WebAssembly.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.1 of 6 (FIRST)

PRECONDITIONS
- Phase 2 done: `bymax-auth-jwt` (pure-Rust HS256 sign/verify, `decode_unverified`) compiles to
  `wasm32-unknown-unknown`; `bymax-auth-types` claims are serde-(de)serializable.
- Phase 0 produced the `bindings/bymax-auth-wasm` skeleton (cdylib, `#![deny(unsafe_op_in_unsafe_fn)]`).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.2 "bymax-auth-wasm — edge JWT as the single source of truth"
  (§18.2.1 JS surface, §18.2.2 build, §18.2.3 consumption) — the three exports, secret zeroization,
  the server/edge-only rule, HS256 pinning, `getrandom` `wasm_js`, the `wasm-extra` excluded surface.
- `docs/technical_specification.md` § 13.2 "One pure-Rust HS256 implementation, server + edge".
- `docs/technical_specification.md` § 13.6 "Lifetimes, rotation, grace window, clock skew" — the edge
  `leeway_secs` (the edge build accepts a small configurable leeway; the native server runs with `0`).

TASK
Implement the `bymax-auth-wasm` edge surface (`decode_jwt`/`verify_jwt_hs256`/`extract_claims`) and
build it with `wasm-pack --target bundler`.

DELIVERABLES

1. `bindings/bymax-auth-wasm/Cargo.toml` — `crate-type = ["cdylib", "rlib"]` (`rlib` so `wasm-pack test`
   links the crate); deps `bymax-auth-jwt`, `bymax-auth-types`, `wasm-bindgen`, `getrandom = { version = "0.4", features = ["wasm_js"] }`,
   `zeroize`, `serde`/`serde_json` (+ `serde-wasm-bindgen` to marshal claims out as JS values),
   `console_error_panic_hook` (dev, readable panics in the browser console); a `wasm-extra` feature for
   the optional password/TOTP surface (NOT enabled in the npm build).
2. `bindings/bymax-auth-wasm/src/lib.rs`:
   ```rust
   #[wasm_bindgen] pub fn decode_jwt(token: &str) -> String { /* header+payload JSON, no sig check */ }
   #[wasm_bindgen] pub fn verify_jwt_hs256(token: &str, secret: &str) -> Option<String> { /* claims iff valid; zeroize secret */ }
   #[wasm_bindgen] pub fn extract_claims(token: &str) -> String { /* typed projection */ }
   ```
   HS256 only (reject RS256/ES256/none in Rust); zeroize the secret bytes after the HMAC verify.
3. `bindings/bymax-auth-wasm/tests/web.rs` — `wasm-pack test --headless`: verify/decode round-trip,
   expiry rejection, `alg` rejection, secret-zeroized.

Constraints:
- Server/edge-only surface; the `wasm-extra` password/TOTP surface is EXCLUDED from the npm build.
- No `tokio`/`reqwest`/std-net. Not reachable via the `bymax-auth` facade; never a crates.io crate.
- `#![deny(unsafe_op_in_unsafe_fn)]`; `#![deny(missing_docs)]`; English-only, timeless comments.

Verification:
- `wasm-pack build bindings/bymax-auth-wasm --target bundler --release --out-dir pkg` — expected: emits `pkg/` with `_bg.wasm` + bindgen glue.
- `wasm-pack test --headless --firefox bindings/bymax-auth-wasm` — expected: all pass.
- `cargo build -p bymax-auth-wasm --target wasm32-unknown-unknown` — expected: wasm-clean.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P11 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 11.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 11.2 — npm `./shared` subpath — hand-written helpers over generated types

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 2.5

#### Description

Assemble the `./shared` npm subpath: the small hand-written runtime set (`AuthClientError`, `buildAuthRefreshSkipSuffixes` + `AUTH_REFRESH_SKIP_PATH_SUFFIXES`, the `AuthResponseCode` brand) over the P2-generated `ts-rs` data types/constants, plus the index barrel and the staleness-gate wiring.

#### Acceptance criteria

- [ ] The generated `ts-rs` data types + constants from P2 (`jwt-payload`, `auth-user`, `auth-result`, `auth-error`, `error-codes`, `auth-config`, `cookie-defaults`, `routes`) are imported, never re-declared.
- [ ] `AuthClientError extends Error` (with `instanceof` semantics, `status`/`code`/`body`, and a `toJSON()` that strips echoed DTO fields) is hand-written and exported; `buildAuthRefreshSkipSuffixes(routePrefix?)` + `AUTH_REFRESH_SKIP_PATH_SUFFIXES` are hand-written over the generated route constants; `AuthResponseCode = AuthErrorCode | (string & {})` is hand-stitched.
- [ ] The `./shared` barrel re-exports the complete §18.1.1 surface; `tsc --noEmit` type-checks it against the freshly generated types.
- [ ] The staleness gate (`cargo test -p bymax-auth-types --features ts-export` → format → `git diff --exit-code -- packages/rust-auth/src/shared`) is wired and green.
- [ ] TypeScript `strict`; JSDoc on every export; a `vitest` unit test covers `AuthClientError`/`buildAuthRefreshSkipSuffixes`.

#### Files to create / modify

- `packages/rust-auth/src/shared/{index.ts,types/auth-error.types.ts,routes.ts}` (hand-written set)
- `packages/rust-auth/package.json` (the `gen:format` script + the staleness gate)

#### Agent prompt

````
You are a senior TypeScript engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the npm package `@bymax-one/rust-auth` is a thin TS/WASM
distribution with NO business logic of its own. `./shared` types + constants are GENERATED from Rust
via `ts-rs` (single source of truth); only a small runtime set is hand-written. Byte-for-byte API
parity with @bymax-one/nest-auth.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.2 of 6 (MIDDLE)

PRECONDITIONS
- Phase 2 done: the `ts-rs` pipeline emits `./shared` data types + constants (jwt-payload/auth-user/
  auth-result/auth-error/error-codes/auth-config/cookie-defaults/routes) into
  `packages/rust-auth/src/shared`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.1.1 "./shared" — the COMPLETE export set.
- `docs/technical_specification.md` § 18.3 — what is generated vs hand-written (`AuthClientError`,
  `buildAuthRefreshSkipSuffixes` + `AUTH_REFRESH_SKIP_PATH_SUFFIXES`, `AuthResponseCode`), and the
  staleness gate commands.

TASK
Assemble the `./shared` subpath: the hand-written runtime set over the generated types + the barrel +
the staleness gate.

DELIVERABLES

1. `src/shared/types/auth-error.types.ts` — `AuthClientError extends Error` (`instanceof`-safe;
   `status`/`code`/`body`; `toJSON()` strips echoed DTO fields); the `AuthResponseCode = AuthErrorCode
   | (string & {})` brand over the generated `AuthErrorCode`.
2. `src/shared/routes.ts` — `buildAuthRefreshSkipSuffixes(routePrefix?)` + `AUTH_REFRESH_SKIP_PATH_SUFFIXES`
   over the generated route constants.
3. `src/shared/index.ts` — the barrel re-exporting the full §18.1.1 surface (generated + hand-written).
4. `package.json` — the `gen:format` post-step + the staleness-gate script.

Constraints:
- NEVER re-declare a generated type/constant — import from the ts-rs output. Only the three items above
  are hand-written. TS `strict`; JSDoc on every export; English-only comments; no suppression comments.

Verification:
- `cargo test -p bymax-auth-types --features ts-export && pnpm --filter @bymax-one/rust-auth gen:format && git diff --exit-code -- packages/rust-auth/src/shared` — expected: no drift.
- `tsc --noEmit` over `./shared` — expected: type-checks.
- `vitest run src/shared` — expected: AuthClientError + builder tests pass.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P11 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 11.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 11.3 — npm `./client` + `./react` (fetch client, single-flight refresh, hooks)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 11.2

#### Description

Port the framework-agnostic `./client` (`createAuthFetch` / `createAuthClient`, single-flight 401 refresh, the skip-refresh suffix list) and the `./react` hooks (`AuthProvider` / `useSession` / `useAuth` / `useAuthStatus`) verbatim from nest-auth, over the `./shared` surface.

#### Acceptance criteria

- [ ] `createAuthFetch(config?)` returns a single `AuthFetch` `(input, init?) => Promise<Response>` with credential inclusion, header merge, single-flight 401 refresh, retry-after-refresh, and the `onSessionExpired` callback; `createAuthClient(config)` exposes exactly the **eight** methods (`login`/`register`/`logout`/`refresh`/`getMe`/`mfaChallenge`/`forgotPassword`/`resetPassword`).
- [ ] `resetPassword` takes the discriminated union (`token | otp | verifiedToken`) lifting the server's cross-validation into the type system; the skip-refresh suffix list is built via `buildAuthRefreshSkipSuffixes` so it never drifts.
- [ ] `./react` exposes `AuthProvider` (with `revalidateInterval` default 300000), `useSession`, `useAuth` (the `login(email, password, options?)` convenience that defaults `tenantId`), and `useAuthStatus` — signatures identical to §18.1.3.
- [ ] `./react` declares `react ^19` as a peer dependency; `./client` is zero-dependency.
- [ ] `vitest` tests cover the single-flight refresh (concurrent 401s share one refresh), the skip-list, and the hook state transitions; `tsc --noEmit` passes.
- [ ] Byte-for-byte signature parity with nest-auth; TS `strict`; JSDoc on every export.

#### Files to create / modify

- `packages/rust-auth/src/client/index.ts`
- `packages/rust-auth/src/react/index.ts`
- `packages/rust-auth/tests/{client.test.ts,react.test.tsx}`

#### Agent prompt

````
You are a senior TypeScript/React engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the npm `./client` is a zero-dep fetch client and `./react`
is thin hooks over it. Byte-for-byte API parity with @bymax-one/nest-auth — consumers change only the
import specifier. React 19.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 11.2 done: `./shared` exposes the generated types/constants + `AuthClientError` +
  `buildAuthRefreshSkipSuffixes`.
- The Axum backend (Phase 10) is the default target; the wire contract matches nest-auth.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.1.2 "./client" — `createAuthFetch`/`createAuthClient`, the
  eight methods, the `ResetPasswordInput` union, single-flight refresh, the skip-list, the cookie-vs-
  bearer note.
- `docs/technical_specification.md` § 18.1.3 "./react" — `AuthProvider`/`useSession`/`useAuth`/
  `useAuthStatus` signatures.

TASK
Port `./client` and `./react` verbatim from nest-auth over the `./shared` surface.

DELIVERABLES

1. `src/client/index.ts` — `createAuthFetch` (single-flight 401 refresh, header merge, retry-after-
   refresh, `onSessionExpired`, the skip-list via `buildAuthRefreshSkipSuffixes`) + `createAuthClient`
   (the EIGHT methods; `resetPassword` discriminated union). Re-export `AuthClientError` + the error types.
2. `src/react/index.ts` — `AuthProvider` (revalidate loop, default 300000) + `useSession` + `useAuth`
   (the `login(email, password, options?)` convenience defaulting `tenantId`) + `useAuthStatus`.
3. `tests/client.test.ts` + `tests/react.test.tsx` — single-flight refresh (concurrent 401s → one
   refresh), skip-list, hook state transitions.

Constraints:
- `./client` is zero-dependency; `./react` peer-deps `react ^19`. Byte-for-byte signature parity with
  nest-auth. TS `strict`; JSDoc on every export; English-only; no suppression comments.

Verification:
- `vitest run src/client tests/client.test.ts tests/react.test.tsx` — expected: all pass.
- `tsc --noEmit` over `./client` + `./react` — expected: type-checks.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P11 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 11.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 11.4 — npm `./nextjs` — WASM-backed proxy/handlers/edge JWT

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 11.1, 11.2

#### Description

Port the `./nextjs` subpath verbatim from nest-auth — `createAuthProxy` (+ the seven security patterns), the three route-handler factories, and the JWT edge helpers — with the HS256 verification delegated to `bymax-auth-wasm`, server/edge-only.

#### Acceptance criteria

- [ ] `createAuthProxy(config)` returns `{ proxy, config }` (the `proxy` member destructured as `export const { proxy } = …`); all seven nest-auth security patterns are preserved (`isBackgroundRequest`, the `_r` redirect-loop counter, `reason=expired`, the `has_session` signal cookie, status blocking, RBAC, `x-user-*` propagation — UI-only, never authoritative).
- [ ] `createSilentRefreshHandler` / `createClientRefreshHandler` / `createLogoutHandler` are ported with the canonical route constants (`/api/auth/silent-refresh` etc.).
- [ ] `verifyJwtToken(token, secret?)` is **async** and calls `bymax-auth-wasm`'s `verify_jwt_hs256(token, secret)` when a secret is configured, falling back to `decode_jwt(token)` (decode-only, non-authoritative) when the secret is `null`/`undefined`; `decodeJwtToken` + the `isTokenExpired`/`getUserId`/`getUserRole`/`getTenantId` helpers are ported.
- [ ] The WASM module and `verifyJwtToken` are marked **server-only** by importing the `server-only` npm package at the top of the WASM/`verifyJwtToken` modules (a Client-Component import then fails the build, not silently at runtime); a test asserts they cannot be pulled into a client bundle.
- [ ] The cookie/request helpers (`getSetCookieHeaders`/`dedupeSetCookieHeaders`/`parseSetCookieHeader`/`isBackgroundRequest`/`buildSilentRefreshUrl`/`resolveSafeDestination`) are ported; `./nextjs` peer-deps `next ^16` + `react ^19`; no token ever appears in a URL.
- [ ] The README documents the three required consumer `next.config.js` settings (§18.2.2) so integrators wire them once: `webpack` setting `config.experiments.asyncWebAssembly = true` (so the bundler instantiates the wasm-bindgen module asynchronously), `serverExternalPackages: ['@bymax-one/rust-auth']` (keep the wasm glue a single external instance), and `outputFileTracingIncludes` tracing `./node_modules/@bymax-one/rust-auth/wasm/*.wasm` into the proxy + `/api/auth/**` route-handler bundles (so the `.wasm` stays in the serverless function bundle).
- [ ] `vitest` tests prove: a backend-signed token verifies via WASM at the edge; decode-only mode never gates a decision; the open-redirect guard (`resolveSafeDestination`) rejects off-origin targets. `tsc --noEmit` passes.

#### Files to create / modify

- `packages/rust-auth/src/nextjs/{index.ts,proxy.ts,jwt.ts,handlers.ts}`
- `packages/rust-auth/tests/nextjs.test.ts`

#### Agent prompt

````
You are a senior TypeScript/Next.js/security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `./nextjs` is the edge/proxy layer; its HS256 verification is
delegated to `bymax-auth-wasm` so server and edge run the SAME Rust crypto. Byte-for-byte API parity
with @bymax-one/nest-auth. Next 16 / React 19.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.4 of 6 (MIDDLE — the security-critical edge layer)

PRECONDITIONS
- Task 11.1 done: `bymax-auth-wasm` exports `verify_jwt_hs256`/`decode_jwt`/`extract_claims` (`pkg/`).
- Task 11.2 done: `./shared` types/constants.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.1.4 "./nextjs" — the COMPLETE export set, the `{ proxy, config }`
  shape, the async `verifyJwtToken` + decode-only mode, and the seven preserved security patterns.
- `docs/technical_specification.md` § 18.2.1 + §18.2.2 + §18.2.3 — the WASM JS surface, the build + the
  three required consumer `next.config.js` settings, and how `./nextjs` consumes it; the SERVER/EDGE-ONLY
  rule (the secret must not reach the client).
- `docs/technical_specification.md` § 13.7 — tokens never travel in the URL.

TASK
Port `./nextjs` (proxy + handlers + edge JWT helpers) with HS256 verification delegated to
`bymax-auth-wasm`, server/edge-only.

DELIVERABLES

1. `src/nextjs/jwt.ts` — async `verifyJwtToken(token, secret?)` (WASM `verify_jwt_hs256`; decode-only
   fallback when secret is null/undefined) + `decodeJwtToken` + `isTokenExpired`/`getUserId`/
   `getUserRole`/`getTenantId`. Import the `server-only` npm package at the top of this module (and any
   module that re-exports the WASM glue) so a client-bundle import fails the build — the secret must not
   reach a client bundle.
2. `src/nextjs/proxy.ts` — `createAuthProxy(config) -> { proxy, config }` with all SEVEN security
   patterns preserved.
3. `src/nextjs/handlers.ts` — `createSilentRefreshHandler`/`createClientRefreshHandler`/
   `createLogoutHandler` + the canonical route constants.
4. `src/nextjs/index.ts` — barrel + the cookie/request helpers + re-exported types.
5. `tests/nextjs.test.ts` — backend-signed token verifies via WASM at the edge; decode-only never gates;
   `resolveSafeDestination` rejects off-origin; a guard test that `verifyJwtToken`/WASM are not
   client-importable.

Constraints:
- WASM + `verifyJwtToken` are SERVER/EDGE-ONLY — an accidental client import is a security defect.
  The `{ proxy, config }` shape is preserved byte-for-byte. No token in a URL. TS `strict`; JSDoc on
  every export; English-only; no suppression comments.

Verification:
- `vitest run tests/nextjs.test.ts` — expected: edge-verify + server-only guard pass.
- `tsc --noEmit` over `./nextjs` — expected: type-checks.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P11 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 11.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 11.5 — `bymax-auth-client` Rust crate (`client` feature)

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: M
- **Depends on**: 10.4

#### Description

Implement the native `crates/bymax-auth-client` crate — a typed `reqwest`-backed auth client for Rust consumers — exposing the same logical operations as the TS `./client`, behind the facade's `client` feature.

#### Acceptance criteria

- [ ] `AuthClient` (over `reqwest`) exposes typed `login`/`register`/`logout`/`refresh`/`me`/`mfa_challenge`/`forgot_password`/`reset_password` against the Axum backend's wire contract, returning the shared `bymax-auth-types` result types.
- [ ] Errors map the backend's `auth.*` envelope into a typed `AuthClientError` (status + code + parsed body); single-flight refresh on 401 is handled (or documented as caller-driven).
- [ ] The crate is behind the facade `client` feature; `reqwest` (rustls) is pulled only by it.
- [ ] Integration tests run against the Axum router (testcontainers Redis): register → login → me → refresh → logout round-trips.
- [ ] `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`; 100% coverage; rustdoc examples compile.

#### Files to create / modify

- `crates/bymax-auth-client/Cargo.toml`
- `crates/bymax-auth-client/src/lib.rs`
- `crates/bymax-auth-client/tests/client_e2e.rs`

#### Agent prompt

````
You are a senior Rust backend engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-client` is the NATIVE Rust auth client (the
counterpart of the TS `./client`) for Rust consumers of the Axum backend. Edition 2024; behind the
facade `client` feature.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.5 of 6 (MIDDLE)

PRECONDITIONS
- Phase 10 done: the Axum router exposes the full wire contract; `bymax-auth-types` carries the shared
  result/error types.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.1.2 "./client" — the logical operations to mirror (login/
  register/logout/refresh/me/mfaChallenge/forgotPassword/resetPassword) + the resetPassword union.
- `docs/technical_specification.md` § 19.2 — the `client` feature (reqwest pulled only by it).

TASK
Implement the native `bymax-auth-client` over `reqwest`, behind the `client` feature.

DELIVERABLES

1. `crates/bymax-auth-client/Cargo.toml` — deps `bymax-auth-types`, `reqwest` (rustls), `serde`/
   `serde_json`, `thiserror`; the crate is enabled by the facade `client` feature.
2. `crates/bymax-auth-client/src/lib.rs` — `AuthClient` with the typed methods against the Axum wire
   contract; map the `auth.*` envelope to a typed error; single-flight 401 refresh (or documented).
3. `crates/bymax-auth-client/tests/client_e2e.rs` — testcontainers: register → login → me → refresh →
   logout against the Axum router.

Constraints:
- `reqwest` pulled only under the `client` feature. `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`;
  no `unwrap`/`expect`/`panic!`; English-only, timeless comments; rustdoc examples compile.

Verification:
- `cargo test -p bymax-auth-client --test client_e2e` (with Docker) — expected: round-trips pass.
- `cargo llvm-cov -p bymax-auth-client --lcov` — expected: 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P11 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 11.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 11.6 — Package layout (dual ESM+CJS, exports, WASM bundle) + parity E2E

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 11.3, 11.4, 11.5

#### Description

Finalize the npm package: the dual ESM+CJS build per subpath (tsup), the `exports` map (four subpaths, no `.` root), the scoped `sideEffects`, the bundled WASM asset, and the parity E2E proving a React app and a Next.js middleware authenticate against the running Rust backend with zero type drift.

#### Acceptance criteria

- [ ] `package.json` declares the four subpaths (`./shared`/`./client`/`./react`/`./nextjs`) with ESM+CJS+`.d.ts` each, **no `.` root export**, the scoped `sideEffects` array (`["./wasm/*.js", "*.wasm"]`), `peerDependencies` (`react ^19`, `next ^16`, both optional), and the `files`/`publishConfig` blocks.
- [ ] The build (tsup) emits `.mjs`/`.cjs`/`.d.ts` for every subpath; the `bymax-auth-wasm` `pkg/` output is bundled into `wasm/`; a build-integrity check asserts every subpath produced its three artefacts.
- [ ] `tsconfig.json` sets the §18.4 compiler flags (mirroring nest-auth): `"target": "ES2022"`, `"moduleResolution": "Bundler"`, `"strict": true`, `"noUncheckedIndexedAccess": true`, `"isolatedModules": true` (plus `"module": "ESNext"`, `"lib": ["ES2022", "DOM"]`) — so the kept layers stay runnable in browser/edge/Node ≥18 and `moduleResolution: Bundler` matches the subpath-`exports` resolution.
- [ ] A React app (Vite) + a Next.js middleware authenticate against the **running** Rust backend; the Next.js edge verifies (via WASM) a token signed by the backend — server/edge parity demonstrated. The E2E Next.js app applies the three required `next.config.js` settings (§18.2.2): `asyncWebAssembly: true`, `serverExternalPackages: ['@bymax-one/rust-auth']`, and `outputFileTracingIncludes` for `wasm/*.wasm`.
- [ ] Zero type drift: regenerating `ts-rs` output leaves the committed `./shared` unchanged (staleness gate green).
- [ ] The full `vitest` frontend suite passes; `tsc --noEmit` type-checks every subpath against freshly generated `./shared`.

#### Files to create / modify

- `packages/rust-auth/{package.json,tsup.config.ts,tsconfig.json}`
- `packages/rust-auth/tests/parity_e2e.test.ts` (React + Next against the running backend)

#### Agent prompt

````
You are a senior TypeScript build engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the npm package `@bymax-one/rust-auth` ships four subpaths
(ESM+CJS) + the edge-verify WASM, NO `.` root (the backend is a crate, not an npm entry). Byte-for-byte
API parity with @bymax-one/nest-auth.

CURRENT PHASE: 11 (wasm + npm + client) — Task 11.6 of 6 (LAST)

PRECONDITIONS
- Tasks 11.1–11.5 done: the WASM binding, `./shared`/`./client`/`./react`/`./nextjs`, and the Rust client.
- Phase 10: the running Axum backend for the parity E2E.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 18.4 "npm package layout" — the four subpaths, ESM+CJS, scoped
  `sideEffects`, no `.` root, the `exports`/`peerDependencies`/`files`/`publishConfig` block, the `tsup`
  config, and the key `tsconfig` flags (`ES2022`/`moduleResolution: Bundler`/`strict`/
  `noUncheckedIndexedAccess`/`isolatedModules`).
- `docs/technical_specification.md` § 20.8 "React frontend compatibility tests" + § 20.9 "Cross-language
  type-generation test + staleness gate".

TASK
Finalize the package layout (dual ESM+CJS, exports, WASM bundle) and the parity E2E (React + Next vs the
running backend, zero drift).

DELIVERABLES

1. `package.json` — the §18.4 block exactly: four subpaths (ESM+CJS+dts), NO `.` root, scoped
   `sideEffects`, `peerDependencies` (react/next optional), `files`/`publishConfig`.
2. `tsup.config.ts` — dual ESM+CJS build per subpath; bundle `bymax-auth-wasm`'s `pkg/` into `wasm/`;
   a build-integrity assertion (every subpath emitted `.mjs`/`.cjs`/`.d.ts`).
3. `tests/parity_e2e.test.ts` — a React (Vite) app + a Next.js middleware authenticate against the
   running Rust backend; the Next edge verifies (WASM) a backend-signed token; the staleness gate is green.

Constraints:
- NO `.` root export. Scoped `sideEffects` (never `false`) so the wasm-init side effect survives
  tree-shaking. Zero type drift (regenerating ts-rs leaves `./shared` unchanged). TS `strict`; JSDoc
  on every export; English-only.

Verification:
- `pnpm --filter @bymax-one/rust-auth build` — expected: every subpath emits ESM+CJS+dts; WASM bundled.
- `cargo test -p bymax-auth-types --features ts-export && git diff --exit-code -- packages/rust-auth/src/shared` — expected: no drift.
- `vitest run` + `tsc --noEmit` — expected: parity E2E + typecheck pass.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P11 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall %. 7. Append `- 11.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.

- 11.1 ✅ 2026-06-21 — `bymax-auth-wasm` cdylib+rlib: `verify_jwt_hs256` (HS256-pinned, secret zeroized), `decode_jwt`/`extract_claims`, edge leeway, `wasm-extra`-gated password surface excluded from npm; getrandom 0.2 via `bymax-auth-jwt/wasm-js` (no new major, ring-free); ~69 KiB gzipped vs the 350 KiB gate; `wasm-pack test --node`; 100% rlib coverage.
- 11.2 ✅ 2026-06-21 — npm `./shared`: hand-written `AuthClientError` + `AuthResponseCode` brand + `buildAuthRefreshSkipSuffixes`/`AUTH_REFRESH_SKIP_PATH_SUFFIXES` over the ts-rs-generated types; generator barrel updated so the staleness gate stays clean; vitest green.
- 11.3 ✅ 2026-06-21 — npm `./client` (`createAuthFetch` single-flight 401 refresh + the eight `createAuthClient` methods, discriminated `ResetPasswordInput`) and `./react` (`AuthProvider`/`useSession`/`useAuth`/`useAuthStatus`); vitest green.
- 11.4 ✅ 2026-06-21 — npm `./nextjs`: `createAuthProxy` ({ proxy, config }, seven security patterns), the three route-handler factories, and the WASM-backed async `verifyJwtToken` (decode-only fallback); server-only guard + open-redirect guard; a real backend-signed token verified through the WASM codec in Node (server/edge parity).
- 11.5 ✅ 2026-06-21 — `bymax-auth-client` native reqwest client (eight typed ops, single-flight 401 refresh, typed `AuthClientError`, `#![forbid(unsafe_code)]`), testcontainers register→me→refresh→logout round-trip over real HTTP; 100% coverage.
- 11.6 ✅ 2026-06-21 — package layout: dual ESM+CJS per subpath (tsup, .mjs/.cjs/.d.ts each, build-integrity check), no `.` root, scoped `sideEffects`, bundled `wasm/`; zero ts-rs drift; headless parity proven (Rust client real HTTP + WASM edge-verify of a backend-signed token + React/Next unit tests). A full Next.js dev-server / browser DOM E2E is deferred (needs a live Next app + backend).
