<p align="center">
  <img src="https://img.shields.io/badge/%40bymax--one-rust--auth-000000?style=for-the-badge&logo=rust&logoColor=white" alt="bymax-auth / @bymax-one/rust-auth" />
</p>

<h1 align="center">bymax-auth · @bymax-one/rust-auth</h1>

<p align="center">
  <strong>Full-stack authentication for Rust (Axum), React & Next.js</strong><br />
  <sub>JWT · MFA · OAuth · Sessions · Multi-Tenant · Pure-Rust Crypto · WebAssembly Edge Verification</sub>
</p>

<p align="center">
  <a href="https://crates.io/crates/bymax-auth"><img src="https://img.shields.io/crates/v/bymax-auth?style=flat-square&colorA=000000&colorB=000000&label=crates.io" alt="crates.io version" /></a>
  <a href="https://crates.io/crates/bymax-auth"><img src="https://img.shields.io/crates/d/bymax-auth?style=flat-square&colorA=000000&colorB=000000" alt="crates.io downloads" /></a>
  <a href="https://www.npmjs.com/package/@bymax-one/rust-auth"><img src="https://img.shields.io/npm/v/@bymax-one/rust-auth?style=flat-square&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://docs.rs/bymax-auth"><img src="https://img.shields.io/docsrs/bymax-auth?style=flat-square&colorA=000000&label=docs.rs" alt="docs.rs" /></a>
  <a href="https://github.com/bymaxone/rust-auth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/bymaxone/rust-auth/ci.yml?branch=main&style=flat-square&colorA=000000&label=CI" alt="CI status" /></a>
  <a href="https://github.com/bymaxone/rust-auth/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-pre--release-lightgrey?style=flat-square&colorA=000000" alt="coverage" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/bymaxone/rust-auth"><img src="https://api.scorecard.dev/projects/github.com/bymaxone/rust-auth/badge?style=flat-square" alt="OpenSSF Scorecard" /></a>
  <a href="https://rustsec.org/"><img src="https://img.shields.io/badge/audit-RustSec-000000?style=flat-square" alt="RustSec audit" /></a>
  <a href="https://github.com/bymaxone/rust-auth/attestations"><img src="https://img.shields.io/badge/provenance-attested-000000?style=flat-square" alt="build provenance" /></a>
  <a href="https://github.com/bymaxone/rust-auth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/bymaxone/rust-auth?style=flat-square&colorA=000000&colorB=000000" alt="license" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-edition%202024-000000?style=flat-square&logo=rust&logoColor=white" alt="Rust edition 2024" /></a>
</p>

<p align="center">
  <a href="https://github.com/bymaxone/rust-auth">GitHub</a> ·
  <a href="https://github.com/bymaxone/rust-auth/issues">Issues</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="https://docs.rs/bymax-auth">docs.rs</a> ·
  <a href="#-api-reference">API Reference</a> ·
  <a href="./examples">Examples</a>
</p>

---

> [!IMPORTANT]
> **🚧 Early development.** This repository is under active construction. The crates are **not yet published** to crates.io or npm, and the API described below is the **target surface** the project is building toward — not all of it exists yet. Badges, version numbers, and install commands reflect the intended 1.0 release. See the [development plan](docs/development_plan.md) for current status.

## ✨ Overview

`bymax-auth` is a **complete authentication and authorization solution** shipped as a lean Cargo workspace (crates.io) **plus** a matching npm package — covering everything from an Axum backend to React hooks, Next.js route handlers, and an edge JWT verifier compiled to **WebAssembly**.

Instead of stitching together a dozen crates and packages for JWT, MFA, OAuth, sessions, password reset, and brute-force protection, you add one library and get a production-ready auth system that spans your entire stack — with the frontend types **generated from the Rust source**, so the server and the client can never drift.

### Why bymax-auth?

- **🎯 One workspace, full stack** — A backend crate (`bymax-auth`) and an npm package (`@bymax-one/rust-auth`) in lockstep. Shared types and constants are generated from Rust via [`ts-rs`](https://github.com/Aleph-Alpha/ts-rs) and re-checked in CI — **zero manual synchronization, zero drift**.
- **🔌 Your database, your rules** — The library defines async traits (`UserRepository`, `EmailProvider`). You implement them with `sqlx`, `SeaORM`, `Diesel`, or anything else. No ORM dependency, no driver baked in.
- **🦀 Pure-Rust crypto only** — Password hashing, MFA encryption, TOTP, and token generation run entirely on [RustCrypto](https://github.com/RustCrypto) (`scrypt`, `argon2`, `aes-gcm`, `hmac`, `sha2`, `subtle`). **No `ring`, no OpenSSL, no C bindings**, and `#![forbid(unsafe_code)]` on every first-party crate.
- **⚡ Pay for what you use** — A tiny always-compiled core; every heavy integration (Redis, Axum, `reqwest`, MFA) is a Cargo feature or a trait you plug. A per-feature dependency budget is enforced in CI, so a minimal build pulls a minimal tree.
- **🏢 Multi-tenant ready** — Every operation is scoped by `tenant_id`, taken from a resolver and **never the request body**. A separate platform-admin identity domain is isolated from tenant users from day one.
- **🌐 Edge-native** — The exact same HS256 verifier that runs on the server compiles to `wasm32-unknown-unknown` and runs in the **Next.js Edge runtime with no network call** — one implementation, server and edge, proven by tests.

```bash
cargo add bymax-auth --features "argon2,sessions,mfa,oauth,oauth-reqwest,redis,axum"
pnpm add @bymax-one/rust-auth
```

> [!NOTE]
> **Production status.** **Bymax Live** — a Rust-backend + React/Next.js application — is the project's first production consumer (the dogfood target). It will run the library as its authentication and authorization layer (sessions, MFA, OAuth, platform admin, Redis), so the wire contract, the security invariants, and server/edge JWT parity are validated against real traffic rather than synthetic tests alone.

---

## 🔥 Features

### 🔐 Core Authentication

- ✅ **Registration & Login** — Email/password hashed with **scrypt _and_ Argon2id** (configurable, rehash-on-verify, self-describing PHC strings)
- ✅ **HS256 Access + Opaque Refresh Tokens** — Atomic rotation with a grace window for concurrent requests; refresh tokens are opaque and never JWTs
- ✅ **Multi-Factor Authentication** — TOTP with `otpauth://` URI + QR, hashed recovery codes, and a temp-token challenge flow
- ✅ **OAuth 2.0** — Google built-in, PKCE + single-use `state`, account create/link/reject decisioning, MFA branch
- ✅ **Password Reset** — Token-link **or** OTP, configurable per deployment, uniformly anti-enumerating
- ✅ **Email Verification** — OTP-based with atomic resend cooldown

### 🛡️ Security

- ✅ **Pure-Rust Crypto** — RustCrypto only (scrypt/Argon2id, AES-256-GCM, HMAC-SHA1 TOTP, HS256); no `ring`/OpenSSL/C on any path
- ✅ **Brute-Force Protection** — Fixed-window Redis counters keyed on `HMAC(tenant:email)` — no PII in keys
- ✅ **Session Management** — Active-session tracking with FIFO eviction, device/IP metadata, and new-session alerts
- ✅ **HttpOnly Cookies** — `Secure`-by-default, refresh cookie path-scoped with `SameSite=Strict`, plus a non-HttpOnly `has_session` signal
- ✅ **Constant-Time Comparisons** — Every secret/token/OTP/recovery-code compare goes through `subtle` — never `==` on secret bytes
- ✅ **JWT Revocation** — Instant access-token revocation via a Redis `jti` blacklist
- ✅ **Anti-Enumeration** — Identical status, body, and timing for known vs. unknown accounts, with an always-run sentinel hash

### 🏢 Multi-Tenant & Platform

- ✅ **Tenant Isolation** — All operations scoped by `tenant_id` via a configurable `TenantIdResolver` (anti-spoofing: the body is ignored)
- ✅ **Platform Admin Auth** — A separate identity domain with its own claims, sessions, and role hierarchy — fully isolated from tenant users
- ✅ **User Invitations** — Single-use tokenized invites with role + tenant assignment and re-validation on accept
- ✅ **Role-Based Access Control** — Hierarchical roles enforced by the `RequireRole<R>` extractor

### 🧩 Developer Experience

- ✅ **Full-Stack Typed** — Rust domain types → TypeScript via `ts-rs`, drift-gated in CI
- ✅ **Two Published Artifacts** — `bymax-auth` on crates.io, `@bymax-one/rust-auth` on npm, versioned in lockstep
- ✅ **Builder + Validated Config** — Assemble the engine with `AuthEngineBuilder`; `build()` fails fast with a typed `ConfigError`
- ✅ **Trait-Pluggable** — Bring your own database, email transport, HTTP client, and stores
- ✅ **Axum-Native Extractors** — `FromRequestParts` guards (`AuthUser`, `RequireRole<R>`, …) — no middleware soup, no Passport equivalent

---

## 📦 Two Packages, One Workspace

The backend ships on **crates.io**; the frontend ships on **npm**. The WebAssembly edge verifier is bundled inside the npm package (never published as a standalone crate).

### Backend — `bymax-auth` (crates.io)

A thin facade over a set of focused internal crates. You enable only the capabilities you need; the always-compiled core stays tiny.

| Feature          | Enables                                                                   |
| ---------------- | ------------------------------------------------------------------------- |
| `scrypt` *(default)* | Default password KDF (parity baseline) — drop-in scrypt                |
| `argon2`         | Argon2id KDF + the hardened `AuthConfig::secure_defaults()` profile        |
| `sessions`       | Redis-backed session tracking + FIFO eviction                              |
| `mfa`            | TOTP setup/verify/challenge, recovery codes (AES-256-GCM secret at rest)   |
| `oauth`          | OAuth 2.0 + PKCE orchestration (transport injected — **zero HTTP deps**)   |
| `oauth-reqwest`  | Bundled `reqwest`-backed `HttpClient` (opt-in; omit to supply your own)    |
| `platform`       | Platform-admin identity domain (login/MFA/sessions)                        |
| `invitations`    | Tokenized user invitations                                                 |
| `redis`          | Canonical Redis stores (`redis` + `deadpool-redis`) with atomic Lua        |
| `axum`           | HTTP router, extractors, DTO validation, cookie delivery, per-route rate limiting, WebSocket tickets |
| `client`         | Native Rust typed auth client                                              |
| `full`           | Every backend feature above                                                |

> [!NOTE]
> There is **no `core` feature** — the engine is always compiled and individual flows are runtime toggles. When a feature is disabled, its crates and dependencies are **never linked** (a no-MFA build pulls in none of `aes-gcm`/`sha1`).

### Frontend — `@bymax-one/rust-auth` (npm)

One package, four entry points — import only what your app needs:

| Subpath     | Import                          | Purpose                                                 | Peer deps   |
| ----------- | ------------------------------- | ------------------------------------------------------- | :---------: |
| **Shared**  | `@bymax-one/rust-auth/shared`   | Types, constants, error codes — **generated from Rust** |    None     |
| **Client**  | `@bymax-one/rust-auth/client`   | Native-`fetch` client with single-flight refresh        |    None     |
| **React**   | `@bymax-one/rust-auth/react`    | `AuthProvider` + hooks                                  |  React 19   |
| **Next.js** | `@bymax-one/rust-auth/nextjs`   | Proxy, route handlers, WASM-backed edge JWT verify      | Next.js 16  |

```
shared (generated, zero deps)
   ↗        ↖
client      (Rust crate: bymax-auth-client)
   ↑
 react
   ↑
nextjs ──→ bymax-auth-wasm (edge HS256 verifier)
```

---

> [!TIP]
> Prefer to learn from working code? The [`examples/`](./examples) directory ships runnable apps — `axum-minimal`, `axum-mfa`, `axum-oauth-google`, `react-vite`, and `nextjs` — each built and linted in CI so they never rot.

## 🚀 Quick Start

### 1. Add the crate

```toml
# Cargo.toml
[dependencies]
bymax-auth = { version = "1", features = ["argon2", "sessions", "mfa", "oauth", "oauth-reqwest", "redis", "axum"] }
```

### 2. Implement the repository trait

The library defines **what** it needs — your app provides **how**. Map the abstract `AuthUser` contract onto your own schema; the only invariant is that `password_hash` is persisted exactly as the library produced it (a self-describing PHC string).

```rust
use async_trait::async_trait;
use bymax_auth::{
    AuthUser, CreateUserData, CreateWithOAuthData, RepositoryError, UpdateMfaData, UserRepository,
};

pub struct PgUserRepository {
    pool: sqlx::PgPool,
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_email(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        sqlx::query_as::<_, AuthUser>(
            "SELECT * FROM users WHERE email = $1 AND tenant_id = $2",
        )
        .bind(email.to_lowercase())
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(RepositoryError::backend)
    }

    async fn create(&self, data: CreateUserData) -> Result<AuthUser, RepositoryError> {
        // INSERT … RETURNING *, storing data.password_hash verbatim.
        todo!()
    }

    async fn update_password(&self, id: &str, password_hash: &str) -> Result<(), RepositoryError> {
        todo!()
    }

    async fn update_mfa(&self, id: &str, data: UpdateMfaData) -> Result<(), RepositoryError> {
        todo!()
    }

    async fn find_by_oauth_id(
        &self,
        provider: &str,
        provider_id: &str,
        tenant_id: &str,
    ) -> Result<Option<AuthUser>, RepositoryError> {
        todo!()
    }

    async fn create_with_oauth(
        &self,
        data: CreateWithOAuthData,
    ) -> Result<AuthUser, RepositoryError> {
        todo!()
    }

    // … link_oauth, update_status, update_email_verified, etc.
}
```

### 3. Implement the email provider trait

Email delivery is fully delegated — the library never imports a mailer SDK. It passes **structured data** (token, OTP, session info, invite data), never rendered HTML.

```rust
use async_trait::async_trait;
use bymax_auth::{EmailProvider, InviteData, SessionInfo};

pub struct ResendEmailProvider { /* client, from, app_url */ }

#[async_trait]
impl EmailProvider for ResendEmailProvider {
    async fn send_password_reset_token(&self, email: &str, token: &str, locale: Option<&str>) {
        // Render and send with your transport of choice (Resend/SES/SMTP).
    }

    async fn send_email_verification_otp(&self, email: &str, otp: &str, locale: Option<&str>) {
        // …
    }

    async fn send_new_session_alert(&self, email: &str, info: &SessionInfo, locale: Option<&str>) {
        // …
    }

    async fn send_invitation(&self, email: &str, data: &InviteData, locale: Option<&str>) {
        // …
    }

    // … password-reset OTP, MFA enabled/disabled notifications, etc.
}
```

> [!WARNING]
> Any consumer-supplied value (display name, tenant name, inviter name, device string) interpolated into an HTML email body MUST be escaped to prevent stored XSS. Tokens and OTPs are library-generated and safe; the placeholders you fill in are not.

### 4. Build the engine and mount the router

`build()` runs full startup validation and returns `Result<AuthEngine, ConfigError>` — a misconfiguration fails fast at boot, never at the first request.

```rust
use std::sync::Arc;
use bymax_auth::{
    auth_router, AuthConfig, AuthEngine, AxumAuthConfig, Environment, RedisStores,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = AuthEngine::builder()
        .config(AuthConfig::secure_defaults()) // or AuthConfig::nest_compat_defaults()
        .environment(Environment::Production)   // resolves Secure cookies + prod redirect checks
        .user_repository(Arc::new(PgUserRepository { pool }))
        .email_provider(Arc::new(ResendEmailProvider { /* … */ }))
        .redis_stores(Arc::new(RedisStores::connect("redis://127.0.0.1").await?))
        .oauth_provider(Arc::new(bymax_auth::GoogleProvider::new(/* client id/secret */)))
        .http_client(Arc::new(bymax_auth::ReqwestHttpClient::default()))
        .build()?;

    let app = auth_router(AxumAuthConfig::new(Arc::new(engine)));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

### 5. Protect your own routes with extractors

Guards are Axum `FromRequestParts` extractors — compose them straight into a handler signature. They read the token from a cookie or `Authorization: Bearer` header — **never from the query string**.

```rust
use axum::Json;
use bymax_auth::{AuthUser, RequireRole, SafeAuthUser, SelfOrAdmin};

// Any authenticated dashboard user.
async fn profile(user: AuthUser) -> Json<SafeAuthUser> {
    Json(user.into_safe())
}

// Admins (and anything above them in the hierarchy) only.
async fn list_users(_: RequireRole<{ "admin" }>) -> &'static str {
    "ok"
}

// The resource owner, or an admin.
async fn update_user(_: SelfOrAdmin) -> &'static str {
    "ok"
}
```

### 6. Frontend integration (React)

Build an `AuthClient` once, hand it to `AuthProvider`; the hooks read the context it populates — exactly as in `@bymax-one/nest-auth`, so existing consumers change only the import specifier.

```tsx
// app/providers.tsx
'use client'
import { AuthProvider } from '@bymax-one/rust-auth/react'
import { createAuthClient } from '@bymax-one/rust-auth/client'

const authClient = createAuthClient({
  // Same-origin calls flow through the Next.js proxy under `/api/auth/*`.
  // Set `baseUrl` only for a cross-origin API.
})

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider client={authClient} onSessionExpired={() => (location.href = '/login')}>
      {children}
    </AuthProvider>
  )
}
```

```tsx
// app/(dashboard)/profile.tsx
'use client'
import { useAuth, useSession } from '@bymax-one/rust-auth/react'

export function Profile() {
  const { user, status } = useSession()
  const { logout } = useAuth()

  if (status === 'loading') return <div>Loading…</div>
  if (status === 'unauthenticated') return <div>Please log in</div>

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={() => logout()}>Sign out</button>
    </div>
  )
}
```

### 7. Frontend integration (Next.js 16, edge JWT via WASM)

Mount the auth proxy at the project root and expose the `/api/auth/*` route handlers. The proxy verifies the access token **at the edge** using the WebAssembly build of the same HS256 verifier the backend uses — no network round-trip.

```typescript
// proxy.ts — Next.js 16 Edge middleware
import { createAuthProxy } from '@bymax-one/rust-auth/nextjs'

export const { proxy } = createAuthProxy({
  publicRoutes: ['/', '/auth/login', '/auth/register'],
  protectedRoutes: [
    { pattern: '/dashboard/:path*', allowedRoles: ['admin', 'member'] },
    { pattern: '/admin/:path*', allowedRoles: ['admin'] },
  ],
  loginPath: '/auth/login',
  apiBase: process.env.API_BASE_URL!,
  jwtSecret: process.env.JWT_SECRET, // verified at the edge via WASM
  cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'has_session' },
  blockedUserStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
})

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] }
```

> [!IMPORTANT]
> The WASM module and `verifyJwtToken` are **server/edge only** — never import them into a Client Component. The HS256 secret must never reach the browser; an accidental client import is a security defect (a `server-only` guard catches it at build time).

```typescript
// app/api/auth/logout/route.ts
import { createLogoutHandler } from '@bymax-one/rust-auth/nextjs'

export const POST = createLogoutHandler({
  apiBase: process.env.API_BASE_URL!,
  mode: 'redirect',
  loginPath: '/auth/login',
  cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'has_session' },
})
```

---

## ⚙️ Configuration

Everything is configured through `AuthConfig`. Two ready-made profiles bundle sensible choices; `Default` equals `nest_compat_defaults()`.

| Profile                        | Posture                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| `AuthConfig::nest_compat_defaults()` | Behavioral parity with `@bymax-one/nest-auth` out of the box (scrypt, email verification required, brute-force `max_attempts = 5`) — the `Default` |
| `AuthConfig::secure_defaults()`      | Hardened opt-in profile (Argon2id, stricter cookies) — available under the `argon2` feature |

| Group              | Key options                                                                  | nest-compat default        |
| ------------------ | ---------------------------------------------------------------------------- | -------------------------- |
| **jwt**            | `secret` (required, ≥ 32 chars), `access_ttl`, `refresh_expires_in_days`     | `15m`, `7d`, HS256 (pinned) |
| **password**       | `active_algorithm`, scrypt `cost_factor` / Argon2id `memory_kib`             | scrypt N=2¹⁵, r=8, p=1     |
| **token_delivery** | `Cookie` \| `Bearer` \| `Both`                                               | `Cookie`                   |
| **cookies**        | names, `refresh_cookie_path`, `same_site`, `resolve_domains`                 | HttpOnly, Secure, Strict   |
| **mfa**            | `encryption_key` (32 bytes), `issuer`, `totp_window`, `recovery_code_count`  | —                          |
| **sessions**       | `enabled`, `default_max_sessions`, `max_sessions_resolver`                   | `false`, `5`               |
| **brute_force**    | `max_attempts`, `window_seconds`                                             | `5`, `900`                 |
| **password_reset** | `method` (`Token` \| `Otp`), `otp_length`, `token_ttl`                       | `Token`, 600 s             |
| **platform**       | `enabled` (requires `roles.platform_hierarchy`)                              | `false`                    |
| **invitations**    | `enabled`, `token_ttl`                                                       | `false`, 48 h              |
| **roles**          | `hierarchy` (required), `platform_hierarchy`                                 | —                          |
| **oauth**          | `google`, `redirect_allowlist`, `*_redirect_url`                            | —                          |
| **controllers**    | per-group route toggles                                                      | feature-driven             |

> [!NOTE]
> `build()` validates every cross-field invariant (secret length/entropy, role referential integrity, parameter floors, `SameSite=None ⇒ Secure`, OAuth redirect allow-listing, required stores) and rejects an invalid config with a precise `ConfigError`.

---

## 🏗️ Architecture

The library is a set of crates you embed in your Axum service — a framework-agnostic core wrapped by thin adapters.

```
┌──────────────────────────────────────────────────────────┐
│                  Your Axum Application                     │
│                                                            │
│   bymax-auth-axum   →  router · extractors · rate-limit    │
│        │                                                   │
│   bymax-auth-core   →  AuthEngine · services · 14 hooks    │
│      ╱   │   ╲                                             │
│  -crypto -jwt -types     (pure-Rust, wasm-safe)            │
│        │                                                   │
│   ┌────▼─────┐   ┌──────────────┐   ┌──────────────┐       │
│   │ User     │   │ Email        │   │ SessionStore │       │
│   │ Repository│  │ Provider     │   │ (bymax-auth- │       │
│   │ (yours)  │   │ (yours)      │   │  redis)      │       │
│   └──────────┘   └──────────────┘   └──────────────┘       │
└──────────────────────────────────────────────────────────┘
         bindings/bymax-auth-wasm  →  edge HS256 verifier (npm)
```

### Design Principles

| Principle                   | Description                                                                                              |
| --------------------------- | -------------------------------------------------------------------------------------------------------- |
| **🔌 Trait-Driven**         | Define contracts, inject implementations — works with `sqlx`, `SeaORM`, `Diesel`, or any store           |
| **🔒 Secure by Default**    | scrypt/Argon2id, HttpOnly cookies, `jti` blacklist, brute-force, anti-enumeration — all on out of the box |
| **🪶 Tiny Mandatory Tree**  | A small always-compiled core; Redis, Axum, `reqwest`, and MFA are feature-gated, with a CI dependency budget |
| **🦀 One Crypto, Everywhere** | A single pure-Rust HS256 primitive runs on the server **and** at the edge (WASM) — never two implementations |
| **🌳 wasm-clean boundary**  | `bymax-auth-wasm` depends only on `-crypto`/`-jwt`/`-types`; a CI job builds `wasm32` to prove it          |
| **⚡ Fast & measured**       | No GC and no FFI boundary; hot paths run in ns–µs while memory-hard KDFs stay tunable — tracked with Criterion benches ([details](#-performance--footprint)) |

---

## 🔐 Security Model

The security architecture is codified as a set of **inviolable invariants** that the quality gates exist to protect — relaxing one is treated as a vulnerability, not a feature.

### JWT Token Type Discrimination

Every token carries a `type` claim that extractors validate before acceptance:

| Token type        | Issued when                               | Accepted by              |
| ----------------- | ----------------------------------------- | ------------------------ |
| `dashboard`       | Successful login or MFA challenge         | `AuthUser`               |
| `platform`        | Platform-admin login or MFA challenge     | `PlatformUser`           |
| `mfa_challenge`   | Login with MFA enabled (pre-verification) | MFA challenge endpoint   |

This prevents **token-type-confusion attacks**. A dashboard token presented to a platform route is rejected with `PlatformAuthRequired` (not the generic `TokenInvalid`), so clients can distinguish wrong-context from expired.

### Algorithm Pinning & Opaque Refresh

Verification pins `header.alg == "HS256"` **before** any signature math — `none`, `RS256`, `ES256`, and every asymmetric algorithm are rejected, and only a symmetric key exists. Refresh tokens are **opaque CSPRNG strings**, inert without their server-side Redis record, persisted only as `sha256(token)` — never signed or parsed as JWTs.

### Separate Auth Contexts for Multi-Tenant SaaS

Platform admins and tenant users are fully isolated — separate repositories, claims, extractors, and routes. `tenant_id` is always taken from the configured `TenantIdResolver`, **never the request body**, preventing tenant spoofing at the architecture level.

### Atomic State on Shared Redis

Every read→decide→write on contended state — refresh rotation + grace, ownership-checked revoke, brute-force increment, OTP verify+consume, single-use WebSocket ticket — runs as a single **atomic Lua script**, closing the concurrency races those flows would otherwise expose.

### Security Checklist

When integrating `bymax-auth` in production, verify each of the following:

- `cookies.resolve_domains` validates against an allow-list — the `Host` header is never used to derive a parent domain
- `oauth.redirect_allowlist` is set so no redirect/callback URL is request-derived (no open redirect)
- The MFA `encryption_key` is 32 bytes from a secret manager; the JWT `secret` is 32 random bytes, high-entropy
- HS256 pinning, constant-time comparisons (`subtle`), and CSPRNG (`OsRng`) are never bypassed
- HttpOnly + `Secure` (outside development); refresh cookie path-scoped with `SameSite=Strict`

---

## 🛡️ Security Table

| Layer             | Implementation                                                       |
| ----------------- | -------------------------------------------------------------------- |
| Password Hashing  | RustCrypto `scrypt` (N=2¹⁵, r=8, p=1) **or** `argon2` Argon2id (PHC) |
| MFA Encryption    | `aes-gcm` AES-256-GCM with a fresh 12-byte CSPRNG IV per call         |
| TOTP              | `hmac` + `sha1` per RFC 4226/6238, ±1 step window, anti-replay marked |
| Recovery Codes    | Keyed **HMAC-SHA-256** digests (never plaintext, never reversible)    |
| Token Generation  | `getrandom`/`OsRng` CSPRNG — 256 bits of entropy                     |
| Secret Comparison | `subtle` constant-time — never `==` on secret bytes                  |
| JWT               | Hand-rolled HS256 (`hmac` + `sha2`), `jti` blacklist via Redis        |
| Cookies           | HttpOnly, Secure-by-default, `SameSite=Strict`, path-scoped refresh   |
| Brute-Force       | Redis atomic fixed-window counters per `HMAC(tenant:email)`           |
| CSRF (OAuth)      | 64-hex single-use `state` (`GETDEL`) + PKCE `code_verifier` (S256)    |
| Edge Verify       | Same HS256 primitive compiled to WebAssembly — no network call        |

> [!IMPORTANT]
> All cryptography uses **RustCrypto** — no `ring`, no OpenSSL, no C/C++ bindings on any target — and every first-party crate is `#![forbid(unsafe_code)]` (the sole exception being the `wasm-bindgen` glue in the edge binding).

---

## 🧱 Tech Stack

<p>
  <img src="https://img.shields.io/badge/Rust-edition%202024-000000?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Axum-0.8-000000?style=flat-square&logo=rust&logoColor=white" alt="Axum" />
  <img src="https://img.shields.io/badge/RustCrypto-pure--rust-000000?style=flat-square&logo=rust&logoColor=white" alt="RustCrypto" />
  <img src="https://img.shields.io/badge/WebAssembly-edge-654FF0?style=flat-square&logo=webassembly&logoColor=white" alt="WebAssembly" />
  <img src="https://img.shields.io/badge/Redis-8-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
</p>

---

## ⚡ Performance & Footprint

Rust's advantage over a managed runtime (Node, the JVM) is **per-operation cost with no garbage collector and no FFI marshalling**. `bymax-auth` is built to spend that advantage deliberately — and to **prove it with benchmarks** rather than assert it.

### Built to be cheap where it should be

| Lever | What it buys |
| --- | --- |
| **No runtime, no GC** | Auth work is synchronous CPU over owned bytes — no allocator pauses, no event-loop hops, predictable tail latency under load |
| **Pure-Rust RustCrypto** | Every primitive is inlined Rust — no C bindings and no per-call FFI boundary to cross (the cost a native Node addon pays on every call) |
| **Static where it's hot** | Internal services are monomorphized; dynamic dispatch (`Arc<dyn _>`) is paid only at the host-pluggable trait boundary, never in the inner loop |
| **Allocation-aware** | Digests return a stack `[u8; 32]`; fixed-size randomness uses a stack `[u8; N]` instead of a `Vec`; transient key material lives in `Zeroizing` buffers wiped on drop |
| **Pay for what you use** | A bare build is a tiny core — Redis, Axum, OAuth, and MFA are feature-gated behind a CI dependency budget, so unused capabilities cost zero binary and zero attack surface |
| **Tiny edge** | The Next.js middleware verifies JWTs through a `wasm-bindgen` module — the *same* HS256 code as the server, with no network round-trip |

### Memory-hard by design — not by accident

Password hashing is **deliberately expensive**: scrypt and Argon2id are memory-hard so an attacker who exfiltrates the hash store cannot brute-force it cheaply. Their cost is a **security knob** (`cost_factor` / `memory_kib`), not a bottleneck — and it is the one operation the engine hands to `tokio::task::spawn_blocking`, so a burst of logins never stalls the async runtime. Everything *around* the KDF stays in the nanosecond–microsecond range.

### Measured, not asserted

Tracked with [Criterion](https://github.com/bheisler/criterion.rs) so a regression surfaces as a number — the same discipline applied to the coverage gate.

| Primitive (per call) | Median | Role |
| --- | --- | --- |
| SHA-256 (`mac::sha256`) | ~110 ns | high-entropy token → Redis key suffix |
| Keyed HMAC-SHA-256 | ~430 ns | low-entropy identifier / recovery-code hashing |
| Secure token (32 B → hex) | ~870 ns | dominated by the OS CSPRNG syscall, not allocation |
| AES-256-GCM encrypt / decrypt | ~2.1 µs / ~1.3 µs | TOTP secret encrypted at rest |
| TOTP generate / verify (±1 window) | ~200 ns / ~710 ns | RFC 6238, constant-time |
| scrypt hash / verify (N=2¹⁵) | ~37 ms | memory-hard — tunable security cost |
| Argon2id hash / verify (19 MiB) | ~10 ms | memory-hard — tunable security cost |

<sub>Indicative medians on an Apple M4 Max, `release` profile, Rust 1.96. Reproduce with `cargo bench -p bymax-auth-crypto --bench crypto --all-features`. Absolute figures are hardware-dependent — the point is the order of magnitude and that the numbers are tracked, not hand-waved.</sub>

> [!NOTE]
> The cheap operations cost **nanoseconds to microseconds**; the only deliberately slow step is the memory-hard KDF, which is a security control you dial in — not a hot loop. Optimisation is a standing project premise, but it never outranks a constant-time, zeroize, or no-oracle guarantee.

---

## 🧪 Testing & Quality

Authentication is critical infrastructure, so the suite is held to a bar beyond "it compiles" — every behavior is pinned so a regression **fails a test**.

- ✅ **100% line + region coverage** — enforced as a release gate via [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) across the full `cargo-hack` feature matrix
- ✅ **Near-100% mutation score** — verified with [`cargo-mutants`](https://mutants.rs/): faults are seeded into the source and the suite must catch them
- ✅ **Property tests + fuzzing** — `proptest` round-trips and `cargo-fuzz` smoke runs over the trust-boundary parsers (JWT, PHC, base32)
- ✅ **Real-Redis E2E** — atomic Lua, rotation/grace, and revocation proven against `redis:8` via [`testcontainers`](https://github.com/testcontainers/testcontainers-rs)
- ✅ **Edge parity** — `wasm-bindgen-test` confirms the WASM verifier accepts a token signed by the backend
- ✅ **Supply chain** — `cargo-deny` (advisories/licenses/bans/sources), `cargo-vet`, a dependency budget, and `cargo-public-api` + `cargo-semver-checks` on every PR

```bash
cargo test --workspace --all-features      # unit + integration
cargo llvm-cov --workspace --all-features  # 100% line/region gate
cargo mutants                              # mutation testing
cargo deny check                           # supply-chain policy
wasm-pack test --node bindings/bymax-auth-wasm
```

> [!NOTE]
> Line coverage proves a line _executed_; mutation testing proves a test _would fail_ if that line were wrong. Both run in CI, alongside a `wasm32-unknown-unknown` build that guarantees the edge crate stays free of server dependencies.

---

## 📖 API Reference

### HTTP Endpoints

Route groups mount only when their feature **and** runtime toggle are enabled, so an unconfigured group contributes zero routes. Paths are shown under the default `auth` prefix.

| Method | Path                          | Guard / Auth                    | Description                                          |
| ------ | ----------------------------- | ------------------------------- | ---------------------------------------------------- |
| POST   | `/auth/register`              | Public                          | Register a dashboard user and issue tokens           |
| POST   | `/auth/login`                 | Public                          | Authenticate (may return an MFA challenge)           |
| POST   | `/auth/logout`                | `AuthUser`                      | Revoke the access `jti` and the refresh session      |
| POST   | `/auth/refresh`               | Public (refresh cookie)         | Rotate the refresh token, issue a new access token   |
| GET    | `/auth/me`                    | `AuthUser`                      | Current dashboard user                               |
| POST   | `/auth/verify-email`          | Public                          | Verify email with an OTP                             |
| POST   | `/auth/resend-verification`   | Public                          | Resend the email-verification OTP                    |
| POST   | `/auth/password/forgot-password` | Public                       | Request a password reset (token or OTP)              |
| POST   | `/auth/password/reset-password`  | Public                       | Submit a new password                                |
| POST   | `/auth/password/verify-otp`   | Public                          | Verify a password-reset OTP                          |
| POST   | `/auth/password/resend-otp`   | Public                          | Resend the password-reset OTP                        |
| POST   | `/auth/mfa/setup`             | `AuthUser`                      | Generate the TOTP secret + recovery codes            |
| POST   | `/auth/mfa/verify-enable`     | `AuthUser`                      | Confirm setup and enable MFA                         |
| POST   | `/auth/mfa/challenge`         | Public (MFA temp token)         | Submit a TOTP / recovery code after login            |
| POST   | `/auth/mfa/disable`           | `AuthUser`                      | Disable MFA                                          |
| POST   | `/auth/mfa/recovery-codes`    | `AuthUser`                      | Regenerate recovery codes (TOTP-gated)               |
| GET    | `/auth/sessions`              | `AuthUser`, `UserStatus`        | List active sessions                                 |
| DELETE | `/auth/sessions/all`          | `AuthUser`, `UserStatus`        | Revoke all sessions                                  |
| DELETE | `/auth/sessions/:id`          | `AuthUser`, `UserStatus`        | Revoke a specific session (ownership-checked)        |
| POST   | `/auth/invitations`           | `AuthUser`                      | Create a tenant invitation                           |
| POST   | `/auth/invitations/accept`    | Public                          | Accept an invitation and create the user             |
| POST   | `/auth/platform/login`        | Public                          | Platform-admin login (separate context)              |
| POST   | `/auth/platform/mfa/challenge`| Public                          | Platform-admin MFA challenge                         |
| GET    | `/auth/platform/me`           | `PlatformUser`                  | Current platform admin                               |
| POST   | `/auth/platform/logout`       | `PlatformUser`                  | Revoke platform tokens                               |
| POST   | `/auth/platform/refresh`      | Public (platform refresh cookie)| Rotate the platform refresh token                    |
| DELETE | `/auth/platform/sessions`     | `PlatformUser`                  | Revoke all platform sessions                         |
| GET    | `/auth/oauth/:provider`       | Public                          | Initiate the OAuth authorize redirect                |
| GET    | `/auth/oauth/:provider/callback` | Public                       | Handle the callback, exchange the code, issue tokens |
| POST   | `/auth/ws-ticket`             | `AuthUser`, `UserStatus`, `MfaSatisfied` | Mint a single-use WebSocket upgrade ticket  |

### Extractors (Axum `FromRequestParts`)

| Extractor               | Purpose                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `AuthUser`              | Validates the dashboard JWT (cookie or `Authorization` header)   |
| `OptionalAuthUser`      | Routes that differ for anonymous vs. authenticated users         |
| `RequireRole<R>`        | Hierarchical role check                                          |
| `PlatformUser`          | Platform-admin JWT validation                                    |
| `RequirePlatformRole<R>`| Platform role hierarchy enforcement                              |
| `CurrentUser`           | Extracts the validated claims                                    |
| `SelfOrAdmin`           | Ownership-or-admin access                                        |
| `UserStatus`            | Blocks inactive/banned users (Redis-cached status)               |
| `MfaSatisfied`          | Enforces a completed MFA verification on the request             |

### React Hooks

| Hook              | Returns                                                                              |
| ----------------- | ------------------------------------------------------------------------------------ |
| `useSession()`    | `{ user, status, isLoading, refresh(), lastValidation }` — session state + revalidate |
| `useAuth()`       | `{ login(), logout(), register(), forgotPassword(), resetPassword() }` — auth actions |
| `useAuthStatus()` | `{ isAuthenticated, isLoading }` — derived state                                     |

### Next.js Factories

| Factory                        | Type         | Purpose                                          |
| ------------------------------ | ------------ | ------------------------------------------------ |
| `createAuthProxy()`            | Proxy config | Auth-aware edge proxy for `proxy.ts`             |
| `createSilentRefreshHandler()` | GET handler  | iframe-based token refresh                       |
| `createClientRefreshHandler()` | POST handler | Client-triggered token refresh                   |
| `createLogoutHandler()`        | POST handler | Clear tokens and session                         |
| `verifyJwtToken()`             | Edge helper  | WASM-backed HS256 verification (server/edge only)|

---

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines before opening a pull request.

```bash
# Clone the repository
git clone https://github.com/bymaxone/rust-auth.git
cd rust-auth

# Build the workspace
cargo build --workspace --all-features

# Run the test suite
cargo test --workspace --all-features

# Lint + format
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Frontend package
cd packages/rust-auth && npm ci && npm run build:wasm && npm run build
```

Runnable apps live under [`examples/`](./examples) (three Axum services, a
React + Vite SPA, a Next.js edge app, and a dogfood integration). The release and
publishing process — and the one-time OIDC / protected-environment setup it
requires — is documented in [`docs/RELEASE.md`](./docs/RELEASE.md).

---

## 🔒 Security Policy

If you discover a security vulnerability, please **do not** open a public issue. Email **support@bymax.one** with the details. We take security seriously and will respond promptly. See [SECURITY.md](./SECURITY.md).

---

## 📄 License

[MIT](./LICENSE) © [Bymax One](https://github.com/bymaxone)

---

<p align="center">
  <sub>Built with ❤️ and 🦀 by <a href="https://github.com/bymaxone">Bymax One</a></sub>
</p>
