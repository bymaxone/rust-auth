# Phase 1 — `bymax-auth-crypto`: hashing, constant-time, tokens, MFA-gated AEAD/TOTP

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P1
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

Phase 0 produced a building, gated, empty workspace. The crate `crates/bymax-auth-crypto` exists as a skeleton (`src/lib.rs` with a crate-level doc and `#![forbid(unsafe_code)]` + `#![deny(missing_docs)]`) and no dependencies. This phase fills it in: `bymax-auth-crypto` is the **single home of every cryptographic primitive** the library uses — password hashing (scrypt + Argon2id, PHC, rehash-on-verify), constant-time comparison, keyed/unkeyed digests, CSPRNG token generation, and the MFA-only primitives (AES-256-GCM secret encryption, TOTP/HOTP, Base32). It depends only on the RustCrypto ecosystem, carries no async runtime, and **must compile to `wasm32-unknown-unknown`** so the edge binding can reuse a subset.

When P1 is done, `bymax-auth-crypto` builds native and `wasm32` across its feature combinations (`scrypt`, `argon2`, `mfa`), an Argon2id-only build pulls no scrypt code, the MFA primitives are absent unless the `mfa` feature is on, and every public item is covered to 100% with property/known-answer tests. **No engine, no Redis, no HTTP** — those are later phases that consume this crate.

---

## Rules-of-phase

1. **RustCrypto only.** No `ring`, no OpenSSL, no C/C++ crypto bindings on any target. Mandatory deps: `hmac`, `sha2`, `subtle`, `rand`/`getrandom`. Hashers: `scrypt` (`scrypt` feature), `argon2` (`argon2` feature), `password-hash` (PHC). MFA-only: `aes-gcm`, `sha1`, `data-encoding` — all behind the `mfa` feature.
2. **`#![forbid(unsafe_code)]`** stays; `#![deny(missing_docs)]` stays — every public item is documented with a rustdoc example where it clarifies usage.
3. **Must compile to `wasm32-unknown-unknown`.** Where randomness is used, `getrandom` must be configured with the `js` feature for the wasm target so browser/edge RNG works.
4. **Constant-time for every secret comparison** via `subtle::ConstantTimeEq` — never `==` on secret/derived bytes.
5. **Typed errors only** (`CryptoError` via `thiserror`); no `unwrap`/`expect`/`panic!` on library paths; crypto failures collapse to opaque errors that never leak which step failed.
6. **Hashing is synchronous here**; this crate exposes sync `hash`/`verify`. Document that callers (the engine, P4) must wrap them in `tokio::task::spawn_blocking` — this crate must not depend on Tokio.
7. **Feature-gated MFA primitives** must be entirely absent from the dependency tree when `mfa` is off (verified by a `cargo tree` assertion).
8. **100% coverage** for the crate, with **property tests** (`proptest`) and **RFC known-answer vectors** for TOTP/HOTP. English-only, timeless comments.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 17 "Cryptography & Security Model" (crate-by-crate choices; always-compiled vs feature-gated; `secrecy`/`zeroize`; AES-GCM IV/tag; `subtle`; `getrandom` js; Base32). § 5.1.3 "Password configuration" (scrypt/Argon2id params + OWASP floors + PHC). § 7.2 "PasswordService" (rehash-on-verify flow; `spawn_blocking`; legacy `scrypt:hex:hex` compatibility).
- [`docs/development_plan.md`](../development_plan.md) — § P1, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules (Rust-adapted).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 1.1 | Crate setup: deps, features, `CryptoError`, wasm/getrandom config | 📋 ToDo | P0 | S | 0.1 |
| 1.2 | Constant-time compare + digests (`compare`, `mac`) | 📋 ToDo | P0 | M | 1.1 |
| 1.3 | Secure token generation (`token`) | 📋 ToDo | P0 | S | 1.1 |
| 1.4 | Password hashing: scrypt + Argon2id, PHC, rehash-on-verify (`password`) | 📋 ToDo | P0 | L | 1.1, 1.2 |
| 1.5 | MFA secret encryption — AES-256-GCM (`aead`, `mfa` feature) | 📋 ToDo | P0 | M | 1.1 |
| 1.6 | MFA TOTP/HOTP + Base32 + otpauth URI (`totp`, `mfa` feature) | 📋 ToDo | P0 | L | 1.1 |

---

## Tasks

### Task 1.1 — Crate setup: deps, features, `CryptoError`, wasm/getrandom config

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 0.1

#### Description

Wire the crate's dependencies and feature flags (`scrypt`, `argon2`, `mfa`), define the shared `CryptoError`, lay out the module skeleton, and configure `getrandom`'s `js` feature for the `wasm32` target.

#### Acceptance criteria

- [ ] `Cargo.toml` declares mandatory deps (`hmac`, `sha2`, `subtle`, `rand`, `getrandom`, `password-hash`, `thiserror`, `secrecy` (carries `zeroize`), `zeroize`) and feature-gated deps: `scrypt` (`scrypt`), `argon2` (`argon2`), `aes-gcm` + `sha1` + `data-encoding` (`mfa`); `default = ["scrypt"]`.
- [ ] `getrandom` is configured with the `js` feature for `cfg(target_arch = "wasm32")`.
- [ ] `src/lib.rs` contains a `compile_error!` that fires at build time when neither the `scrypt` nor the `argon2` feature is enabled (at least one hasher is required); `cargo build -p bymax-auth-crypto --no-default-features` FAILS with that error.
- [ ] `CryptoError` (thiserror) exists with opaque variants (e.g. `Hash`, `Verify`, `Decrypt`, `InvalidParams`, `Encoding`) that never reveal internal step detail.
- [ ] Module skeleton exists: `compare`, `mac`, `token`, `password` (always), `aead` + `totp` (`#[cfg(feature = "mfa")]`).
- [ ] `cargo build -p bymax-auth-crypto` (default), `--features argon2,mfa`, and `--no-default-features --features argon2` all build; `cargo build -p bymax-auth-crypto --target wasm32-unknown-unknown` builds.
- [ ] `cargo tree -p bymax-auth-crypto -e features` shows `aes-gcm`/`sha1`/`data-encoding` ONLY under `mfa`.

#### Files to create / modify

- `crates/bymax-auth-crypto/Cargo.toml`
- `crates/bymax-auth-crypto/src/lib.rs`
- `crates/bymax-auth-crypto/src/error.rs`
- skeleton module files: `compare.rs`, `mac.rs`, `token.rs`, `password/mod.rs`, `aead.rs`, `totp.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace, Tokio for the async engine (NOT here); full parity with @bymax-one/nest-auth.
`bymax-auth-crypto` is the single home of all crypto primitives; it uses RustCrypto only, has no
async runtime, and must compile to wasm32.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.1 of 6 (FIRST)

PRECONDITIONS
- Phase 0 is done: the workspace builds; `crates/bymax-auth-crypto` is an empty skeleton with a
  crate-level `//!` doc, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, and no deps.
- The workspace pins the toolchain (with the `wasm32-unknown-unknown` target) and centralizes
  lints in `[workspace.lints]`.

REQUIRED READING (only these sections — do not load more):
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — the RustCrypto crate
  list, the always-compiled vs `mfa`-gated split, and the `getrandom` js-feature requirement.
- `docs/technical_specification.md` § 19 "Dependencies & Feature Flags" — the per-crate dep
  classification and the feature matrix (for the crypto crate's `scrypt`/`argon2`/`mfa` features).

TASK
Set up the crate's dependencies, feature flags, error type, wasm/getrandom config, and an empty
module skeleton. No primitive implementations yet — only the scaffolding the next tasks fill in.

DELIVERABLES

1. `crates/bymax-auth-crypto/Cargo.toml`:
   - `[dependencies]`: `hmac`, `sha2`, `subtle`, `rand`, `getrandom`, `password-hash`, `thiserror`,
     `secrecy` (mandatory in-memory secret wrapper; carries `zeroize`), `zeroize`. Optional:
     `scrypt` (optional = true), `argon2` (optional = true), `aes-gcm` (optional), `sha1`
     (optional), `data-encoding` (optional).
   - `[features]`:
     ```toml
     default = ["scrypt"]
     scrypt = ["dep:scrypt"]
     argon2 = ["dep:argon2"]
     mfa = ["dep:aes-gcm", "dep:sha1", "dep:data-encoding"]
     ```
   - The `js`-feature wiring for wasm randomness:
     ```toml
     [target.'cfg(target_arch = "wasm32")'.dependencies]
     getrandom = { version = "0.2", features = ["js"] }
     ```
     (Match the `getrandom` major version to what `rand` pulls; if `rand` is on `getrandom` 0.3,
     use the equivalent 0.3 wasm-js config.)
   - `[lints] workspace = true`.
   - `[dev-dependencies]`: `proptest`, `hex` (for known-answer vectors).

2. `crates/bymax-auth-crypto/src/error.rs` — a `CryptoError` enum via `thiserror`:
   ```rust
   /// Opaque cryptographic error. Variants never reveal which internal step failed.
   #[derive(Debug, thiserror::Error)]
   #[non_exhaustive]
   pub enum CryptoError {
       /// Hashing failed.
       #[error("hash operation failed")]
       Hash,
       /// Verification failed (wrong password / corrupt hash).
       #[error("verification failed")]
       Verify,
       /// Authenticated decryption failed (wrong key or tampered ciphertext).
       #[error("decryption failed")]
       Decrypt,
       /// A parameter was outside the accepted range.
       #[error("invalid parameters")]
       InvalidParams,
       /// An encoding/parse error.
       #[error("encoding error")]
       Encoding,
   }
   ```

3. `crates/bymax-auth-crypto/src/lib.rs` — declare the modules and re-export the public surface:
   ```rust
   //! Cryptographic primitives for rust-auth: password hashing, constant-time comparison,
   //! digests, secure token generation, and (under the `mfa` feature) AES-256-GCM and TOTP.
   #![forbid(unsafe_code)]
   #![deny(missing_docs)]

   // At least one password-hasher feature must be enabled; a default build has `scrypt`.
   #[cfg(not(any(feature = "scrypt", feature = "argon2")))]
   compile_error!(
       "bymax-auth-crypto requires at least one password-hasher feature: \
        enable `scrypt` (default) or `argon2`."
   );

   mod error;
   pub mod compare;
   pub mod mac;
   pub mod token;
   pub mod password;
   #[cfg(feature = "mfa")]
   pub mod aead;
   #[cfg(feature = "mfa")]
   pub mod totp;

   pub use error::CryptoError;
   ```

4. Create empty (documented) module files `compare.rs`, `mac.rs`, `token.rs`, `password/mod.rs`,
   `aead.rs`, `totp.rs`, each with a `//!` module doc so `missing_docs` passes.

Constraints:
- RustCrypto only; no `ring`/OpenSSL.
- `#![forbid(unsafe_code)]`; `#![deny(missing_docs)]`.
- Feature-gate `aes-gcm`/`sha1`/`data-encoding` strictly under `mfa` (absent otherwise).
- English-only, timeless comments.

Verification:
- `cargo build -p bymax-auth-crypto` — expected: builds (default = scrypt).
- `cargo build -p bymax-auth-crypto --features argon2,mfa` — expected: builds.
- `cargo build -p bymax-auth-crypto --no-default-features --features argon2` — expected: builds.
- `cargo build -p bymax-auth-crypto --no-default-features 2>&1 | grep -q 'at least one password-hasher'`
  — expected: the build fails with the hasher compile_error.
- `cargo build -p bymax-auth-crypto --target wasm32-unknown-unknown` — expected: builds.
- `cargo tree -p bymax-auth-crypto -e features -i aes-gcm` — expected: shown only via `mfa`.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P1 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 1.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 1.2 — Constant-time compare + digests (`compare`, `mac`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 1.1

#### Description

Implement constant-time byte comparison via `subtle`, plus the unkeyed (`sha256`) and keyed (`hmac_sha256`) digest helpers used for session hashes, brute-force identifiers, and recovery-code hashing.

#### Acceptance criteria

- [ ] `compare::constant_time_eq(a: &[u8], b: &[u8]) -> bool` uses `subtle::ConstantTimeEq`; documents that it may short-circuit only on length (which leaks nothing sensitive here).
- [ ] `mac::sha256(input: &[u8]) -> [u8; 32]` and `mac::hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32]` exist and are documented.
- [ ] A digest-equality helper compares via constant time (no `==` on secret-derived bytes).
- [ ] 100% coverage including a `proptest` that `constant_time_eq` agrees with `==` on equality/inequality, and known-answer vectors for SHA-256 and HMAC-SHA256 (RFC 4231).

#### Files to create / modify

- `crates/bymax-auth-crypto/src/compare.rs`
- `crates/bymax-auth-crypto/src/mac.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-crypto` is the RustCrypto-only, no-async,
wasm-safe home of all crypto primitives. Edition 2024.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 1.1 is done: the crate has its deps (`subtle`, `hmac`, `sha2`), features, `CryptoError`,
  and empty `compare.rs` + `mac.rs` modules.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — the `subtle`
  constant-time rule (all secret comparisons), and where HMAC-SHA256 / SHA-256 are used
  (brute-force identifiers, recovery-code hashing, session hashes).

TASK
Implement constant-time comparison and the SHA-256 / HMAC-SHA256 digest helpers.

DELIVERABLES

1. `crates/bymax-auth-crypto/src/compare.rs`:
   - `pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` built on `subtle::ConstantTimeEq`
     (compare equal-length slices in constant time; return false fast only on length mismatch).
   - A doc example. Note in the docs that length is not secret in this crate's call sites.

2. `crates/bymax-auth-crypto/src/mac.rs`:
   - `pub fn sha256(input: &[u8]) -> [u8; 32]` (via `sha2::Sha256`).
   - `pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32]` (via `hmac::Hmac<Sha256>`).
   - Optionally a `pub fn verify_digest(a: &[u8; 32], b: &[u8; 32]) -> bool` that calls
     `constant_time_eq` (so callers never `==` two digests).

Constraints:
- Never use `==` on secret or secret-derived bytes — route through `constant_time_eq`.
- No `unwrap`/`expect`/`panic!` on library paths (HMAC key-init is infallible for variable-key —
  handle the `Result` without `unwrap`).
- `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-crypto compare mac` — expected: passes, including the RFC 4231
  HMAC-SHA256 known-answer vectors and the SHA-256 vectors.
- `cargo llvm-cov -p bymax-auth-crypto --lcov` — expected: `compare.rs` and `mac.rs` at 100%.
- `cargo clippy -p bymax-auth-crypto -- -D warnings` — expected: clean.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update P1
row in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 1.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 1.3 — Secure token generation (`token`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 1.1

#### Description

Implement CSPRNG-backed secure token generation used for refresh tokens, password-reset tokens, invitation tokens, OAuth state, and the WS upgrade ticket.

#### Acceptance criteria

- [ ] `token::generate_secure_token(byte_len: usize) -> String` draws `byte_len` bytes from a CSPRNG (`rand`/`getrandom`) and hex-encodes them; documents the entropy (`byte_len * 8` bits).
- [ ] A `token::random_bytes(n: usize) -> Vec<u8>` (or fixed-size array variant) primitive backs it.
- [ ] Works on `wasm32-unknown-unknown` (via `getrandom`'s `js` feature from Task 1.1).
- [ ] 100% coverage including a `proptest` asserting output length = `2 * byte_len` hex chars, charset is `[0-9a-f]`, and two successive tokens differ.

#### Files to create / modify

- `crates/bymax-auth-crypto/src/token.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-crypto` is the RustCrypto-only, wasm-safe
crypto crate. Edition 2024.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 1.1 is done: the crate has `rand`/`getrandom` deps (with the wasm `js` feature) and an
  empty `token.rs`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — secure token
  generation (CSPRNG) and the wasm `getrandom` js requirement.
- `docs/technical_specification.md` § 13 "JWT & Token Strategy" — what opaque tokens are used for
  (refresh tokens, reset/invite tokens, OAuth state, WS ticket) and their entropy expectations.

TASK
Implement CSPRNG secure-token generation.

DELIVERABLES

1. `crates/bymax-auth-crypto/src/token.rs`:
   - `pub fn random_bytes(n: usize) -> Vec<u8>` — fills `n` bytes from the OS/browser CSPRNG.
   - `pub fn generate_secure_token(byte_len: usize) -> String` — `random_bytes(byte_len)` hex-encoded.
   - Doc each with the entropy note. A doc example showing a 32-byte (256-bit) token.

   ```rust
   /// Generate a hex-encoded secure random token with `byte_len * 8` bits of entropy.
   ///
   /// ```
   /// let t = bymax_auth_crypto::token::generate_secure_token(32);
   /// assert_eq!(t.len(), 64);
   /// ```
   pub fn generate_secure_token(byte_len: usize) -> String { /* ... */ }
   ```

Constraints:
- Use a cryptographically secure RNG (the `getrandom`-backed `rand` CSPRNG), never a PRNG seeded
  predictably.
- No `unwrap`/`expect`/`panic!` on library paths.
- Must compile and run on `wasm32-unknown-unknown`.
- `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-crypto token` — expected: passes (length, charset, uniqueness props).
- `cargo build -p bymax-auth-crypto --target wasm32-unknown-unknown` — expected: builds.
- `cargo llvm-cov -p bymax-auth-crypto --lcov` — expected: `token.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update P1
row in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 1.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 1.4 — Password hashing: scrypt + Argon2id, PHC, rehash-on-verify (`password`)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 1.1, 1.2

#### Description

Implement the password module: scrypt and (feature-gated) Argon2id hashers producing self-describing PHC strings, constant-time verification, `needs_rehash` for rehash-on-verify, startup parameter-floor validation, and a compatibility parser for the legacy nest-auth `scrypt:hex:hex` format.

#### Acceptance criteria

- [ ] `hash(password, params) -> Result<String, CryptoError>` produces a PHC string for the active algorithm (scrypt or Argon2id).
- [ ] `verify(password, phc) -> Result<bool, CryptoError>` parses any supported PHC (or the legacy `scrypt:hex:hex`) and compares in constant time.
- [ ] `verify` is a TOTAL function: a malformed or unknown-algorithm PHC string returns `Ok(false)` (never an `Err`), and the error path has uniform timing so it is not a timing oracle (the caller cannot distinguish "invalid hash" from "wrong password").
- [ ] `needs_rehash(phc, current_params) -> bool` returns true when the stored hash uses a weaker algorithm or parameters than the current configuration (drives rehash-on-verify).
- [ ] Parameter-floor validation rejects below-minimum params (scrypt: power-of-two N ≥ 2^14; Argon2id: OWASP floor `m ≥ 19456 KiB`, `t ≥ 2`) via `CryptoError::InvalidParams`.
- [ ] An Argon2id-only build (`--no-default-features --features argon2`) compiles and contains no scrypt code.
- [ ] 100% coverage including: PHC round-trip; wrong-password rejection; cross-algorithm verify; `needs_rehash` on a downgraded param set; legacy `scrypt:hex:hex` verify + `needs_rehash == true`; a `proptest` over random passwords.
- [ ] Rustdoc states that callers must run `hash`/`verify` inside `tokio::task::spawn_blocking` (this crate is sync and runtime-free).

#### Files to create / modify

- `crates/bymax-auth-crypto/src/password/mod.rs`
- `crates/bymax-auth-crypto/src/password/scrypt.rs`
- `crates/bymax-auth-crypto/src/password/argon2.rs` (`#[cfg(feature = "argon2")]`)
- `crates/bymax-auth-crypto/src/password/phc.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-crypto` is the RustCrypto-only, no-async,
wasm-safe crypto crate. Password hashing is configurable (scrypt default; Argon2id behind the
`argon2` feature) with rehash-on-verify and PHC self-describing storage. Edition 2024.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.4 of 6 (MIDDLE — the meatiest task)

PRECONDITIONS
- Task 1.1 is done: deps `scrypt` (feature `scrypt`), `argon2` (feature `argon2`),
  `password-hash`, plus `subtle` and `mac`/`compare` from Task 1.2.
- The crate exposes `compare::constant_time_eq` and `CryptoError`.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 5.1.3 "Password configuration" — the scrypt/Argon2id
  parameters and the OWASP floors; the `active_algorithm` model; that Argon2id is `#[cfg(argon2)]`.
- `docs/technical_specification.md` § 7.2 "PasswordService" — the rehash-on-verify flow; the
  PHC self-describing wire format; the legacy `scrypt:hex:hex` compatibility parser; and the
  `spawn_blocking` requirement (which is the CALLER's responsibility — this crate stays sync).
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — constant-time verify.

TASK
Implement the password module: PHC hashing/verification for scrypt and Argon2id, parameter-floor
validation, `needs_rehash`, and the legacy-format compatibility parser.

DELIVERABLES

1. `crates/bymax-auth-crypto/src/password/mod.rs` — the public surface:
   - A `PasswordAlgorithm` discriminator (`Scrypt`; `Argon2id` is `#[cfg(feature = "argon2")]`).
   - Param types `ScryptParams` / `Argon2Params` with `validate()` enforcing the floors.
   - `pub fn hash(password: &[u8], params: &PasswordParams) -> Result<String, CryptoError>`
     (PHC output for the active algorithm).
   - `pub fn verify(password: &[u8], phc: &str) -> Result<bool, CryptoError>` (parse + constant-time).
     `verify` is TOTAL: a malformed or unknown-algorithm `phc` returns `Ok(false)`, never `Err`,
     and the error path keeps uniform timing so it is not a timing oracle.
   - `pub fn needs_rehash(phc: &str, current: &PasswordParams) -> bool`.
   - A module-level rustdoc note: "Run `hash`/`verify` inside `tokio::task::spawn_blocking`; this
     crate is synchronous and runtime-free."

2. `password/scrypt.rs`, `password/argon2.rs` (`#[cfg(feature = "argon2")]`) — the per-algorithm
   PHC implementations using the `password-hash` traits.

3. `password/phc.rs` — PHC parse/format helpers + the legacy `scrypt:hex:hex` compatibility parser
   (recognized on verify; always reported as stale by `needs_rehash` so it upgrades on next login).

Constraints:
- Verification compares via the `password-hash` verifier (constant-time) — never `==` on hashes.
- Parameter floors: scrypt N is a power of two ≥ 2^14; Argon2id `m ≥ 19456` KiB, `t ≥ 2`. Reject
  below-floor params with `CryptoError::InvalidParams`.
- An Argon2id-only build must not reference scrypt (the `scrypt` module is `#[cfg(feature="scrypt")]`).
- No `unwrap`/`expect`/`panic!` on library paths; opaque `CryptoError` on failure (do not leak
  whether the algorithm, salt, or params were the problem).
- `#![forbid(unsafe_code)]`; document every public item; English-only, timeless comments.

Verification:
- `cargo test -p bymax-auth-crypto password` — expected: round-trip, wrong-password rejection,
  cross-algorithm verify, malformed/unknown-PHC → `Ok(false)` (never `Err`), `needs_rehash` on
  downgrade, legacy `scrypt:hex:hex` verify, proptest — all pass.
- `cargo build -p bymax-auth-crypto --no-default-features --features argon2` — expected: builds
  with no scrypt code.
- `cargo llvm-cov -p bymax-auth-crypto --lcov` — expected: `password/*` at 100%.
- `cargo clippy -p bymax-auth-crypto --features argon2 -- -D warnings` — expected: clean.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update P1
row in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 1.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 1.5 — MFA secret encryption — AES-256-GCM (`aead`, `mfa` feature)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 1.1

#### Description

Implement the `mfa`-gated AES-256-GCM module used to encrypt the TOTP secret at rest, with a fresh random 12-byte IV per encryption and the 16-byte auth tag, and a self-describing wire format.

#### Acceptance criteria

- [ ] The `aead` module is `#[cfg(feature = "mfa")]`; with `mfa` off, `aes-gcm` is absent from the dependency tree.
- [ ] `encrypt(plaintext, key) -> Result<String, CryptoError>` uses AES-256-GCM with a fresh CSPRNG 12-byte IV; output is a self-describing string (e.g. `base64(iv):base64(tag):base64(ciphertext)`).
- [ ] `decrypt(wire, key) -> Result<Vec<u8>, CryptoError>` validates the auth tag; any tampering or wrong key yields `CryptoError::Decrypt` (opaque).
- [ ] The 32-byte key is wrapped/zeroized appropriately; key length is validated.
- [ ] 100% coverage including: round-trip; tamper-detection (flip a ciphertext/tag byte → `Decrypt`); wrong-key rejection; malformed-wire rejection; a `proptest` over random plaintexts.

#### Files to create / modify

- `crates/bymax-auth-crypto/src/aead.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-crypto` is the RustCrypto-only, wasm-safe
crypto crate. AES-256-GCM is used (under the `mfa` feature) to encrypt the TOTP secret at rest.
Edition 2024.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.5 of 6 (MIDDLE)

PRECONDITIONS
- Task 1.1 is done: `aes-gcm` is an optional dep behind the `mfa` feature; `aead.rs` is an empty
  `#[cfg(feature = "mfa")]` module; `token::random_bytes` and `CryptoError` exist.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — AES-256-GCM IV/tag
  handling, the self-describing wire format, key handling/zeroize, and the opaque-error rule.
- `docs/technical_specification.md` § 7.5 "MfaService" — that the TOTP secret is stored AES-GCM
  encrypted and decrypted only on use (context, not implementation).

TASK
Implement the `mfa`-gated AES-256-GCM encrypt/decrypt for the MFA secret at rest.

DELIVERABLES

1. `crates/bymax-auth-crypto/src/aead.rs` (`#[cfg(feature = "mfa")]`):
   - `pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<String, CryptoError>` —
     AES-256-GCM, fresh 12-byte random nonce per call (from `token::random_bytes`), output a
     self-describing string `base64(nonce):base64(tag):base64(ciphertext)` (or combined-detached
     equivalent — document the chosen layout).
   - `pub fn decrypt(wire: &str, key: &[u8; 32]) -> Result<Vec<u8>, CryptoError>` — parse, verify
     the tag, return plaintext; any failure → `CryptoError::Decrypt` (never reveal which check failed).
   - Validate inputs; wrap the key with `zeroize` so it clears on drop.

Constraints:
- A NEW random 12-byte nonce per encryption (never reuse a nonce with the same key).
- All failures collapse to opaque `CryptoError` (Decrypt/Encoding); do not distinguish tamper vs
  wrong-key vs malformed in the error.
- The whole module is `#[cfg(feature = "mfa")]`; with `mfa` off, `aes-gcm` must not be in the tree.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-crypto --features mfa aead` — expected: round-trip, tamper, wrong-key,
  malformed-wire, proptest — all pass.
- `cargo tree -p bymax-auth-crypto -e features -i aes-gcm` — expected: present only via `mfa`.
- `cargo build -p bymax-auth-crypto` (no mfa) then `cargo tree -i aes-gcm` — expected: not present.
- `cargo llvm-cov -p bymax-auth-crypto --features mfa --lcov` — expected: `aead.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update P1
row in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 1.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 1.6 — MFA TOTP/HOTP + Base32 + otpauth URI (`totp`, `mfa` feature)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 1.1

#### Description

Implement the `mfa`-gated TOTP/HOTP module per RFC 6238 / RFC 4226: code generation and window-tolerant verification, Base32 secret encoding (`data-encoding`), and the `otpauth://` provisioning URI for authenticator apps.

#### Acceptance criteria

- [ ] The `totp` module is `#[cfg(feature = "mfa")]`; with `mfa` off, `sha1`/`data-encoding` are absent from the tree.
- [ ] HOTP (RFC 4226) and TOTP (RFC 6238) generation are implemented over HMAC-SHA1 with a 30s step and 6-digit default.
- [ ] `verify(secret, code, time, window) -> bool` accepts a code within `±window` steps, compared in constant time.
- [ ] Base32 secret encode/decode via `data-encoding` (RFC 4648, no padding, uppercase).
- [ ] `provisioning_uri(secret, account, issuer) -> String` produces a valid `otpauth://totp/...` URI.
- [ ] 100% coverage including the **RFC 6238 / RFC 4226 known-answer test vectors**, window boundary tests, and a Base32 round-trip `proptest`.

#### Files to create / modify

- `crates/bymax-auth-crypto/src/totp.rs`

#### Agent prompt

````
You are a senior Rust cryptography engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; `bymax-auth-crypto` is the RustCrypto-only, wasm-safe
crypto crate. TOTP (RFC 6238) is the MFA mechanism (under the `mfa` feature). Edition 2024.

CURRENT PHASE: 1 (bymax-auth-crypto) — Task 1.6 of 6 (LAST)

PRECONDITIONS
- Task 1.1 is done: `sha1` and `data-encoding` are optional deps behind `mfa`; `totp.rs` is an
  empty `#[cfg(feature = "mfa")]` module; `compare::constant_time_eq` exists.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 17 "Cryptography & Security Model" — the TOTP primitives
  (RFC 6238/4226, HMAC-SHA1, Base32 via `data-encoding`) and the `mfa` gating.
- `docs/technical_specification.md` § 7.5 "MfaService" — the setup/verify/challenge context: the
  provisioning URI, the verification window, and that anti-replay lives in the engine (NOT here).

TASK
Implement the `mfa`-gated TOTP/HOTP primitives, Base32 secret encoding, and the otpauth URI.

DELIVERABLES

1. `crates/bymax-auth-crypto/src/totp.rs` (`#[cfg(feature = "mfa")]`):
   - `pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32` (RFC 4226, HMAC-SHA1, dynamic
     truncation).
   - `pub fn totp(secret: &[u8], unix_time: u64, step_secs: u64, digits: u32) -> u32` (RFC 6238).
   - `pub fn verify(secret: &[u8], code: &str, unix_time: u64, window: u8) -> bool` — checks the
     code across `±window` steps; constant-time digit comparison.
   - `pub fn encode_secret_base32(secret: &[u8]) -> String` / `decode_secret_base32(s: &str) ->
     Result<Vec<u8>, CryptoError>` via `data-encoding` (RFC 4648, uppercase, no padding).
   - `pub fn provisioning_uri(secret: &[u8], account: &str, issuer: &str) -> String` →
     `otpauth://totp/{issuer}:{account}?secret=...&issuer=...&period=30&digits=6&algorithm=SHA1`
     (URL-encode the label/params).

Constraints:
- Verification compares the candidate code to the generated code in constant time.
- Anti-replay is NOT this crate's concern (the engine handles it) — do not add Redis/state here.
- The whole module is `#[cfg(feature = "mfa")]`; with `mfa` off, `sha1`/`data-encoding` absent.
- No `unwrap`/`expect`/`panic!`; `#![forbid(unsafe_code)]`; document every public item; English-only.

Verification:
- `cargo test -p bymax-auth-crypto --features mfa totp` — expected: the RFC 6238/4226 known-answer
  vectors pass, window-boundary tests pass, Base32 round-trip proptest passes.
- `cargo build -p bymax-auth-crypto` (no mfa) then `cargo tree -i sha1` — expected: not present.
- `cargo build -p bymax-auth-crypto --features mfa --target wasm32-unknown-unknown` — expected: builds.
- `cargo llvm-cov -p bymax-auth-crypto --features mfa --lcov` — expected: `totp.rs` at 100%.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Set progress `6/6`. 5. Update
the P1 row in `docs/development_plan.md` (mark ✅ when all six tasks are done). 6. Recompute the
overall %. 7. Append `- 1.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
