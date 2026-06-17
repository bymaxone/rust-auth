# Phase 0 — Foundation: workspace, toolchain & CI skeleton

> **Status**: 📋 ToDo · **Progress**: 0 / 6 tasks · **Last updated**: 2026-06-17
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P0
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

The repository currently contains only `docs/technical_specification.md` (the 25-section source of truth) and `docs/development_plan.md` (the 13-phase roadmap). There is no Rust code, no `CLAUDE.md`/`AGENTS.md`, and no CI. The roadmap's **Global conventions** table is the authoritative convention source for now.

Phase 0 produces a **building, fully-gated, empty workspace**: a Cargo workspace with every member crate scaffolded (lint headers, crate-level docs, no logic), a pinned toolchain, the facade's feature taxonomy and hasher guard, supply-chain configuration, a CI workflow that runs every gate green on the stubs, and the standard governance/repo files. When P0 is done, `cargo build`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo llvm-cov`, and `cargo deny check` all pass, the `wasm32-unknown-unknown` build of `bymax-auth-wasm` compiles, and the repo is ready for P1/P2 to add real crates. **No authentication logic is written in this phase.**

---

## Rules-of-phase

1. **Edition 2024**, with a pinned MSRV (the support floor) in `[workspace.package].rust-version` and a pinned toolchain (latest stable) in `rust-toolchain.toml` — they are intentionally distinct; the `msrv` CI job builds on the floor.
2. **`#![forbid(unsafe_code)]`** on every first-party crate — the **sole exception** is `bymax-auth-wasm`, which confines `wasm-bindgen`'s generated `unsafe` under `#![deny(unsafe_op_in_unsafe_fn)]` with a documented justification.
3. **`#![deny(missing_docs)]`** on every public crate; each crate carries a crate-level `//!` doc.
4. **`cargo fmt --check`** and **`cargo clippy --workspace -- -D warnings`** are clean.
5. **Typed errors only**; no `unwrap`/`expect`/`panic!` on library code paths (test/build code may use them).
6. **Minimal-dependency premise**: do not add a dependency in P0 unless a task requires it; heavy integrations are feature-gated (none are pulled by the default build).
7. **No `core` feature**; `default = ["scrypt"]`; at least one hasher feature (`scrypt` or `argon2`) must be enabled — enforced by a `compile_error!`.
8. **English-only** and **timeless comments** — no `Phase N`/`Task`/roadmap references inside any committed file (code, config, or docs).
9. **Conventional Commits**, enforced locally (commitlint + husky).
10. **Never create `.gitkeep`/`.keep` or empty-directory placeholders** — directories emerge from real files only.
11. **`Cargo.lock` is committed** (this is a workspace with binaries/examples and a published library; the lockfile is part of the supply-chain posture).

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md) — § 3 Architecture, § 4 Workspace & Package Structure, § 19 Dependencies & Feature Flags, § 21 CI/CD & Release Engineering.
- [`docs/development_plan.md`](../development_plan.md) — § P0, § Global conventions, § Update protocol.
- `/bymax-workflow:standards` skill — universal coding rules (adapt the TypeScript-specific items to their Rust equivalents).

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 0.1 | Cargo workspace + crate skeletons | 📋 ToDo | P0 | M | — |
| 0.2 | Toolchain pinning, workspace lints & formatting | 📋 ToDo | P0 | S | 0.1 |
| 0.3 | Facade feature taxonomy, hasher guard & docs.rs metadata | 📋 ToDo | P0 | M | 0.1 |
| 0.4 | Supply-chain configuration (deny / vet / audit) | 📋 ToDo | P0 | M | 0.1 |
| 0.5 | CI skeleton workflow | 📋 ToDo | P0 | M | 0.1, 0.2, 0.3, 0.4 |
| 0.6 | Repo governance & docs files | 📋 ToDo | P1 | S | 0.1 |

---

## Tasks

### Task 0.1 — Cargo workspace + crate skeletons

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: —

#### Description

Create the Cargo workspace root and a skeleton crate for every workspace member (facade, internal crates, the WASM binding) plus the npm-package directory, each with crate-level docs and the correct lint headers but no logic.

#### Acceptance criteria

- [ ] `cargo build --workspace` succeeds.
- [ ] Root `Cargo.toml` declares `[workspace]` members and a `[workspace.package]` with `edition = "2024"`, a `rust-version` MSRV, `license = "MIT"`, `repository`, and `authors`.
- [ ] Crates exist at `crates/bymax-auth`, `crates/bymax-auth-{types,crypto,jwt,core,redis,axum,client}`, and `bindings/bymax-auth-wasm`, each with `Cargo.toml` + `src/lib.rs`.
- [ ] Every first-party crate carries `#![forbid(unsafe_code)]` except `bymax-auth-wasm` (which uses `#![deny(unsafe_op_in_unsafe_fn)]` with a justification comment); every public crate carries `#![deny(missing_docs)]` and a crate-level `//!` doc.
- [ ] `packages/rust-auth/package.json` exists as a minimal stub (`@bymax-one/rust-auth`, private/unpublished for now).
- [ ] No `.gitkeep` or empty-directory placeholder files exist.

#### Files to create / modify

- `Cargo.toml` (workspace root)
- `crates/bymax-auth/Cargo.toml`, `crates/bymax-auth/src/lib.rs`
- `crates/bymax-auth-types/{Cargo.toml,src/lib.rs}` and the same for `-crypto`, `-jwt`, `-core`, `-redis`, `-axum`, `-client`
- `bindings/bymax-auth-wasm/{Cargo.toml,src/lib.rs}`
- `packages/rust-auth/package.json`

#### Agent prompt

````
You are a senior Rust release/build engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend package `@bymax-one/rust-auth` (npm).
Rust edition 2024, single cargo workspace, Tokio for the async engine; full feature
parity with @bymax-one/nest-auth.

CURRENT PHASE: 0 (Foundation: workspace, toolchain & CI skeleton) — Task 0.1 of 6 (FIRST)

PRECONDITIONS
- The repo contains only `docs/` (technical_specification.md, development_plan.md). No Rust code yet.

REQUIRED READING (only these sections — do not load more):
- `docs/technical_specification.md` § 4 "Workspace & Package Structure" (the crate tree, the
  facade pattern, the `bindings/bymax-auth-wasm` placement, the npm package layout).
- `docs/technical_specification.md` § 3 "Architecture" (framework-agnostic core; which crates
  are wasm-safe: types/crypto/jwt).

TASK
Scaffold the Cargo workspace and an empty, documented skeleton crate for every member listed
below. No authentication logic — only crate metadata, lint headers, and crate-level docs.

DELIVERABLES

1. `Cargo.toml` (workspace root):
   - `[workspace]` with `resolver = "3"` and `members = ["crates/*", "bindings/*"]`.
   - `[workspace.package]` with `edition = "2024"`, `rust-version = "1.90"` (a recent-stable MSRV floor; the toolchain in Task 0.2
     tracks the latest stable and the `msrv` CI job builds on this floor), `license = "MIT"`,
     `repository = "https://github.com/bymaxone/rust-auth"`, `authors = ["Bymax One"]`.
   - A `[workspace.dependencies]` section (may start empty or with shared internal-crate
     version pins) so member crates can use `workspace = true` later.

   ```toml
   [workspace]
   resolver = "3"
   members = ["crates/*", "bindings/*"]

   [workspace.package]
   edition = "2024"
   rust-version = "1.90"
   license = "MIT"
   repository = "https://github.com/bymaxone/rust-auth"
   authors = ["Bymax One"]
   ```

2. The eight crates under `crates/` — `bymax-auth` (facade), `bymax-auth-types`,
   `bymax-auth-crypto`, `bymax-auth-jwt`, `bymax-auth-core`, `bymax-auth-redis`,
   `bymax-auth-axum`, `bymax-auth-client`. Each gets:
   - `Cargo.toml` with `[package]` `name`, `version = "0.0.0"`, `edition.workspace = true`,
     `rust-version.workspace = true`, `license.workspace = true`, `repository.workspace = true`,
     a one-line `description`, and (for now) no dependencies.
   - `src/lib.rs` starting with a crate-level `//!` doc line and the lint headers:

     ```rust
     //! Workspace-internal crate of `bymax-auth`. (Replace with the crate's real summary.)
     #![forbid(unsafe_code)]
     #![deny(missing_docs)]
     ```

3. `bindings/bymax-auth-wasm/Cargo.toml` + `src/lib.rs`:
   - `[lib] crate-type = ["cdylib", "rlib"]`.
   - `src/lib.rs` uses the documented unsafe exception instead of `forbid`:

     ```rust
     //! WASM edge bindings (npm-only; not published to crates.io). The only crate that
     //! cannot `forbid(unsafe_code)` because wasm-bindgen emits generated unsafe glue;
     //! that unsafe is confined to the bindgen boundary.
     #![deny(unsafe_op_in_unsafe_fn)]
     #![deny(missing_docs)]
     ```

4. `packages/rust-auth/package.json`:
   - Minimal stub: `{"name": "@bymax-one/rust-auth", "version": "0.0.0", "private": true,
     "description": "Frontend (React/Next.js) auth for the rust-auth backend"}`.

Constraints:
- `#![forbid(unsafe_code)]` on every first-party crate EXCEPT `bymax-auth-wasm`.
- `#![deny(missing_docs)]` on every public crate; each crate has a `//!` summary so the
  missing-docs lint passes on an otherwise-empty crate.
- English-only, timeless comments — no roadmap/phase/task references in any committed file.
- Do NOT create `.gitkeep` or empty-directory placeholders; let the real files create the dirs.
- Add no dependencies in this task.

Verification:
- `cargo build --workspace` — expected: builds with no errors and no warnings.
- `cargo build -p bymax-auth-wasm` — expected: builds (cdylib + rlib).
- `grep -q 'resolver = "3"' Cargo.toml` — expected: match (resolver 3 is the edition-2024 default; matches spec §4 + plan P0).
- `find . -name .gitkeep -o -name .keep` — expected: no output.

Completion Protocol (after you finish):
1. Set this task's status emoji to ✅ in the per-task block and the task index.
2. Tick the acceptance-criteria checkboxes that are now satisfied.
3. Update the task row in the Task index table.
4. Increment the phase progress counter to `1/6` in the header.
5. Update the P0 row in `docs/development_plan.md` (status + Last updated).
6. Recompute the overall progress percentage in `docs/development_plan.md`.
7. Append a completion-log entry: `- 0.1 ✅ <YYYY-MM-DD> — <one-line summary>`.
````

---

### Task 0.2 — Toolchain pinning, workspace lints & formatting

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: S
- **Depends on**: 0.1

#### Description

Pin the Rust toolchain (channel, components, and the `wasm32` target), centralize lints in `[workspace.lints]`, add `rustfmt.toml` and `.gitignore`, and commit `Cargo.lock`.

#### Acceptance criteria

- [ ] `rust-toolchain.toml` pins a stable channel and the `rustfmt`, `clippy`, `llvm-tools-preview` components and the `wasm32-unknown-unknown` target.
- [ ] `[workspace.lints]` defines the shared rust + clippy lint posture, inherited by every crate via `[lints] workspace = true`.
- [ ] `cargo fmt --check` is clean across the workspace.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- [ ] `.gitignore` excludes `/target` and editor cruft; `Cargo.lock` is committed.

#### Files to create / modify

- `rust-toolchain.toml`
- `rustfmt.toml`
- `Cargo.toml` (add `[workspace.lints]`); each crate `Cargo.toml` (add `[lints] workspace = true`)
- `.gitignore`
- `Cargo.lock` (commit)

#### Agent prompt

````
You are a senior Rust release/build engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition
2024, cargo workspace, Tokio for the async engine; full parity with @bymax-one/nest-auth.

CURRENT PHASE: 0 (Foundation) — Task 0.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 0.1 is done: the workspace and all skeleton crates build (`cargo build --workspace`).

REQUIRED READING (only these):
- `docs/development_plan.md` § "Global conventions" (the Workspace, Safety, and Lint/format rows).

TASK
Pin the toolchain, centralize the lint posture in the workspace, add formatting config and a
`.gitignore`, and commit the lockfile.

DELIVERABLES

1. `rust-toolchain.toml`:
   ```toml
   [toolchain]
   channel = "1.96"            # latest stable for dev/CI; the MSRV floor (rust-version = 1.90) is lower and enforced by the dedicated `msrv` CI job
   components = ["rustfmt", "clippy", "llvm-tools-preview"]
   targets = ["wasm32-unknown-unknown"]
   ```

2. `Cargo.toml` — add a `[workspace.lints]` table, e.g.:
   ```toml
   [workspace.lints.rust]
   unsafe_code = "forbid"
   missing_docs = "deny"
   rust_2024_compatibility = "warn"

   [workspace.lints.clippy]
   all = { level = "deny", priority = -1 }
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   ```
   Then add `[lints]\nworkspace = true` to every crate's `Cargo.toml`. NOTE: `bymax-auth-wasm`
   cannot inherit `unsafe_code = "forbid"` — give it its own `[lints.rust] unsafe_code = "allow"`
   (it keeps `#![deny(unsafe_op_in_unsafe_fn)]` from Task 0.1) and a comment explaining why.
   The `unwrap_used`/`expect_used`/`panic` denials may be relaxed under `#[cfg(test)]` later;
   for now lib code has none.

3. `rustfmt.toml` — a small, explicit config (e.g. `edition = "2024"`, `max_width = 100`,
   `imports_granularity = "Crate"`, `group_imports = "StdExternalCrate"`).

4. `.gitignore` — at least `/target`, `**/*.rs.bk`, `.DS_Store`, editor folders.

5. Commit `Cargo.lock` (do not gitignore it).

Constraints:
- After adding lints, the workspace must still be clean: fix any clippy finding by changing code,
  never by adding `#[allow(...)]` suppression (none should be needed on empty stubs).
- English-only, timeless comments.

Verification:
- `cargo fmt --check` — expected: no diff.
- `cargo clippy --workspace --all-targets -- -D warnings` — expected: clean.
- `rustup show` (or `cargo --version`) — expected: the pinned toolchain is active.
- `git check-ignore Cargo.lock` — expected: no output (it is tracked).

Completion Protocol:
1. Set status to ✅ (per-task block + index). 2. Tick acceptance criteria. 3. Update the index row.
4. Set progress to `2/6`. 5. Update the P0 row in `docs/development_plan.md`. 6. Recompute the
overall %. 7. Append: `- 0.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 0.3 — Facade feature taxonomy, hasher guard & docs.rs metadata

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 0.1

#### Description

Define the facade crate's complete feature taxonomy (`default = ["scrypt"]`, no `core` feature), enforce the "at least one hasher" invariant with a `compile_error!`, and configure docs.rs to build with `full`.

#### Acceptance criteria

- [ ] `crates/bymax-auth/Cargo.toml` `[features]` matches the canonical taxonomy: `default = ["scrypt"]`; `scrypt`, `argon2`, `sessions`, `mfa`, `oauth`, `oauth-reqwest` (= `["oauth", ...]`), `platform`, `invitations`, `redis`, `axum`, `client`; a `full` meta-feature; **no `core` feature**.
- [ ] `[package.metadata.docs.rs]` sets `features = ["full"]`.
- [ ] `crates/bymax-auth/src/lib.rs` contains a `compile_error!` that fires when neither `scrypt` nor `argon2` is enabled.
- [ ] `cargo build -p bymax-auth` (default) builds; `cargo build -p bymax-auth --features full` builds; `cargo build -p bymax-auth --no-default-features --features argon2` builds; `cargo build -p bymax-auth --no-default-features` FAILS with the hasher `compile_error!`.

#### Files to create / modify

- `crates/bymax-auth/Cargo.toml`
- `crates/bymax-auth/src/lib.rs`

#### Agent prompt

````
You are a senior Rust release/build engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; backend crate `bymax-auth` (crates.io), frontend
`@bymax-one/rust-auth` (npm). Rust edition 2024, cargo workspace; full parity with nest-auth.

CURRENT PHASE: 0 (Foundation) — Task 0.3 of 6 (MIDDLE)

PRECONDITIONS
- Task 0.1 is done: `crates/bymax-auth` exists as a building skeleton with lint headers.
- The internal crates exist but are still empty; the facade's feature-forwarding targets
  (e.g. `bymax-auth-core/mfa`) do not exist yet — so the facade's features may forward to
  optional dependencies that are not added until later phases. In THIS task, define the feature
  NAMES and the hasher guard; you may leave the `dep:`/`crate/feature` forwarding commented with
  a `# wired in a later phase` note where the target crate has no such feature yet, OR forward
  only to already-existing crate features. Do not add real dependencies to make them resolve.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 4 "Workspace & Package Structure" (the facade `[features]`
  block and the feature → crate mapping table).
- `docs/technical_specification.md` § 19 "Dependencies & Feature Flags" (the feature matrix and
  the "no core feature / at least one hasher" rules).

TASK
Author the facade's feature taxonomy, the docs.rs metadata, and the at-least-one-hasher guard.

DELIVERABLES

1. `crates/bymax-auth/Cargo.toml`:
   ```toml
   [features]
   default = ["scrypt"]

   # password hashers (at least one required — see the compile_error! in lib.rs)
   scrypt = []   # forwards to bymax-auth-crypto/scrypt once that feature exists
   argon2 = []   # forwards to bymax-auth-crypto/argon2 once that feature exists

   # optional engine flows (each forwards to a bymax-auth-core sub-feature in a later phase)
   sessions    = []
   mfa         = []
   oauth       = []   # OAuth orchestration + traits; NO http client
   oauth-reqwest = ["oauth"]   # adds the bundled ReqwestHttpClient (pulls reqwest) later
   platform    = []
   invitations = []

   # infrastructure / adapters
   redis  = []
   axum   = []
   client = []

   full = [
       "scrypt", "argon2", "sessions", "mfa", "oauth", "oauth-reqwest",
       "platform", "invitations", "redis", "axum", "client",
   ]

   [package.metadata.docs.rs]
   features = ["full"]
   ```
   IMPORTANT: there is deliberately NO `core` feature. As later phases add the internal crates
   as optional dependencies, replace the empty `[]` bodies with the real forwarding
   (`["dep:bymax-auth-redis"]`, `["bymax-auth-core/mfa"]`, etc.). Add a top-of-block comment
   stating that the empty bodies are placeholders that get wired as their target crates land.

2. `crates/bymax-auth/src/lib.rs` — add the hasher guard near the top (after the lint headers):
   ```rust
   #[cfg(not(any(feature = "scrypt", feature = "argon2")))]
   compile_error!(
       "bymax-auth requires at least one password-hasher feature: enable `scrypt` (default) \
        or `argon2` (recommended for new projects via AuthConfig::secure_defaults())."
   );
   ```

Constraints:
- `default = ["scrypt"]`; no `core` feature; features strictly additive.
- Keep the crate building under every hasher-enabled configuration; the only configuration that
  must fail to compile is "no hasher".
- English-only, timeless comments (the placeholder note must not reference phases — say
  "wired when the target crate is added", not "Phase N").

Verification:
- `cargo build -p bymax-auth` — expected: builds (default = scrypt).
- `cargo build -p bymax-auth --features full` — expected: builds.
- `cargo build -p bymax-auth --no-default-features --features argon2` — expected: builds.
- `cargo build -p bymax-auth --no-default-features 2>&1 | grep -q 'at least one password-hasher'`
  — expected: the build fails with the hasher compile_error.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`.
5. Update P0 row in `docs/development_plan.md`. 6. Recompute %. 7. Append
`- 0.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 0.4 — Supply-chain configuration (deny / vet / audit)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 0.1

#### Description

Add the supply-chain policy files: `cargo-deny` (advisories, licenses, bans, sources), `cargo-vet` scaffolding with imported audit sets, and ensure `cargo-audit` runs against the lockfile.

#### Acceptance criteria

- [ ] `deny.toml` denies vulnerability/unmaintained advisories; sets a license allow-list (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-DFS-2016); bans `openssl`/`openssl-sys`, duplicate semver-major versions, and `ring`; restricts sources to crates.io.
- [ ] `supply-chain/config.toml` (and the generated `imports.lock`) exist with `cargo-vet` configured to import the Google, Mozilla, and Bytecode Alliance audit sets.
- [ ] `cargo deny check` passes on the current (tiny) dependency graph.
- [ ] `cargo audit` runs against `Cargo.lock` with no advisories.

#### Files to create / modify

- `deny.toml`
- `supply-chain/config.toml`, `supply-chain/imports.lock`

#### Agent prompt

````
You are a senior Rust supply-chain / release engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library with an explicit supply-chain-hardening posture
(minimal dependencies, every direct dep justified). Backend crate `bymax-auth` (crates.io),
frontend `@bymax-one/rust-auth` (npm). Edition 2024, cargo workspace.

CURRENT PHASE: 0 (Foundation) — Task 0.4 of 6 (MIDDLE)

PRECONDITIONS
- Task 0.1 is done: the workspace builds. The dependency graph is currently tiny (essentially
  just the standard library + build internals), so the policy must pass on an almost-empty graph
  and stay valid as real deps land in later phases.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 19 "Dependencies & Feature Flags" (the `cargo-deny` policy:
  ban-list, license allow-list, sources; the `cargo-vet` audit-import posture; cargo-geiger note).
- `docs/technical_specification.md` § 21 "CI/CD & Release Engineering" (where these gates run).

TASK
Author `deny.toml` and initialize `cargo-vet` so the supply-chain gates pass today and encode
the policy for the future.

DELIVERABLES

1. `deny.toml`:
   - `[advisories]` — deny vulnerabilities and unmaintained crates; `yanked = "deny"`.
   - `[licenses]` — `allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
     "Unicode-DFS-2016", "Unicode-3.0"]`; deny copyleft by omission; `confidence-threshold = 0.9`.
   - `[bans]` — `multiple-versions = "deny"` (with a small, documented `skip`/`skip-tree` list if
     a transitive duplicate is unavoidable); `deny = [{ name = "openssl" }, { name = "openssl-sys" },
     { name = "ring" }]` with a comment that `ring` is banned because it breaks the wasm32 path and
     RustCrypto is the policy.
   - `[sources]` — `unknown-registry = "deny"`, `unknown-git = "deny"`, `allow-registry =
     ["https://github.com/rust-lang/crates.io-index"]`.

2. `cargo-vet` scaffolding — run `cargo vet init` (creates `supply-chain/config.toml` +
   `supply-chain/audits.toml` + `imports.lock`), then add the well-known imported audit sets to
   `config.toml`:
   ```toml
   [imports.google]
   url = "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml"
   [imports.mozilla]
   url = "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"
   [imports.bytecode-alliance]
   url = "https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml"
   ```

Constraints:
- The policy must PASS on the current graph (`cargo deny check` exit 0). If a transitive build
  dependency trips a rule, prefer documenting a narrow exception in `deny.toml` over loosening a
  whole category — and add a comment explaining each exception.
- Do not add runtime dependencies in this task.
- English-only, timeless comments.

Verification:
- `cargo deny check` — expected: `advisories ok`, `bans ok`, `licenses ok`, `sources ok`.
- `cargo vet --locked` (or `cargo vet`) — expected: runs; any unaudited crates are recorded as
  exemptions, not errors.
- `cargo audit` — expected: no vulnerabilities.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`.
5. Update P0 row in `docs/development_plan.md`. 6. Recompute %. 7. Append
`- 0.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 0.5 — CI skeleton workflow

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 0.1, 0.2, 0.3, 0.4

#### Description

Add the `ci.yml` GitHub Actions workflow that runs every foundational gate (fmt, clippy, build, test, coverage, cargo-deny, an MSRV build, and a `wasm32` build of `bymax-auth-wasm`) green on the stub workspace, plus `dependabot.yml`. Full release/CodeQL/Scorecard workflows are deferred to P12.

#### Acceptance criteria

- [ ] `.github/workflows/ci.yml` runs, on PR + push to main: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo build --workspace`, `cargo test --workspace`, `cargo llvm-cov` (coverage artifact), `cargo deny check`, an MSRV-pinned build job, and a `wasm32-unknown-unknown` build of `bymax-auth-wasm`.
- [ ] Workflow uses least-privilege `permissions: contents: read`, `concurrency` with `cancel-in-progress: true`, pinned action major versions, and `timeout-minutes` per job.
- [ ] `.github/dependabot.yml` updates `cargo` and `github-actions` weekly (PRs only).
- [ ] The workflow is valid YAML and every gate is green on the current stub workspace.

#### Files to create / modify

- `.github/workflows/ci.yml`
- `.github/dependabot.yml`

#### Agent prompt

````
You are a senior Rust CI/CD engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; backend crate `bymax-auth` (crates.io), frontend
`@bymax-one/rust-auth` (npm). Edition 2024, cargo workspace, pinned toolchain via
`rust-toolchain.toml`. Bymax CI conventions: least-privilege permissions, concurrency, pinned
actions, OIDC for publishing (publishing itself is a later phase).

CURRENT PHASE: 0 (Foundation) — Task 0.5 of 6 (MIDDLE)

PRECONDITIONS
- Tasks 0.1–0.4 are done: the workspace builds; `rust-toolchain.toml`, `[workspace.lints]`,
  `rustfmt.toml`, the facade features/guard, and `deny.toml` all exist. `cargo fmt --check`,
  `cargo clippy -- -D warnings`, and `cargo deny check` already pass locally.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21 "CI/CD & Release Engineering" (the `ci` job set,
  least-privilege/concurrency/pinned-actions conventions, the WASM build-integrity check; note
  that release/codeql/scorecard are NOT part of this skeleton — they land in the release phase).
- `docs/development_plan.md` § P0 (scope) and § "Global conventions" (the Tests row).

TASK
Author the `ci.yml` workflow that runs every foundational gate green on the stub workspace, plus
`dependabot.yml`. Do NOT add release/publish, CodeQL, or Scorecard workflows — those are scoped
to a later phase.

DELIVERABLES

1. `.github/workflows/ci.yml`:
   - Triggers: `pull_request` + `push` to `main` + `workflow_dispatch`.
   - Top-level `permissions: { contents: read }`; `concurrency: { group: ci-${{ github.ref }},
     cancel-in-progress: true }`.
   - Use a maintained Rust toolchain action pinned to a major version and a cargo cache action;
     install the toolchain from `rust-toolchain.toml`. Install `cargo-llvm-cov` and `cargo-deny`
     via a pinned installer action (e.g. `taiki-e/install-action`).
   - Jobs (each with `timeout-minutes`):
     - `fmt`: `cargo fmt --all --check`.
     - `clippy`: `cargo clippy --workspace --all-targets -- -D warnings`.
     - `test`: `cargo build --workspace` then `cargo test --workspace`.
     - `coverage`: `cargo llvm-cov --workspace --lcov --output-path lcov.info`; upload the LCOV as
       an artifact (`if: always()`).
     - `supply-chain`: `cargo deny check`.
     - `msrv`: build the workspace on the pinned MSRV (read `rust-version` / use the pinned
       toolchain) to prove the MSRV holds.
     - `wasm`: add the `wasm32-unknown-unknown` target and run
       `cargo build -p bymax-auth-wasm --target wasm32-unknown-unknown` (the wasm build-integrity
       tripwire — it must compile clean with no tokio/std-net leakage).

2. `.github/dependabot.yml`:
   - `version: 2`; ecosystems `cargo` and `github-actions`; `schedule.interval: weekly`;
     open PRs only (no auto-merge).

Constraints:
- Least privilege: never grant `write` at the workflow level; a job widens scope only if it needs
  it (none here do).
- Pin every action to at least a major version tag; pin the toolchain via `rust-toolchain.toml`.
- The workflow must be green on the current EMPTY workspace (no tests yet is fine — `cargo test`
  passes with zero tests; coverage runs on empty crates).
- English-only, timeless comments — no phase/task references in the YAML.

Verification:
- `yamllint .github/workflows/ci.yml .github/dependabot.yml` (or `gh workflow view`) — expected:
  valid YAML.
- Locally reproduce each gate: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`,
  `cargo test --workspace`, `cargo llvm-cov --workspace`, `cargo deny check`,
  `cargo build -p bymax-auth-wasm --target wasm32-unknown-unknown` — expected: all succeed.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`.
5. Update P0 row in `docs/development_plan.md`. 6. Recompute %. 7. Append
`- 0.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 0.6 — Repo governance & docs files

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: S
- **Depends on**: 0.1

#### Description

Add the standard public-repository governance and documentation files (license, security policy, contributing, code of conduct, changelog, README stub) and wire local Conventional-Commits enforcement (commitlint + husky).

#### Acceptance criteria

- [ ] `LICENSE` (MIT), `SECURITY.md` (disclosure policy + contact), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 by reference) all exist.
- [ ] `CHANGELOG.md` follows Keep-a-Changelog + SemVer and has an `Unreleased` section.
- [ ] `README.md` stub states the two-package model (`bymax-auth` = Rust backend on crates.io; `@bymax-one/rust-auth` = React/Next.js frontend on npm; the backend is never bundled in npm; `bymax-auth-wasm` is a build artifact, not a crates.io crate), a feature-matrix placeholder, a security note, a production-status line naming Bymax Live as the dogfood consumer, and badge placeholders.
- [ ] `commitlint.config.cjs`, `.husky/commit-msg`, `.husky/pre-commit`, `.husky/pre-push`, `.gitmessage`, and a root `package.json` (husky/commitlint devDeps + `prepare: husky`) exist; the commit-msg hook rejects a non-Conventional commit; the `pre-push` hook runs the fast local gate (`cargo fmt --check` + `cargo test`) before push.
- [ ] No text claims the library exists to demonstrate any author's or company's seniority/authority.

#### Files to create / modify

- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `README.md`
- `commitlint.config.cjs`, `.husky/commit-msg`, `.husky/pre-commit`, `.husky/pre-push`, `.gitmessage`, `package.json` (root)

#### Agent prompt

````
You are a senior open-source maintainer / release engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend package `@bymax-one/rust-auth` (npm). Edition
2024, cargo workspace. The first production consumer ("dogfood") is Bymax Live, a Rust-backend +
React/Next.js application.

CURRENT PHASE: 0 (Foundation) — Task 0.6 of 6 (LAST)

PRECONDITIONS
- Task 0.1 is done: the workspace exists. There is a `packages/rust-auth/package.json` stub.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21 "CI/CD & Release Engineering" (required repo files,
  README contents, badges, the two-package public-docs clarity points, Bymax Live dogfood) and
  § 25 "Examples & Dogfooding".

TASK
Create the public governance/documentation files and wire local Conventional-Commits enforcement.

DELIVERABLES

1. `LICENSE` — the MIT license text, copyright "Bymax One".
2. `SECURITY.md` — supported versions + a private disclosure process (security contact email;
   ask reporters not to open public issues for vulnerabilities).
3. `CONTRIBUTING.md` — how to build/test, the gate set (fmt/clippy/coverage/deny), Conventional
   Commits, and the DCO/sign-off or PR expectations.
4. `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 by reference/link (do not transcribe the full
   enumerated text), with the contact for reports.
5. `CHANGELOG.md` — Keep-a-Changelog header + SemVer note + an `## [Unreleased]` section.
6. `README.md` (stub — expanded in the release phase) covering:
   - One-line vision.
   - The TWO-PACKAGE model, stated explicitly: `bymax-auth` is the Rust backend published to
     crates.io; `@bymax-one/rust-auth` is the React/Next.js frontend published to npm; the Rust
     backend is NOT bundled inside the npm package; `bymax-auth-wasm` is a build artifact for the
     npm package, NOT a crates.io crate.
   - A feature-matrix placeholder (a heading + "see the technical specification").
   - A short Security section.
   - A "Production status" line naming Bymax Live as the first dogfood production consumer.
   - Badge placeholders (CI, coverage, crates.io, npm, docs.rs, audit, OpenSSF Scorecard,
     provenance).
7. Conventional-Commits governance:
   - root `package.json` with `devDependencies` for `husky` + `@commitlint/cli` +
     `@commitlint/config-conventional`, and `"scripts": { "prepare": "husky" }`.
   - `commitlint.config.cjs` = `module.exports = { extends: ['@commitlint/config-conventional'] };`
   - `.husky/commit-msg` running `npx --no -- commitlint --edit "$1"`.
   - `.husky/pre-commit` running `cargo fmt --all --check` (a fast local guard).
   - `.husky/pre-push` running the fast local gate before push: `cargo fmt --all --check`
     then `cargo test --workspace` (the Rust analogue of a pre-push test guard).
   - `.gitmessage` with a short Conventional-Commits template + the project's commit scopes.

Constraints:
- English-only; professional, neutral tone. Do NOT include any statement that the library exists
  to showcase an author's or company's seniority/authority — keep it strictly product-focused.
- Timeless content — no roadmap/phase references.
- Do not transcribe the full Contributor Covenant body; reference it.

Verification:
- `ls LICENSE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md README.md
  commitlint.config.cjs .gitmessage .husky/commit-msg .husky/pre-commit .husky/pre-push
  package.json` — expected: all present.
- `grep -q Unreleased CHANGELOG.md` — expected: match.
- `echo "bad message" | npx --no -- commitlint` — expected: non-zero exit (rejects non-Conventional).
- `grep -qi 'bymax live' README.md` — expected: match.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `6/6`.
5. Update the P0 row in `docs/development_plan.md` (mark ✅ when all six tasks are done).
6. Recompute the overall % in `docs/development_plan.md`. 7. Append
`- 0.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.
