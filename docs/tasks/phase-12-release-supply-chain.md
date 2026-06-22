# Phase 12 — Release engineering, supply-chain, docs, examples, dogfood

> **Status**: 🔄 Partial — non-publishing scope ✅ Done; release/publish pipeline DEFERRED · **Progress**: docs + examples + extra CI gates + dogfood + browser E2E shipped (2026-06-22); the `release` workflow, OIDC trusted publishing, SBOM/attestation publishing, the protected environment, and the tag↔version publish gate are deferred to a future release phase (see [`docs/RELEASE.md`](../RELEASE.md)) · **Last updated**: 2026-06-22
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) § P12
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

---

## Context

The full crate set, the npm package, the WASM binding, and the Rust client all exist and pass their own gates (P0–P11). This final phase stands up the **release pipeline and the supply-chain/provenance controls** that make `rust-auth` a publishable, professional 1.0: the full `ci` gate, the `codeql`/`scorecard`/`audit` security workflows, the `cargo-mutants` pre-release gate, the dual-registry `release` workflow (crates.io + npm via OIDC Trusted Publishing), CycloneDX SBOMs, GitHub Artifact Attestations, the documentation (docs.rs + TypeDoc + a strong README), the required repo files, the six official examples, and the production dogfood smokes. After P12, a tagged build publishes the 1.0 to **both** registries with provenance, SBOM, and attestations — nothing long-lived, nothing unverifiable.

The defining premise is that for a public auth library **the supply chain is part of the threat model**: the posture is explicit and verifiable end to end (advisory scanning, ban-list, audit ledger, pinned graph, SBOM, transitive-unsafe report, signed provenance, OIDC publishing, Scorecard transparency), so a downstream consumer can prove cryptographically *what* shipped (SBOM) and *that* it was built by this repo's release workflow and not substituted (attestations + OIDC). The dual-registry reality (`bymax-auth` on crates.io, `@bymax-one/rust-auth` on npm, `bymax-auth-wasm` compiled into the npm artefact but never a crate) shapes the publish order and the README's two-package map.

When P12 is done, a tagged dry-run publishes to both registries via OIDC (no tokens) emitting provenance + SBOM + attestations for the crate tarball(s), the npm tarball, the `*_bg.wasm`, and the SBOM itself; every CI gate is green across the feature matrix; all six examples build and lint; both dogfood smokes pass; the mutation score meets the agreed floor; and the §24 Security Invariants are a blocking CI contract. **This is the publishable 1.0 — nothing is out of scope.**

---

## Rules-of-phase

1. **OIDC Trusted Publishing only.** No `CARGO_REGISTRY_TOKEN` / `NPM_TOKEN` secrets; the `release` workflow runs one-at-a-time (`concurrency: release, cancel-in-progress: false`) behind a **protected, manually-approved** GitHub Environment so an accidental tag cannot publish unattended.
2. **Fail-fast (hard release gates).** A failure in type generation (`ts-rs`), the WASM build (`wasm-pack`), SBOM generation, the advisory audit (`cargo-audit`), or **any** artefact attestation aborts the release with **nothing published**.
3. **Publish `crates/*` only.** The facade `bymax-auth` plus the internal crates publish to crates.io in leaf-first DAG order (facade last); `bymax-auth-wasm` ships **solely inside** the npm artefact (never crates.io); the tag↔version gate keeps the crate and npm versions in lockstep.
4. **Coverage is a hard PR gate; mutation testing is the pre-release gate.** 100% lines/regions across the `cargo-hack` feature matrix on every PR; `cargo-mutants` near-100% before release. Any PR weakening a §24 Security Invariant is blocked.
5. **Least privilege + pinned actions everywhere.** Workflow-level `permissions: contents: read`; jobs widen only the exact scope they need (`id-token: write`, `attestations: write`, …); all actions pinned (ideally by SHA) for Scorecard's Pinned-Dependencies check; `persist-credentials: false` on checkout where applicable.
6. **Examples and the dogfood are demonstration/consumer code**, not part of the published surface — but they are built and linted in CI so they cannot rot. Timeless comments (no plan/phase references) in every committed workflow, doc, and example.

---

## Reference docs

- [`docs/technical_specification.md`](../technical_specification.md):
  - § 21 "CI/CD & Release Engineering" (§21.1 `ci`, §21.2 `codeql`, §21.3 `scorecard`, §21.4 `audit`, §21.5 `release` dual-OIDC publish, §21.6 dogfood smokes, §21.7 required repo files, §21.8 docs.rs + TypeDoc + badges, §21.9 Conventional Commits + hooks, §21.10 the complete supply-chain provenance set).
  - § 19 "Dependencies & Feature Flags" (incl. §19.6 the dependency policy, ban-list, license allow-list, dependency-budget cap) — what `cargo-deny`/`cargo-vet`/the budget gate enforce.
  - § 20 "Testing Strategy & Quality Gates" (§20.5 per-crate vs workspace + WASM testing, §20.6 `cargo-mutants`, §20.8–§20.9 frontend + type-gen gates, §20.10 fuzz) — the gates the `ci` workflow runs.
  - § 24 "Security Invariants" — the blocking CI contract; any PR weakening one is blocked.
  - § 25 "Examples & Dogfooding" (§25.1 the six official examples, §25.2 the Bymax Live dogfood).
- [`docs/development_plan.md`](../development_plan.md) — § P12, § "Global conventions".
- `/bymax-workflow:standards` skill — universal coding rules.

---

## Task index

| ID | Task | Status | Priority | Size | Depends on |
|---|---|---|---|---|---|
| 12.1 | Full `ci` workflow (fmt/clippy/cov-100%/doctests/deny/vet/budget/WASM/ts-rs/tsc/ESLint) | 📋 ToDo | P0 | M | 11.6 |
| 12.2 | `codeql` + `scorecard` + `audit` workflows + `cargo-mutants` pre-release gate | 📋 ToDo | P0 | M | 12.1 |
| 12.3 | `release` workflow — dual OIDC publish + SBOM + attestations + fail-fast | 📋 ToDo | P0 | L | 12.1 |
| 12.4 | Docs (docs.rs + TypeDoc + README) + required repo files + commit hooks | 📋 ToDo | P0 | M | — |
| 12.5 | Official examples (axum-minimal/mfa/oauth · react-vite · nextjs · bymax-live-auth) | 📋 ToDo | P1 | L | 10.7, 11.6 |
| 12.6 | Dogfood smokes + §24 Security-Invariant CI gate + release dry-run | 📋 ToDo | P0 | M | 12.3, 12.5 |

---

## Tasks

### Task 12.1 — Full `ci` workflow (fmt/clippy/cov-100%/doctests/deny/vet/budget/WASM/ts-rs/tsc/ESLint)

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 11.6

#### Description

Build out the full `ci` workflow (expanding the P0 skeleton) so every per-PR + push-to-`main` gate runs: format, clippy-as-error, build, 100% coverage across the `cargo-hack` feature matrix, doctests, `cargo-deny`/`cargo-vet`/the dependency-budget gate, a short time-boxed `cargo-fuzz` smoke, `cargo public-api` + `cargo-semver-checks`, WASM build-integrity + size budget, the `ts-rs` staleness gate, and `tsc`/ESLint over the npm package (`cargo-geiger` runs at release, not per-PR).

#### Acceptance criteria

- [ ] Workflow-level `permissions: contents: read`; `concurrency: ci-${{ github.ref }}` (cancel-in-progress); toolchain from `rust-toolchain.toml` (+ `wasm32-unknown-unknown`); `Swatinem/rust-cache`.
- [ ] Gates: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -D warnings`; `cargo build --workspace --all-features --locked`; `cargo llvm-cov --workspace --all-features --fail-under-lines 100 --fail-under-regions 100` (+ the `cargo-hack` feature matrix); `cargo test --doc --workspace`.
- [ ] WASM build-integrity (`bymax-auth-wasm` compiles wasm-clean + `wasm-pack build`) + a `*_bg.wasm` size-budget check (`≤ 350 KB` gzipped — the same ceiling asserted in P11); an MSRV build job.
- [ ] A short, time-boxed `cargo-fuzz` smoke (e.g. `cargo +nightly fuzz run <target> -- -max_total_time=60`) runs in `ci` over the trust-boundary parser targets (JWT segments/claims, `Cookie`/`Authorization` headers, PHC strings, base32/base64url, OTP/recovery-code inputs) — no panic, fail closed; `fuzz/` target scaffolding for those parsers exists (§20.10).
- [ ] `ci` runs `cargo public-api` (public-surface snapshot) + `cargo-semver-checks` to gate the public API surface — a breaking change cannot ship unnoticed (§2.5 #10).
- [ ] Supply-chain: `cargo deny check advisories bans licenses sources` + `dependency-review-action` on PR; `cargo vet --locked`; the dependency-budget gate (per-crate count ≤ the §19.6 cap). (`cargo-geiger` is NOT a per-PR gate — it runs at release, §21.10/§19.6; see Task 12.3 Job D.)
- [ ] The `ts-rs` staleness gate (`cargo test -p bymax-auth-types --features ts-export` → `git diff --exit-code -- packages/rust-auth/src/shared`); `tsc --noEmit` + ESLint over `packages/rust-auth/src`.
- [ ] The frontend `vitest` + Testing Library (`@testing-library/react`) suite runs in `ci` on every PR that touches the npm package — hooks/provider, the fetch client, and the Next.js proxy/handlers against a mock backend and the generated `./shared` types (§20.8).
- [ ] The workflow is green on the current tree; all actions pinned.

#### Files to create / modify

- `.github/workflows/ci.yml`
- `xtask/` or scripts for the size-budget + dependency-budget checks (if not inlined)

#### Agent prompt

````
You are a senior Rust release/CI engineer working on the rust-auth project.

PROJECT: rust-auth — a public, production-grade authentication & authorization library.
Backend crate `bymax-auth` (crates.io); frontend `@bymax-one/rust-auth` (npm). Rust edition 2024,
cargo workspace + a TS/WASM npm package. 100% coverage is a HARD PR gate; the supply chain is part of
the threat model.

CURRENT PHASE: 12 (release engineering) — Task 12.1 of 6 (FIRST)

PRECONDITIONS
- Phases 0–11 done: all crates + the npm package + the WASM binding compile and pass their own tests.
- Phase 0 produced a `ci` skeleton (fmt/clippy/build/test/llvm-cov + a `cargo deny` step).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21.1 "ci workflow" — the COMPLETE step table.
- `docs/technical_specification.md` § 19.6 — the ban-list/license/advisory/source policy + the
  dependency-budget cap the gates enforce.
- `docs/technical_specification.md` § 20.5 / §20.6 / §20.8 / §20.9 — per-crate-vs-workspace + WASM
  testing, the feature matrix, the staleness gate.

TASK
Expand the `ci` workflow to run every per-PR gate in §21.1.

DELIVERABLES

1. `.github/workflows/ci.yml` — `permissions: contents: read`; `concurrency`; toolchain + cache; the
   full gate set: fmt, clippy `-D warnings`, build `--locked`, `cargo llvm-cov … --fail-under-lines 100
   --fail-under-regions 100` + `cargo-hack` matrix, doctests, WASM build-integrity + size budget, MSRV,
   `cargo deny`/`cargo vet`/dependency-budget, the ts-rs staleness gate, `tsc --noEmit`,
   ESLint. All actions pinned.
2. The size-budget + dependency-budget check scripts (inlined or under `xtask/`).

Constraints:
- Least-privilege permissions; pinned actions; 100% coverage is a HARD gate (fail-under-lines/regions).
- Timeless comments (no plan/phase references) in the workflow. English-only.

Verification:
- `act` or a CI dry-run on the current tree — expected: every gate runs and passes.
- `cargo deny check` + `cargo vet --locked` locally — expected: pass.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `1/6`. 5. Update the P12 row in `docs/development_plan.md`. 6. Recompute the overall %.
7. Append: `- 12.1 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 12.2 — `codeql` + `scorecard` + `audit` workflows + `cargo-mutants` pre-release gate

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 12.1

#### Description

Add the security/quality workflows: `codeql` (Rust, `security-extended`), `scorecard` (OSSF), the scheduled `audit` (RustSec `cargo-audit`), and the `cargo-mutants` near-100% mutation gate placed as a pre-release (not per-PR) check.

#### Acceptance criteria

- [ ] `codeql.yml`: `analyze` job, `permissions: { contents: read, security-events: write }`, `languages: rust` + `queries: security-extended`, weekly cron + push/PR.
- [ ] `scorecard.yml`: `analysis` job, `permissions: { security-events: write, id-token: write, contents: read, actions: read }`, `publish_results: true`, push-to-`main` + weekly cron, SARIF upload, `persist-credentials: false`.
- [ ] `audit.yml`: scheduled `cargo-audit` (RustSec) against the committed `Cargo.lock`, `permissions: contents: read`, failing on new advisories.
- [ ] `cargo-mutants` runs over the logic crates as a **pre-release** gate (not per-PR), blocking when the score drops below the agreed near-100% floor; the floor is documented.
- [ ] `criterion` benchmarks are wired for the hot paths (JWT sign/verify, hashing, refresh rotation, TOTP verify, the main endpoints) and run on demand + on a schedule with results retained as artefacts — **observational, explicitly NON-gating** (no per-PR pass/fail) (§20.11).
- [ ] All actions pinned; the workflows are syntactically valid and runnable.

#### Files to create / modify

- `.github/workflows/{codeql.yml,scorecard.yml,audit.yml}`
- `.github/workflows/release.yml` (the mutation-gate step) or a dedicated `mutants.yml`
- `mutants.toml` / config documenting the floor

#### Agent prompt

````
You are a senior Rust security/CI engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; supply-chain transparency is part of the product. Edition 2024.

CURRENT PHASE: 12 (release engineering) — Task 12.2 of 6 (MIDDLE)

PRECONDITIONS
- Task 12.1 done: the full `ci` workflow.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21.2 "codeql" + § 21.3 "scorecard" + § 21.4 "audit" — the three
  security workflows' shapes/permissions/triggers.
- `docs/technical_specification.md` § 20.6 "Mutation testing — cargo-mutants (PRE-RELEASE gate)".

TASK
Add the `codeql`/`scorecard`/`audit` workflows + the `cargo-mutants` pre-release gate.

DELIVERABLES

1. `.github/workflows/codeql.yml` — Rust, `security-extended`, weekly + push/PR.
2. `.github/workflows/scorecard.yml` — OSSF Scorecard, `publish_results: true`, `persist-credentials: false`.
3. `.github/workflows/audit.yml` — scheduled `cargo-audit` against the committed `Cargo.lock`.
4. The `cargo-mutants` PRE-RELEASE gate (in `release.yml` or `mutants.yml`) + a documented floor.

Constraints:
- Mutation testing is PRE-RELEASE, not per-PR (it is slow). Least-privilege permissions; pinned actions.
- Timeless comments; English-only.

Verification:
- Workflow lint (e.g. `actionlint`) — expected: valid.
- `cargo mutants --list` over the logic crates — expected: enumerates mutants (the gate runs pre-release).

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `2/6`. 5. Update the P12 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 12.2 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 12.3 — `release` workflow — dual OIDC publish + SBOM + attestations + fail-fast

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: L
- **Depends on**: 12.1

#### Description

Build the tag-driven `release` workflow: tag↔version match, the full verify rerun, crates.io OIDC Trusted Publishing in leaf-first DAG order (`crates/*` only), npm OIDC `--provenance` publish with the `wasm-pack` build, CycloneDX SBOMs, GitHub Artifact Attestations for every shipped artefact, the GitHub Release, fail-fast gating, and the WASM-only security-patch policy.

#### Acceptance criteria

- [ ] Tag-driven (`v*.*.*`) + `workflow_dispatch`; `concurrency: { group: release, cancel-in-progress: false }`; a protected, manually-approved Environment gates publishing; workflow-level `permissions: contents: read`.
- [ ] Pre-publish: tag↔version match (facade `Cargo.toml` + `package.json`); rerun the `ci` gate on the tagged SHA; the `cargo-mutants` pre-release gate.
- [ ] Job A (crates.io, `id-token: write`): ordered leaf-first publish of `crates/*` only (types → jwt/crypto → redis/client → core → axum → facade) via `release-plz`/`cargo-release` OIDC Trusted Publishing — **no `CARGO_REGISTRY_TOKEN`**; each `.crate` tarball gets a GitHub Artifact Attestation. `bymax-auth-wasm` is **not** in this order.
- [ ] Job B (npm, `id-token: write`): `wasm-pack build … --target bundler --release` → bundle into `wasm/`; the ts-rs staleness gate; build + assert ESM+CJS+dts per subpath; `npm publish --provenance` via OIDC (**no `NPM_TOKEN`**); attest the npm tarball.
- [ ] Job C (GitHub Release, `contents: write`): extract the tag's `CHANGELOG.md` section, `gh release create` passing notes via an **env var** (never `${{ }}` interpolation); upload the SBOM + attestation bundle.
- [ ] Job D (SBOM + attestation, `id-token: write` + `attestations: write`): CycloneDX SBOM for the crate graph, the npm package, and the WASM artefact; Artifact Attestations binding provenance to the crate tarball(s), the npm tarball, `*_bg.wasm`, and the SBOM itself; plus a non-blocking `cargo-geiger` transitive-`unsafe` report at release (§19.6/§21.10).
- [ ] Fail-fast: a failure in `ts-rs`, `wasm-pack`, SBOM, `cargo-audit`, or any attestation aborts with nothing published. The WASM-only-patch policy is documented (a WASM-only fix triggers an npm patch release; `release-plz` bumps both in lockstep).

#### Files to create / modify

- `.github/workflows/release.yml`
- `release-plz.toml` (or `cargo-release` config) for the leaf-first order

#### Agent prompt

````
You are a senior Rust release engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; dual-registry (`bymax-auth` on crates.io, `@bymax-one/rust-auth`
on npm). `bymax-auth-wasm` is compiled into the npm artefact, NEVER a crates.io crate. Publishing is OIDC
Trusted Publishing only — NO long-lived tokens. Edition 2024.

CURRENT PHASE: 12 (release engineering) — Task 12.3 of 6 (MIDDLE — the heart of the release)

PRECONDITIONS
- Task 12.1 done: the `ci` gate (reused on the tagged SHA). All crates + the npm package + WASM build.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21.5 "release workflow — dual publish via OIDC" — the pre-publish
  validation, Jobs A–D, the leaf-first crate order, the fail-fast gates, and the WASM-only-patch policy.
- `docs/technical_specification.md` § 21.10 "Supply-chain provenance (the complete set)" — SBOM +
  attestations + OIDC + the verifiability guarantee.

TASK
Build the `release` workflow: tag↔version, crates.io OIDC (leaf-first), npm OIDC `--provenance` + wasm-pack,
CycloneDX SBOM, GitHub Artifact Attestations, the GitHub Release, fail-fast.

DELIVERABLES

1. `.github/workflows/release.yml` — the four jobs (A crates.io, B npm, C GitHub Release, D SBOM+attest)
   exactly per § 21.5; `concurrency: release, cancel-in-progress: false`; protected Environment; tag↔version
   gate; the mutation pre-release gate; fail-fast on ts-rs/wasm/SBOM/audit/attestation.
2. `release-plz.toml` (or `cargo-release` config) — the leaf-first publish order; `crates/*` only
   (`bymax-auth-wasm` excluded); the lockstep crate↔npm version bump.

Constraints:
- OIDC ONLY — no `CARGO_REGISTRY_TOKEN`/`NPM_TOKEN`. Publish `crates/*` only; the WASM ships solely inside
  npm. Notes via env var, never `${{ }}` interpolation. Pinned actions; least-privilege per job.
  Timeless comments; English-only.

Verification:
- `actionlint .github/workflows/release.yml` — expected: valid.
- A `workflow_dispatch` dry-run (publish steps `--dry-run`) — expected: tag↔version, build, SBOM, and
  attestation steps succeed without publishing.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `3/6`. 5. Update the P12 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 12.3 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 12.4 — Docs (docs.rs + TypeDoc + README) + required repo files + commit hooks

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: —

#### Description

Complete the documentation and governance set: docs.rs config (feature `full`, `--cfg docsrs`), TypeDoc for the npm surface, the strong README (two-package map, feature matrix, the two default profiles, condensed threat model, badge row), the required repo files (expanding the P0 stubs), `dependabot.yml`, and the Conventional-Commit local hooks.

#### Acceptance criteria

- [ ] `[package.metadata.docs.rs]` on the facade renders the `full` feature set with `--cfg docsrs`; `RUSTDOCFLAGS="-D warnings"` is wired in CI and rustdoc on every public item passes (`#![deny(missing_docs)]`).
- [ ] TypeDoc config renders `./shared`/`./client`/`./react`/`./nextjs` into HTML API docs, generated in the release pipeline **and published** (e.g. to GitHub Pages) so the dual-registry product has docs on both registries — the JS-side analogue of docs.rs (§21.8).
- [ ] `README.md` carries, in order: a one-paragraph vision; the **two-package map** (`bymax-auth` = Rust backend on crates.io; `@bymax-one/rust-auth` = React/Next frontend on npm; the backend is **not** in npm; `bymax-auth-wasm` is a build artefact, not a crate); the feature list; a minimal runnable example; the feature-flag matrix (§19.2); the **two default profiles** (`default()` ≡ `nest_compat_defaults()` scrypt, `secure_defaults()` Argon2id); a Security section with a condensed §17.2 threat model + a pointer to `SECURITY.md`; a production-status statement (Bymax Live is the first dogfood consumer); and the badge row.
- [ ] Required files complete (expanding the P0 stubs): `LICENSE` (MIT), `SECURITY.md` (coordinated-disclosure policy + supported-versions), `CHANGELOG.md` (Keep-a-Changelog/SemVer), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`; `deny.toml` + `supply-chain/` present; `Cargo.lock` committed.
- [ ] `.github/dependabot.yml` (cargo + github-actions) + `ISSUE_TEMPLATE/`; the Conventional-Commit hooks (`commit-msg` → commitlint; `pre-commit` → fmt + clippy; `pre-push` → fast test) via `cargo-husky` / committed hooks.
- [ ] **No plan/phase references** in any committed doc or workflow; the README contains no marketing about demonstrating the author's/company's seniority.

#### Files to create / modify

- `README.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
- `crates/bymax-auth/Cargo.toml` (`[package.metadata.docs.rs]`)
- `packages/rust-auth/typedoc.json`
- `.github/dependabot.yml`, `.github/ISSUE_TEMPLATE/`, the commit-hook config

#### Agent prompt

````
You are a senior Rust/TypeScript docs + DX engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; dual-registry (`bymax-auth` crates.io + `@bymax-one/rust-auth`
npm). The README is the front door of a public library and must make the two-package split unambiguous.
Edition 2024.

CURRENT PHASE: 12 (release engineering) — Task 12.4 of 6 (MIDDLE)

PRECONDITIONS
- Phase 0 produced stub repo files (LICENSE/SECURITY/CONTRIBUTING/CHANGELOG/README); this task completes them.

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21.7 "Required repo files" + § 21.8 "Documentation + README badges"
  + § 21.9 "Conventional Commits + local hooks".
- `docs/technical_specification.md` § 17.2 (the threat-model table to condense for the README Security section)
  + § 5.1.9 (the two default profiles) + § 19.2 (the feature-flag matrix).

TASK
Complete docs.rs config, TypeDoc, the strong README, the required repo files, dependabot, and the commit hooks.

DELIVERABLES

1. `crates/bymax-auth/Cargo.toml` — `[package.metadata.docs.rs]` (feature `full`, `--cfg docsrs`).
2. `packages/rust-auth/typedoc.json` — render the four subpaths.
3. `README.md` — the full §21.8 structure (vision, two-package map, feature list, minimal example,
   feature-flag matrix, the two default profiles, condensed threat model + SECURITY pointer, production
   status (Bymax Live), badge row).
4. `SECURITY.md`/`CHANGELOG.md`/`CONTRIBUTING.md`/`CODE_OF_CONDUCT.md`/`LICENSE` — completed to the standard.
5. `.github/dependabot.yml` + `ISSUE_TEMPLATE/` + the Conventional-Commit hooks (`cargo-husky`/committed).

Constraints:
- NO plan/phase references in any committed doc/workflow. NO marketing about demonstrating
  seniority/authority. Timeless, self-explanatory prose. English-only.

Verification:
- `cargo doc --no-deps --features full` with `RUSTDOCFLAGS="-D warnings"` — expected: builds, no missing-docs.
- `typedoc --emit none` — expected: the four subpaths render.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `4/6`. 5. Update the P12 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 12.4 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 12.5 — Official examples (axum-minimal/mfa/oauth · react-vite · nextjs · bymax-live-auth)

- **Status**: 📋 ToDo
- **Priority**: P1
- **Size**: L
- **Depends on**: 10.7, 11.6

#### Description

Build the six official examples under `examples/` — `axum-minimal`, `axum-mfa`, `axum-oauth-google`, `react-vite`, `nextjs`, and `bymax-live-auth` — wired to the published surface and built + linted in CI so they cannot rot.

#### Acceptance criteria

- [ ] `axum-minimal`: mount `bymax-auth-axum`, an in-memory repo + recording email provider + a Redis, register → login → `/me`.
- [ ] `axum-mfa`: the local-login MFA lifecycle (setup → verify-enable → challenge); `axum-oauth-google`: the OAuth authorize→callback against a configured Google provider.
- [ ] `react-vite`: the `./react` hooks + `./client` against a running backend; `nextjs`: `createAuthProxy` + the route handlers + the WASM-backed `verifyJwtToken` (edge parity).
- [ ] `bymax-live-auth`: the dogfood integration shape (the production consumer pattern) — the auth wiring Bymax Live uses, as a runnable reference.
- [ ] All six build and lint in CI (a dedicated examples job) so a contract change that breaks an example fails CI; each carries a short README.
- [ ] Examples are demonstration code (not published); timeless comments; no plan/phase references.

#### Files to create / modify

- `examples/{axum-minimal,axum-mfa,axum-oauth-google,react-vite,nextjs,bymax-live-auth}/` (each a runnable app + README)
- `.github/workflows/ci.yml` (an examples build+lint job)

#### Agent prompt

````
You are a senior Rust/TypeScript engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; the official examples exercise and validate the library (they
are demonstration code, NOT published). Edition 2024; dual-registry. `bymax-live-auth` mirrors the
production consumer (Bymax Live).

CURRENT PHASE: 12 (release engineering) — Task 12.5 of 6 (MIDDLE — the broadest task)

PRECONDITIONS
- Phase 10 done: the Axum adapter (the backend the examples mount/target).
- Phase 11 done: the npm package + WASM (the frontend examples consume).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 25.1 "Official examples" + § 25.2 "Dogfood: Bymax Live" — the six
  examples and the dogfood shape.
- `docs/technical_specification.md` § 21.6 "Dogfood / smoke test" — the happy-path scripts the examples mirror.

TASK
Build the six official examples and wire an examples build+lint job in CI.

DELIVERABLES

1. `examples/axum-minimal/` — mount `bymax-auth-axum` + in-memory repo + recording email + Redis;
   register → login → `/me`.
2. `examples/axum-mfa/` — the MFA lifecycle; `examples/axum-oauth-google/` — authorize→callback.
3. `examples/react-vite/` — `./react` + `./client` vs a running backend.
4. `examples/nextjs/` — `createAuthProxy` + handlers + WASM-backed `verifyJwtToken` (edge parity).
5. `examples/bymax-live-auth/` — the dogfood integration shape (the production consumer pattern).
6. `.github/workflows/ci.yml` — an examples build+lint job so the examples cannot rot.
   Each example carries a short README.

Constraints:
- Examples are demonstration code (not published). Timeless comments; NO plan/phase references; NO
  marketing about demonstrating seniority. English-only.

Verification:
- `cargo build` in each Rust example + `pnpm build` in each TS example — expected: all build.
- The CI examples job — expected: builds + lints all six.

Completion Protocol:
1. Status ✅ (block + index). 2. Tick AC. 3. Update index row. 4. Progress `5/6`. 5. Update the P12 row
in `docs/development_plan.md`. 6. Recompute %. 7. Append `- 12.5 ✅ <YYYY-MM-DD> — <summary>`.
````

---

### Task 12.6 — Dogfood smokes + §24 Security-Invariant CI gate + release dry-run

- **Status**: 📋 ToDo
- **Priority**: P0
- **Size**: M
- **Depends on**: 12.3, 12.5

#### Description

Add the pre-tag dogfood smokes (a crate Axum app + an npm Next.js app against the to-be-published artefacts), wire the §24 Security Invariants as a blocking CI gate, and run the full tagged dry-run proving a dual-registry publish via OIDC with provenance, SBOM, and attestations.

#### Acceptance criteria

- [ ] **Crate smoke:** a throwaway Axum app depends on the facade (`axum,redis,mfa,sessions,oauth`), wires an in-memory repo + recording email + a `testcontainers` Redis, boots the router, and runs register → login → `/me` → refresh → logout asserting status codes, JSON bodies, and Set-Cookie headers — against a `cargo package`d / `--dry-run` build.
- [ ] **npm smoke:** a throwaway Next.js app installs the `npm pack` tarball, mounts `createAuthProxy` + the handlers, imports the WASM-backed `verifyJwtToken`, and asserts a backend-signed token verifies at the edge (server/edge parity) and that `./client`/`./react` import + type-check.
- [ ] A failure in either smoke blocks the tag (wired into the release pre-publish job).
- [ ] The §24 Security Invariants are a **blocking** CI gate: an automated check (grep/test-based) fails a PR that weakens an invariant — no token in a query string, HS256 pinned, secrets never logged, the no-`.` npm root, `bymax-auth-wasm` not a crate, etc.
- [ ] A full `workflow_dispatch` **dry-run** of `release` publishes to BOTH registries via OIDC (publish steps in dry-run), emitting provenance + a CycloneDX SBOM + Artifact Attestations for the crate tarball(s), the npm tarball, the `*_bg.wasm`, and the SBOM (verifiable with `gh attestation verify`).
- [ ] Every CI gate is green across the feature matrix; the mutation score meets the agreed floor.

#### Files to create / modify

- `examples/smoke-crate/` (the Axum smoke) + `examples/smoke-npm/` (the Next.js smoke)
- `.github/workflows/release.yml` (wire the smokes into pre-publish)
- `.github/workflows/ci.yml` (the §24-invariant gate) + a `scripts/check-invariants.*`

#### Agent prompt

````
You are a senior Rust/TypeScript release + security engineer working on the rust-auth project.

PROJECT: rust-auth — public auth library; before a tag is cut, two throwaway consumers prove the
published surface works, and the §24 Security Invariants are a blocking CI contract. Dual-registry,
OIDC publishing. Edition 2024.

CURRENT PHASE: 12 (release engineering) — Task 12.6 of 6 (LAST)

PRECONDITIONS
- Task 12.3 done: the `release` workflow (dual OIDC + SBOM + attestations).
- Task 12.5 done: the examples (the smokes reuse their shape).

REQUIRED READING (only these):
- `docs/technical_specification.md` § 21.6 "Dogfood / smoke test before tagging" — the crate + npm smokes.
- `docs/technical_specification.md` § 24 "Security Invariants" — the blocking CI contract.
- `docs/technical_specification.md` § 21.10 — the provenance set the dry-run must emit.

TASK
Add the dogfood smokes, wire the §24 invariant CI gate, and run the full tagged dry-run.

DELIVERABLES

1. `examples/smoke-crate/` — the Axum app smoke (register → login → /me → refresh → logout vs a
   `cargo package`d build + testcontainers Redis; assert status/body/Set-Cookie).
2. `examples/smoke-npm/` — the Next.js app smoke (install `npm pack` tarball; `createAuthProxy` +
   WASM `verifyJwtToken`; backend-signed token verifies at the edge; `./client`/`./react` type-check).
3. `.github/workflows/release.yml` — wire both smokes into pre-publish (a failure blocks the tag).
4. `scripts/check-invariants.*` + a `ci.yml` gate — fail a PR that weakens a §24 invariant (no token in
   URL, HS256 pinned, secrets not logged, no `.` npm root, wasm-not-a-crate, …).

Constraints:
- A smoke failure blocks the tag; an invariant-weakening PR is blocked. The dry-run publishes to BOTH
  registries via OIDC (dry-run) emitting provenance + SBOM + attestations. Timeless comments; English-only.

Verification:
- `cargo run -p smoke-crate` (with Docker) + the npm smoke — expected: both happy-paths pass.
- `workflow_dispatch` release dry-run — expected: tag↔version, dual OIDC (dry-run), SBOM, and
  attestations succeed; `gh attestation verify` validates the emitted attestations.
- The §24-invariant gate on a deliberately-weakening branch — expected: CI fails.

Completion Protocol:
1. Set status ✅ (block + index). 2. Tick acceptance criteria. 3. Update the index row. 4. Set
progress `6/6`. 5. Update the P12 row in `docs/development_plan.md` (mark ✅ when all six tasks are
done). 6. Recompute the overall % — and mark the project's task-scaffolding complete. 7. Append
`- 12.6 ✅ <YYYY-MM-DD> — <summary>`.
````

---

## Completion log

> Append-only. One line per completed task: `- <task-id> ✅ YYYY-MM-DD — <one-line summary>`.

- P12 (non-publishing scope) ✅ 2026-06-22 — docs.rs metadata on all public crates, TypeDoc + ESLint for the npm package, `docs/RELEASE.md`; the six official examples (own workspace, excluded from the 100% coverage gate); extra CI gates (codeql, scorecard, scheduled audit, public-api + semver-checks, dependency-budget, time-boxed cargo-fuzz, scheduled cargo-mutants, §24 invariants); crate + npm dogfood smokes; and a Playwright browser E2E (login → request → silent refresh → logout with edge WASM verification).
- DEFERRED (future release phase) — the `release` workflow, crates.io + npm OIDC trusted publishing, SBOM/attestation publishing, the protected GitHub environment, and the tag↔version publish gate. Documented in `docs/RELEASE.md` (tasks 12.3 publish jobs + the publishing half of 12.6 dry-run).
