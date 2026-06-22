# Release process (deferred)

This document describes the **publish/release pipeline** for `rust-auth` and the
**one-time setup** a maintainer must perform before the first tagged release can
publish the 1.0 to crates.io and npm.

> **Status: the publish pipeline is intentionally not yet active.** The
> documentation, the official `examples/`, the extra CI quality and security
> gates, the dogfood smokes, and the browser end-to-end suite are all in place and
> green. The **registry-publishing** half of the pipeline — OIDC Trusted
> Publishing to crates.io and npm, the `release` workflow itself, the published
> SBOM/attestations tied to a real publish, the protected GitHub Environment, and
> any actual `cargo publish` / `npm publish` — is **deferred to a future release
> phase**. Nothing in this repository performs a registry publish today. This file
> is the blueprint for wiring it up when that phase begins.

The design follows `docs/technical_specification.md` § 21.5 (release workflow),
§ 21.7 (required repo files), and § 21.10 (the complete supply-chain provenance
set). It is described here so the future implementation has an exact contract to
build against, and so a reader understands why the publish step does not yet
exist.

---

## What ships, and where

`rust-auth` is a **dual-registry** product:

| Artefact | Registry | Notes |
| --- | --- | --- |
| `bymax-auth` (facade) + the internal `bymax-auth-*` crates | **crates.io** | published in leaf-first DAG order, facade last |
| `@bymax-one/rust-auth` | **npm** | bundles the compiled WASM edge verifier |
| `bymax-auth-wasm` | **neither** | a `cdylib` build artefact, compiled **into** the npm package — never a crates.io crate |

The crate version (facade `Cargo.toml`) and the npm version (`package.json`) move
in **lockstep**; the tag drives both.

---

## One-time maintainer setup (the deferred prerequisites)

Before the first publish can run, a maintainer with org-admin rights must
configure the following. **None of this is wired today — it is the work the
deferred release phase unblocks.**

1. **crates.io OIDC Trusted Publishing.** On crates.io, add this repository
   (`bymaxone/rust-auth`) and the `release` workflow as a **Trusted Publisher**
   for each published crate (`bymax-auth-types`, `bymax-auth-jwt`,
   `bymax-auth-crypto`, `bymax-auth-redis`, `bymax-auth-client`, `bymax-auth-core`,
   `bymax-auth-axum`, `bymax-auth`). This lets the workflow exchange its GitHub
   OIDC token for a short-lived crates.io credential — **no `CARGO_REGISTRY_TOKEN`
   secret is ever stored**.

2. **npm OIDC Trusted Publishing.** On npm, configure the `@bymax-one/rust-auth`
   package with this repository + the `release` workflow as a Trusted Publisher so
   `npm publish --provenance` runs against a short-lived, identity-bound credential
   — **no `NPM_TOKEN` secret**.

3. **A protected GitHub Environment** (e.g. `release`) with **required reviewers**
   (manual approval) and, ideally, a branch/tag restriction. The publishing jobs
   reference this environment so an accidental tag cannot publish unattended.

4. **Repository settings** confirmed: branch protection on `main`, the
   `id-token: write` + `attestations: write` permissions available to the workflow,
   and Artifact Attestations enabled for the org.

5. **The tag ↔ version contract.** A release is cut by pushing a `v<MAJOR>.<MINOR>.<PATCH>`
   tag whose version **exactly matches** the facade crate version and the npm
   package version. The pre-publish job asserts this and aborts on mismatch.

---

## The `release` workflow (to be added)

Tag-driven (`v*.*.*`) plus `workflow_dispatch`, with
`concurrency: { group: release, cancel-in-progress: false }` (a release is
destructive and one-at-a-time) and workflow-level `permissions: contents: read`.
Each job widens only the scope it needs.

**Pre-publish validation (shared first job)**

- **Tag ↔ version match** — `${GITHUB_REF_NAME#v}` must equal the facade
  `Cargo.toml` version and the `package.json` version.
- **Full verify** — rerun the `ci` gate (fmt / clippy / build / 100 % coverage /
  doctests / supply-chain) on the tagged SHA.
- **Mutation gate** — `cargo-mutants` over the logic crates must meet the agreed
  near-100 % floor (this is the deliberate pre-release placement of the slow gate;
  see `.github/workflows/mutants.yml`).
- **Dogfood smokes** — the crate Axum smoke and the npm Next.js smoke
  (`examples/smoke-crate`, `examples/smoke-npm`) must pass against the
  to-be-published artefacts. A smoke failure blocks the tag.

**Job A — crates.io publish (`id-token: write`, `contents: read`).** Ordered,
leaf-first publish of `crates/*` **only** via crates.io OIDC Trusted Publishing
(`release-plz` preferred, `cargo-release` as the alternative). Order:

1. `bymax-auth-types`
2. `bymax-auth-jwt`, `bymax-auth-crypto`
3. `bymax-auth-redis`, `bymax-auth-client`
4. `bymax-auth-core`
5. `bymax-auth-axum`
6. `bymax-auth` (facade) last

`bymax-auth-wasm` is **not** in this order. Each `.crate` tarball receives a
GitHub Artifact Attestation.

**Job B — npm publish (`id-token: write`, `contents: read`).**
`wasm-pack build … --target bundler --release` → bundle into `wasm/`; run the
`ts-rs` staleness gate; build + assert ESM + CJS + `.d.ts` per subpath;
`npm publish --provenance` via npm OIDC. Attest the npm tarball.

**Job C — GitHub Release (`contents: write`).** Extract the tag's `CHANGELOG.md`
section and `gh release create`, passing the notes via an **environment variable
(never `${{ }}` interpolation)** to close the shell-injection vector. Upload the
SBOM + attestation bundle as release assets.

**Job D — SBOM + attestation (`id-token: write`, `attestations: write`,
`contents: read`).** Generate a CycloneDX SBOM for the crate graph, the npm
package, and the WASM artefact; emit GitHub Artifact Attestations binding
provenance to the crate tarball(s), the npm tarball, `*_bg.wasm`, and the SBOM
itself (verifiable downstream with `gh attestation verify`); run a **non-blocking**
`cargo-geiger` transitive-`unsafe` report.

**Fail-fast.** A failure in type generation (`ts-rs`), the WASM build
(`wasm-pack`), SBOM generation, the advisory audit (`cargo-audit`), or **any**
artefact attestation aborts the release with **nothing published**.

**WASM-only security-patch policy.** The compiled `.wasm` ships inside the npm
artefact, so a security fix touching **only** the WASM edge-verification path —
even with no change to any TS source — still **triggers an npm patch release** so
consumers receive the rebuilt binary. `release-plz` bumps the affected crate and
the npm package together; the tag ↔ version gate keeps them in lockstep.

---

## Supply-chain provenance (the complete set)

Every layer below is required at release time. The per-PR layers
(`cargo-deny` / `cargo-vet` / `cargo-audit` / dependency budget) are already wired
in `ci`; the **release-time** layers (SBOM, attestations, OIDC publishing,
`cargo-geiger`) are what the deferred `release` workflow adds.

| Control | Tool / mechanism | When | Status |
| --- | --- | --- | --- |
| Advisory scanning | `cargo-audit` (RustSec) | per-PR + daily cron | active (`ci`, `audit`) |
| Policy / ban-list | `cargo-deny` | per-PR | active (`ci`) |
| Dependency audit ledger | `cargo-vet` | per-PR | active (`ci`) |
| Dependency budget | `cargo tree` count gate | per-PR | active (`ci`) |
| Pinned graph | committed `Cargo.lock` | always | active |
| SBOM | CycloneDX | each release | **deferred** (this doc) |
| Transitive `unsafe` report | `cargo-geiger` | each release | **deferred** (this doc) |
| Build provenance | GitHub Artifact Attestations (Sigstore) | each release | **deferred** (this doc) |
| Registry trust | crates.io + npm OIDC Trusted Publishing | each release | **deferred** (this doc) |
| Posture transparency | OpenSSF Scorecard | push-to-`main` + weekly | active (`scorecard`) |

When the deferred half lands, a downstream consumer can answer two questions
cryptographically: **what** is inside a release (SBOM) and **that** it was built by
this repository's release workflow and not substituted (attestations + OIDC).

---

## Cutting a release (once the pipeline is active)

1. Land all changes on `main` through PRs; CI is green.
2. Update `CHANGELOG.md` (move `Unreleased` items under the new version section).
3. Bump the facade crate version and the npm `package.json` version together.
4. Tag: `git tag v<X.Y.Z> && git push origin v<X.Y.Z>`.
5. Approve the protected `release` environment when prompted.
6. The workflow validates, publishes crates.io (leaf-first) and npm (with
   provenance), emits the SBOM + attestations, and creates the GitHub Release.
7. Verify with `gh attestation verify` against the published artefacts.

Until this pipeline is implemented and the prerequisites above are configured,
**no release is published** — the crates and the npm package remain unpublished by
design.
