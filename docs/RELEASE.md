# Release process

This document describes what `.github/workflows/release.yml` does today, what it
does **not** do, and what a maintainer must do by hand around it. It is written
against that workflow file; where the two disagree, the workflow is the behaviour
and this file is wrong.

Nothing has been published yet. Neither the crates nor `@bymax-one/rust-auth`
exist on their registries, and the workspace and npm versions are still `0.0.0`.

---

## What ships, and where

`rust-auth` is a **dual-registry** product with one version:

| Artefact | Registry | Notes |
| --- | --- | --- |
| `bymax-auth` (facade) + the internal `bymax-auth-*` crates | **crates.io** | eight crates; `cargo publish --workspace` orders them from the dependency graph |
| `@bymax-one/rust-auth` | **npm** | bundles the compiled WASM edge verifier |
| `bymax-auth-wasm` | **neither** | `publish = false`; a build artefact compiled into the npm package |

The workspace version (`[workspace.package]` in `Cargo.toml`), every publishable
crate, every internal `=x.y.z` pin and `packages/rust-auth/package.json` carry one
number. `scripts/check-release-versions.sh` proves it, and CI runs it on every
push (job `release versions`), so a drifted pin is a red check long before a tag.

---

## What the `release` workflow does

Triggered by a `v*.*.*` tag push, or by `workflow_dispatch`. One run at a time
(`concurrency: release`, no cancellation). Workflow-level permissions are
`contents: read`; each job widens only what it needs.

1. **`verify`** — runs `scripts/check-release-versions.sh "$GITHUB_REF_NAME"`
   (tag = workspace version = every crate = every pin = npm version), then
   `cargo publish --workspace --dry-run`, which packages every crate and rebuilds
   it from its tarball.
2. **`crates`** (needs `verify`) — environment `crates-io-publish`; exchanges the
   job's OIDC token for a short-lived crates.io credential
   (`rust-lang/crates-io-auth-action`) and runs `cargo publish --workspace --no-verify`.
3. **`npm`** (needs `crates`) — environment `npm-publish`; builds the WASM and the
   ESM + CJS bundles, runs `attw` (`check:exports`) and the Vitest suite with
   coverage, then `npm publish --provenance --access public` (OIDC, no `NPM_TOKEN`).
4. **`release`** (needs `crates` and `npm`) — creates the GitHub Release, using the
   tag's `CHANGELOG.md` section as the body. The notes travel in an environment
   variable, never through `${{ }}` interpolation.

If `crates` succeeds and `npm` fails, the crates are already published and cannot
be unpublished: both registries are append-only, so the fix is a new version.

### What it does not do

State this plainly when deciding whether a tag is a release:

- **No SBOM.** No CycloneDX document is generated or attached to the release.
- **No artefact attestations.** Nothing runs `actions/attest-build-provenance`, so
  `gh attestation verify` has nothing to verify. The only provenance is the one
  `npm publish --provenance` attaches to the npm package; the crates carry none.
- **No `cargo-geiger` report.**
- **No re-run of the quality gates.** `release.yml` does not run the `ci` jobs,
  the dogfood smokes or the mutation sweep. It trusts that the tagged commit was
  green in `ci`; the tagger has to check that.
- **No mutation gate.** The release floor is zero missed mutants, and it is
  measured by hand (below), not enforced by the workflow.

`docs/technical_specification.md` §21.5 and §21.10 describe the SBOM and
attestation jobs as part of the release pipeline. They are not implemented; until
they are, that part of the specification describes intent, not behaviour.

---

## One-time maintainer setup (not yet done)

1. **Create the two GitHub Environments** the workflow names:
   `crates-io-publish` and `npm-publish`, each with required reviewers. They do
   not exist in the repository today. Until they do, a job that names an
   environment creates it unprotected on first use, and a pushed tag publishes
   with no approval step.
2. **Publish the first version of every crate by hand.** crates.io can attach a
   Trusted Publisher only to a crate that already exists, and none of the eight
   does. Publish them in dependency order from a maintainer's machine, then
   configure `bymaxone/rust-auth` + workflow `release.yml` + environment
   `crates-io-publish` as the Trusted Publisher of each crate.
3. **Publish the first version of `@bymax-one/rust-auth` by hand**, for the same
   reason, then configure its npm Trusted Publisher the same way
   (environment `npm-publish`).
4. Confirm branch protection on `main`.

After steps 2 and 3 the first publish has happened outside the workflow; the
workflow's `crates` and `npm` jobs publish every later version.

---

## Cutting a release

1. Land every change on `main` through pull requests; `ci` is green.
2. Move the `Unreleased` items of `CHANGELOG.md` under a `## [X.Y.Z]` heading
   (the release job finds its notes by that heading).
3. Bump the workspace version, the internal `=x.y.z` pins and
   `packages/rust-auth/package.json` together, in one pull request.
   `scripts/check-release-versions.sh` must pass.
4. Run the full mutation sweep (`mutation-sweep` workflow, dispatched on the merge
   commit of step 3) and require every shard to have tested exactly what it was
   assigned, with zero missed. The receipt must name the SHA that gets tagged.
5. Tag that same commit and push the tag: `git tag vX.Y.Z <sha>`, then push
   `vX.Y.Z` to `origin`.
6. Approve the `crates-io-publish` and `npm-publish` environments when prompted.
7. Check the result: the crates on crates.io, the package and its provenance on
   npm, and the GitHub Release body.

`workflow_dispatch` resumes an interrupted release only when it is run with the
**tag** selected as the ref. Run on a branch, `GITHUB_REF_NAME` is the branch name
and `verify` fails the tag check.

---

## Supply-chain controls

| Control | Tool / mechanism | When | Status |
| --- | --- | --- | --- |
| Advisory scanning | `cargo-audit` (RustSec) | per-PR + daily cron | active (`ci`, `audit`) |
| Policy / ban-list | `cargo-deny` | per-PR | active (`ci`) |
| Dependency audit ledger | `cargo-vet` | per-PR | active (`ci`) |
| Dependency budget | `cargo tree` count gate | per-PR | active (`ci`) |
| Pinned graph | committed `Cargo.lock` | always | active |
| Version coherence | `scripts/check-release-versions.sh` | per-PR + release | active (`ci`, `release`) |
| Public API / SemVer | `cargo public-api` + `cargo-semver-checks` | per-PR | active (`ci`) |
| Registry trust | crates.io + npm OIDC Trusted Publishing | each release | wired in `release.yml`; needs the setup above |
| npm provenance | `npm publish --provenance` | each release | wired in `release.yml` |
| Posture transparency | OpenSSF Scorecard | push-to-`main` + weekly | active (`scorecard`) |
| SBOM | CycloneDX | each release | **absent** |
| Artefact attestations | GitHub Artifact Attestations | each release | **absent** |
| Transitive `unsafe` report | `cargo-geiger` | each release | **absent** |
