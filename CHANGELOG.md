# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire/contract surface (token shapes, cookie names, the error envelope) is
treated as the public API for SemVer purposes — a breaking wire change is a major
version bump.

## [Unreleased]

### Added

- Initial workspace scaffolding: the Cargo workspace, the facade and internal
  crate skeletons, the WASM edge binding, the npm package stub, the pinned
  toolchain and lint posture, the supply-chain policy (`cargo-deny` / `cargo-vet`),
  the CI workflow, and the repository governance files.
- `[package.metadata.docs.rs]` on every public crate so docs.rs renders the full
  feature surface with `--cfg docsrs`.
- TypeDoc and ESLint configuration for the `@bymax-one/rust-auth` npm package — the
  JavaScript-side API documentation and lint gate.
- The six official `examples/` apps (`axum-minimal`, `axum-mfa`,
  `axum-oauth-google`, `react-vite`, `nextjs`, `bymax-live-auth`), built and linted
  in CI and excluded from the 100 % coverage workspace.
- Extra CI quality and security gates: CodeQL, OpenSSF Scorecard, a scheduled
  RustSec `audit`, a `cargo public-api` + `cargo-semver-checks` public-surface gate,
  a dependency-budget gate, a time-boxed `cargo-fuzz` smoke, a scheduled
  `cargo-mutants` pre-release mutation gate, and a Security-Invariants (§24) check.
- Non-publishing dogfood smokes (a crate Axum app and an npm Next.js app) and a
  Playwright browser end-to-end suite driving login → request → refresh → logout
  with edge JWT verification.
- `docs/RELEASE.md` documenting the deferred publish pipeline and the one-time
  OIDC / protected-environment setup it requires.

[Unreleased]: https://github.com/bymaxone/rust-auth/commits/main
