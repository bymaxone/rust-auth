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
- **Cross-site request refusal** — an `Origin` / `Sec-Fetch-Site` check on
  cookie-authenticated writes, as a tower layer. `SameSite` covers this for
  `Lax`/`Strict`; it does not for `None`, which the library allows and which sends
  the session cookie cross-site. On by default; `cookies.trusted_origins` is
  required as soon as `same_site` is `None`, and refused under any other posture.
- **Breached-password refusal** — the `PasswordBreachChecker` seam with a bundled
  `HibpBreachChecker` (feature `breach`) riding the crate's existing `HttpClient`,
  so a deployment supplies the transport it already has. Only a 5-character SHA-1
  prefix leaves the process, and the checker fails **open** by contract: an
  unreachable corpus must never stop someone changing their password. Off by
  default (`AllowAllBreachChecker`).
- **Absolute session lifetime** — `jwt.absolute_session_lifetime_days` caps how
  long one login can be extended by rotation. `refresh_expires_in_days` bounds a
  token, not a session. Off by default: switching it on ends sessions already
  older than the cap.
- **`email_verified` on the OAuth profile** — `create_with_oauth` was called with
  `Some(true)` unconditionally. No bug today (the bundled Google provider refuses
  an unverified profile before building one), but the first third-party provider
  written against the old contract would have created a verified account from an
  address nobody proved they owned.
- **Per-route rate limits pinned to the shared contract** — the adapter already
  enforced them; what was missing was the agreement, with 21 numbers duplicated
  across two repositories and nothing checking they matched.

### Changed

- **Family-lineage reuse detection replaces the previous sentinel.** A login opens
  a family; every rotation inherits it; a replay past the grace window revokes that
  lineage and only that lineage. `revoke_family` prunes the **prefixed** index
  member (`rt:{hash}`), not the bare hash — the index format changed underneath it,
  and pruning a bare hash would have left every revoked session listed until the
  index itself expired.
- **The rotation Lua scripts no longer decode stored records.** `nest-auth` drives
  its end-to-end tier against an in-memory Redis whose Lua VM has no `cjson`, so a
  script that decodes JSON is one the shared contract cannot be exercised against
  on that side. The grace record's family and the family owner's id are parsed by
  the caller instead, with a real parser.
- **The grace window is single-shot.** The pointer was served on every request
  inside the window, so one captured consumed token could mint a session
  repeatedly. It is consumed on use now, matching `nest-auth`.

### Fixed

- **A grace pointer could resurrect a revoked lineage.** Reuse detection only
  proves the *replayed* token's own pointer expired; a pointer planted by an
  earlier rotation of the same lineage can still be live, and recovering from it
  minted a session carrying the revoked family id. A recovery now requires its
  family index to still exist. Red-checked with a three-token lineage.
- **A consumed token replayed after a revoke-all reported `Invalid` rather than
  `Reused`.** The `cf:` marker deliberately outlives both the pointer and the
  revoke-all, so a replay stays a theft signal. It never minted a session either
  way.
- **`handlers.ts` in `packages/rust-auth` had no tests at all** — the one module
  that writes `Set-Cookie` back to a browser. It is at 100 % lines now, and the
  package runs under a coverage ratchet in CI so it can only go up.

### Internal

- **The mutation gate's configuration was never being read.** `cargo-mutants`
  loads `.cargo/mutants.toml` and nothing else; the file sat at the repository
  root, where it is ignored in silence — so `examine_globs` scoped nothing,
  `bindings/`, `examples/` and `fuzz/` were being mutated despite the excludes,
  and CI had been running the same way. Moved, with the path requirement written
  into its header and a one-line check (`cargo mutants --list` must print only
  `crates/` paths). With the file finally read, `additional_cargo_args` supplies
  `--all-features` and cargo refuses the flag twice, so the copy on CI's command
  line is gone.
- Every surviving mutant the sweep reported is closed — killed by a new test or
  recorded in `.cargo/mutants.toml` with the reason it cannot be. Re-running the
  sweep over the survivors is what caught four fixes that asserted the wrong
  thing, so each of those is red-checked by hand. The first full sweep under the
  corrected configuration confirms it: **1,630 mutants, 1,242 caught, 95 detected
  by timeout, 293 unviable, zero survivors** (8 h wall clock).
- Recorded for whoever tunes the gate next: 95 of the 95 timeouts sit in the
  container-backed stores (`bymax-auth-redis`, 90 of them, and three in
  `bymax-auth-client`). A mutation there is detected by the suite *hanging* rather
  than asserting, and each one spends the full 119 s window — roughly half the
  run's wall clock. Shortening the window would buy hours at the cost of gate
  integrity, since a legitimately slow test cut short is reported as detected and
  would hide a survivor; the sound fix is making those tests fail fast instead.

[Unreleased]: https://github.com/bymaxone/rust-auth/commits/main
