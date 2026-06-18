# Contributing

Thanks for your interest in improving `rust-auth`. This guide covers how to
build, test, and submit changes.

## Prerequisites

- The pinned Rust toolchain — installed automatically from `rust-toolchain.toml`
  (channel, components, and the `wasm32-unknown-unknown` target).
- Node.js, for the commit hooks and the npm package.
- The dev tools the gates use: `cargo-llvm-cov`, `cargo-deny`, `cargo-vet`, and
  `cargo-audit`.

## Build and test

```bash
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

## Quality gates (run before opening a PR)

```bash
cargo fmt --all --check                                              # formatting
cargo clippy --workspace --all-targets --all-features -- -D warnings # lints
cargo llvm-cov --workspace --all-features                            # coverage
cargo deny check                                                     # supply-chain policy
cargo build -p bymax-auth-wasm --target wasm32-unknown-unknown       # edge build integrity
```

CI runs the same gates on every pull request; a change is mergeable only when
they are all green. Coverage is held to 100% on crates that carry logic.

## Commit convention

Commits follow [Conventional Commits](https://www.conventionalcommits.org/). A
local `commit-msg` hook (commitlint) enforces the format, and `pre-commit` /
`pre-push` hooks run the fast local gates. Install the hooks once with:

```bash
npm install
```

Example: `feat(mfa): add recovery-code regeneration`.

## Pull requests

- Keep each change focused; explain the *why*, not just the *what*.
- Add or update tests for every behavior change — the suite is the contract.
- Keep comments and documentation in English and timeless (describe what the code
  does and why, never which roadmap step produced it).
- By contributing, you agree that your work is licensed under the repository's
  [MIT license](./LICENSE).
