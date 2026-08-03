#!/usr/bin/env bash
#
# Run the gates CI runs, with the commands CI runs them with.
#
# Every command below is copied from a workflow step, not paraphrased from one, and the step
# it came from is named above it. That is the whole point: a local check that merely RESEMBLES
# CI passes while CI fails, which happened three times in one review round — `cargo hack`
# without `-D warnings`, `--all-features` standing in for the feature matrix, and `examples/`
# (a separate Cargo workspace, with its own lockfile) never built at all. Each looked verified
# locally and was not.
#
# The first version of this script fell into the same trap it was written to close: its `npm`
# gate ran `pnpm typecheck` — against a package locked by package-lock.json, so a different
# dependency tree than the one CI builds — where CI runs `npm ci`, a wasm build, a bundle
# build, `tsc`, `typedoc` and the suite; and its `examples` gate ran `cargo check` where CI
# runs a build, clippy-as-error, and production builds of two frontend examples. Both could
# pass against a tree CI rejects. If you extend this file, copy the step — do not summarise it.
#
# Sources:
#   fmt / clippy / test / coverage   bymaxone/.github → .github/workflows/rust-ci.yml
#   everything else                  .github/workflows/ci.yml
#
# Usage:
#   scripts/verify-like-ci.sh                  # every gate below
#   scripts/verify-like-ci.sh fmt clippy       # only the named ones
#   scripts/verify-like-ci.sh coverage         # opt-in, see below
#
# Gates: fmt clippy test hack wasm doc examples-rust examples-web npm
#
# Deliberately NOT in the default run, and the only two CI gates this script omits:
#   coverage   — available by name; several minutes. It IS a blocking PR gate at
#                `--fail-under-lines 100 --fail-under-functions 100`, so "not in the default
#                run" means "you must remember to run it", not "it will not stop your PR".
#                Run it before pushing anything that adds a function or a branch.
#   mutation   — never runs on a PR (post-merge on main only); use `cargo mutants` directly.
# Nothing else is omitted. A gate that cannot run in your environment must FAIL here rather
# than be skipped, because "it did not run" and "it passed" have to stay distinguishable.

set -uo pipefail

# Load cargo onto PATH for callers that do not source the interactive shell profile — GUI git
# clients launched by launchd, CI-shaped non-interactive shells, agent harnesses. Same guard
# the pre-push hook carries, and a no-op in a terminal that already has cargo.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

cd "$(dirname "$0")/.."

ALL_GATES=(fmt clippy test hack wasm doc examples-rust examples-web npm)

# Spelled out rather than `("${@:-${ALL_GATES[@]}}")`. That form does work — bash keeps `$@`'s
# word-splitting inside the `:-` default even within the quotes, so the list expands to one
# element per gate (verified on bash 3.2, the macOS system shell). It reads like it collapses
# into a single element, though, and a reviewer read it that way. A line whose correctness
# depends on a special case the reader has to know is not worth the two lines it saves.
if [ $# -eq 0 ]; then
  GATES=("${ALL_GATES[@]}")
else
  GATES=("$@")
fi

failed=()

run() {
  local name=$1
  shift
  printf '\n\033[1m── %s\033[0m\n' "$name"
  # Subshell: `gate_npm` cd's into the package, and a gate must not be able to change the
  # directory the next one starts from.
  if ("$@"); then
    printf '\033[32m   ok\033[0m\n'
  else
    printf '\033[31m   FAILED\033[0m\n'
    failed+=("$name")
  fi
}

# ── core (reusable rust-ci.yml) ───────────────────────────────────────────────

gate_fmt() { cargo fmt --all --check; }

gate_clippy() { cargo clippy --workspace --all-targets --all-features --locked -- -D warnings; }

gate_test() {
  cargo build --workspace --all-features --locked &&
    cargo test --workspace --all-features --locked
}

gate_coverage() {
  cargo llvm-cov --workspace --all-features --locked \
    --fail-under-lines 100 --fail-under-functions 100 \
    --lcov --output-path lcov.info
}

# ── feature matrix (ci.yml: feature-matrix) ───────────────────────────────────

# Two halves, exactly as the job splits them: the hasher-gated crates carry a compile_error!
# that rules out isolated non-hasher features, so they are checked against valid combinations
# and excluded from --each-feature.
# `RUSTFLAGS=-D warnings` is not decoration: the CI runner sets it job-wide (via
# `setup-rust-toolchain`), so a warning there is a red job. Without it this gate is strictly
# weaker than the one it claims to reproduce — a function used only under one feature is dead
# code in the builds that omit it, which is a warning locally and a failure in CI. That exact
# shape shipped a green local run into two red jobs.
gate_hack() {
  local features
  export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"
  for features in scrypt argon2 'scrypt,argon2' 'scrypt,mfa' 'argon2,mfa' 'scrypt,argon2,mfa'; do
    echo "checking bymax-auth-crypto --features $features"
    cargo check -p bymax-auth-crypto --no-default-features --features "$features" --locked || return 1
  done
  for features in scrypt argon2 'scrypt,argon2' full; do
    echo "checking bymax-auth --features $features"
    cargo check -p bymax-auth --no-default-features --features "$features" --locked || return 1
  done
  cargo hack check --workspace --exclude bymax-auth-crypto --exclude bymax-auth --each-feature --locked
}

# ── wasm target (ci.yml: wasm binding build / wasm-pack) ──────────────────────
#
# Compiles the binding for `wasm32-unknown-unknown`, which is the only way its
# `wasm-bindgen-test` target is built at all: `tests/web.rs` is gated to that architecture, so
# `cargo check --workspace --all-targets` on the host silently skips it. A signature change to
# an exported function therefore compiles clean locally and fails in the `wasm-pack` job — which
# is exactly what happened, four stale call sites at once.
#
# `cargo check` rather than a full `wasm-pack test`: the point is the compile, and this runs in
# seconds where wasm-pack downloads a toolchain and a headless runner.

gate_wasm() {
  if ! rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
    echo "wasm32-unknown-unknown target missing — install it with:" >&2
    echo "  rustup target add wasm32-unknown-unknown" >&2
    return 1
  fi
  cargo check -p bymax-auth-wasm --target wasm32-unknown-unknown --all-targets --locked
}

# ── rustdoc (ci.yml: doc) ─────────────────────────────────────────────────────

gate_doc() { RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked; }

# ── examples (ci.yml: examples) ───────────────────────────────────────────────

# examples/ is its own Cargo workspace with its own Cargo.lock, so the root build never
# touches it: a signature change that breaks every example passes everything above.
gate_examples_rust() {
  (cd examples && cargo build --locked) &&
    (cd examples && cargo clippy --all-targets --locked -- -D warnings)
}

# The frontend examples consume the npm package by `file:` path, so the package's dist/ and
# wasm/ have to exist on disk first. `next build` is the reason this half is not optional: it
# type-checks and compiles every route AND the middleware, which is where a proxy change that
# no unit test can reach — a `Location` Next refuses to parse, say — actually surfaces.
gate_examples_web() {
  (cd packages/rust-auth && npm ci && npm run build:wasm && npm run build) &&
    (cd examples/react-vite && npm ci --no-audit --no-fund && npm run build) &&
    (cd examples/nextjs &&
      npm ci --no-audit --no-fund &&
      AUTH_ACCESS_TOKEN_SECRET=an-edge-ci-secret-key-0123456789abcdef \
        AUTH_BACKEND_URL=http://127.0.0.1:8080 \
        npm run build)
}

# ── npm package (ci.yml: npm) ─────────────────────────────────────────────────

# npm, not pnpm: the package is locked by package-lock.json and CI installs with `npm ci`, so
# a pnpm run resolves a different tree and proves nothing about the one CI builds.
gate_npm() {
  cd packages/rust-auth || return 1
  npm ci &&
    npm run build:wasm &&
    npm run build &&
    npx tsc --noEmit &&
    npm run lint &&
    npx typedoc --emit none &&
    npm test
}

for gate in "${GATES[@]}"; do
  fn="gate_${gate//-/_}"
  if ! declare -F "$fn" >/dev/null; then
    echo "unknown gate: $gate (have: ${ALL_GATES[*]} coverage)" >&2
    exit 2
  fi
  run "$gate" "$fn"
done

printf '\n'
if [ ${#failed[@]} -eq 0 ]; then
  printf '\033[32mall gates passed\033[0m\n'
else
  printf '\033[31mfailed: %s\033[0m\n' "${failed[*]}"
  exit 1
fi
