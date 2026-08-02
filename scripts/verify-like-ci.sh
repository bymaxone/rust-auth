#!/usr/bin/env bash
#
# Run the gates CI runs, with the flags CI runs them with.
#
# Every command below is copied from a workflow, not paraphrased from one. That is the
# point: a local check that merely resembles CI passes while CI fails, which happened
# three times in one round — `cargo hack` without `-D warnings`, `--all-features` standing
# in for the feature matrix, and `examples/` (a separate workspace, with its own lockfile)
# never built at all. Each of those looked verified locally and was not.
#
# Sources:
#   crates + coverage  bymaxone/.github → .github/workflows/rust-ci.yml
#   the rest           .github/workflows/ci.yml
#
# Usage:
#   scripts/verify-like-ci.sh              # every gate
#   scripts/verify-like-ci.sh fmt clippy   # only the named ones
#
# Gates: fmt clippy test hack doc examples npm coverage
# `coverage` is the slow one and is excluded from the default run; ask for it by name.

set -uo pipefail

# Load cargo onto PATH for callers that do not source the interactive shell profile — GUI git
# clients launched by launchd, CI-shaped non-interactive shells, agent harnesses. Same guard
# the pre-push hook carries, and a no-op in a terminal that already has cargo.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

cd "$(dirname "$0")/.."

ALL_GATES=(fmt clippy test hack doc examples npm)
GATES=("${@:-${ALL_GATES[@]}}")

failed=()

run() {
  local name=$1
  shift
  printf '\n\033[1m── %s\033[0m\n' "$name"
  if "$@"; then
    printf '\033[32m   ok\033[0m\n'
  else
    printf '\033[31m   FAILED\033[0m\n'
    failed+=("$name")
  fi
}

gate_fmt() { cargo fmt --all --check; }

gate_clippy() { cargo clippy --workspace --all-targets --all-features --locked -- -D warnings; }

gate_test() {
  cargo build --workspace --all-features --locked &&
    cargo test --workspace --all-features --locked
}

# Two halves, exactly as the feature-matrix job splits them: the hasher-gated crates
# carry a compile_error! that rules out isolated non-hasher features, so they are checked
# against valid combinations and excluded from --each-feature.
gate_hack() {
  local features
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

gate_doc() { RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked; }

# examples/ is its own workspace with its own Cargo.lock. The root build never touches it,
# so a signature change that breaks every example still passes everything above.
gate_examples() { (cd examples && cargo check --workspace --locked); }

gate_npm() {
  (cd packages/rust-auth && pnpm -s typecheck && pnpm -s lint && pnpm -s test:cov)
}

gate_coverage() {
  cargo llvm-cov --workspace --all-features --locked \
    --fail-under-lines 100 --fail-under-functions 100 \
    --lcov --output-path lcov.info
}

for gate in "${GATES[@]}"; do
  if ! declare -F "gate_$gate" >/dev/null; then
    echo "unknown gate: $gate (have: ${ALL_GATES[*]} coverage)" >&2
    exit 2
  fi
  run "$gate" "gate_$gate"
done

printf '\n'
if [ ${#failed[@]} -eq 0 ]; then
  printf '\033[32mall gates passed\033[0m\n'
else
  printf '\033[31mfailed: %s\033[0m\n' "${failed[*]}"
  exit 1
fi
