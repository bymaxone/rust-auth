#!/usr/bin/env bash
# Dependency-budget gate.
#
# Resolves the PRODUCTION (non-dev) dependency graph for the shipped crates and
# asserts each stays at or under a documented cap. This is the Rust analogue of a
# bundle-size tripwire: it fails on unexplained transitive-graph growth, so a heavy
# new dependency is a conscious, reviewed decision rather than silent bloat. When a
# cap is legitimately exceeded, raise it here in the same PR with a justification.
#
# Usage: scripts/dependency-budget.sh
set -euo pipefail

# Resolve to the repository root so `cargo tree` runs against this workspace
# regardless of the caller's working directory (mirrors check-invariants.sh).
cd "$(dirname "$0")/.."

# Each entry: "<crate>:<features>:<cap>". Empty <features> means default features.
# `lib` selects the library target's normal edges only (no dev-dependencies).
BUDGETS=(
  "bymax-auth-types::40"
  "bymax-auth-jwt::55"
  "bymax-auth-crypto:scrypt,argon2,mfa:70"
  "bymax-auth-core:full:130"
  "bymax-auth-redis:mfa,oauth,platform:130"
  "bymax-auth-client::100"
  "bymax-auth-axum:full:165"
)

status=0
for entry in "${BUDGETS[@]}"; do
  crate="${entry%%:*}"
  rest="${entry#*:}"
  features="${rest%%:*}"
  cap="${rest##*:}"

  feature_args=()
  if [[ -n "$features" ]]; then
    feature_args=(--features "$features")
  fi

  # Resolve the normal (production) dependency graph. Capture cargo's own stderr and
  # surface it on failure rather than discarding it, so a resolver/feature error is
  # diagnosable in CI instead of silently producing an empty (under-cap) graph.
  tree_err="$(mktemp)"
  if ! tree_out="$(cargo tree -p "$crate" ${feature_args[@]+"${feature_args[@]}"} \
      --edges normal --prefix none --no-dedupe 2>"$tree_err")"; then
    echo "FAIL  $crate (${features:-default}): 'cargo tree' failed" >&2
    cat "$tree_err" >&2
    rm -f "$tree_err"
    status=1
    continue
  fi
  rm -f "$tree_err"

  # Count the unique crates in the resolved graph.
  count="$(printf '%s\n' "$tree_out" \
    | sed 's/ v[0-9].*//' \
    | grep -v '^$' \
    | sort -u \
    | wc -l \
    | tr -d ' ')"

  if (( count > cap )); then
    echo "FAIL  $crate (${features:-default}): $count crates > cap $cap" >&2
    status=1
  else
    echo "ok    $crate (${features:-default}): $count crates <= cap $cap"
  fi
done

if (( status != 0 )); then
  echo "" >&2
  echo "Dependency budget exceeded. Either drop the new dependency or raise the cap" >&2
  echo "in scripts/dependency-budget.sh with a justification in the PR." >&2
fi
exit "$status"
