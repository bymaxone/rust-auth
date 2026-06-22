#!/usr/bin/env bash
# Security-Invariants gate (a subset of the inviolable contract in the technical
# specification § 24, expressed as automatable structural checks).
#
# This is a blocking CI gate: a change that weakens one of these invariants fails the
# build. It complements — it does not replace — the coverage, mutation, property, and
# fuzz gates that protect the same contract dynamically. Each check below names the
# invariant it guards. Run from the repository root.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
note() { printf 'FAIL  %s\n' "$1" >&2; fail=1; }
pass() { printf 'ok    %s\n' "$1"; }

# Search only first-party source, never generated output, dependencies, or examples.
SRC_GLOB=(crates bindings)

# ── Invariant 3: HS256 is pinned; asymmetric algorithms are never trusted. ──────────
# The JWT verifier must never gain a branch that accepts RS256/ES256/none by trusting
# the inbound `alg`. A signature-verification dependency that brings algorithm
# agility (jsonwebtoken) is forbidden.
# Match a dependency-key line (`jsonwebtoken = ...`), not a prose comment that merely
# explains why the crate is avoided (those start with `#`).
if grep -rEn '^[[:space:]]*jsonwebtoken[[:space:]]*=' "${SRC_GLOB[@]}" \
     --include='*.toml' >/dev/null 2>&1; then
  note "invariant 3: the 'jsonwebtoken' crate (algorithm agility) must not be a dependency"
else
  pass "invariant 3: no algorithm-agile JWT dependency"
fi

# ── Invariant 17: RustCrypto only — no ring / OpenSSL on any first-party path. ──────
if grep -rEn '^[[:space:]]*(ring|openssl|openssl-sys)[[:space:]]*=' "${SRC_GLOB[@]}" \
     --include='*.toml' >/dev/null 2>&1; then
  note "invariant 17: ring/openssl must not appear as a first-party dependency"
else
  pass "invariant 17: no ring/openssl dependency declared"
fi

# `#![forbid(unsafe_code)]` on every first-party crate except the wasm bindgen glue,
# which must instead carry `#![deny(unsafe_op_in_unsafe_fn)]`.
missing_forbid=0
while IFS= read -r librs; do
  case "$librs" in
    bindings/bymax-auth-wasm/*)
      grep -q 'deny(unsafe_op_in_unsafe_fn)' "$librs" || { note "invariant 17: $librs must deny unsafe_op_in_unsafe_fn"; missing_forbid=1; }
      ;;
    *)
      grep -q 'forbid(unsafe_code)' "$librs" || { note "invariant 17: $librs must forbid unsafe_code"; missing_forbid=1; }
      ;;
  esac
done < <(find crates bindings -name lib.rs)
(( missing_forbid == 0 )) && pass "invariant 17: every first-party crate forbids unsafe (wasm glue excepted)"

# ── Invariant 4: bearer/refresh credentials are never read from the query string. ──
# Flag any extractor that pulls an access/refresh token out of a query map.
if grep -rEn 'query[^;]*(access_token|refresh_token|bearer)' "${SRC_GLOB[@]}" \
     --include='*.rs' -i >/dev/null 2>&1; then
  note "invariant 4: a token must never be read from the query string"
else
  pass "invariant 4: no token read from a query string"
fi

# ── npm: there is no `.` root export; the wasm binding is not a crates.io crate. ────
if grep -E '"\."[[:space:]]*:' packages/rust-auth/package.json >/dev/null 2>&1; then
  note "npm root export: package.json must not declare a '.' root export"
else
  pass "npm: no '.' root export"
fi

if grep -q 'publish = false' bindings/bymax-auth-wasm/Cargo.toml; then
  pass "wasm: bymax-auth-wasm is publish = false (never a crates.io crate)"
else
  note "wasm: bymax-auth-wasm must be publish = false"
fi

# ── Invariant 10: secrets are never logged. ────────────────────────────────────────
# A coarse tripwire: a tracing macro must not interpolate a raw secret/token/password
# field. This catches the obvious regressions; the log-surface unit tests assert the
# rest. The pattern looks for a tracing call on the same line as a bare secret field.
if grep -rEn '(trace|debug|info|warn|error)!\([^)]*(\bpassword\b|\bsecret\b|\brefresh_token\b|\baccess_token\b|\botp\b)[^)]*=[^)]*[^h])' \
     "${SRC_GLOB[@]}" --include='*.rs' >/dev/null 2>&1; then
  note "invariant 10: a tracing macro appears to interpolate a raw secret field"
else
  pass "invariant 10: no obvious secret interpolated into a tracing macro"
fi

echo ""
if (( fail != 0 )); then
  echo "Security-Invariant gate FAILED — a change weakens the § 24 contract." >&2
  exit 1
fi
echo "Security-Invariant gate passed."
