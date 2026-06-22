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

# A banned dependency can be declared two ways in a Cargo manifest: the inline form
# `name = "1.0"` / `name = { ... }`, and the table form `[dependencies.name]` (also
# `[dev-dependencies.name]`, `[build-dependencies.name]`, and any `[target.*]`
# variant such as `[target.'cfg(unix)'.dependencies.name]`). The gate must catch BOTH
# so a table-style declaration can't slip a banned crate past it. `<name>` may itself
# be an alternation group like `(ring|openssl)`.
#
# Table headers are matched loosely: anything between `[` and `.<name>]` is allowed,
# as long as the line ends in `.<name>]` and contains `dependencies`. That covers the
# `dev-`/`build-` prefixes and the quoted `target.'…'.` segment without enumerating
# every shape.
banned_dep_pattern() {
  local name="$1"
  printf '(^[[:space:]]*%s[[:space:]]*=|^[[:space:]]*\[[^]]*dependencies\.%s\][[:space:]]*$)' \
    "$name" "$name"
}

# ── Invariant 3: HS256 is pinned; asymmetric algorithms are never trusted. ──────────
# The JWT verifier must never gain a branch that accepts RS256/ES256/none by trusting
# the inbound `alg`. A signature-verification dependency that brings algorithm
# agility (jsonwebtoken) is forbidden.
# Match a dependency declaration (inline `jsonwebtoken = ...` or a
# `[dependencies.jsonwebtoken]` table header), not a prose comment that merely
# explains why the crate is avoided (those start with `#`).
if grep -rEn "$(banned_dep_pattern jsonwebtoken)" "${SRC_GLOB[@]}" \
     --include='*.toml' >/dev/null 2>&1; then
  note "invariant 3: the 'jsonwebtoken' crate (algorithm agility) must not be a dependency"
else
  pass "invariant 3: no algorithm-agile JWT dependency"
fi

# ── Invariant 17: RustCrypto only — no ring / OpenSSL on any first-party path. ──────
if grep -rEn "$(banned_dep_pattern '(ring|openssl|openssl-sys)')" "${SRC_GLOB[@]}" \
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
# A coarse tripwire: a tracing macro must not interpolate or capture a raw
# secret/token/password value. This catches the obvious regressions; the log-surface
# unit tests assert the rest. The pattern looks for a `tracing::`/bare tracing call
# whose argument list either format-interpolates `{secret}` or captures the secret as
# a tracing field (`secret =`, including the `%`/`?` sigils).
#
# POSIX ERE has no `\b` word boundary (it is a literal backspace), so the left word
# boundary is spelled out explicitly: the secret token must be flanked on the left by
# a non-identifier character (start of arg list, `{`, whitespace, `(` …) or the line
# edge, which keeps `password`/`access_token` from matching inside `password_hash` or
# `access_token_ttl`. The `[a-z0-9_]` class is the Rust identifier alphabet (input is
# lower-cased via `-i`).
#
# The RIGHT side is the discriminator that separates a logged value from harmless
# prose: the secret must be immediately followed by `}` (closing a `{secret}`
# interpolation) or by an optional run of spaces and then `=` (a captured tracing
# field). A secret word sitting inside a quoted message — e.g. `"otp redacted"` or
# `"password reset token…"` — is followed by a space and another word, so it does not
# match.
secret_field='(password|secret|refresh_token|access_token|otp)'
# After the macro's opening `(`, an optional run of argument text ending in a
# non-identifier char provides the left word boundary; when the secret is the very
# first argument it sits directly against `(`, so that whole prefix group is optional.
left="(trace|debug|info|warn|error)!\(([^)]*[^a-z0-9_])?"
tracing_secret="${left}${secret_field}(\}|[[:space:]]*=)"

# Self-test: a security gate is only worth running if it still discriminates. Assert
# the pattern CATCHES a planted interpolation and does NOT fire on benign prose, so a
# future edit that silently neuters it (e.g. an un-anchored boundary) fails loudly
# instead of passing every change.
plant='tracing::info!("login with {password}");'
prose='tracing::warn!("password reset token method selected");'
if ! printf '%s\n' "$plant" | grep -Eqi "$tracing_secret"; then
  note "invariant 10: SELF-TEST FAILED — the gate no longer catches a planted {password} interpolation"
fi
if printf '%s\n' "$prose" | grep -Eqi "$tracing_secret"; then
  note "invariant 10: SELF-TEST FAILED — the gate now false-positives on benign log prose"
fi

if grep -rEni "$tracing_secret" "${SRC_GLOB[@]}" --include='*.rs' >/dev/null 2>&1; then
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
