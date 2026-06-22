#!/usr/bin/env bash
# Enforce the edge-wasm size budget.
#
# The gzipped `*_bg.wasm` of the npm JWT-only build (without `wasm-extra`) must stay at or
# under a fixed ceiling so the CI size gate is real, not a placeholder. The ceiling is
# documented-as-adjustable (it may be revised as `wasm-opt` output settles), but the gate
# always enforces a concrete number.
#
# Usage:
#   wasm-pack build bindings/bymax-auth-wasm --target bundler --release --out-dir pkg
#   bindings/bymax-auth-wasm/check-wasm-size.sh [pkg-dir]
#
# Override the ceiling with MAX_GZIP_KB (KiB). Default: 350.
set -euo pipefail

pkg_dir="${1:-bindings/bymax-auth-wasm/pkg}"
max_gzip_kb="${MAX_GZIP_KB:-350}"

wasm_file="$(find "$pkg_dir" -maxdepth 1 -name '*_bg.wasm' | head -n1 || true)"
if [ -z "$wasm_file" ]; then
  echo "error: no *_bg.wasm found in '$pkg_dir' — run wasm-pack build first" >&2
  exit 1
fi

gzip_bytes="$(gzip -c "$wasm_file" | wc -c | tr -d ' ')"
max_bytes=$((max_gzip_kb * 1024))
gzip_kb=$(((gzip_bytes + 1023) / 1024))

echo "edge wasm: $wasm_file"
echo "  gzipped: ${gzip_bytes} bytes (~${gzip_kb} KiB) | ceiling: ${max_gzip_kb} KiB"

if [ "$gzip_bytes" -gt "$max_bytes" ]; then
  echo "error: gzipped wasm (~${gzip_kb} KiB) exceeds the ${max_gzip_kb} KiB ceiling" >&2
  exit 1
fi

echo "ok: within the size budget"
