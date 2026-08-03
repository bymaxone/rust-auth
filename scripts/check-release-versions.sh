#!/usr/bin/env bash
# Every artifact this repository publishes carries the same version, and this is
# what proves it.
#
# The workspace ships eight crates to crates.io and one package to npm, and the
# crates pin each other exactly (`=x.y.z` in `[workspace.dependencies]`). A single
# stale pin publishes a crate that cannot resolve its own sibling — and crates.io
# and npm are both append-only, so the correction is a new version, never an edit.
#
# Run with no argument to check the tree against itself. Pass a version (with or
# without the leading `v`) to also require the tree to match a tag about to be cut.
#
#   scripts/check-release-versions.sh
#   scripts/check-release-versions.sh v0.1.0
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "✗ $*" >&2
  exit 1
}

# The workspace version is the single source every crate inherits.
workspace_version=$(
  awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version[[:space:]]*=/{gsub(/[",]/,"");print $3;exit}' Cargo.toml
)
[ -n "$workspace_version" ] || fail "no version in [workspace.package] of Cargo.toml"

echo "workspace version: $workspace_version"

# Every publishable crate must resolve to it. A crate that opted out of inheritance
# would otherwise publish its own number without anything noticing.
mismatched=$(
  cargo metadata --no-deps --format-version 1 |
    python3 -c "
import json, sys
want = sys.argv[1]
for p in json.load(sys.stdin)['packages']:
    if p.get('publish') == []:      # publish = false — not our concern
        continue
    if p['version'] != want:
        print(f\"{p['name']} is {p['version']}\")
" "$workspace_version"
)
[ -z "$mismatched" ] && echo "✓ every publishable crate resolves to $workspace_version" ||
  fail "crate version mismatch:
$mismatched"

# The internal pins are exact by design; each must name the same version.
bad_pins=$(
  awk '/^\[workspace\.dependencies\]/{f=1;next} /^\[/{f=0} f && /^bymax-auth/{print}' Cargo.toml |
    grep -v "version = \"=$workspace_version\"" || true
)
[ -z "$bad_pins" ] && echo "✓ every internal pin is =$workspace_version" ||
  fail "internal pin does not name =$workspace_version:
$bad_pins"

# The npm package ships the TypeScript half of the same release.
npm_version=$(node -p "require('./packages/rust-auth/package.json').version")
[ "$npm_version" = "$workspace_version" ] &&
  echo "✓ @bymax-one/rust-auth is $npm_version" ||
  fail "@bymax-one/rust-auth is $npm_version, workspace is $workspace_version"

# And, when releasing, the tag has to agree with all of it.
if [ $# -gt 0 ]; then
  tag_version=${1#v}
  [ "$tag_version" = "$workspace_version" ] &&
    echo "✓ tag v$tag_version matches" ||
    fail "tag v$tag_version does not match the workspace version $workspace_version"
fi

echo "✓ every published artifact carries $workspace_version"
