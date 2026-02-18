#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_TOML="$ROOT/Cargo.toml"

fail() {
  echo "error: $*" >&2
  exit 1
}

version_from_cargo() {
  awk -F '"' '
    /^\[workspace\.package\]/ {in_ws=1; next}
    in_ws && /^version = / {print $2; exit}
    in_ws && /^\[/ {exit}
  ' "$CARGO_TOML"
}

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(version_from_cargo)"
fi
[[ -n "$VERSION" ]] || fail "unable to determine version"

BASE="$ROOT/dist/releases/$VERSION"
[[ -d "$BASE" ]] || fail "missing release directory: $BASE"

mapfile -t ARCHIVES < <(
  find "$BASE" -maxdepth 1 -type f \( \
    -name "rulia-tools-${VERSION}-*.tar.gz" -o \
    -name "rulia-tools-${VERSION}-*.zip" \
  \) | LC_ALL=C sort
)

[[ ${#ARCHIVES[@]} -gt 0 ]] || fail "no archives found in $BASE"

if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD=(shasum -a 256)
else
  fail "sha256sum or shasum not found"
fi

SUMS_FILE="$BASE/SHA256SUMS"
TMP_FILE="$BASE/.SHA256SUMS.tmp"
: > "$TMP_FILE"

for file in "${ARCHIVES[@]}"; do
  hash="$(${SHA_CMD[@]} "$file" | awk '{print $1}')"
  [[ -n "$hash" ]] || fail "unable to compute sha256 for $file"
  printf '%s  %s\n' "$hash" "$(basename "$file")" >> "$TMP_FILE"
done

mv "$TMP_FILE" "$SUMS_FILE"

"$ROOT/tools/release/manifest.sh" "$VERSION"

cat <<SUMMARY
sha256sums: $SUMS_FILE
manifest: $BASE/manifest.json
SUMMARY
