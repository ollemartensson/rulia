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
SUMS_FILE="$BASE/SHA256SUMS"
OUT_FILE="$BASE/manifest.json"

[[ -f "$SUMS_FILE" ]] || fail "missing SHA256SUMS: $SUMS_FILE"

ARTIFACT_COUNT=0
ARTIFACT_BASE_URL="${ARTIFACT_BASE_URL:-}"
if [[ -n "$ARTIFACT_BASE_URL" && "$ARTIFACT_BASE_URL" != */ ]]; then
  ARTIFACT_BASE_URL="${ARTIFACT_BASE_URL}/"
fi

{
  printf '{\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "artifacts": [\n'

  while IFS=' ' read -r hash file; do
    [[ -n "$hash" ]] || continue
    [[ -n "$file" ]] || continue

    target="$file"
    target="${target#rulia-tools-${VERSION}-}"
    if [[ "$target" == *.tar.gz ]]; then
      target="${target%.tar.gz}"
    elif [[ "$target" == *.zip ]]; then
      target="${target%.zip}"
    fi

    if [[ $ARTIFACT_COUNT -gt 0 ]]; then
      printf ',\n'
    fi

    printf '    {\n'
    printf '      "target": "%s",\n' "$target"
    printf '      "file": "%s",\n' "$file"
    if [[ -n "$ARTIFACT_BASE_URL" ]]; then
      printf '      "url": "%s",\n' "${ARTIFACT_BASE_URL}${file}"
    fi
    printf '      "sha256": "%s",\n' "$hash"
    printf '      "bins": ["rulia","rulia-fmt","rulia-lsp"]\n'
    printf '    }'
    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
  done < "$SUMS_FILE"

  printf '\n  ]\n'
  printf '}\n'
} > "$OUT_FILE"

[[ $ARTIFACT_COUNT -gt 0 ]] || fail "manifest contains no artifacts"

cat <<SUMMARY
manifest: $OUT_FILE
SUMMARY
