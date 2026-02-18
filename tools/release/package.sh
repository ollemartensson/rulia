#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
  echo "error: $*" >&2
  exit 1
}

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <version> <target>" >&2
  exit 2
fi

VERSION="$1"
TARGET="$2"

BASE="$ROOT/dist/releases/$VERSION"
TARGET_DIR="$BASE/$TARGET"
BIN_DIR="$TARGET_DIR/bin"
LIB_DIR="$TARGET_DIR/lib"
INCLUDE_DIR="$TARGET_DIR/include"

[[ -d "$BIN_DIR" ]] || fail "missing bin dir: $BIN_DIR"
[[ -d "$LIB_DIR" ]] || fail "missing lib dir: $LIB_DIR"
[[ -d "$INCLUDE_DIR" ]] || fail "missing include dir: $INCLUDE_DIR"

EXT=".tar.gz"
EXE=""
LIB_NAME=""
case "$TARGET" in
  *-pc-windows-*)
    EXT=".zip"
    EXE=".exe"
    LIB_NAME="rulia.dll"
    ;;
  *-apple-darwin*)
    EXT=".tar.gz"
    EXE=""
    LIB_NAME="librulia.dylib"
    ;;
  *)
    EXT=".tar.gz"
    EXE=""
    LIB_NAME="librulia.so"
    ;;
esac

ARCHIVE="rulia-tools-${VERSION}-${TARGET}${EXT}"
ARCHIVE_PATH="$BASE/$ARCHIVE"

for bin in rulia rulia-fmt rulia-lsp; do
  [[ -f "$BIN_DIR/${bin}${EXE}" ]] || fail "missing binary: $BIN_DIR/${bin}${EXE}"
done

[[ -f "$LIB_DIR/$LIB_NAME" ]] || fail "missing library: $LIB_DIR/$LIB_NAME"
[[ -f "$INCLUDE_DIR/rulia_ffi_v1.h" ]] || fail "missing header: $INCLUDE_DIR/rulia_ffi_v1.h"

for doc in LICENSE-APACHE LICENSE-MIT VERSION; do
  [[ -f "$TARGET_DIR/$doc" ]] || fail "missing file: $TARGET_DIR/$doc"
done

STAGE="$BASE/.stage-$TARGET"
FILELIST="$BASE/.filelist-$TARGET"
rm -rf "$STAGE" "$FILELIST"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/include"

for bin in rulia rulia-fmt rulia-lsp; do
  install -m 0755 "$BIN_DIR/${bin}${EXE}" "$STAGE/bin/${bin}${EXE}"
done

install -m 0755 "$LIB_DIR/$LIB_NAME" "$STAGE/lib/$LIB_NAME"
install -m 0644 "$INCLUDE_DIR/rulia_ffi_v1.h" "$STAGE/include/rulia_ffi_v1.h"

install -m 0644 "$TARGET_DIR/LICENSE-APACHE" "$STAGE/LICENSE-APACHE"
install -m 0644 "$TARGET_DIR/LICENSE-MIT" "$STAGE/LICENSE-MIT"
install -m 0644 "$TARGET_DIR/VERSION" "$STAGE/VERSION"

find "$STAGE" -exec touch -t 197001010000 {} +

(
  cd "$STAGE"
  LC_ALL=C find . -type f | LC_ALL=C sort | sed 's|^\./||' > "$FILELIST"
)

if [[ "$EXT" == ".zip" ]]; then
  command -v zip >/dev/null 2>&1 || fail "zip not found (required for Windows packaging)"
  (
    cd "$STAGE"
    zip -X -q "$ARCHIVE_PATH" -@ < "$FILELIST"
  )
else
  TAR_BIN="tar"
  if command -v gtar >/dev/null 2>&1; then
    TAR_BIN="gtar"
  fi

  if "$TAR_BIN" --version 2>/dev/null | grep -qi "gnu"; then
    "$TAR_BIN" --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
      -czf "$ARCHIVE_PATH" -C "$STAGE" -T "$FILELIST"
  else
    "$TAR_BIN" --mtime '1970-01-01' --uid 0 --gid 0 --uname 0 --gname 0 --numeric-owner \
      -czf "$ARCHIVE_PATH" -C "$STAGE" -T "$FILELIST"
  fi
fi

rm -rf "$STAGE" "$FILELIST"

cat <<SUMMARY
archive: $ARCHIVE_PATH
SUMMARY
