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

VERSION="$(version_from_cargo)"
[[ -n "$VERSION" ]] || fail "unable to determine version from $CARGO_TOML"

HOST_TARGET="$(rustc -vV | awk -F': ' '/^host: / {print $2; exit}')"
[[ -n "$HOST_TARGET" ]] || fail "unable to determine host target from rustc -vV"

BUILD_TARGET="${CARGO_BUILD_TARGET:-$HOST_TARGET}"

if [[ "$BUILD_TARGET" == "$HOST_TARGET" && -z "${CARGO_BUILD_TARGET:-}" ]]; then
  BUILD_DIR="$ROOT/target/release"
  CARGO_TARGET_ARGS=()
else
  BUILD_DIR="$ROOT/target/$BUILD_TARGET/release"
  CARGO_TARGET_ARGS=(--target "$BUILD_TARGET")
fi

DIST="$ROOT/dist/releases/$VERSION/$BUILD_TARGET"
BIN_DIR="$DIST/bin"
LIB_DIR="$DIST/lib"
INCLUDE_DIR="$DIST/include"
mkdir -p "$BIN_DIR" "$LIB_DIR" "$INCLUDE_DIR"

EXE=""
LIB_SRC=""
LIB_DST=""
case "$BUILD_TARGET" in
  *-pc-windows-*)
    EXE=".exe"
    LIB_SRC="rulia_ffi.dll"
    LIB_DST="rulia.dll"
    ;;
  *-apple-darwin*)
    EXE=""
    LIB_SRC="librulia_ffi.dylib"
    LIB_DST="librulia.dylib"
    ;;
  *)
    EXE=""
    LIB_SRC="librulia_ffi.so"
    LIB_DST="librulia.so"
    ;;
esac

pushd "$ROOT" >/dev/null
cargo build -p rulia-cli --release "${CARGO_TARGET_ARGS[@]}"
cargo build -p rulia-fmt --release "${CARGO_TARGET_ARGS[@]}"
cargo build -p rulia-lsp --release "${CARGO_TARGET_ARGS[@]}"
cargo build -p rulia-ffi --release "${CARGO_TARGET_ARGS[@]}"
popd >/dev/null

for bin in rulia rulia-fmt rulia-lsp; do
  SRC="$BUILD_DIR/${bin}${EXE}"
  [[ -f "$SRC" ]] || fail "missing build output: $SRC"
  install -m 0755 "$SRC" "$BIN_DIR/${bin}${EXE}"
done

LIB_SRC_PATH="$BUILD_DIR/$LIB_SRC"
[[ -f "$LIB_SRC_PATH" ]] || fail "missing build output: $LIB_SRC_PATH"
install -m 0755 "$LIB_SRC_PATH" "$LIB_DIR/$LIB_DST"

HEADER_SRC="$ROOT/include/rulia_ffi_v1.h"
[[ -f "$HEADER_SRC" ]] || fail "missing header: $HEADER_SRC"
install -m 0644 "$HEADER_SRC" "$INCLUDE_DIR/rulia_ffi_v1.h"

install -m 0644 "$ROOT/LICENSE-APACHE" "$DIST/LICENSE-APACHE"
install -m 0644 "$ROOT/LICENSE-MIT" "$DIST/LICENSE-MIT"

printf '%s\n' "$VERSION" > "$DIST/VERSION"

cat <<SUMMARY
release version: $VERSION
host target: $HOST_TARGET
build target: $BUILD_TARGET
dist dir: $DIST
binaries: rulia rulia-fmt rulia-lsp
library: $LIB_DST
header: include/rulia_ffi_v1.h
licenses: LICENSE-APACHE LICENSE-MIT
version file: VERSION
SUMMARY
