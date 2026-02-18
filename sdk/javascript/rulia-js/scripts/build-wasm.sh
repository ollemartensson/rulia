#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PKG_ROOT}/../../.." && pwd)"

TMP_WORKSPACE="$(mktemp -d)"
cleanup() {
  rm -r "${TMP_WORKSPACE}" 2>/dev/null || true
}
trap cleanup EXIT

cp -R "${REPO_ROOT}/engine/rulia" "${TMP_WORKSPACE}/rulia"
cp -R "${REPO_ROOT}/engine/rulia-wasm" "${TMP_WORKSPACE}/rulia-wasm"

cat > "${TMP_WORKSPACE}/Cargo.toml" <<'EOF'
[workspace]
members = ["rulia", "rulia-wasm"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.82"
license = "GPL-3.0-only"
repository = "https://github.com/factflow/rulia"
keywords = ["rulia"]
categories = ["encoding"]

[workspace.dependencies]
thiserror = "2"
sha2 = "0.10"
hex = "0.4"
blake3 = "1"
criterion = "0.5"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
num-bigint = "0.4"
EOF

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
wasm-pack build "${TMP_WORKSPACE}/rulia-wasm" \
  --target nodejs \
  --out-dir "${PKG_ROOT}/pkg" \
  --release
