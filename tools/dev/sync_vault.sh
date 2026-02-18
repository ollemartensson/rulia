#!/bin/bash
set -e

# Configuration
VAULT_DIR="../rulia-vault"
CURRENT_DIR="$(pwd)"

if [ ! -d "$VAULT_DIR" ]; then
    echo "Error: Vault directory not found at $VAULT_DIR"
    exit 1
fi

echo "🔄 Syncing from Vault ($VAULT_DIR)..."

# Function to sync directories
sync_dir() {
    src=$1
    dst=$2
    echo "  -> $src to $dst"
    # rsync options:
    # -a: archive mode (preserve perms, times, etc.)
    # -v: verbose
    # --delete: remove files in dest that are gone in source
    # --exclude: ignore target/build artifacts
    rsync -a --delete \
        --exclude "target" \
        --exclude ".gradle" \
        --exclude "build" \
        --exclude ".git" \
        --exclude ".idea" \
        --exclude "node_modules" \
        "$VAULT_DIR/$src/" "$CURRENT_DIR/$dst/"
}

# 1. Engine (crates -> engine)
sync_dir "crates" "engine"

# 2. SDK (bindings -> sdk)
sync_dir "bindings" "sdk"

# 3. Examples (demo -> examples)
sync_dir "demo" "examples"

# 4. Include
sync_dir "include" "include"

# 5. Editors
sync_dir "editors" "editors"

# 6. Tools
sync_dir "tools/release" "tools/release"
sync_dir "tools/tree-sitter-rulia" "editors/tree-sitter-rulia"

# 7. Fuzz
sync_dir "fuzz" "fuzz"

# 8. Spec (docs -> spec)
# Note: We handle spec specially to preserve the cleanup rules
echo "  -> docs to spec (with filtering)"
rsync -a --delete \
    --exclude "archive" \
    --exclude "design" \
    --exclude "prompts" \
    --exclude "pm" \
    "$VAULT_DIR/docs/" "$CURRENT_DIR/spec/"

# 9. Re-apply License Headers
# (Since sync overwrites files, we re-run the license patch)
echo "📝 Re-applying Commercial License headers..."
find engine -name "Cargo.toml" -exec sed -i "" "s/license = \"MIT OR Apache-2.0\"/license = \"GPL-3.0-only\"/g" {} +

echo "✅ Sync complete."
echo "   Review changes with: git status"

